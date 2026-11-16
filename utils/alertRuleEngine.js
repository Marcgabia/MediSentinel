import { SEVERITY_RANK } from './auditConstants.js';

/**
 * Pure rule-evaluation helpers. The alert service supplies counts from the database;
 * these functions decide whether an event is relevant to a rule, how events are grouped,
 * and whether a threshold has been reached. Alerts are investigation indicators, not proof.
 */

const hourInTimezone = (date, timezone) => {
  try {
    const parts = new Intl.DateTimeFormat('en-US', { hour: 'numeric', hourCycle: 'h23', timeZone: timezone || 'UTC' }).formatToParts(date);
    return Number(parts.find((p) => p.type === 'hour').value);
  } catch {
    return date.getUTCHours();
  }
};

export const isOutsideBusinessHours = (date, { startHour = 7, endHour = 21, timezone = 'UTC' } = {}) => {
  const hour = hourInTimezone(date, timezone);
  return startHour <= endHour ? (hour < startHour || hour >= endHour) : (hour < startHour && hour >= endHour);
};

/** Does a stored audit event match the selection criteria of a rule? */
export const eventMatchesRule = (rule, event) => {
  if (!rule || !rule.isEnabled || rule.ruleType === 'API_AUTH_FAILURE') return false;
  const p = rule.params || {};
  const checks = [];
  if (Array.isArray(p.actions) && p.actions.length) checks.push(p.actions.includes(event.actionType));
  if (Array.isArray(p.outcomes) && p.outcomes.length) checks.push(p.outcomes.includes(event.outcome));
  if (Array.isArray(p.categories) && p.categories.length) checks.push(p.categories.includes(event.actionCategory));
  if (p.minSeverity) checks.push((SEVERITY_RANK[event.severity] ?? 0) >= (SEVERITY_RANK[p.minSeverity] ?? 0));
  if (Array.isArray(p.sourceSystemIds) && p.sourceSystemIds.length) checks.push(p.sourceSystemIds.map(Number).includes(Number(event.sourceSystemId)));

  let matched;
  if (!checks.length) matched = true;
  else if (p.matchMode === 'any') matched = checks.some(Boolean);
  else matched = checks.every(Boolean);

  if (matched && rule.ruleType === 'OFF_HOURS') {
    matched = isOutsideBusinessHours(new Date(event.occurredAt), p);
  }
  return matched;
};

/** Key that identifies "the same pattern" for counting and alert de-duplication. */
export const groupKeyFor = (rule, event) => {
  const groupBy = rule.params?.groupBy || 'actor';
  if (groupBy === 'source') return `source:${event.sourceSystemId}`;
  if (groupBy === 'event') return `event:${event.id}`;
  return `actor:${event.sourceSystemId}:${(event.actorUserId || event.actorUsername || 'unknown').toLowerCase()}`;
};

export const fingerprintFor = (rule, event) => `${rule.code}|${groupKeyFor(rule, event)}`;

export const thresholdReached = (rule, count) => Number(count) >= Math.max(1, Number(rule.threshold) || 1);

export const windowStartFor = (rule, reference = new Date()) =>
  new Date(reference.getTime() - Math.max(1, Number(rule.windowMinutes) || 1) * 60000);

export const describeAlert = (rule, event, count) => {
  const who = event.actorUsername || event.actorUserId || 'unknown user';
  const groupBy = rule.params?.groupBy || 'actor';
  if (groupBy === 'event') {
    return `${event.actionType} on ${event.entityType || 'record'} ${event.entityId || ''} by ${who} (${event.sourceSystemName}).`.replace(/\s+/g, ' ');
  }
  const subject = groupBy === 'source' ? event.sourceSystemName : `${who} on ${event.sourceSystemName}`;
  return `${count} events by ${subject} within ${rule.windowMinutes} min (limit ${rule.threshold}).`;
};
