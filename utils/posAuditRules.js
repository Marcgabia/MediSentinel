// Pure analysis of POS audit records (no database access; unit tested).
//
// Wording matters: every result is an INDICATOR for human review. A missing event is only
// reported when the source system's expected-event registry includes it AND the observation
// window has elapsed, so in-flight or never-instrumented activity is not reported as "missing".
import {
  posDefinition, rulesFor, normalizeStatus, isAllowedTransition, TERMINAL_STATUSES, TRANSACTION_STATUS_TRANSITIONS
} from './posEventCatalog.js';

const isPlainObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const time = (v) => new Date(v).getTime();

export const traceOf = (record) => (isPlainObject(record?.metadata?.trace) ? record.metadata.trace : {});
export const statusOf = (values) => (isPlainObject(values) ? normalizeStatus(values.transactionStatus ?? values.status) : null);
export const paymentStatusOf = (values) => (isPlainObject(values) ? normalizeStatus(values.paymentStatus) : null);
export const transactionRefOf = (record) => {
  const trace = traceOf(record);
  if (trace.references?.transactionId) return trace.references.transactionId;
  return rulesFor(record.actionType)?.entityKind === 'TRANSACTION' ? record.entityId || null : null;
};

const hasIdentity = (p) => Boolean(p && (p.userId || p.username));
const personLabel = (p) => (p ? p.username || p.userId || null : null);
const actorOf = (record) => (record.actorUserId || record.actorUsername
  ? { userId: record.actorUserId || null, username: record.actorUsername || null, role: record.actorRole || null } : null);

// ---------------------------------------------------------------------------
// Record-level POS validation (QA: POS Event Validation)
// ---------------------------------------------------------------------------
/**
 * @param record   stored audit_logs row (raw)
 * @param options.eventType      registered event type (rules may come from DB)
 * @param options.source         source_systems row for record.sourceSystemId (or null)
 * @param options.registryCodes  Set of action codes registered as expected for the source
 * @returns [{ code, severity, message }]
 */
export const validatePosRecord = (record, { eventType = null, source, registryCodes = null } = {}) => {
  const rules = (eventType?.rules && (typeof eventType.rules === 'string' ? JSON.parse(eventType.rules) : eventType.rules)) || rulesFor(record.actionType) || {};
  const trace = traceOf(record);
  const problems = [];
  const add = (code, severity, message) => problems.push({ code, severity, message });
  const systemActor = record.metadata?.actorType === 'SYSTEM';

  if (source === null || (source && source.systemCode !== record.sourceSystemCode)) {
    add('PV_SOURCE', 'HIGH', source ? `Record names source "${record.sourceSystemCode}" but belongs to registered source "${source.systemCode}".` : 'Record references a source system that is not registered.');
  } else if (source?.isInternal) {
    add('PV_SOURCE', 'MEDIUM', `${record.actionType} is a pharmacy application event but was recorded by MediSentinel itself.`);
  }
  if (registryCodes && registryCodes.size && !registryCodes.has(record.actionType)) {
    add('PV_UNREGISTERED_EVENT', 'LOW', `${record.actionType} is not in this source system's expected event registry.`);
  }
  if (!systemActor && !record.actorUserId) {
    add('PV_USER_REFERENCE', 'LOW', 'No stable user ID (actor.userId); the user can only be identified by username.');
  }
  const occurred = time(record.occurredAt);
  const received = time(record.receivedAt);
  if (Number.isNaN(occurred) || Number.isNaN(received) || occurred - received > 300000) {
    add('PV_TIMESTAMP', 'MEDIUM', 'Event timestamp is invalid or later than the server receipt time.');
  }
  if (rules.entityTypes && record.entityType && !rules.entityTypes.includes(record.entityType)) {
    add('PV_ENTITY_TYPE', 'LOW', `Entity type "${record.entityType}" is not one of the expected types (${rules.entityTypes.join(', ')}).`);
  }
  if (rules.entityKind === 'TRANSACTION' && ['TRANSACTION', 'VOID'].includes(rules.group)) {
    const ref = trace.references?.transactionId;
    if (!ref && !record.entityId) add('PV_TRANSACTION_REFERENCE', 'MEDIUM', 'Transaction event has no transaction reference.');
    else if (ref && record.entityId && ref !== record.entityId && rules.entityTypes?.includes(record.entityType)) {
      add('PV_TRANSACTION_REFERENCE', 'MEDIUM', `Entity ID "${record.entityId}" does not match references.transactionId "${ref}".`);
    }
  }
  if (rules.expectBefore && !isPlainObject(record.previousValues)) add('PV_BEFORE_VALUES', 'MEDIUM', `${record.actionType} has no previous values (changes.before).`);
  if (rules.expectAfter && !isPlainObject(record.newValues)) add('PV_AFTER_VALUES', 'MEDIUM', `${record.actionType} has no new values (changes.after).`);
  if (rules.requiresReason && !trace.reason) add('PV_REASON', 'MEDIUM', `${record.actionType} has no reason.`);
  // Authorization on TRANSACTION_VOIDED may legitimately live on a separate approval event, so it
  // is judged at transaction level (analyzeTransaction), not here.
  if (rules.requiresAuthorization && rules.setsStatus !== 'voided') {
    const auth = trace.authorization;
    if (!auth || (!hasIdentity(auth.authorizedBy) && !auth.reference)) {
      add('PV_AUTHORIZATION', 'MEDIUM', `${record.actionType} has no authorizing user or verified authorization reference.`);
    } else if (rules.expectedAuthorizationOutcomes && auth.outcome && !rules.expectedAuthorizationOutcomes.includes(auth.outcome)) {
      add('PV_AUTHORIZATION', 'MEDIUM', `${record.actionType} reports authorization outcome ${auth.outcome} (expected ${rules.expectedAuthorizationOutcomes.join(' or ')}).`);
    }
  }
  if (rules.expectsCorrelation && !record.correlationId) add('PV_CORRELATION', 'LOW', `${record.actionType} has no correlation ID, so it cannot be linked to related events.`);
  if (rules.expectsBranch && !trace.branchId) add('PV_BRANCH', 'LOW', `${record.actionType} does not identify the branch.`);
  if (rules.report) {
    const r = trace.report || {};
    if (/EXPORTED$/.test(record.actionType) && !r.exportFormat) add('PV_REPORT_DETAILS', 'LOW', 'Report export does not state the export format.');
    if (/GENERATED$|EXPORTED$/.test(record.actionType) && !(r.reportType || (r.dateFrom && r.dateTo))) add('PV_REPORT_DETAILS', 'LOW', 'Report event does not state the report type or date range.');
  }
  if (rules.lookup && !trace.lookup?.resultStatus) add('PV_LOOKUP_RESULT', 'LOW', `${record.actionType} does not state the lookup result status.`);
  return problems;
};

// ---------------------------------------------------------------------------
// Transaction timeline analysis
// ---------------------------------------------------------------------------
const STATE_CHANGING = new Set(['TRANSACTION_UPDATED', 'CHECKOUT_COMPLETED', 'PAYMENT_RECORDED', 'TRANSACTION_STATUS_CHANGED', 'TRANSACTION_CANCELLED', 'TRANSACTION_VOID_REQUESTED', 'TRANSACTION_VOIDED']);

export const sortEvents = (events) => [...events].sort((a, b) => (time(a.occurredAt) - time(b.occurredAt)) || (Number(a.id) - Number(b.id)));

/**
 * @param events  every stored record of ONE transaction on ONE source system
 * @param opts.expectedCodes             Set of action codes the source is registered to send
 * @param opts.now                       Date
 * @param opts.observationWindowMs       wait this long after the last event before reporting a missing event
 * @param opts.voidAuthorizationRequired whether voids must name an authorizer / verified reference
 * @param opts.instrumentationStart      first TRANSACTION_CREATED ever received from the source (or null)
 */
export const analyzeTransaction = (events, {
  expectedCodes = new Set(), now = new Date(), observationWindowMs = 30 * 60000, voidAuthorizationRequired = true,
  instrumentationStart = null, transitions = TRANSACTION_STATUS_TRANSITIONS
} = {}) => {
  const ordered = sortEvents(events);
  const issues = [];
  const issue = (code, severity, message, record = null) => issues.push({ code, severity, message, auditLogId: record?.id ?? null, eventId: record?.eventId ?? null });
  const first = ordered[0];
  const last = ordered[ordered.length - 1];
  const settled = last ? time(now) - time(last.occurredAt) >= observationWindowMs : false;
  const expects = (code) => expectedCodes.has(code);

  const summary = {
    transactionRef: first ? transactionRefOf(first) || first.entityId : null,
    sourceSystemId: first?.sourceSystemId ?? null,
    sourceSystemName: first?.sourceSystemName ?? null,
    branchId: null,
    customerRef: null,
    firstAt: first?.occurredAt ?? null,
    lastAt: last?.occurredAt ?? null,
    eventCount: ordered.length,
    initialStatus: null,
    statusBeforeVoid: null,
    currentStatus: null,
    paymentStatus: null,
    statusHistory: [],
    processedBy: null,
    voidRequest: null,
    voidDecisions: [],
    voided: null,
    authorizedBy: null,
    authorizationReference: null,
    voidReason: null,
    hasVoidActivity: false
  };

  let current = null;
  let terminalAt = null;
  const successCounts = {};

  for (const record of ordered) {
    const trace = traceOf(record);
    const rules = rulesFor(record.actionType) || {};
    const success = record.outcome === 'SUCCESS';
    summary.branchId = summary.branchId || trace.branchId || null;
    summary.customerRef = summary.customerRef || trace.references?.customerId || null;
    if (rules.group === 'VOID') summary.hasVoidActivity = true;

    const ref = trace.references?.transactionId;
    if (ref && record.entityId && ref !== record.entityId && rules.entityKind === 'TRANSACTION' && rules.entityTypes?.includes(record.entityType)) {
      issue('TC_REFERENCE_MISMATCH', 'MEDIUM', `Event ${record.eventId} names entity ${record.entityId} but references transaction ${ref}.`, record);
    }
    if (!success) {
      if (record.actionType === 'TRANSACTION_VOID_REJECTED') {
        // A rejection is a real decision whether the source reports it as SUCCESS or DENIED.
        const auth = trace.authorization || {};
        summary.voidDecisions.push({ actionType: record.actionType, outcome: auth.outcome === 'FAILED' ? 'FAILED' : 'REJECTED', by: auth.authorizedBy || null, reference: auth.reference || null, method: auth.method || null, at: record.occurredAt, auditLogId: record.id });
      } else if (rules.group === 'VOID') {
        summary.voidDecisions.push({ actionType: record.actionType, outcome: record.outcome, by: actorOf(record), at: record.occurredAt, auditLogId: record.id, failed: true });
      }
      continue;
    }
    successCounts[record.actionType] = (successCounts[record.actionType] || 0) + 1;

    // ---- activity after a terminal status --------------------------------------------
    if (terminalAt && STATE_CHANGING.has(record.actionType)) {
      issue('TC_EVENT_AFTER_TERMINAL', 'MEDIUM', `${record.actionType} was recorded after the transaction became ${current}.`, record);
    }

    // ---- status tracking -------------------------------------------------------------
    const reportedFrom = statusOf(record.previousValues);
    const to = statusOf(record.newValues) || rules.setsStatus || null;
    if (!summary.initialStatus) summary.initialStatus = reportedFrom || to;
    if (reportedFrom && current && reportedFrom !== current) {
      issue('TC_STATUS_GAP', 'MEDIUM', `${record.actionType} reports previous status "${reportedFrom}" but the last recorded status was "${current}" — an intermediate change may not have been audited.`, record);
    }
    const from = reportedFrom || current;
    if (to && from && to !== from) {
      if (!isAllowedTransition(from, to, transitions)) {
        issue('TC_STATUS_TRANSITION', 'MEDIUM', `Status transition "${from}" → "${to}" is not an expected transaction flow.`, record);
      }
      summary.statusHistory.push({ from, to, at: record.occurredAt, actionType: record.actionType, auditLogId: record.id });
    } else if (to && !from) {
      summary.statusHistory.push({ from: null, to, at: record.occurredAt, actionType: record.actionType, auditLogId: record.id });
    }
    if (to === 'voided' && !summary.statusBeforeVoid) summary.statusBeforeVoid = from || null;
    if (to) current = to;
    if (current && TERMINAL_STATUSES.includes(current) && !terminalAt) terminalAt = record.occurredAt;
    const pay = paymentStatusOf(record.newValues);
    if (pay) summary.paymentStatus = pay;

    // ---- who did what ----------------------------------------------------------------
    if (record.actionType === 'CHECKOUT_COMPLETED' || (record.actionType === 'TRANSACTION_CREATED' && !summary.processedBy)) {
      summary.processedBy = actorOf(record);
    }
    if (record.actionType === 'TRANSACTION_VOID_REQUESTED') {
      if (!summary.statusBeforeVoid) summary.statusBeforeVoid = current;
      summary.voidRequest = { by: trace.authorization?.requestedBy || actorOf(record), at: record.occurredAt, reason: trace.reason || null, auditLogId: record.id };
      summary.voidReason = summary.voidReason || trace.reason || null;
    }
    if (record.actionType === 'TRANSACTION_VOID_APPROVED' || record.actionType === 'TRANSACTION_VOID_REJECTED') {
      const auth = trace.authorization || {};
      const outcome = record.actionType === 'TRANSACTION_VOID_APPROVED' ? 'APPROVED' : (auth.outcome === 'FAILED' ? 'FAILED' : 'REJECTED');
      summary.voidDecisions.push({ actionType: record.actionType, outcome, by: auth.authorizedBy || null, reference: auth.reference || null, method: auth.method || null, at: record.occurredAt, auditLogId: record.id });
      if (outcome === 'APPROVED' && (hasIdentity(auth.authorizedBy) || auth.reference)) {
        summary.authorizedBy = auth.authorizedBy || null;
        summary.authorizationReference = auth.reference || null;
      }
    }
    if (record.actionType === 'TRANSACTION_VOIDED') {
      const auth = trace.authorization || {};
      summary.voided = { by: actorOf(record), at: record.occurredAt, reason: trace.reason || null, authorizedBy: auth.authorizedBy || null, reference: auth.reference || null, outcome: auth.outcome || null, auditLogId: record.id };
      summary.voidReason = summary.voidReason || trace.reason || null;
      if (hasIdentity(auth.authorizedBy) || auth.reference) {
        summary.authorizedBy = auth.authorizedBy || summary.authorizedBy;
        summary.authorizationReference = auth.reference || summary.authorizationReference;
      }
      if (!summary.voidRequest && auth.requestedBy) summary.voidRequest = { by: auth.requestedBy, at: null, reason: trace.reason || null, auditLogId: null };

      // A void that follows a rejection with no later approval
      const decisions = summary.voidDecisions.filter((dcs) => !dcs.failed);
      const lastDecision = decisions[decisions.length - 1];
      if (lastDecision && lastDecision.outcome !== 'APPROVED') {
        issue('TC_VOID_AFTER_REJECTION', 'HIGH', 'Transaction was voided after its most recent void authorization was rejected, with no later approval recorded.', record);
      }
    }
  }
  summary.currentStatus = current;

  // ---- one-time events recorded more than once -------------------------------------------
  for (const [code, n] of Object.entries(successCounts)) {
    if (n > 1 && (rulesFor(code) || {}).oneTime) {
      issue('TC_DUPLICATE_EVENT', 'LOW', `${code} was recorded ${n} times with different event IDs (possible duplicate submission).`);
    }
  }

  // ---- expected events (only when registered AND the observation window has elapsed) ----
  const reached = (status) => summary.statusHistory.some((h) => h.to === status);
  const voidedEvent = successCounts.TRANSACTION_VOIDED > 0;
  if (settled) {
    if (reached('completed') && !successCounts.CHECKOUT_COMPLETED && expects('CHECKOUT_COMPLETED')) {
      issue('TC_COMPLETION_MISSING', 'MEDIUM', 'Transaction reached "completed" but no CHECKOUT_COMPLETED event was recorded.');
    }
    if (reached('voided') && !voidedEvent && expects('TRANSACTION_VOIDED')) {
      issue('TC_VOID_EVENT_MISSING', 'HIGH', 'Transaction status changed to "voided" but no TRANSACTION_VOIDED event was recorded.');
    }
    const decisions = summary.voidDecisions.filter((dcs) => !dcs.failed);
    const lastDecision = decisions[decisions.length - 1];
    if (lastDecision?.outcome === 'APPROVED' && expects('TRANSACTION_VOIDED')
      && !(summary.voided && time(summary.voided.at) >= time(lastDecision.at))) {
      issue('TC_APPROVED_NOT_FINALIZED', 'MEDIUM', 'Void was approved but no final TRANSACTION_VOIDED outcome was recorded.');
    }
    if (first && !successCounts.TRANSACTION_CREATED && expects('TRANSACTION_CREATED')
      && instrumentationStart && time(first.occurredAt) > time(instrumentationStart)) {
      issue('TC_CREATION_MISSING', 'LOW', 'No TRANSACTION_CREATED event was recorded although the source was already sending creation events.');
    }
  }
  if (voidedEvent) {
    if (!successCounts.TRANSACTION_VOID_REQUESTED && expects('TRANSACTION_VOID_REQUESTED') && settled) {
      issue('TC_VOID_REQUEST_MISSING', 'LOW', 'Transaction was voided without a recorded TRANSACTION_VOID_REQUESTED event.');
    }
    if (voidAuthorizationRequired && !hasIdentity(summary.authorizedBy) && !summary.authorizationReference) {
      issue('TC_VOID_AUTHORIZATION_MISSING', 'HIGH', 'Transaction was voided without an authorizing user or verified authorization reference.', ordered.find((r) => r.id === summary.voided?.auditLogId));
    }
  }

  return { summary, issues };
};

// ---------------------------------------------------------------------------
// Void investigation indicators
// ---------------------------------------------------------------------------
export const VOID_INDICATORS = {
  MISSING_REASON: 'Missing void reason',
  MISSING_AUTHORIZATION: 'Missing authorization reference',
  FAILED_AUTHORIZATION: 'Failed or rejected authorization',
  REPEATED_VOIDS: 'Repeated void activity by requester',
  INCONSISTENT_STATUS: 'Inconsistent transaction status',
  SELF_AUTHORIZED: 'Requester authorized own void'
};
const STATUS_ISSUES = new Set(['TC_STATUS_TRANSITION', 'TC_STATUS_GAP', 'TC_EVENT_AFTER_TERMINAL', 'TC_VOID_AFTER_REJECTION', 'TC_VOID_EVENT_MISSING', 'TC_APPROVED_NOT_FINALIZED']);

export const requesterKey = (sourceSystemId, person) => (person ? `${sourceSystemId}|${person.userId || `u:${person.username}`}` : null);

/** Indicators are prompts for review — they never imply wrongdoing by themselves. */
export const voidIndicators = ({ summary, issues }, { repeatedVoidCounts = new Map(), threshold = 3 } = {}) => {
  const out = [];
  const add = (code, detail) => out.push({ code, label: VOID_INDICATORS[code], detail });
  const voidEventsNeedingReason = [summary.voidRequest, summary.voided].filter(Boolean);
  if (voidEventsNeedingReason.length && voidEventsNeedingReason.every((e) => !e.reason)) add('MISSING_REASON', 'No reason was recorded on the void request or the void.');
  if (issues.some((i) => i.code === 'TC_VOID_AUTHORIZATION_MISSING')) add('MISSING_AUTHORIZATION', 'No authorizing user or verified reference was recorded.');
  const failed = summary.voidDecisions.filter((dcs) => dcs.failed || dcs.outcome !== 'APPROVED');
  if (failed.length) add('FAILED_AUTHORIZATION', `${failed.length} rejected or failed void authorization attempt(s).`);
  const requester = summary.voidRequest?.by || null;
  const count = repeatedVoidCounts.get(requesterKey(summary.sourceSystemId, requester)) || 0;
  if (requester && count >= threshold) add('REPEATED_VOIDS', `${personLabel(requester)} requested ${count} voids in the configured window.`);
  const statusIssues = issues.filter((i) => STATUS_ISSUES.has(i.code));
  if (statusIssues.length) add('INCONSISTENT_STATUS', statusIssues.map((i) => i.message).join(' '));
  const authorizer = summary.authorizedBy;
  if (requester && authorizer && ((requester.userId && requester.userId === authorizer.userId) || (!requester.userId && requester.username && requester.username === authorizer.username))) {
    add('SELF_AUTHORIZED', `${personLabel(requester)} both requested and authorized the void.`);
  }
  return out;
};

// ---------------------------------------------------------------------------
// Configuration continuity: a recorded "before" value that differs from the last recorded
// "after" value means a change happened in between without a corresponding audit record.
// ---------------------------------------------------------------------------
export const configurationGaps = (events) => {
  const gaps = [];
  const known = new Map(); // field -> { value, auditLogId }
  for (const record of sortEvents(events)) {
    if (record.outcome !== 'SUCCESS') continue;
    if (isPlainObject(record.previousValues)) {
      for (const [field, value] of Object.entries(record.previousValues)) {
        const prior = known.get(field);
        if (prior && JSON.stringify(prior.value) !== JSON.stringify(value)) {
          gaps.push({ field, recordedAfter: prior.value, reportedBefore: value, auditLogId: record.id, previousAuditLogId: prior.auditLogId, eventId: record.eventId });
        }
      }
    }
    if (isPlainObject(record.newValues)) {
      for (const [field, value] of Object.entries(record.newValues)) known.set(field, { value, auditLogId: record.id });
    }
  }
  return gaps;
};

export const isPosEvent = (code) => Boolean(posDefinition(code));
