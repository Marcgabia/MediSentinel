import { Op } from 'sequelize';
import { sequelize, Alert, AlertActivity, AlertRule, AuditLog, IntegrationLog, SourceSystem, User, InvestigationCase } from '../models/index.js';
import {
  eventMatchesRule, fingerprintFor, thresholdReached, describeAlert
} from '../utils/alertRuleEngine.js';
import { ALERT_ACTIVE_STATUSES, ALERT_STATUSES, SEVERITY_RANK } from '../utils/auditConstants.js';
import { notifyPermission, notifyUsers } from './notificationService.js';

export const formatAlertId = (id) => `ALR-${String(id).padStart(6, '0')}`;

let ruleCache = null;
let ruleCacheAt = 0;
export const invalidateRuleCache = () => { ruleCache = null; };

const enabledRules = async () => {
  if (ruleCache && Date.now() - ruleCacheAt < 15000) return ruleCache;
  ruleCache = await AlertRule.findAll({ where: { isEnabled: true }, raw: true });
  ruleCacheAt = Date.now();
  return ruleCache;
};

/** Build a WHERE clause selecting the events that count toward `rule` for the same group as `event`. */
export const buildRuleWhere = (rule, event) => {
  const p = rule.params || {};
  const windowEnd = new Date(event.occurredAt);
  const windowStart = new Date(windowEnd.getTime() - Math.max(1, rule.windowMinutes) * 60000);
  const where = { occurredAt: { [Op.between]: [windowStart, windowEnd] } };

  const criteria = [];
  if (p.actions?.length) criteria.push({ actionType: { [Op.in]: p.actions } });
  if (p.outcomes?.length) criteria.push({ outcome: { [Op.in]: p.outcomes } });
  if (p.categories?.length) criteria.push({ actionCategory: { [Op.in]: p.categories } });
  if (p.minSeverity) {
    const allowed = Object.keys(SEVERITY_RANK).filter((s) => s !== 'INFORMATIONAL' && SEVERITY_RANK[s] >= SEVERITY_RANK[p.minSeverity]);
    criteria.push({ severity: { [Op.in]: allowed } });
  }
  if (criteria.length) {
    if (p.matchMode === 'any') where[Op.or] = criteria;
    else where[Op.and] = criteria;
  }

  const groupBy = p.groupBy || 'actor';
  where.sourceSystemId = event.sourceSystemId;
  if (groupBy === 'actor') {
    if (event.actorUserId) where.actorUserId = event.actorUserId;
    else if (event.actorUsername) where.actorUsername = event.actorUsername;
    else { where.actorUserId = null; where.actorUsername = null; }
  }
  if (groupBy === 'event') where.id = event.id;
  return where;
};

const severityNotificationType = (severity) => (severity === 'CRITICAL' ? 'CRITICAL_AUDIT_ALERT' : 'SUSPICIOUS_ACTIVITY');

const upsertAlert = async ({ detectedAt, rule, fingerprint, sourceSystemId, actorUserId, actorUsername, relatedAuditLogId, relatedEventIds, count, title, description, details, notificationType }) => {
  const now = detectedAt ? new Date(detectedAt) : new Date();
  return sequelize.transaction(async (transaction) => {
    const existing = await Alert.findOne({
      where: { fingerprint, status: { [Op.in]: ALERT_ACTIVE_STATUSES } },
      order: [['id', 'DESC']],
      transaction,
      lock: transaction.LOCK.UPDATE
    });
    if (existing) {
      const ids = [...new Set([...(existing.relatedEventIds || []), ...relatedEventIds])].slice(-200);
      await existing.update({ occurrenceCount: existing.occurrenceCount + 1, lastDetectedAt: now, relatedEventIds: ids, description }, { transaction });
      return { alert: existing, created: false };
    }
    const alert = await Alert.create({
      ruleId: rule.id || null,
      alertType: rule.code,
      title,
      description,
      severity: rule.severity,
      status: 'OPEN',
      sourceSystemId: sourceSystemId || null,
      actorUserId: actorUserId || null,
      actorUsername: actorUsername || null,
      relatedAuditLogId: relatedAuditLogId || null,
      relatedEventIds,
      occurrenceCount: count,
      fingerprint,
      firstDetectedAt: now,
      lastDetectedAt: now,
      details
    }, { transaction });
    await AlertActivity.create({ alertId: alert.id, activityType: 'DETECTED', toStatus: 'OPEN', note: description }, { transaction });
    return { alert, created: true };
  }).then(async (result) => {
    if (result.created) {
      await notifyPermission('alerts.view', {
        type: notificationType || severityNotificationType(rule.severity),
        severity: rule.severity,
        title: `${formatAlertId(result.alert.id)} · ${title}`,
        message: description,
        link: `/alerts/${result.alert.id}`,
        relatedAlertId: result.alert.id,
        relatedAuditLogId: relatedAuditLogId || null
      });
    }
    return result;
  });
};

/** Evaluate every enabled rule against a newly stored audit event. Never throws. */
export const evaluateEvent = async (record) => {
  const event = record.get ? record.get({ plain: true }) : record;
  const triggered = [];
  try {
    const rules = await enabledRules();
    for (const rule of rules) {
      if (!eventMatchesRule(rule, event)) continue;
      const where = buildRuleWhere(rule, event);
      const groupBy = rule.params?.groupBy || 'actor';
      const count = rule.ruleType === 'OFF_HOURS' || groupBy === 'event' ? 1 : await AuditLog.count({ where });
      if (!thresholdReached(rule, count)) continue;
      const related = groupBy === 'event'
        ? [event.id]
        : (await AuditLog.findAll({ where, attributes: ['id'], order: [['id', 'DESC']], limit: 100, raw: true })).map((r) => r.id);
      const result = await upsertAlert({
        detectedAt: event.receivedAt,
        rule,
        fingerprint: fingerprintFor(rule, event),
        sourceSystemId: event.sourceSystemId,
        actorUserId: event.actorUserId,
        actorUsername: event.actorUsername,
        relatedAuditLogId: event.id,
        relatedEventIds: related.map(Number),
        count,
        title: rule.name,
        description: describeAlert(rule, event, count),
        details: { windowMinutes: rule.windowMinutes, threshold: rule.threshold, observedCount: count, sourceSystemName: event.sourceSystemName }
      });
      triggered.push(result);
    }
  } catch (error) {
    console.error('[alerts] rule evaluation failed:', error.message);
  }
  return triggered;
};

/** Called after an API authentication failure has been written to integration_logs. */
export const evaluateApiAuthFailure = async ({ keyId, ipAddress, sourceSystemId }) => {
  try {
    const rule = (await enabledRules()).find((r) => r.ruleType === 'API_AUTH_FAILURE');
    if (!rule) return null;
    const since = new Date(Date.now() - rule.windowMinutes * 60000);
    const where = { outcome: 'REJECTED_AUTH', createdAt: { [Op.gte]: since } };
    if (keyId) where.keyId = keyId; else where.ipAddress = ipAddress || null;
    const count = await IntegrationLog.count({ where });
    if (!thresholdReached(rule, count)) return null;
    const subject = keyId ? `key ${keyId}` : `address ${ipAddress || 'unknown'}`;
    return upsertAlert({
      rule,
      fingerprint: `${rule.code}|${keyId ? `key:${keyId}` : `ip:${ipAddress}`}`,
      sourceSystemId,
      actorUserId: null,
      actorUsername: keyId || ipAddress || 'unknown',
      relatedAuditLogId: null,
      relatedEventIds: [],
      count,
      title: rule.name,
      description: `${count} failed API sign-ins from ${subject} within ${rule.windowMinutes} min.`,
      details: { keyId, ipAddress, observedCount: count },
      notificationType: 'REPEATED_AUTH_FAILURE'
    });
  } catch (error) {
    console.error('[alerts] API auth evaluation failed:', error.message);
    return null;
  }
};

// ---------------------------------------------------------------------------
// Alert management
// ---------------------------------------------------------------------------
const includeAll = [
  { model: SourceSystem, as: 'sourceSystem', attributes: ['id', 'name', 'systemCode'] },
  { model: User, as: 'assignedTo', attributes: ['id', 'fullName', 'username'] },
  { model: AlertRule, as: 'rule', attributes: ['id', 'code', 'name'] }
];

export const listAlerts = async ({ status, severity, sourceSystemId, alertType, search, page = 1, limit = 25 }) => {
  const where = {};
  if (status === 'active') where.status = { [Op.in]: ALERT_ACTIVE_STATUSES };
  else if (ALERT_STATUSES.includes(status)) where.status = status;
  if (severity) where.severity = severity;
  if (sourceSystemId) where.sourceSystemId = sourceSystemId;
  if (alertType) where.alertType = alertType;
  if (search) where[Op.or] = [{ title: { [Op.like]: `%${search}%` } }, { actorUsername: { [Op.like]: `%${search}%` } }, { description: { [Op.like]: `%${search}%` } }];
  const { rows, count } = await Alert.findAndCountAll({
    where, include: includeAll, order: [['lastDetectedAt', 'DESC']], limit, offset: (page - 1) * limit, distinct: true
  });
  return { rows: rows.map((a) => ({ ...a.get({ plain: true }), alertCode: formatAlertId(a.id) })), count };
};

export const getAlert = async (id) => {
  const alert = await Alert.findByPk(id, {
    include: [
      ...includeAll,
      { model: User, as: 'acknowledgedBy', attributes: ['id', 'fullName'] },
      { model: User, as: 'resolvedBy', attributes: ['id', 'fullName'] },
      { model: AuditLog, as: 'relatedAuditLog' },
      { model: AlertActivity, as: 'activities', include: [{ model: User, as: 'user', attributes: ['id', 'fullName', 'username'] }] }
    ],
    order: [[{ model: AlertActivity, as: 'activities' }, 'createdAt', 'ASC']]
  });
  if (!alert) return null;
  const plain = alert.get({ plain: true });
  const relatedIds = (plain.relatedEventIds || []).slice(-50);
  const relatedEvents = relatedIds.length
    ? await AuditLog.findAll({ where: { id: { [Op.in]: relatedIds } }, order: [['occurredAt', 'DESC']], raw: true })
    : [];
  const cases = await InvestigationCase.findAll({ where: { originAlertId: plain.id }, attributes: ['id', 'caseNumber', 'status'], raw: true });
  return { ...plain, alertCode: formatAlertId(plain.id), relatedEvents, cases };
};

export const alertCounts = async () => {
  const rows = await Alert.findAll({
    attributes: ['status', 'severity', [sequelize.fn('COUNT', sequelize.col('id')), 'count']],
    group: ['status', 'severity'], raw: true
  });
  const active = rows.filter((r) => ALERT_ACTIVE_STATUSES.includes(r.status));
  return {
    active: active.reduce((s, r) => s + Number(r.count), 0),
    activeCritical: active.filter((r) => r.severity === 'CRITICAL').reduce((s, r) => s + Number(r.count), 0),
    activeHigh: active.filter((r) => r.severity === 'HIGH').reduce((s, r) => s + Number(r.count), 0),
    total: rows.reduce((s, r) => s + Number(r.count), 0)
  };
};

/**
 * Apply a management action to an alert. Returns { alert, before, after } for audit recording.
 * action ∈ acknowledge | assign | note | investigate | resolve | dismiss | reopen
 */
export const applyAlertAction = async (id, action, { userId, note, assigneeId }, transaction) => {
  const alert = await Alert.findByPk(id, { transaction, lock: transaction.LOCK.UPDATE });
  if (!alert) { const e = new Error('Alert not found'); e.status = 404; throw e; }
  const before = { status: alert.status, assignedToUserId: alert.assignedToUserId };
  const now = new Date();
  const activity = { alertId: alert.id, userId, fromStatus: alert.status, note: note || null };
  const isActive = ALERT_ACTIVE_STATUSES.includes(alert.status);
  const fail = (msg) => { const e = new Error(msg); e.status = 400; throw e; };

  switch (action) {
    case 'acknowledge':
      if (alert.status !== 'OPEN') fail('Only OPEN alerts can be acknowledged.');
      await alert.update({ status: 'ACKNOWLEDGED', acknowledgedByUserId: userId, acknowledgedAt: now }, { transaction });
      activity.activityType = 'ACKNOWLEDGED';
      break;
    case 'assign': {
      if (!isActive) fail('Closed alerts cannot be assigned.');
      const assignee = await User.findByPk(assigneeId, { include: [{ association: 'role' }], transaction });
      if (!assignee || !assignee.isActive) fail('Select an active user to assign.');
      if (!(assignee.role?.permissions || []).includes('alerts.manage')) fail('The selected user is not permitted to manage alerts.');
      await alert.update({ assignedToUserId: assignee.id, status: 'INVESTIGATING' }, { transaction });
      activity.activityType = 'ASSIGNED';
      activity.note = `Assigned to ${assignee.fullName}${note ? ` — ${note}` : ''}`;
      break;
    }
    case 'note':
      if (!note || !note.trim()) fail('Note text is required.');
      activity.activityType = 'NOTE';
      break;
    case 'investigate':
      if (!isActive) fail('Closed alerts cannot be moved to investigation.');
      await alert.update({ status: 'INVESTIGATING' }, { transaction });
      activity.activityType = 'STATUS_CHANGED';
      break;
    case 'resolve':
      if (!isActive) fail('Alert is already closed.');
      if (!note || !note.trim()) fail('Resolution notes are required.');
      await alert.update({ status: 'RESOLVED', resolvedByUserId: userId, resolvedAt: now, resolutionNotes: note }, { transaction });
      activity.activityType = 'RESOLVED';
      break;
    case 'dismiss':
      if (!isActive) fail('Alert is already closed.');
      if (!note || !note.trim()) fail('A reason is required to dismiss an alert.');
      await alert.update({ status: 'DISMISSED', resolvedByUserId: userId, resolvedAt: now, resolutionNotes: note }, { transaction });
      activity.activityType = 'DISMISSED';
      break;
    case 'reopen':
      if (isActive) fail('Alert is already open.');
      await alert.update({ status: 'OPEN', resolvedAt: null, resolvedByUserId: null }, { transaction });
      activity.activityType = 'STATUS_CHANGED';
      break;
    default:
      fail('Unknown alert action.');
  }
  activity.toStatus = alert.status;
  await AlertActivity.create(activity, { transaction });
  return { alert, before, after: { status: alert.status, assignedToUserId: alert.assignedToUserId }, assigneeId: action === 'assign' ? alert.assignedToUserId : null };
};

export const notifyAlertAssignee = (alert, assigneeId) => notifyUsers([assigneeId], {
  type: 'SUSPICIOUS_ACTIVITY',
  severity: alert.severity,
  title: `${formatAlertId(alert.id)} assigned to you`,
  message: alert.title,
  link: `/alerts/${alert.id}`,
  relatedAlertId: alert.id
});

// ---------------------------------------------------------------------------
// Rule configuration
// ---------------------------------------------------------------------------
export const listRules = () => AlertRule.findAll({ order: [['ruleType', 'ASC'], ['name', 'ASC']], raw: true });

export const updateRule = async (id, input, userId, transaction) => {
  const rule = await AlertRule.findByPk(id, { transaction });
  if (!rule) { const e = new Error('Rule not found'); e.status = 404; throw e; }
  const before = { threshold: rule.threshold, windowMinutes: rule.windowMinutes, severity: rule.severity, isEnabled: rule.isEnabled, params: rule.params };
  const threshold = Number.parseInt(input.threshold, 10);
  const windowMinutes = Number.parseInt(input.windowMinutes, 10);
  if (!(threshold >= 1 && threshold <= 100000)) { const e = new Error('Threshold must be between 1 and 100000.'); e.status = 400; throw e; }
  if (!(windowMinutes >= 1 && windowMinutes <= 10080)) { const e = new Error('Window must be between 1 and 10080 minutes.'); e.status = 400; throw e; }
  if (!['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].includes(input.severity)) { const e = new Error('Invalid severity.'); e.status = 400; throw e; }
  const params = { ...(rule.params || {}) };
  if (rule.ruleType === 'OFF_HOURS') {
    const startHour = Number.parseInt(input.startHour, 10);
    const endHour = Number.parseInt(input.endHour, 10);
    if (startHour >= 0 && startHour <= 23) params.startHour = startHour;
    if (endHour >= 0 && endHour <= 23) params.endHour = endHour;
    if (input.timezone) {
      try { new Intl.DateTimeFormat('en-US', { timeZone: input.timezone }); params.timezone = input.timezone; } catch { /* keep previous */ }
    }
  }
  await rule.update({ threshold, windowMinutes, severity: input.severity, isEnabled: input.isEnabled === 'on' || input.isEnabled === true || input.isEnabled === 'true', params, updatedByUserId: userId }, { transaction });
  invalidateRuleCache();
  return { rule, before, after: { threshold: rule.threshold, windowMinutes: rule.windowMinutes, severity: rule.severity, isEnabled: rule.isEnabled, params: rule.params } };
};
