import crypto from 'crypto';
import { Op } from 'sequelize';
import {
  sequelize, AuditLog, SourceSystem, Alert, InvestigationCaseEvent, InvestigationCase, IntegrationLog, AuditEventType
} from '../models/index.js';
import { INTERNAL_SOURCE_CODE, EVENT_SEVERITIES, EVENT_OUTCOMES, EVENT_CATEGORIES } from '../utils/auditConstants.js';
import { ingestEvent } from './auditIngestionService.js';
import { verifyStoredRecord } from './auditIntegrityService.js';
import { diffChanges, summarizeDiff } from '../utils/changeDiff.js';
import { ROUTINE_CODES } from '../utils/posEventCatalog.js';
import { transactionRefOf } from '../utils/posAuditRules.js';

let internalSource = null;
export const getInternalSource = async () => {
  if (!internalSource) {
    const row = await SourceSystem.findOne({ where: { systemCode: INTERNAL_SOURCE_CODE } });
    if (!row) throw new Error('Internal MediSentinel source system is missing. Run `npm run migrate`.');
    internalSource = row.get({ plain: true });
  }
  return internalSource;
};
export const resetInternalSourceCache = () => { internalSource = null; };

const clientIp = (req) => {
  const raw = req?.ip || req?.socket?.remoteAddress || null;
  if (!raw) return null;
  return raw.startsWith('::ffff:') ? raw.slice(7) : raw;
};

/**
 * Record a MediSentinel governance event in the central (integrity-protected) audit trail.
 * Passes through exactly the same validation + sealing pipeline as external events.
 */
export const recordInternalEvent = async ({
  user, req, action, module, entity, description, before = null, after = null,
  outcome = 'SUCCESS', severity, metadata, correlationId, transaction
}) => {
  const source = await getInternalSource();
  const actor = user
    ? {
      userId: user.id !== undefined && user.id !== null ? String(user.id) : undefined,
      username: user.username ? String(user.username).slice(0, 150) : undefined,
      role: user.roleCode || user.role?.code || (typeof user.role === 'string' ? user.role : undefined)
    }
    : { type: 'SYSTEM', username: 'medisentinel' };
  const payload = {
    eventId: `MS-${crypto.randomUUID()}`,
    occurredAt: new Date().toISOString(),
    sourceSystem: INTERNAL_SOURCE_CODE,
    sourceModule: module,
    actor,
    action,
    entity: entity ? { type: entity.type, id: String(entity.id) } : undefined,
    description,
    changes: before || after ? { before: before || null, after: after || null } : undefined,
    outcome,
    severity,
    correlationId: correlationId || req?.correlationId,
    context: req ? { ipAddress: clientIp(req) || undefined, userAgent: req.get?.('user-agent')?.slice(0, 512) } : undefined,
    metadata
  };
  if (payload.context && !payload.context.ipAddress) delete payload.context.ipAddress;
  const result = await ingestEvent({ payload, sourceSystem: source, channel: 'INTERNAL', transaction, skipIntegrationLog: true });
  if (result.status !== 'accepted') {
    throw new Error(`Internal audit event rejected: ${JSON.stringify(result.errors)}`);
  }
  return result.auditLog;
};

// ---------------------------------------------------------------------------
// Search
// ---------------------------------------------------------------------------
const parseDate = (value, endOfDay = false) => {
  if (!value) return null;
  const str = String(value);
  const date = /^\d{4}-\d{2}-\d{2}$/.test(str) ? new Date(`${str}T${endOfDay ? '23:59:59.999' : '00:00:00.000'}`) : new Date(str);
  return Number.isNaN(date.getTime()) ? null : date;
};

/** Translate query-string filters into a Sequelize WHERE clause (pure; unit tested). */
export const buildAuditWhere = (q = {}) => {
  const where = {};
  const and = [];
  if (q.q) {
    const term = `%${String(q.q).trim()}%`;
    and.push({ [Op.or]: [
      { actorUsername: { [Op.like]: term } }, { eventId: { [Op.like]: term } },
      { entityId: { [Op.like]: term } }, { description: { [Op.like]: term } }, { correlationId: { [Op.like]: term } }
    ] });
  }
  if (q.username) where.actorUsername = { [Op.like]: `%${String(q.username).trim()}%` };
  if (q.actorUserId) where.actorUserId = String(q.actorUserId);
  if (q.eventId) where.eventId = String(q.eventId).trim();
  if (q.entityId) where.entityId = String(q.entityId).trim();
  if (q.entityType) where.entityType = String(q.entityType).trim();
  if (q.description) where.description = { [Op.like]: `%${String(q.description).trim()}%` };
  if (q.correlationId) where.correlationId = String(q.correlationId).trim();
  if (q.sourceSystemId) where.sourceSystemId = Number(q.sourceSystemId);
  if (q.sourceModule) where.sourceModule = String(q.sourceModule);
  if (q.actionType) where.actionType = Array.isArray(q.actionType) ? { [Op.in]: q.actionType } : String(q.actionType);
  if (q.actorRole) where.actorRole = String(q.actorRole);
  if (q.category && EVENT_CATEGORIES.includes(q.category)) where.actionCategory = q.category;
  if (q.severity && EVENT_SEVERITIES.includes(q.severity)) where.severity = q.severity;
  if (q.outcome && EVENT_OUTCOMES.includes(q.outcome)) where.outcome = q.outcome;
  if (q.excludeInternal === 'true' || q.excludeInternal === true) where.sourceSystemCode = { [Op.ne]: INTERNAL_SOURCE_CODE };
  // Generated column derived from the sealed metadata.trace.branchId
  if (q.branchId) and.push(sequelize.where(sequelize.col('branchId'), String(q.branchId).trim()));
  if (q.hideRoutine === 'true' || q.hideRoutine === true) and.push({ actionType: { [Op.notIn]: ROUTINE_CODES } });
  const from = parseDate(q.from);
  const to = parseDate(q.to, true);
  if (from || to) {
    where.occurredAt = {};
    if (from) where.occurredAt[Op.gte] = from;
    if (to) where.occurredAt[Op.lte] = to;
  }
  if (and.length) where[Op.and] = and;
  return where;
};

export const searchAuditLogs = async (q, { limit, offset }) => {
  const where = buildAuditWhere(q);
  const direction = q.sort === 'oldest' ? 'ASC' : 'DESC';
  const { rows, count } = await AuditLog.findAndCountAll({
    where,
    attributes: { exclude: ['previousValues', 'newValues', 'metadata', 'userAgent'] },
    order: [['occurredAt', direction], ['id', direction]],
    limit, offset, raw: true
  });
  return { rows, count };
};

export const getFilterOptions = async () => {
  const [sources, modules, roles, eventTypes] = await Promise.all([
    SourceSystem.findAll({ attributes: ['id', 'name', 'systemCode', 'isInternal'], order: [['isInternal', 'ASC'], ['name', 'ASC']], raw: true }),
    sequelize.query('SELECT DISTINCT sourceModule AS v FROM audit_logs ORDER BY v LIMIT 300', { type: sequelize.QueryTypes.SELECT }),
    sequelize.query('SELECT DISTINCT actorRole AS v FROM audit_logs WHERE actorRole IS NOT NULL ORDER BY v LIMIT 300', { type: sequelize.QueryTypes.SELECT }),
    AuditEventType.findAll({ attributes: ['code', 'name', 'category'], order: [['category', 'ASC'], ['name', 'ASC']], raw: true })
  ]);
  return {
    sources,
    modules: modules.map((m) => m.v),
    roles: roles.map((r) => r.v),
    eventTypes,
    severities: EVENT_SEVERITIES,
    outcomes: EVENT_OUTCOMES,
    categories: EVENT_CATEGORIES
  };
};

export const getAuditDetail = async (id) => {
  const record = await AuditLog.findByPk(id);
  if (!record) return null;
  const log = record.get({ plain: true });
  const integrity = await verifyStoredRecord(log);
  const diffRows = diffChanges(log.previousValues, log.newValues);
  const [alerts, caseLinks, correlated, integrationLog, eventType] = await Promise.all([
    Alert.findAll({
      where: { [Op.or]: [{ relatedAuditLogId: log.id }, sequelize.where(sequelize.fn('JSON_CONTAINS', sequelize.col('relatedEventIds'), String(log.id)), 1)] },
      order: [['createdAt', 'DESC']], limit: 20, raw: true
    }),
    InvestigationCaseEvent.findAll({ where: { auditLogId: log.id }, include: [{ model: InvestigationCase, as: 'case', attributes: ['id', 'caseNumber', 'title', 'status'] }] }),
    log.correlationId
      ? AuditLog.findAll({ where: { correlationId: log.correlationId, id: { [Op.ne]: log.id } }, attributes: ['id', 'eventId', 'actionType', 'sourceSystemName', 'occurredAt', 'outcome'], order: [['occurredAt', 'ASC']], limit: 50, raw: true })
      : [],
    IntegrationLog.findOne({ where: { auditLogId: log.id, outcome: 'ACCEPTED' }, raw: true }),
    AuditEventType.findOne({ where: { code: log.actionType }, raw: true })
  ]);
  const trace = log.metadata?.trace || null;
  return {
    log,
    trace,
    transactionRef: transactionRefOf(log),
    eventType,
    integrity,
    diffRows,
    diffSummary: summarizeDiff(diffRows),
    hasChanges: Boolean(log.previousValues || log.newValues),
    alerts: alerts.map((a) => ({ ...a, alertCode: `ALR-${String(a.id).padStart(6, '0')}` })),
    cases: caseLinks.map((l) => l.case.get({ plain: true })),
    correlated,
    integrationLog,
    deliveryDelayMs: new Date(log.receivedAt).getTime() - new Date(log.occurredAt).getTime()
  };
};
