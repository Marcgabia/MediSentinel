import { Op } from 'sequelize';
import {
  sequelize, AuditLog, AuditEventType, AuditEventRegistry, SourceSystem, IdentityMapping, InvestigationCaseEvent,
  InvestigationCase, InvestigationNote, QaFinding, User
} from '../models/index.js';
import { INTERNAL_SOURCE_CODE, POS_QA_CATEGORIES } from '../utils/auditConstants.js';
import {
  POS_EVENT_DEFINITIONS, POS_EVENT_CODES, POS_GROUPS, TRANSACTION_CODES, VOID_CODES, CUSTOMER_CODES,
  CONFIGURATION_CODES, ROUTINE_CODES, codesInGroup, rulesFor
} from '../utils/posEventCatalog.js';
import {
  analyzeTransaction, voidIndicators, transactionRefOf, traceOf, requesterKey, sortEvents, VOID_INDICATORS
} from '../utils/posAuditRules.js';
import { diffChanges } from '../utils/changeDiff.js';
import { getSettingsMap } from './settingsService.js';
import { recordInternalEvent } from './auditService.js';
import { localDateSql, ymd } from '../utils/sqlDates.js';
import { actionLabel } from '../utils/viewHelpers.js';

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------
const httpError = (status, message) => Object.assign(new Error(message), { status });
const clean = (v) => (v === undefined || v === null ? '' : String(v).trim());
const TX_CODES_SQL = TRANSACTION_CODES;

/** Records belonging to one transaction: explicit reference, or the entity of a transaction event. */
export const transactionMatch = (refs) => {
  const list = Array.isArray(refs) ? refs : [refs];
  return {
    [Op.or]: [
      sequelize.where(sequelize.col('transactionRef'), { [Op.in]: list }),
      { entityId: { [Op.in]: list }, actionType: { [Op.in]: TRANSACTION_CODES } }
    ]
  };
};

export const posSettings = async () => {
  const s = await getSettingsMap(['pos.observationWindowMinutes', 'pos.voidAuthorizationRequired', 'pos.repeatedVoidThreshold', 'pos.repeatedVoidWindowHours']);
  return {
    observationWindowMs: Number(s['pos.observationWindowMinutes'] ?? 30) * 60000,
    voidAuthorizationRequired: Number(s['pos.voidAuthorizationRequired'] ?? 1) !== 0,
    repeatedVoidThreshold: Number(s['pos.repeatedVoidThreshold'] ?? 3) || 3,
    repeatedVoidWindowMs: Number(s['pos.repeatedVoidWindowHours'] ?? 24) * 3600000
  };
};

export const expectedCodesFor = async (sourceSystemId) => {
  const rows = await AuditEventRegistry.findAll({
    where: { sourceSystemId, isActive: true },
    include: [{ model: AuditEventType, as: 'eventType', attributes: ['code'] }]
  });
  return new Set(rows.map((r) => r.eventType.code));
};

export const instrumentationStartFor = async (sourceSystemId) => {
  const row = await AuditLog.findOne({
    where: { sourceSystemId, actionType: 'TRANSACTION_CREATED', outcome: 'SUCCESS' },
    attributes: [[sequelize.fn('MIN', sequelize.col('occurredAt')), 'first']], raw: true
  });
  return row?.first || null;
};

const analysisOptions = async (sourceSystemId, settings) => ({
  expectedCodes: await expectedCodesFor(sourceSystemId),
  instrumentationStart: await instrumentationStartFor(sourceSystemId),
  observationWindowMs: settings.observationWindowMs,
  voidAuthorizationRequired: settings.voidAuthorizationRequired,
  now: new Date()
});

const eventNames = async () => new Map((await AuditEventType.findAll({ attributes: ['code', 'name'], raw: true })).map((t) => [t.code, t.name]));

const parseDay = (value, endOfDay = false) => {
  const s = clean(value);
  if (!s) return null;
  const d = /^\d{4}-\d{2}-\d{2}$/.test(s) ? new Date(`${s}T${endOfDay ? '23:59:59.999' : '00:00:00.000'}`) : new Date(s);
  return Number.isNaN(d.getTime()) ? null : d;
};

export const dateRange = (q, defaultDays = 30, maxDays = 366) => {
  let to = parseDay(q.to, true) || new Date();
  let from = parseDay(q.from) || new Date(to.getTime() - (defaultDays - 1) * 86400000);
  if (from > to) [from, to] = [to, from];
  if (to - from > maxDays * 86400000) from = new Date(to.getTime() - maxDays * 86400000);
  from.setHours(0, 0, 0, 0);
  return { from, to };
};

const withDisplay = (record, names) => {
  const trace = traceOf(record);
  const rows = diffChanges(record.previousValues, record.newValues);
  return {
    ...record,
    actionName: names.get(record.actionType) || actionLabel(record.actionType),
    trace,
    authorization: trace.authorization || null,
    diffRows: rows.filter((r) => r.isChanged).length ? rows.filter((r) => r.isChanged) : rows,
    hasChanges: Boolean(record.previousValues || record.newValues)
  };
};

// ---------------------------------------------------------------------------
// Transaction Audit Timeline
// ---------------------------------------------------------------------------
export const getTransactionTimeline = async (ref, { sourceSystemId } = {}) => {
  const transactionRef = clean(ref);
  if (!transactionRef) return null;
  const where = { [Op.and]: [transactionMatch(transactionRef)] };
  if (sourceSystemId) where.sourceSystemId = Number(sourceSystemId);
  const records = await AuditLog.findAll({ where, order: [['occurredAt', 'ASC'], ['id', 'ASC']], limit: 1000, raw: true });
  if (!records.length) return { ref: transactionRef, events: [], analyses: [], correlated: [], cases: [] };

  const names = await eventNames();
  const settings = await posSettings();
  const ids = records.map((r) => r.id);

  // Related events that share a correlation ID (possibly from other systems).
  const correlationIds = [...new Set(records.map((r) => r.correlationId).filter(Boolean))];
  const correlated = correlationIds.length ? await AuditLog.findAll({
    where: { correlationId: { [Op.in]: correlationIds }, id: { [Op.notIn]: ids } },
    attributes: ['id', 'eventId', 'actionType', 'sourceSystemName', 'sourceModule', 'actorUsername', 'actorUserId', 'occurredAt', 'outcome', 'correlationId', 'entityType', 'entityId'],
    order: [['occurredAt', 'ASC']], limit: 200, raw: true
  }) : [];

  // One analysis per source system (the same reference could exist on two systems).
  const bySource = new Map();
  records.forEach((r) => { if (!bySource.has(r.sourceSystemId)) bySource.set(r.sourceSystemId, []); bySource.get(r.sourceSystemId).push(r); });
  const analyses = [];
  for (const [sid, events] of bySource) {
    const analysis = analyzeTransaction(events, await analysisOptions(sid, settings));
    analyses.push({ ...analysis, indicators: analysis.summary.hasVoidActivity ? voidIndicators(analysis, { threshold: settings.repeatedVoidThreshold }) : [] });
  }

  const caseLinks = await InvestigationCaseEvent.findAll({
    where: { auditLogId: { [Op.in]: ids } },
    include: [{ model: InvestigationCase, as: 'case', attributes: ['id', 'caseNumber', 'title', 'status'] }]
  });
  const caseMap = new Map();
  caseLinks.forEach((l) => caseMap.set(l.case.id, l.case.get({ plain: true })));
  const cases = [...caseMap.values()];
  if (cases.length) {
    const notes = await InvestigationNote.findAll({
      where: { caseId: { [Op.in]: cases.map((c) => c.id) } },
      include: [{ model: User, as: 'author', attributes: ['fullName'] }],
      order: [['createdAt', 'DESC']], limit: 50
    });
    cases.forEach((c) => { c.notes = notes.filter((n) => n.caseId === c.id).map((n) => n.get({ plain: true })); });
  }

  return {
    ref: transactionRef,
    events: records.map((r) => withDisplay(r, names)),
    analyses,
    correlated,
    cases,
    firstAuditLogId: records[0].id
  };
};

/** Recently active transaction references (for the timeline search page). */
export const recentTransactions = async ({ q, sourceSystemId, limit = 25 } = {}) => {
  const conds = ["sourceSystemCode <> ?", 'actionType IN (?)'];
  const repl = [INTERNAL_SOURCE_CODE, TX_CODES_SQL];
  if (sourceSystemId) { conds.push('sourceSystemId = ?'); repl.push(Number(sourceSystemId)); }
  if (clean(q)) { conds.push('COALESCE(transactionRef, entityId) LIKE ?'); repl.push(`%${clean(q)}%`); }
  return sequelize.query(
    `SELECT COALESCE(transactionRef, entityId) AS ref, sourceSystemId, MAX(sourceSystemName) AS sourceSystemName,
            COUNT(*) AS events, MIN(occurredAt) AS firstAt, MAX(occurredAt) AS lastAt,
            SUM(actionType = 'TRANSACTION_VOIDED' AND outcome = 'SUCCESS') AS voids
       FROM audit_logs WHERE ${conds.join(' AND ')} AND COALESCE(transactionRef, entityId) IS NOT NULL
      GROUP BY ref, sourceSystemId ORDER BY lastAt DESC LIMIT ${Number(limit) || 25}`,
    { replacements: repl, type: sequelize.QueryTypes.SELECT }
  );
};

// ---------------------------------------------------------------------------
// Transaction Void Investigation
// ---------------------------------------------------------------------------
export const listVoidInvestigations = async (q = {}) => {
  const { from, to } = dateRange(q, 30);
  const settings = await posSettings();
  const conds = ['actionType IN (?)', 'occurredAt >= ?', 'occurredAt <= ?', 'sourceSystemCode <> ?'];
  const repl = [VOID_CODES, from, to, INTERNAL_SOURCE_CODE];
  if (q.sourceSystemId) { conds.push('sourceSystemId = ?'); repl.push(Number(q.sourceSystemId)); }
  if (clean(q.branchId)) { conds.push('branchId = ?'); repl.push(clean(q.branchId)); }
  if (clean(q.ref)) { conds.push('COALESCE(transactionRef, entityId) LIKE ?'); repl.push(`%${clean(q.ref)}%`); }
  const keys = await sequelize.query(
    `SELECT sourceSystemId, COALESCE(transactionRef, entityId) AS ref, MAX(occurredAt) AS lastAt FROM audit_logs
      WHERE ${conds.join(' AND ')} AND COALESCE(transactionRef, entityId) IS NOT NULL
      GROUP BY sourceSystemId, ref ORDER BY lastAt DESC LIMIT 500`,
    { replacements: repl, type: sequelize.QueryTypes.SELECT }
  );

  const bySource = new Map();
  keys.forEach((k) => { if (!bySource.has(k.sourceSystemId)) bySource.set(k.sourceSystemId, []); bySource.get(k.sourceSystemId).push(k.ref); });

  const analyses = [];
  for (const [sid, refs] of bySource) {
    const opts = await analysisOptions(sid, settings);
    const records = await AuditLog.findAll({ where: { sourceSystemId: sid, [Op.and]: [transactionMatch(refs)] }, raw: true, limit: 20000 });
    const grouped = new Map();
    records.forEach((r) => {
      const ref = transactionRefOf(r) || r.entityId;
      if (!refs.includes(ref)) return;
      if (!grouped.has(ref)) grouped.set(ref, []);
      grouped.get(ref).push(r);
    });
    for (const [ref, events] of grouped) {
      const analysis = analyzeTransaction(events, opts);
      analysis.summary.transactionRef = ref;
      analyses.push(analysis);
    }
  }

  // Repeated-void counts per requester within the configured window ending at each void.
  const timesByRequester = new Map();
  const voidTime = (a) => a.summary.voidRequest?.at || a.summary.voided?.at || a.summary.lastAt;
  analyses.forEach((a) => {
    const key = requesterKey(a.summary.sourceSystemId, a.summary.voidRequest?.by);
    if (!key) return;
    if (!timesByRequester.has(key)) timesByRequester.set(key, []);
    timesByRequester.get(key).push(new Date(voidTime(a)).getTime());
  });

  const requesterFilter = clean(q.requester).toLowerCase();
  const rows = analyses.map((a) => {
    const key = requesterKey(a.summary.sourceSystemId, a.summary.voidRequest?.by);
    const t = new Date(voidTime(a)).getTime();
    const count = key ? (timesByRequester.get(key) || []).filter((x) => x <= t && x >= t - settings.repeatedVoidWindowMs).length : 0;
    const indicators = voidIndicators(a, { repeatedVoidCounts: new Map(key ? [[key, count]] : []), threshold: settings.repeatedVoidThreshold });
    return { ...a.summary, issues: a.issues, indicators, indicatorCodes: indicators.map((i) => i.code) };
  }).filter((row) => {
    if (q.indicator && !row.indicatorCodes.includes(q.indicator)) return false;
    if (requesterFilter) {
      const by = row.voidRequest?.by || {};
      if (![by.userId, by.username].filter(Boolean).some((v) => String(v).toLowerCase() === requesterFilter)) return false;
    }
    if (q.flagged === 'true' && !row.indicators.length) return false;
    return true;
  }).sort((a, b) => new Date(b.lastAt) - new Date(a.lastAt));

  const indicatorTotals = Object.entries(VOID_INDICATORS).map(([code, label]) => ({ code, label, count: rows.filter((r) => r.indicatorCodes.includes(code)).length }));
  return { rows, from, to, indicatorTotals, truncated: keys.length >= 500, repeatedVoidThreshold: settings.repeatedVoidThreshold };
};

// ---------------------------------------------------------------------------
// Configuration Change History
// ---------------------------------------------------------------------------
export const listConfigurationChanges = async (q = {}, { limit = 25, offset = 0 } = {}) => {
  const where = { actionType: { [Op.in]: CONFIGURATION_CODES }, sourceSystemCode: { [Op.ne]: INTERNAL_SOURCE_CODE } };
  const and = [];
  if (q.sourceSystemId) where.sourceSystemId = Number(q.sourceSystemId);
  if (clean(q.actionType) && CONFIGURATION_CODES.includes(clean(q.actionType))) where.actionType = clean(q.actionType);
  if (clean(q.entityId)) where.entityId = clean(q.entityId);
  if (clean(q.branchId)) and.push(sequelize.where(sequelize.col('branchId'), clean(q.branchId)));
  if (clean(q.user)) and.push({ [Op.or]: [{ actorUsername: clean(q.user) }, { actorUserId: clean(q.user) }] });
  if (clean(q.field)) {
    const field = clean(q.field).replace(/[^A-Za-z0-9_]/g, '');
    if (field) and.push(sequelize.literal(`(JSON_CONTAINS_PATH(newValues, 'one', '$.${field}') OR JSON_CONTAINS_PATH(previousValues, 'one', '$.${field}'))`));
  }
  const from = parseDay(q.from);
  const to = parseDay(q.to, true);
  if (from || to) where.occurredAt = { ...(from ? { [Op.gte]: from } : {}), ...(to ? { [Op.lte]: to } : {}) };
  if (and.length) where[Op.and] = and;

  const { rows, count } = await AuditLog.findAndCountAll({ where, order: [['occurredAt', 'DESC'], ['id', 'DESC']], limit, offset, raw: true });
  const names = await eventNames();
  const changes = rows.map((r) => withDisplay(r, names));

  // Group consecutive events that belong to the same administrative action (shared correlation ID).
  const groups = [];
  changes.forEach((c) => {
    const lastGroup = groups[groups.length - 1];
    if (c.correlationId && lastGroup && lastGroup.correlationId === c.correlationId && lastGroup.sourceSystemId === c.sourceSystemId) lastGroup.events.push(c);
    else groups.push({ correlationId: c.correlationId, sourceSystemId: c.sourceSystemId, events: [c] });
  });
  groups.forEach((g) => { g.isGroup = g.events.length > 1; });
  return { groups, count };
};

export const configurationEventTypes = () => POS_EVENT_DEFINITIONS
  .filter((d) => CONFIGURATION_CODES.includes(d.code))
  .map((d) => ({ code: d.code, name: d.name }))
  .concat([{ code: 'SETTINGS_MODIFIED', name: 'Other Administrative Settings' }]);

// ---------------------------------------------------------------------------
// Cross-System Activity View
// ---------------------------------------------------------------------------
export const ACTIVITY_GROUPS = Object.entries(POS_GROUPS).map(([code, label]) => ({ code, label }));

const resolvePerson = async (personKey) => {
  const mappings = await IdentityMapping.findAll({ where: { personKey, isActive: true }, raw: true });
  return mappings;
};

export const buildCrossSystemWhere = async (q = {}) => {
  const where = {};
  const and = [];
  if (q.includeInternal !== 'true') where.sourceSystemCode = { [Op.ne]: INTERNAL_SOURCE_CODE };
  if (q.sourceSystemId) where.sourceSystemId = Number(q.sourceSystemId);
  if (clean(q.person)) {
    const key = clean(q.person);
    const mappings = await resolvePerson(key);
    and.push({ [Op.or]: [
      sequelize.where(sequelize.col('sharedUserId'), key),
      ...mappings.map((m) => ({ sourceSystemId: m.sourceSystemId, actorUserId: m.actorUserId }))
    ] });
  }
  if (clean(q.userId)) where.actorUserId = clean(q.userId);
  if (clean(q.username)) where.actorUsername = clean(q.username);
  if (clean(q.transactionRef)) and.push(transactionMatch(clean(q.transactionRef)));
  if (clean(q.branchId)) and.push(sequelize.where(sequelize.col('branchId'), clean(q.branchId)));
  if (clean(q.correlationId)) where.correlationId = clean(q.correlationId);
  if (clean(q.entityType)) where.entityType = clean(q.entityType);
  if (clean(q.entityId)) where.entityId = clean(q.entityId);
  if (clean(q.activity)) {
    const activity = clean(q.activity);
    if (POS_GROUPS[activity]) where.actionType = { [Op.in]: codesInGroup(activity) };
    else if (/^[A-Z0-9_]+$/.test(activity)) where.actionType = activity;
  }
  if (q.hideRoutine === 'true') and.push({ actionType: { [Op.notIn]: ROUTINE_CODES } });
  const from = parseDay(q.from);
  const to = parseDay(q.to, true);
  if (from || to) where.occurredAt = { ...(from ? { [Op.gte]: from } : {}), ...(to ? { [Op.lte]: to } : {}) };
  if (and.length) where[Op.and] = and;
  return where;
};

export const searchCrossSystem = async (q = {}, { limit = 50, offset = 0 } = {}) => {
  const where = await buildCrossSystemWhere(q);
  const { rows, count } = await AuditLog.findAndCountAll({
    where,
    attributes: ['id', 'eventId', 'occurredAt', 'sourceSystemId', 'sourceSystemCode', 'sourceSystemName', 'sourceModule', 'actorUserId', 'actorUsername', 'actorRole',
      'actionType', 'entityType', 'entityId', 'outcome', 'severity', 'correlationId', 'description', 'branchId', 'transactionRef', 'sharedUserId'],
    order: [['occurredAt', 'DESC'], ['id', 'DESC']], limit, offset, raw: true
  });

  // Per-system identities that matched. Same username on two systems = two identities.
  const identities = await AuditLog.findAll({
    where,
    attributes: ['sourceSystemId', 'sourceSystemName', 'actorUserId', 'actorUsername', 'sharedUserId', [sequelize.fn('COUNT', sequelize.col('id')), 'events']],
    group: ['sourceSystemId', 'sourceSystemName', 'actorUserId', 'actorUsername', 'sharedUserId'],
    order: [[sequelize.literal('events'), 'DESC']], limit: 30, raw: true
  });
  const mappings = identities.length ? await IdentityMapping.findAll({
    where: { isActive: true, [Op.or]: identities.filter((i) => i.actorUserId).map((i) => ({ sourceSystemId: i.sourceSystemId, actorUserId: i.actorUserId })) },
    raw: true
  }) : [];
  const mappingFor = (i) => mappings.find((m) => m.sourceSystemId === i.sourceSystemId && m.actorUserId === i.actorUserId) || null;
  const identityRows = identities.map((i) => ({ ...i, mapping: mappingFor(i) }));
  const usernames = new Map();
  identityRows.forEach((i) => { if (i.actorUsername) usernames.set(i.actorUsername, (usernames.get(i.actorUsername) || new Set()).add(i.sourceSystemId)); });
  const sharedUsernames = [...usernames.entries()].filter(([, set]) => set.size > 1).map(([name]) => name);

  // Correlation IDs on this page that span more than one system.
  const corr = [...new Set(rows.map((r) => r.correlationId).filter(Boolean))];
  const crossCorrelations = corr.length ? await sequelize.query(
    `SELECT correlationId, COUNT(DISTINCT sourceSystemId) AS systems, COUNT(*) AS events, GROUP_CONCAT(DISTINCT sourceSystemName ORDER BY sourceSystemName SEPARATOR ', ') AS sourceNames
       FROM audit_logs WHERE correlationId IN (?) GROUP BY correlationId HAVING systems > 1 ORDER BY events DESC LIMIT 20`,
    { replacements: [corr], type: sequelize.QueryTypes.SELECT }
  ) : [];

  return { rows, count, identities: identityRows, sharedUsernames, crossCorrelations };
};

// ---------------------------------------------------------------------------
// Identity mappings (explicit cross-system identity)
// ---------------------------------------------------------------------------
const PERSON_KEY = /^[A-Za-z0-9._:-]{2,64}$/;

export const listIdentityMappings = async ({ includeInactive = false } = {}) => {
  const rows = await IdentityMapping.findAll({
    where: includeInactive ? {} : { isActive: true },
    include: [
      { model: SourceSystem, as: 'sourceSystem', attributes: ['id', 'name', 'systemCode'] },
      { model: User, as: 'createdBy', attributes: ['fullName'] }
    ],
    order: [['personKey', 'ASC'], ['id', 'ASC']]
  });
  return rows.map((r) => r.get({ plain: true }));
};

export const createIdentityMapping = async (input, user, req) => {
  const personKey = clean(input.personKey);
  const actorUserId = clean(input.actorUserId);
  const verificationNote = clean(input.verificationNote);
  const sourceSystemId = Number(input.sourceSystemId);
  if (!PERSON_KEY.test(personKey)) throw httpError(400, 'Person key must be 2–64 letters, digits, dots, dashes, colons or underscores.');
  if (!actorUserId || actorUserId.length > 128) throw httpError(400, 'Enter the user ID as reported by the source system.');
  if (verificationNote.length < 5) throw httpError(400, 'Describe how this identity was verified (e.g. HR record, signed form).');
  const source = await SourceSystem.findByPk(sourceSystemId);
  if (!source || source.isInternal) throw httpError(400, 'Select a registered external source system.');

  return sequelize.transaction(async (transaction) => {
    const existing = await IdentityMapping.findOne({ where: { sourceSystemId, actorUserId, isActive: true }, transaction, lock: transaction.LOCK.UPDATE });
    if (existing) throw httpError(409, `${source.name} user ${actorUserId} is already mapped to ${existing.personKey}. Deactivate that mapping first.`);
    const mapping = await IdentityMapping.create({
      personKey, displayName: clean(input.displayName).slice(0, 150) || null, sourceSystemId, actorUserId,
      verificationNote: verificationNote.slice(0, 500), createdByUserId: user.id
    }, { transaction });
    await recordInternalEvent({
      user, req, action: 'IDENTITY_MAPPING_CHANGED', module: 'Cross-System Traceability', entity: { type: 'IdentityMapping', id: mapping.id },
      description: `Mapped ${source.systemCode} user ${actorUserId} to person ${personKey}`,
      after: { personKey, sourceSystem: source.systemCode, actorUserId, verificationNote: mapping.verificationNote }, transaction
    });
    return mapping;
  });
};

export const deactivateIdentityMapping = async (id, user, req) => sequelize.transaction(async (transaction) => {
  const mapping = await IdentityMapping.findByPk(id, { transaction, lock: transaction.LOCK.UPDATE });
  if (!mapping || !mapping.isActive) throw httpError(404, 'Active mapping not found.');
  await mapping.update({ isActive: false, deactivatedByUserId: user.id, deactivatedAt: new Date() }, { transaction });
  await recordInternalEvent({
    user, req, action: 'IDENTITY_MAPPING_CHANGED', module: 'Cross-System Traceability', entity: { type: 'IdentityMapping', id: mapping.id },
    description: `Deactivated identity mapping ${mapping.personKey} ↔ user ${mapping.actorUserId}`,
    before: { isActive: true }, after: { isActive: false }, transaction
  });
  return mapping;
});

// ---------------------------------------------------------------------------
// Pharmacy operations dashboard (every figure comes from stored audit records)
// ---------------------------------------------------------------------------
export const posDashboard = async (q = {}) => {
  const { from, to } = dateRange(q, 30, 366);
  const conds = ['a.sourceSystemCode <> ?', 'a.occurredAt >= ?', 'a.occurredAt <= ?', 'a.actionType IN (?)'];
  const repl = [INTERNAL_SOURCE_CODE, from, to, POS_EVENT_CODES];
  if (q.sourceSystemId) { conds.push('a.sourceSystemId = ?'); repl.push(Number(q.sourceSystemId)); }
  if (clean(q.branchId)) { conds.push('a.branchId = ?'); repl.push(clean(q.branchId)); }
  if (clean(q.user)) { conds.push('(a.actorUserId = ? OR a.actorUsername = ?)'); repl.push(clean(q.user), clean(q.user)); }
  if (clean(q.actionType) && POS_EVENT_CODES.includes(clean(q.actionType))) { conds.push('a.actionType = ?'); repl.push(clean(q.actionType)); }
  const W = conds.join(' AND ');
  const run = (sql, extra = []) => sequelize.query(sql, { replacements: [...extra, ...repl], type: sequelize.QueryTypes.SELECT });
  const day = localDateSql('a.occurredAt');

  const [totals, completed, voided, trend, voidTrend, statusChanges, byCashier, byBranch, bySource, pendingFindings] = await Promise.all([
    run(`SELECT COUNT(*) AS total,
                COALESCE(SUM(a.outcome IN ('FAILURE','DENIED')), 0) AS failed,
                COALESCE(SUM(a.actionType IN (?)), 0) AS configuration,
                COALESCE(SUM(a.actionType IN (?)), 0) AS customer,
                COALESCE(SUM(a.actionCategory = 'ADMINISTRATIVE'), 0) AS administrative
           FROM audit_logs a WHERE ${W}`, [CONFIGURATION_CODES, CUSTOMER_CODES]),
    run(`SELECT COUNT(DISTINCT a.sourceSystemId, COALESCE(a.transactionRef, a.entityId)) AS n FROM audit_logs a WHERE ${W} AND a.actionType = 'CHECKOUT_COMPLETED' AND a.outcome = 'SUCCESS'`),
    run(`SELECT COUNT(DISTINCT a.sourceSystemId, COALESCE(a.transactionRef, a.entityId)) AS n FROM audit_logs a WHERE ${W} AND a.actionType = 'TRANSACTION_VOIDED' AND a.outcome = 'SUCCESS'`),
    run(`SELECT ${day} AS k, COUNT(*) AS n FROM audit_logs a WHERE ${W} GROUP BY k`),
    run(`SELECT ${day} AS k, COUNT(*) AS n FROM audit_logs a WHERE ${W} AND a.actionType = 'TRANSACTION_VOIDED' AND a.outcome = 'SUCCESS' GROUP BY k`),
    sequelize.query(
      `SELECT CONCAT(COALESCE(LOWER(JSON_UNQUOTE(JSON_EXTRACT(a.previousValues, '$.transactionStatus'))), 'new'), ' → ',
                     LOWER(JSON_UNQUOTE(JSON_EXTRACT(a.newValues, '$.transactionStatus')))) AS k, COUNT(*) AS n
         FROM audit_logs a WHERE ${W} AND a.outcome = 'SUCCESS' AND a.actionType IN (?)
          AND JSON_EXTRACT(a.newValues, '$.transactionStatus') IS NOT NULL
        GROUP BY k ORDER BY n DESC LIMIT 10`,
      { replacements: [...repl, TRANSACTION_CODES], type: sequelize.QueryTypes.SELECT }
    ),
    run(`SELECT CONCAT(COALESCE(a.actorUsername, a.actorUserId, 'unknown'), ' · ', a.sourceSystemName) AS k, COUNT(*) AS n FROM audit_logs a WHERE ${W} GROUP BY k ORDER BY n DESC LIMIT 10`),
    run(`SELECT COALESCE(a.branchId, 'Not reported') AS k, COUNT(*) AS n FROM audit_logs a WHERE ${W} GROUP BY k ORDER BY n DESC LIMIT 10`),
    run(`SELECT a.sourceSystemName AS k, COUNT(*) AS n FROM audit_logs a WHERE ${W} GROUP BY k ORDER BY n DESC LIMIT 10`),
    QaFinding.count({ where: { status: { [Op.in]: ['OPEN', 'UNDER_INVESTIGATION'] }, category: { [Op.in]: POS_QA_CATEGORIES }, ...(q.sourceSystemId ? { sourceSystemId: Number(q.sourceSystemId) } : {}) } })
  ]);

  const days = [];
  for (let d = new Date(from); d <= to; d = new Date(d.getTime() + 86400000)) days.push(ymd(d));
  const fill = (rows) => {
    const map = Object.fromEntries(rows.map((r) => [String(r.k).slice(0, 10), Number(r.n)]));
    return { labels: days.map((k) => k.slice(5)), values: days.map((k) => map[k] || 0) };
  };
  const pairs = (rows) => ({ labels: rows.map((r) => r.k), values: rows.map((r) => Number(r.n)) });
  const t = totals[0] || {};

  return {
    from, to,
    cards: {
      totalPosEvents: Number(t.total || 0),
      completedTransactions: Number(completed[0]?.n || 0),
      voidedTransactions: Number(voided[0]?.n || 0),
      configurationChanges: Number(t.configuration || 0),
      customerActivities: Number(t.customer || 0),
      administrativeActivities: Number(t.administrative || 0),
      failedPosEvents: Number(t.failed || 0),
      pendingFindings
    },
    charts: {
      posTrend: fill(trend),
      posVoids: fill(voidTrend),
      posStatus: pairs(statusChanges),
      posCashier: pairs(byCashier),
      posBranch: pairs(byBranch),
      posSource: pairs(bySource)
    }
  };
};

export const posFilterOptions = async () => {
  const [sources, branches] = await Promise.all([
    SourceSystem.findAll({ where: { isInternal: false }, attributes: ['id', 'name', 'systemCode'], order: [['name', 'ASC']], raw: true }),
    sequelize.query('SELECT DISTINCT branchId AS v FROM audit_logs WHERE branchId IS NOT NULL ORDER BY v LIMIT 200', { type: sequelize.QueryTypes.SELECT })
  ]);
  return {
    sources,
    branches: branches.map((b) => b.v),
    eventTypes: POS_EVENT_DEFINITIONS.map((d) => ({ code: d.code, name: d.name, group: d.rules.group })),
    groups: ACTIVITY_GROUPS,
    indicators: Object.entries(VOID_INDICATORS).map(([code, label]) => ({ code, label }))
  };
};

export { sortEvents, rulesFor };
