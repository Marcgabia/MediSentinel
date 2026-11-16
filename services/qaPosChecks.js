import { Op } from 'sequelize';
import { sequelize, AuditLog, IntegrationLog } from '../models/index.js';
import { INTERNAL_SOURCE_CODE } from '../utils/auditConstants.js';
import { POS_EVENT_CODES, TRANSACTION_CODES, CONFIGURATION_CODES, rulesFor } from '../utils/posEventCatalog.js';
import { validatePosRecord, analyzeTransaction, configurationGaps, transactionRefOf } from '../utils/posAuditRules.js';
import { expectedCodesFor, instrumentationStartFor, posSettings, transactionMatch } from './posAuditService.js';

/**
 * QA checks for pharmacy-application audit events. Called by executeVerification() with the
 * shared run context, so results and findings follow the existing QA workflow (fingerprints,
 * de-duplication, resolve → verify, reopening).
 *
 * Findings are indicators for follow-up with the source system team; a "missing" event is
 * only reported when the source's expected-event registry includes it and the observation
 * window has elapsed.
 */

const MAX_FINDINGS_PER_CHECK = 50;
const SEVERITY_RANK = { HIGH: 3, MEDIUM: 2, LOW: 1 };
const FINDING_SEVERITY = { HIGH: 'HIGH', MEDIUM: 'MEDIUM', LOW: 'LOW' };
const statusFrom = (items) => {
  if (!items.length) return 'PASS';
  return items.some((i) => SEVERITY_RANK[i.severity] >= 2) ? 'FAIL' : 'WARNING';
};
const sinceFor = (settings) => new Date(Date.now() - (settings['qa.lookbackDays'] || 7) * 86400000);
const chunk = (list, size) => { const out = []; for (let i = 0; i < list.length; i += size) out.push(list.slice(i, i + size)); return out; };

// ---------------------------------------------------------------------------
// POS Event Validation
// ---------------------------------------------------------------------------
const PV_CHECKS = [
  ['PV_SOURCE', 'Registered POS source system'],
  ['PV_UNREGISTERED_EVENT', 'Event registered for the source system'],
  ['PV_USER_REFERENCE', 'Valid user reference'],
  ['PV_TIMESTAMP', 'Valid event timestamp'],
  ['PV_ENTITY_TYPE', 'Expected entity type'],
  ['PV_TRANSACTION_REFERENCE', 'Valid transaction reference'],
  ['PV_BEFORE_VALUES', 'Previous values recorded'],
  ['PV_AFTER_VALUES', 'New values recorded'],
  ['PV_REASON', 'Required reason (void / cancellation)'],
  ['PV_AUTHORIZATION', 'Authorization identity or verified reference'],
  ['PV_CORRELATION', 'Correlation information'],
  ['PV_BRANCH', 'Branch identified'],
  ['PV_REPORT_DETAILS', 'Report parameters recorded'],
  ['PV_LOOKUP_RESULT', 'Lookup result recorded']
];

const checkPosEventValidation = async (ctx, { sourcesById, eventTypes, settings }) => {
  const since = sinceFor(settings);
  const records = await AuditLog.findAll({
    where: { actionType: { [Op.in]: POS_EVENT_CODES }, receivedAt: { [Op.gte]: since }, sourceSystemCode: { [Op.ne]: INTERNAL_SOURCE_CODE } },
    order: [['id', 'ASC']], limit: 20000, raw: true
  });
  if (!records.length) {
    for (const [code, name] of PV_CHECKS) await ctx.result('POS_EVENT_VALIDATION', code, name, 'NOT_TESTED', `No pharmacy application events received in the last ${settings['qa.lookbackDays']} day(s).`);
    return;
  }
  const registry = new Map();
  const problemsByCode = new Map(PV_CHECKS.map(([code]) => [code, []]));
  for (const record of records) {
    if (!registry.has(record.sourceSystemId)) registry.set(record.sourceSystemId, await expectedCodesFor(record.sourceSystemId));
    const source = sourcesById.get(record.sourceSystemId) || null;
    const problems = validatePosRecord(record, { eventType: eventTypes.get(record.actionType), source, registryCodes: registry.get(record.sourceSystemId) });
    problems.forEach((p) => problemsByCode.get(p.code)?.push({ ...p, record }));
  }

  for (const [code, name] of PV_CHECKS) {
    const items = problemsByCode.get(code);
    const status = statusFrom(items);
    await ctx.result('POS_EVENT_VALIDATION', code, name, status,
      items.length ? `${items.length} of ${records.length} pharmacy event(s) failed: ${items[0].message}` : `All ${records.length} pharmacy event(s) passed.`,
      { itemsChecked: records.length, itemsFailed: items.length, details: { failed: items.slice(0, 100).map((i) => ({ auditLogId: i.record.id, eventId: i.record.eventId, actionType: i.record.actionType, message: i.message })) } });

    // MEDIUM/HIGH problems: one finding per record. LOW problems: one finding per source & check.
    const serious = items.filter((i) => SEVERITY_RANK[i.severity] >= 2);
    for (const item of serious.slice(0, MAX_FINDINGS_PER_CHECK)) {
      await ctx.finding({
        category: 'POS_EVENT_VALIDATION', checkCode: code, sourceSystemId: item.record.sourceSystemId,
        relatedAuditLogId: item.record.id, relatedEventId: item.record.eventId,
        title: `${name}: ${item.record.actionType}`, description: `Audit #${item.record.id} (${item.record.eventId}, ${item.record.sourceSystemName}): ${item.message}`,
        severity: FINDING_SEVERITY[item.severity], recommendedAction: 'Share the event with the source system team and correct the payload mapping for this action. The audit record itself is preserved unchanged.',
        fingerprint: `${code}|audit:${item.record.id}`
      });
    }
    const minor = items.filter((i) => SEVERITY_RANK[i.severity] < 2);
    const minorBySource = new Map();
    minor.forEach((i) => { if (!minorBySource.has(i.record.sourceSystemId)) minorBySource.set(i.record.sourceSystemId, []); minorBySource.get(i.record.sourceSystemId).push(i); });
    for (const [sourceSystemId, list] of minorBySource) {
      const actions = [...new Set(list.map((i) => i.record.actionType))];
      await ctx.finding({
        category: 'POS_EVENT_VALIDATION', checkCode: code, sourceSystemId, relatedAuditLogId: list[0].record.id, relatedEventId: list[0].record.eventId,
        title: `${name} (${list.length} event${list.length > 1 ? 's' : ''})`,
        description: `${list[0].record.sourceSystemName}: ${list.length} event(s) (${actions.slice(0, 6).join(', ')}) — ${list[0].message}`,
        severity: 'LOW', recommendedAction: 'Ask the source system team to include this information; it improves traceability but does not invalidate the records.',
        fingerprint: `${code}|source:${sourceSystemId}`, details: { auditLogIds: list.slice(0, 100).map((i) => i.record.id) }
      });
    }
  }
};

// ---------------------------------------------------------------------------
// Transaction Audit Consistency
// ---------------------------------------------------------------------------
const TC_CHECKS = [
  { code: 'TC_COMPLETION', name: 'Completed transactions have completion events', issues: ['TC_COMPLETION_MISSING'], needs: 'CHECKOUT_COMPLETED' },
  { code: 'TC_VOID_EVENTS', name: 'Voided transactions have void events', issues: ['TC_VOID_EVENT_MISSING', 'TC_VOID_REQUEST_MISSING', 'TC_VOID_AUTHORIZATION_MISSING'], needs: 'TRANSACTION_VOIDED' },
  { code: 'TC_VOID_FINAL', name: 'Approved voids have a final outcome', issues: ['TC_APPROVED_NOT_FINALIZED', 'TC_VOID_AFTER_REJECTION'], needs: 'TRANSACTION_VOIDED' },
  { code: 'TC_STATUS', name: 'Consistent transaction status transitions', issues: ['TC_STATUS_TRANSITION', 'TC_STATUS_GAP', 'TC_EVENT_AFTER_TERMINAL'] },
  { code: 'TC_REFERENCES', name: 'Valid transaction references', issues: ['TC_REFERENCE_MISMATCH', 'TC_CREATION_MISSING'] },
  { code: 'TC_DUPLICATES', name: 'No duplicate transaction audit events', issues: ['TC_DUPLICATE_EVENT'] }
];

const checkTransactionConsistency = async (ctx, { external, settings }) => {
  const since = sinceFor(settings);
  const pos = await posSettings();
  let anyTransactions = false;

  for (const source of external) {
    const refs = (await sequelize.query(
      `SELECT DISTINCT COALESCE(transactionRef, entityId) AS ref FROM audit_logs
        WHERE sourceSystemId = ? AND actionType IN (?) AND receivedAt >= ? AND COALESCE(transactionRef, entityId) IS NOT NULL LIMIT 2000`,
      { replacements: [source.id, TRANSACTION_CODES, since], type: sequelize.QueryTypes.SELECT }
    )).map((r) => r.ref);
    if (!refs.length) continue;
    anyTransactions = true;

    const expectedCodes = await expectedCodesFor(source.id);
    const opts = {
      expectedCodes, instrumentationStart: await instrumentationStartFor(source.id), now: new Date(),
      observationWindowMs: pos.observationWindowMs, voidAuthorizationRequired: pos.voidAuthorizationRequired
    };
    const grouped = new Map();
    for (const part of chunk(refs, 500)) {
      const rows = await AuditLog.findAll({ where: { sourceSystemId: source.id, [Op.and]: [transactionMatch(part)] }, raw: true, limit: 50000 });
      rows.forEach((r) => {
        const ref = transactionRefOf(r) || r.entityId;
        if (!grouped.has(ref)) grouped.set(ref, []);
        grouped.get(ref).push(r);
      });
    }
    const issuesByCode = new Map();
    for (const [ref, events] of grouped) {
      if (!refs.includes(ref)) continue;
      const { issues } = analyzeTransaction(events, opts);
      issues.forEach((i) => { if (!issuesByCode.has(i.code)) issuesByCode.set(i.code, []); issuesByCode.get(i.code).push({ ...i, ref }); });
    }

    for (const check of TC_CHECKS) {
      if (check.needs && !expectedCodes.has(check.needs)) {
        await ctx.result('TRANSACTION_CONSISTENCY', check.code, check.name, 'NOT_TESTED',
          `${source.name}: ${check.needs} is not in this system's expected event registry, so missing events cannot be judged.`, { sourceSystemId: source.id, itemsChecked: refs.length });
        continue;
      }
      const items = check.issues.flatMap((code) => issuesByCode.get(code) || []);
      const status = items.length ? (items.some((i) => SEVERITY_RANK[i.severity] >= 2) ? 'FAIL' : 'WARNING') : 'PASS';
      await ctx.result('TRANSACTION_CONSISTENCY', check.code, check.name, status,
        items.length ? `${source.name}: ${items.length} issue(s) across ${new Set(items.map((i) => i.ref)).size} of ${refs.length} transaction(s). ${items[0].message}` : `${source.name}: ${refs.length} transaction(s) checked, no issues.`,
        { sourceSystemId: source.id, itemsChecked: refs.length, itemsFailed: new Set(items.map((i) => i.ref)).size, details: { issues: items.slice(0, 100).map((i) => ({ transactionRef: i.ref, code: i.code, message: i.message, auditLogId: i.auditLogId })) } });
      for (const item of items.slice(0, MAX_FINDINGS_PER_CHECK)) {
        await ctx.finding({
          category: 'TRANSACTION_CONSISTENCY', checkCode: check.code, sourceSystemId: source.id, relatedAuditLogId: item.auditLogId, relatedEventId: item.eventId,
          title: `Transaction ${item.ref}: ${check.name.toLowerCase()}`,
          description: `${source.name}, transaction ${item.ref}: ${item.message} This is an indicator for review, not proof of wrongdoing.`,
          severity: FINDING_SEVERITY[item.severity] || 'MEDIUM',
          recommendedAction: `Open the transaction timeline (/audit/transactions/${encodeURIComponent(item.ref)}?sourceSystemId=${source.id}) and confirm with the ${source.name} team whether the activity occurred and whether its audit event was sent.`,
          fingerprint: `${item.code}|${source.id}|${item.ref}`.slice(0, 255)
        });
      }
    }
  }
  if (!anyTransactions) {
    for (const check of TC_CHECKS) await ctx.result('TRANSACTION_CONSISTENCY', check.code, check.name, 'NOT_TESTED', `No transaction events received in the last ${settings['qa.lookbackDays']} day(s).`);
  }
};

// ---------------------------------------------------------------------------
// Configuration Audit Verification
// ---------------------------------------------------------------------------
const checkConfigurationAudit = async (ctx, { sourcesById, settings }) => {
  const since = sinceFor(settings);
  const records = await AuditLog.findAll({
    where: { actionType: { [Op.in]: CONFIGURATION_CODES }, receivedAt: { [Op.gte]: since }, sourceSystemCode: { [Op.ne]: INTERNAL_SOURCE_CODE } },
    order: [['id', 'ASC']], limit: 20000, raw: true
  });
  const checks = [
    ['CA_VALUES', 'Previous and new values recorded'], ['CA_RESPONSIBLE_USER', 'Responsible user identified'],
    ['CA_SOURCE', 'Source system registered'], ['CA_TIMESTAMP', 'Valid event timestamps'], ['CA_CONTINUITY', 'Every configuration change has an audit record']
  ];
  if (!records.length) {
    for (const [code, name] of checks) await ctx.result('CONFIGURATION_AUDIT', code, name, 'NOT_TESTED', `No configuration change events received in the last ${settings['qa.lookbackDays']} day(s).`);
    return;
  }
  const failures = Object.fromEntries(checks.map(([code]) => [code, []]));
  for (const r of records) {
    const rules = rulesFor(r.actionType) || {};
    const isObj = (v) => v && typeof v === 'object' && !Array.isArray(v);
    if ((rules.expectBefore && !isObj(r.previousValues)) || (rules.expectAfter && !isObj(r.newValues))) {
      failures.CA_VALUES.push({ r, message: `${r.actionType} is missing ${!isObj(r.previousValues) && rules.expectBefore ? 'previous' : 'new'} values.` });
    }
    if (r.metadata?.actorType === 'SYSTEM' || (!r.actorUserId && !r.actorUsername)) failures.CA_RESPONSIBLE_USER.push({ r, message: `${r.actionType} does not identify the administrator who made the change.` });
    const source = sourcesById.get(r.sourceSystemId);
    if (!source || source.systemCode !== r.sourceSystemCode) failures.CA_SOURCE.push({ r, message: 'Change came from a source system that is not registered under this code.' });
    const occurred = new Date(r.occurredAt).getTime();
    if (Number.isNaN(occurred) || occurred - new Date(r.receivedAt).getTime() > 300000) failures.CA_TIMESTAMP.push({ r, message: 'Event timestamp is invalid or later than its receipt.' });
  }

  // Continuity: replay each configured entity's full history.
  const entities = [...new Set(records.map((r) => `${r.sourceSystemId}|${r.entityType || ''}|${r.entityId || ''}`))];
  for (const key of entities.slice(0, 500)) {
    const [sourceSystemId, entityType, entityId] = key.split('|');
    const history = await AuditLog.findAll({
      where: { sourceSystemId: Number(sourceSystemId), actionType: { [Op.in]: CONFIGURATION_CODES }, entityType: entityType || null, entityId: entityId || null },
      order: [['occurredAt', 'ASC'], ['id', 'ASC']], limit: 5000, raw: true
    });
    configurationGaps(history).forEach((gap) => failures.CA_CONTINUITY.push({
      r: history.find((h) => h.id === gap.auditLogId),
      message: `"${gap.field}" was recorded as ${JSON.stringify(gap.recordedAfter)} (audit #${gap.previousAuditLogId}) but the next change reports its previous value as ${JSON.stringify(gap.reportedBefore)} — a change in between has no audit record.`
    }));
  }

  const severities = { CA_VALUES: 'MEDIUM', CA_RESPONSIBLE_USER: 'MEDIUM', CA_SOURCE: 'HIGH', CA_TIMESTAMP: 'MEDIUM', CA_CONTINUITY: 'MEDIUM' };
  for (const [code, name] of checks) {
    const items = failures[code];
    const status = items.length ? (code === 'CA_CONTINUITY' ? 'WARNING' : 'FAIL') : 'PASS';
    await ctx.result('CONFIGURATION_AUDIT', code, name, status,
      items.length ? `${items.length} of ${records.length} configuration change(s) failed: ${items[0].message}` : `All ${records.length} configuration change(s) passed.`,
      { itemsChecked: records.length, itemsFailed: items.length, details: { failed: items.slice(0, 100).map((i) => ({ auditLogId: i.r?.id, message: i.message })) } });
    for (const item of items.slice(0, MAX_FINDINGS_PER_CHECK)) {
      await ctx.finding({
        category: 'CONFIGURATION_AUDIT', checkCode: code, sourceSystemId: item.r?.sourceSystemId ?? null, relatedAuditLogId: item.r?.id ?? null, relatedEventId: item.r?.eventId ?? null,
        title: `${name}: ${item.r?.actionType || 'configuration change'}`, description: `Audit #${item.r?.id} (${item.r?.sourceSystemName}): ${item.message}`,
        severity: severities[code],
        recommendedAction: code === 'CA_CONTINUITY'
          ? 'Ask the source system team whether this setting was changed outside the audited screens (direct database edit, import, another tool) and whether that path sends audit events.'
          : 'Correct the source system\'s configuration audit payload. The stored record is preserved unchanged.',
        fingerprint: `${code}|audit:${item.r?.id}`
      });
    }
  }
};

// ---------------------------------------------------------------------------
// Cross-System Consistency
// ---------------------------------------------------------------------------
const checkCrossSystem = async (ctx, { settings }) => {
  const since = sinceFor(settings);
  const q = (sql, replacements) => sequelize.query(sql, { replacements, type: sequelize.QueryTypes.SELECT });

  const total = await AuditLog.count({ where: { receivedAt: { [Op.gte]: since }, sourceSystemCode: { [Op.ne]: INTERNAL_SOURCE_CODE } } });
  if (!total) {
    for (const [code, name] of [['CS_EVENT_IDS', 'Event identifiers unique across systems'], ['CS_SOURCE_IDENTITY', 'Source systems correctly identified'], ['CS_CORRELATION_FORMAT', 'Correlation IDs properly formatted'], ['CS_REFERENCES', 'Related event references consistent'], ['CS_IDEMPOTENCY', 'Duplicate submissions handled idempotently']]) {
      await ctx.result('CROSS_SYSTEM_CONSISTENCY', code, name, 'NOT_TESTED', `No external events received in the last ${settings['qa.lookbackDays']} day(s).`);
    }
    return;
  }

  // 1. Event IDs reused by different systems (allowed by the API, but ambiguous for traceability)
  const reused = await q(`SELECT eventId, COUNT(DISTINCT sourceSystemId) AS systems FROM audit_logs
    WHERE receivedAt >= ? AND sourceSystemCode <> ? GROUP BY eventId HAVING systems > 1 LIMIT 50`, [since, INTERNAL_SOURCE_CODE]);
  await ctx.result('CROSS_SYSTEM_CONSISTENCY', 'CS_EVENT_IDS', 'Event identifiers unique across systems', reused.length ? 'WARNING' : 'PASS',
    reused.length ? `${reused.length} event ID(s) were used by more than one source system.` : `All ${total} event ID(s) are unique across source systems.`,
    { itemsChecked: total, itemsFailed: reused.length, details: { reused } });
  if (reused.length) {
    await ctx.finding({
      category: 'CROSS_SYSTEM_CONSISTENCY', checkCode: 'CS_EVENT_IDS', title: 'Event IDs reused across systems',
      description: `${reused.length} event ID(s) appear on more than one source system (e.g. ${reused.slice(0, 3).map((r) => r.eventId).join(', ')}). Records stay distinct, but references by event ID are ambiguous.`,
      severity: 'LOW', recommendedAction: 'Ask integrators to generate globally unique event IDs (UUID v4).', fingerprint: 'CS_EVENT_IDS|global'
    });
  }

  // 2. Snapshot source code matches the registered source
  const mismatched = await q(`SELECT a.id, a.eventId, a.sourceSystemId, a.sourceSystemCode, s.systemCode FROM audit_logs a
    JOIN source_systems s ON s.id = a.sourceSystemId WHERE a.receivedAt >= ? AND a.sourceSystemCode <> s.systemCode LIMIT 100`, [since]);
  await ctx.result('CROSS_SYSTEM_CONSISTENCY', 'CS_SOURCE_IDENTITY', 'Source systems correctly identified', mismatched.length ? 'FAIL' : 'PASS',
    mismatched.length ? `${mismatched.length} record(s) carry a source code that differs from their registered source.` : 'Every record\'s source code matches its registered source system.',
    { itemsChecked: total, itemsFailed: mismatched.length, details: { mismatched: mismatched.slice(0, 50) } });
  for (const m of mismatched.slice(0, MAX_FINDINGS_PER_CHECK)) {
    await ctx.finding({
      category: 'CROSS_SYSTEM_CONSISTENCY', checkCode: 'CS_SOURCE_IDENTITY', sourceSystemId: m.sourceSystemId, relatedAuditLogId: m.id, relatedEventId: m.eventId,
      title: 'Record source code does not match its source system', description: `Audit #${m.id} records "${m.sourceSystemCode}" but belongs to "${m.systemCode}".`,
      severity: 'HIGH', recommendedAction: 'Investigate how the record was written; source codes are fixed at ingestion.', fingerprint: `CS_SOURCE_IDENTITY|audit:${m.id}`
    });
  }

  // 3. Correlation ID format
  const badCorrelation = await q(`SELECT id, eventId, sourceSystemId, correlationId FROM audit_logs
    WHERE receivedAt >= ? AND correlationId IS NOT NULL AND (correlationId NOT REGEXP '^[A-Za-z0-9._:-]+$' OR CHAR_LENGTH(correlationId) > 128) LIMIT 100`, [since]);
  const withCorrelation = await AuditLog.count({ where: { receivedAt: { [Op.gte]: since }, correlationId: { [Op.ne]: null } } });
  await ctx.result('CROSS_SYSTEM_CONSISTENCY', 'CS_CORRELATION_FORMAT', 'Correlation IDs properly formatted', withCorrelation ? (badCorrelation.length ? 'FAIL' : 'PASS') : 'NOT_TESTED',
    withCorrelation ? (badCorrelation.length ? `${badCorrelation.length} correlation ID(s) are malformed.` : `All ${withCorrelation} correlation ID(s) are well-formed.`) : 'No events carried a correlation ID.',
    { itemsChecked: withCorrelation, itemsFailed: badCorrelation.length });
  for (const b of badCorrelation.slice(0, MAX_FINDINGS_PER_CHECK)) {
    await ctx.finding({
      category: 'CROSS_SYSTEM_CONSISTENCY', checkCode: 'CS_CORRELATION_FORMAT', sourceSystemId: b.sourceSystemId, relatedAuditLogId: b.id, relatedEventId: b.eventId,
      title: 'Malformed correlation ID', description: `Audit #${b.id} has correlation ID "${String(b.correlationId).slice(0, 80)}".`,
      severity: 'MEDIUM', recommendedAction: 'Correlation IDs must be ≤128 characters of letters, digits, dot, dash, colon or underscore.', fingerprint: `CS_CORRELATION_FORMAT|audit:${b.id}`
    });
  }

  // 4. References from non-transaction events (e.g. inventory) to transactions nobody recorded
  const referencing = await q(`SELECT COUNT(*) AS n FROM audit_logs WHERE receivedAt >= ? AND transactionRef IS NOT NULL AND actionType NOT IN (?)`, [since, TRANSACTION_CODES]);
  const dangling = await q(`SELECT a.transactionRef AS ref, a.sourceSystemId, MIN(a.id) AS auditLogId, MAX(a.sourceSystemName) AS sourceSystemName, COUNT(*) AS n FROM audit_logs a
    WHERE a.receivedAt >= ? AND a.transactionRef IS NOT NULL AND a.actionType NOT IN (?)
      AND NOT EXISTS (SELECT 1 FROM audit_logs b WHERE b.transactionRef = a.transactionRef AND b.actionType IN (?))
    GROUP BY a.transactionRef, a.sourceSystemId LIMIT 50`, [since, TRANSACTION_CODES, TRANSACTION_CODES]);
  const refCount = Number(referencing[0]?.n || 0);
  await ctx.result('CROSS_SYSTEM_CONSISTENCY', 'CS_REFERENCES', 'Related event references consistent', refCount ? (dangling.length ? 'WARNING' : 'PASS') : 'NOT_TESTED',
    refCount ? (dangling.length ? `${dangling.length} transaction reference(s) are referenced by other events but have no transaction events.` : `All ${refCount} cross-references resolve to recorded transactions.`) : 'No events referenced transactions from outside the transaction module.',
    { itemsChecked: refCount, itemsFailed: dangling.length, details: { dangling } });
  for (const d of dangling.slice(0, MAX_FINDINGS_PER_CHECK)) {
    await ctx.finding({
      category: 'CROSS_SYSTEM_CONSISTENCY', checkCode: 'CS_REFERENCES', sourceSystemId: d.sourceSystemId, relatedAuditLogId: d.auditLogId,
      title: `Reference to unrecorded transaction ${d.ref}`, description: `${d.sourceSystemName} recorded ${d.n} event(s) referencing transaction ${d.ref}, but no system has sent transaction events for it.`,
      severity: 'LOW', recommendedAction: 'Confirm the reference format with both teams and whether the POS sends events for this transaction.', fingerprint: `CS_REFERENCES|${d.sourceSystemId}|${d.ref}`.slice(0, 255)
    });
  }

  // 5. Idempotency: unique index present and every DUPLICATE response points to the stored original
  const [indexRow] = await q(`SELECT COUNT(*) AS n FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'audit_logs' AND INDEX_NAME = 'uq_audit_source_event' AND NON_UNIQUE = 0`, []);
  const duplicates = await IntegrationLog.count({ where: { outcome: 'DUPLICATE', createdAt: { [Op.gte]: since } } });
  const conflicts = await IntegrationLog.count({ where: { outcome: 'CONFLICT', createdAt: { [Op.gte]: since } } });
  const orphan = await q(`SELECT COUNT(*) AS n FROM integration_logs l LEFT JOIN audit_logs a ON a.id = l.auditLogId
    WHERE l.outcome = 'DUPLICATE' AND l.createdAt >= ? AND (a.id IS NULL OR a.eventId <> l.eventId)`, [since]);
  const orphanCount = Number(orphan[0]?.n || 0);
  const indexOk = Number(indexRow?.n || 0) > 0;
  const status = !indexOk || orphanCount ? 'FAIL' : conflicts ? 'WARNING' : 'PASS';
  await ctx.result('CROSS_SYSTEM_CONSISTENCY', 'CS_IDEMPOTENCY', 'Duplicate submissions handled idempotently', status,
    `${indexOk ? 'Unique (source, eventId) index present' : 'Unique (source, eventId) index MISSING'}; ${duplicates} duplicate submission(s) answered with the original record${orphanCount ? `, ${orphanCount} without a matching original` : ''}; ${conflicts} conflicting reuse(s) of an event ID.`,
    { itemsChecked: duplicates + conflicts, itemsFailed: orphanCount + (indexOk ? 0 : 1), details: { duplicates, conflicts, orphanCount, indexOk } });
  if (!indexOk || orphanCount) {
    await ctx.finding({
      category: 'CROSS_SYSTEM_CONSISTENCY', checkCode: 'CS_IDEMPOTENCY', title: 'Duplicate handling is not idempotent',
      description: indexOk ? `${orphanCount} duplicate response(s) do not point to the original stored event.` : 'The unique index uq_audit_source_event is missing; duplicate events could be stored.',
      severity: 'HIGH', recommendedAction: 'Restore the unique index and review integration logs for duplicated records.', fingerprint: 'CS_IDEMPOTENCY|global'
    });
  }
};

export const runPosQualityChecks = async (ctx, context) => {
  await checkPosEventValidation(ctx, context);
  await checkTransactionConsistency(ctx, context);
  await checkConfigurationAudit(ctx, context);
  await checkCrossSystem(ctx, context);
};
