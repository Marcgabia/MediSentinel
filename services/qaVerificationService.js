import { Op } from 'sequelize';
import {
  sequelize, QaRun, QaResult, QaFinding, AuditLog, AuditEventType, AuditEventRegistry, IntegrationLog, SourceSystem, User
} from '../models/index.js';
import { verifyRecord, GENESIS_HASH } from '../utils/integrityHelper.js';
import { EVENT_OUTCOMES, EVENT_SEVERITIES, QA_CATEGORY_LABELS, FINDING_STATUSES, FINDING_SEVERITIES } from '../utils/auditConstants.js';
import { appendOnlyTriggersPresent, findDuplicateEventIds } from './auditIntegrityService.js';
import { listSourcesWithHealth } from './integrationService.js';
import { getSettingsMap } from './settingsService.js';
import { notifyPermission } from './notificationService.js';
import { recordInternalEvent } from './auditService.js';
import { runPosQualityChecks } from './qaPosChecks.js';

/**
 * Quality Assurance verifies MediSentinel's OWN audit operations: event validity, record
 * integrity, expected event coverage and integration delivery quality. It does not test the
 * business logic of the POS / inventory systems.
 */

export const formatRunId = (id) => `QA-RUN-${String(id).padStart(5, '0')}`;
export const formatFindingId = (id) => `QAF-${String(id).padStart(5, '0')}`;

const isPlainObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const pct = (num, den) => (den ? Math.round((num / den) * 1000) / 10 : 0);

// ---------------------------------------------------------------------------
// Pure check helpers (unit tested)
// ---------------------------------------------------------------------------

/** Re-validate a stored audit record. Returns a list of problems (empty when valid). */
export const validateStoredRecord = (record, eventTypes, { toleranceMs = 300000 } = {}) => {
  const problems = [];
  if (!record.eventId) problems.push('Missing event ID.');
  if (!record.sourceSystemId || !record.sourceSystemCode) problems.push('Missing source system reference.');
  if (!record.sourceModule) problems.push('Missing source module.');
  const type = eventTypes.get(record.actionType);
  if (!type) problems.push(`Action "${record.actionType}" is not a registered event type.`);
  if (!EVENT_OUTCOMES.includes(record.outcome)) problems.push(`Invalid outcome "${record.outcome}".`);
  if (!EVENT_SEVERITIES.includes(record.severity)) problems.push(`Invalid severity "${record.severity}".`);
  const occurred = new Date(record.occurredAt).getTime();
  const received = new Date(record.receivedAt).getTime();
  if (Number.isNaN(occurred)) problems.push('Invalid occurredAt timestamp.');
  if (Number.isNaN(received)) problems.push('Invalid receivedAt timestamp.');
  if (!Number.isNaN(occurred) && !Number.isNaN(received) && occurred - received > toleranceMs) problems.push('Event occurrence time is later than server receipt time.');
  const systemActor = record.metadata?.actorType === 'SYSTEM';
  if (!systemActor && !record.actorUserId && !record.actorUsername) problems.push('Missing user identity.');
  if (type?.requiresEntity && (!record.entityType || !record.entityId)) problems.push('Missing entity type or identifier.');
  if (record.previousValues !== null && record.previousValues !== undefined && !isPlainObject(record.previousValues)) problems.push('Previous values are not a JSON object.');
  if (record.newValues !== null && record.newValues !== undefined && !isPlainObject(record.newValues)) problems.push('New values are not a JSON object.');
  if (type?.requiresChanges && !isPlainObject(record.newValues)) problems.push(`${record.actionType} record has no "after" values.`);
  return problems;
};

/** Combine check statuses into one overall result. */
export const overallStatus = (statuses) => {
  if (statuses.includes('FAIL')) return 'FAIL';
  if (statuses.includes('WARNING')) return 'WARNING';
  if (statuses.includes('PASS')) return 'PASS';
  return 'NOT_TESTED';
};

/** Coverage status for one registry entry. */
export const coverageStatusFor = ({ receivedCount, invalidCount }) => {
  if (receivedCount > 0) return 'VERIFIED';
  if (invalidCount > 0) return 'INVALID_ONLY';
  return 'NOT_OBSERVED';
};

// ---------------------------------------------------------------------------
// Run context
// ---------------------------------------------------------------------------
class RunContext {
  constructor(run) {
    this.run = run;
    this.results = [];
    this.detected = new Set();
    this.executedCategories = new Set();
    this.stats = { newFindings: 0, reopened: 0, recurring: 0, verified: 0, bySeverity: {}, newCritical: [] };
  }

  async result(category, checkCode, checkName, status, summary, { sourceSystemId = null, itemsChecked = 0, itemsFailed = 0, details = null } = {}) {
    this.executedCategories.add(category);
    const row = await QaResult.create({ runId: this.run.id, category, checkCode, checkName, status, summary: summary.slice(0, 1000), sourceSystemId, itemsChecked, itemsFailed, details });
    this.results.push(row);
    return row;
  }

  async finding({ category, checkCode, sourceSystemId = null, relatedAuditLogId = null, relatedEventId = null, title, description, severity, recommendedAction, fingerprint, details = null }) {
    this.detected.add(fingerprint);
    const now = new Date();
    const existing = await QaFinding.findOne({ where: { fingerprint, status: { [Op.ne]: 'VERIFIED' } }, order: [['id', 'DESC']] });
    if (existing) {
      const update = { lastDetectedAt: now, occurrenceCount: existing.occurrenceCount + 1, lastRunId: this.run.id, description, details };
      if (existing.status === 'RESOLVED') {
        update.status = 'OPEN';
        update.resolutionNotes = `${existing.resolutionNotes || ''}\n[Reopened by ${formatRunId(this.run.id)}: issue detected again]`.trim();
        this.stats.reopened += 1;
      } else {
        this.stats.recurring += 1;
      }
      await existing.update(update);
      return existing;
    }
    const created = await QaFinding.create({
      runId: this.run.id, lastRunId: this.run.id, category, checkCode, sourceSystemId, relatedAuditLogId, relatedEventId,
      title: title.slice(0, 200), description, severity, recommendedAction, status: 'OPEN', fingerprint: fingerprint.slice(0, 255),
      occurrenceCount: 1, firstDetectedAt: now, lastDetectedAt: now, details
    });
    this.stats.newFindings += 1;
    this.stats.bySeverity[severity] = (this.stats.bySeverity[severity] || 0) + 1;
    if (['CRITICAL', 'HIGH'].includes(severity)) this.stats.newCritical.push(created);
    return created;
  }
}

// ---------------------------------------------------------------------------
// Checks
// ---------------------------------------------------------------------------
const MAX_RECORD_FINDINGS = 50;

/** Single pass over audit_logs: integrity (HMAC + chain) and stored-record validation. */
const checkStoredRecords = async (ctx, eventTypes, sourcesById) => {
  let lastId = 0;
  let previousHash = GENESIS_HASH;
  let checked = 0;
  const integrity = { SIGNATURE_MISMATCH: [], MISSING_INTEGRITY: [], INVALID_HASH_FORMAT: [], UNKNOWN_SIGNING_KEY: [], CHAIN_BROKEN: [] };
  const invalidRecords = [];

  for (;;) {
    const batch = await AuditLog.findAll({ where: { id: { [Op.gt]: lastId } }, order: [['id', 'ASC']], limit: 1000, raw: true });
    if (!batch.length) break;
    for (const record of batch) {
      checked += 1;
      const verdict = verifyRecord(record, previousHash);
      verdict.issues.forEach((issue) => integrity[issue.code]?.push({ record, message: issue.message }));
      const problems = validateStoredRecord(record, eventTypes);
      if (problems.length) invalidRecords.push({ record, problems });
      previousHash = record.integrityHash || previousHash;
      lastId = record.id;
    }
  }

  // --- AUDIT_INTEGRITY ----------------------------------------------------
  const integrityChecks = [
    ['AI_SIGNATURE', 'Integrity signature validity', ['SIGNATURE_MISMATCH'], 'CRITICAL', 'Audit record content does not match its integrity signature',
      'Treat as a potential unauthorised modification: preserve database backups and binary logs, compare against the most recent backup, and open an investigation case.'],
    ['AI_MISSING', 'Missing integrity information', ['MISSING_INTEGRITY'], 'CRITICAL', 'Audit record has no integrity value',
      'Determine how the record was inserted outside the ingestion pipeline and review database write access.'],
    ['AI_FORMAT', 'Hash / signature format', ['INVALID_HASH_FORMAT'], 'HIGH', 'Audit record has a malformed integrity value',
      'Inspect the record for corruption and compare with backups.'],
    ['AI_KEY', 'Signing key availability', ['UNKNOWN_SIGNING_KEY'], 'HIGH', 'Audit record was signed with an unavailable key',
      'Restore the retired signing key via AUDIT_SIGNING_KEYS_RETIRED so the record can be verified.'],
    ['AI_CHAIN', 'Hash-chain continuity', ['CHAIN_BROKEN'], 'CRITICAL', 'Audit hash chain is broken',
      'A record may have been deleted, inserted or reordered. Compare record IDs around this point with backups and open an investigation.']
  ];
  for (const [code, name, issueCodes, severity, title, action] of integrityChecks) {
    const items = issueCodes.flatMap((c) => integrity[c]);
    if (!checked) {
      await ctx.result('AUDIT_INTEGRITY', code, name, 'NOT_TESTED', 'No audit records exist yet.', {});
      continue;
    }
    await ctx.result('AUDIT_INTEGRITY', code, name, items.length ? 'FAIL' : 'PASS',
      items.length ? `${items.length} of ${checked} record(s) failed.` : `All ${checked} record(s) passed.`,
      { itemsChecked: checked, itemsFailed: items.length, details: { failed: items.slice(0, 100).map((i) => ({ auditLogId: i.record.id, eventId: i.record.eventId })) } });
    for (const item of items.slice(0, MAX_RECORD_FINDINGS)) {
      await ctx.finding({
        category: 'AUDIT_INTEGRITY', checkCode: code, sourceSystemId: item.record.sourceSystemId,
        relatedAuditLogId: item.record.id, relatedEventId: item.record.eventId,
        title, description: `Audit #${item.record.id} (${item.record.eventId}, ${sourcesById.get(item.record.sourceSystemId)?.name || 'unknown source'}): ${item.message}`,
        severity, recommendedAction: action, fingerprint: `${code}|audit:${item.record.id}`
      });
    }
    if (items.length > MAX_RECORD_FINDINGS) {
      await ctx.finding({
        category: 'AUDIT_INTEGRITY', checkCode: code, title: `${title} (additional records)`,
        description: `${items.length - MAX_RECORD_FINDINGS} further record(s) failed this check. See ${formatRunId(ctx.run.id)} details.`,
        severity, recommendedAction: action, fingerprint: `${code}|overflow`
      });
    }
  }

  const duplicates = await findDuplicateEventIds();
  await ctx.result('AUDIT_INTEGRITY', 'AI_DUPLICATES', 'Duplicate event identifiers', duplicates.length ? 'FAIL' : (checked ? 'PASS' : 'NOT_TESTED'),
    duplicates.length ? `${duplicates.length} duplicated event identifier(s) found.` : (checked ? 'Every (source, eventId) pair is unique.' : 'No audit records exist yet.'),
    { itemsChecked: checked, itemsFailed: duplicates.length, details: { duplicates: duplicates.slice(0, 50) } });
  for (const dup of duplicates.slice(0, MAX_RECORD_FINDINGS)) {
    await ctx.finding({
      category: 'AUDIT_INTEGRITY', checkCode: 'AI_DUPLICATES', sourceSystemId: dup.sourceSystemId, relatedEventId: dup.eventId,
      title: 'Duplicate event identifier stored', description: `Event ${dup.eventId} is stored ${dup.occurrences} times for the same source system.`,
      severity: 'HIGH', recommendedAction: 'Verify that the unique index uq_audit_source_event exists and review how the duplicate was inserted.',
      fingerprint: `AI_DUPLICATES|${dup.sourceSystemId}|${dup.eventId}`
    });
  }

  const triggers = await appendOnlyTriggersPresent();
  const triggersOk = triggers.update && triggers.delete;
  await ctx.result('AUDIT_INTEGRITY', 'AI_APPEND_ONLY', 'Append-only database protection', triggersOk ? 'PASS' : 'FAIL',
    triggersOk ? 'UPDATE and DELETE triggers are installed on audit_logs.' : 'Append-only triggers are missing from audit_logs.', { itemsChecked: 2, itemsFailed: (triggers.update ? 0 : 1) + (triggers.delete ? 0 : 1), details: triggers });
  if (!triggersOk) {
    await ctx.finding({
      category: 'AUDIT_INTEGRITY', checkCode: 'AI_APPEND_ONLY', title: 'Append-only protection disabled',
      description: `Database triggers protecting audit_logs are missing (update: ${triggers.update}, delete: ${triggers.delete}). Records could be altered without application involvement.`,
      severity: 'CRITICAL', recommendedAction: 'Re-run migration 002 (delete its row from schema_migrations, then `npm run migrate`) and review who removed the triggers.',
      fingerprint: 'AI_APPEND_ONLY|triggers'
    });
  }

  // --- EVENT_VALIDATION (stored records) -----------------------------------
  await ctx.result('EVENT_VALIDATION', 'EV_STORED_RECORDS', 'Stored audit record completeness',
    checked ? (invalidRecords.length ? 'FAIL' : 'PASS') : 'NOT_TESTED',
    checked ? (invalidRecords.length ? `${invalidRecords.length} of ${checked} stored record(s) are incomplete or inconsistent.` : `All ${checked} stored record(s) contain valid, complete information.`) : 'No audit records exist yet.',
    { itemsChecked: checked, itemsFailed: invalidRecords.length, details: { invalid: invalidRecords.slice(0, 100).map((i) => ({ auditLogId: i.record.id, problems: i.problems })) } });
  for (const item of invalidRecords.slice(0, MAX_RECORD_FINDINGS)) {
    await ctx.finding({
      category: 'EVENT_VALIDATION', checkCode: 'EV_STORED_RECORDS', sourceSystemId: item.record.sourceSystemId,
      relatedAuditLogId: item.record.id, relatedEventId: item.record.eventId,
      title: 'Stored audit record fails validation', description: `Audit #${item.record.id}: ${item.problems.join(' ')}`,
      severity: 'MEDIUM', recommendedAction: 'Review event type configuration and the submitting system\'s payload mapping.',
      fingerprint: `EV_STORED_RECORDS|audit:${item.record.id}`
    });
  }
  return checked;
};

const checkSubmissions = async (ctx, sources, settings) => {
  const since = new Date(Date.now() - settings['qa.lookbackDays'] * 86400000);
  const warnRate = settings['qa.invalidRateWarningPercent'];
  const rows = await IntegrationLog.findAll({
    where: { createdAt: { [Op.gte]: since } },
    attributes: ['sourceSystemId', 'outcome', 'errorCode', [sequelize.fn('COUNT', sequelize.col('id')), 'n']],
    group: ['sourceSystemId', 'outcome', 'errorCode'], raw: true
  });
  const bySource = new Map();
  rows.forEach((r) => {
    const key = r.sourceSystemId ?? 'unknown';
    if (!bySource.has(key)) bySource.set(key, { total: 0, accepted: 0, invalid: 0, auth: 0, invalidCodes: {}, authCodes: {} });
    const s = bySource.get(key);
    const n = Number(r.n);
    if (!['CONNECTION_TEST_OK', 'CONNECTION_TEST_FAILED'].includes(r.outcome)) s.total += n;
    if (r.outcome === 'ACCEPTED') s.accepted += n;
    if (r.outcome === 'REJECTED_VALIDATION') { s.invalid += n; s.invalidCodes[r.errorCode || 'UNKNOWN'] = (s.invalidCodes[r.errorCode || 'UNKNOWN'] || 0) + n; }
    if (r.outcome === 'REJECTED_AUTH') { s.auth += n; s.authCodes[r.errorCode || 'UNKNOWN'] = (s.authCodes[r.errorCode || 'UNKNOWN'] || 0) + n; }
  });

  for (const source of sources) {
    const s = bySource.get(source.id);
    if (!s || !s.total) {
      await ctx.result('EVENT_VALIDATION', 'EV_SUBMISSIONS', 'Submitted event validity', 'NOT_TESTED', `No submissions from ${source.name} in the last ${settings['qa.lookbackDays']} day(s).`, { sourceSystemId: source.id });
      await ctx.result('EVENT_VALIDATION', 'EV_AUTHENTICATION', 'API authentication validity', 'NOT_TESTED', `No authenticated requests from ${source.name} in the lookback period.`, { sourceSystemId: source.id });
      continue;
    }
    const submitted = s.accepted + s.invalid;
    const rate = pct(s.invalid, submitted);
    const status = s.invalid === 0 ? 'PASS' : rate <= warnRate ? 'WARNING' : 'FAIL';
    await ctx.result('EVENT_VALIDATION', 'EV_SUBMISSIONS', 'Submitted event validity', status,
      s.invalid ? `${s.invalid} of ${submitted} submission(s) from ${source.name} were rejected as invalid (${rate}%).` : `All ${submitted} submission(s) from ${source.name} passed validation.`,
      { sourceSystemId: source.id, itemsChecked: submitted, itemsFailed: s.invalid, details: { errorCodes: s.invalidCodes } });
    if (s.invalid) {
      for (const [code, n] of Object.entries(s.invalidCodes)) {
        await ctx.finding({
          category: 'EVENT_VALIDATION', checkCode: 'EV_SUBMISSIONS', sourceSystemId: source.id,
          title: `Invalid event submissions (${code})`, description: `${source.name} submitted ${n} event(s) rejected with ${code} in the last ${settings['qa.lookbackDays']} day(s).`,
          severity: status === 'FAIL' ? 'MEDIUM' : 'LOW',
          recommendedAction: 'Review the rejected payloads in Integration Logs and share the validation errors with the source system team.',
          fingerprint: `EV_SUBMISSIONS|${source.id}|${code}`
        });
      }
    }
    const authStatus = s.auth === 0 ? 'PASS' : 'WARNING';
    await ctx.result('EVENT_VALIDATION', 'EV_AUTHENTICATION', 'API authentication validity', authStatus,
      s.auth ? `${s.auth} request(s) for ${source.name} failed authentication (${Object.keys(s.authCodes).join(', ')}).` : `All requests from ${source.name} were properly authenticated.`,
      { sourceSystemId: source.id, itemsChecked: s.total, itemsFailed: s.auth, details: { errorCodes: s.authCodes } });
    if (s.auth) {
      await ctx.finding({
        category: 'EVENT_VALIDATION', checkCode: 'EV_AUTHENTICATION', sourceSystemId: source.id,
        title: 'API authentication failures', description: `${s.auth} authentication failure(s) for ${source.name}'s credentials: ${JSON.stringify(s.authCodes)}.`,
        severity: 'MEDIUM', recommendedAction: 'Check the source system\'s clock synchronisation and credential configuration; revoke the key if the requests are not recognised.',
        fingerprint: `EV_AUTHENTICATION|${source.id}`
      });
    }
  }
  const unknown = bySource.get('unknown');
  if (unknown?.auth) {
    await ctx.result('EVENT_VALIDATION', 'EV_UNKNOWN_CALLERS', 'Unidentified API callers', 'WARNING', `${unknown.auth} request(s) used missing or unknown credentials.`, { itemsChecked: unknown.total, itemsFailed: unknown.auth, details: { errorCodes: unknown.authCodes } });
    await ctx.finding({
      category: 'EVENT_VALIDATION', checkCode: 'EV_UNKNOWN_CALLERS', title: 'Requests with unknown credentials',
      description: `${unknown.auth} API request(s) could not be associated with any registered credential: ${JSON.stringify(unknown.authCodes)}.`,
      severity: 'MEDIUM', recommendedAction: 'Review Integration Logs for the calling IP addresses; block unrecognised callers at the network edge.',
      fingerprint: 'EV_UNKNOWN_CALLERS|global'
    });
  } else {
    await ctx.result('EVENT_VALIDATION', 'EV_UNKNOWN_CALLERS', 'Unidentified API callers', 'PASS', 'No requests with unknown credentials in the lookback period.');
  }
};

const checkCoverage = async (ctx, sources) => {
  const coverage = [];
  for (const source of sources) {
    const registry = await AuditEventRegistry.findAll({ where: { sourceSystemId: source.id, isActive: true }, include: [{ model: AuditEventType, as: 'eventType' }] });
    if (!registry.length) {
      await ctx.result('EVENT_COVERAGE', 'EC_COVERAGE', 'Expected event coverage', 'NOT_TESTED', `No expected events are registered for ${source.name}.`, { sourceSystemId: source.id });
      continue;
    }
    if (source.health.status === 'NEVER_CONNECTED') {
      await ctx.result('EVENT_COVERAGE', 'EC_COVERAGE', 'Expected event coverage', 'NOT_TESTED',
        `${source.name} has never communicated with MediSentinel; ${registry.length} expected event type(s) cannot be verified yet.`,
        { sourceSystemId: source.id, itemsChecked: registry.length, details: { entries: registry.map((r) => ({ code: r.eventType.code, status: 'NOT_OBSERVED', receivedCount: 0, invalidCount: 0 })) } });
      coverage.push({ source, verified: 0, required: registry.filter((r) => r.isRequired).length });
      continue;
    }
    const codes = registry.map((r) => r.eventType.code);
    const [received, invalid] = await Promise.all([
      AuditLog.findAll({ where: { sourceSystemId: source.id, actionType: { [Op.in]: codes } }, attributes: ['actionType', [sequelize.fn('COUNT', sequelize.col('id')), 'n'], [sequelize.fn('MAX', sequelize.col('receivedAt')), 'last']], group: ['actionType'], raw: true }),
      IntegrationLog.findAll({ where: { sourceSystemId: source.id, outcome: 'REJECTED_VALIDATION', actionCode: { [Op.in]: codes } }, attributes: ['actionCode', [sequelize.fn('COUNT', sequelize.col('id')), 'n']], group: ['actionCode'], raw: true })
    ]);
    const recMap = Object.fromEntries(received.map((r) => [r.actionType, r]));
    const invMap = Object.fromEntries(invalid.map((r) => [r.actionCode, Number(r.n)]));
    const entries = registry.map((r) => {
      const receivedCount = Number(recMap[r.eventType.code]?.n || 0);
      const invalidCount = invMap[r.eventType.code] || 0;
      return { code: r.eventType.code, name: r.eventType.name, module: r.sourceModule, isRequired: r.isRequired, receivedCount, invalidCount, lastReceivedAt: recMap[r.eventType.code]?.last || null, status: coverageStatusFor({ receivedCount, invalidCount }) };
    });
    const required = entries.filter((e) => e.isRequired);
    const verified = required.filter((e) => e.status === 'VERIFIED').length;
    const invalidOnly = entries.filter((e) => e.status === 'INVALID_ONLY');
    const notObserved = required.filter((e) => e.status === 'NOT_OBSERVED');
    const status = invalidOnly.length ? 'FAIL' : notObserved.length ? 'WARNING' : 'PASS';
    coverage.push({ source, verified, required: required.length });
    await ctx.result('EVENT_COVERAGE', 'EC_COVERAGE', 'Expected event coverage', status,
      `${source.name}: ${verified} of ${required.length} required event type(s) verified (${pct(verified, required.length)}%).${notObserved.length ? ` Not yet observed: ${notObserved.map((e) => e.code).join(', ')}.` : ''}${invalidOnly.length ? ` Only invalid submissions: ${invalidOnly.map((e) => e.code).join(', ')}.` : ''}`,
      { sourceSystemId: source.id, itemsChecked: required.length, itemsFailed: required.length - verified, details: { entries } });
    for (const e of invalidOnly) {
      await ctx.finding({
        category: 'EVENT_COVERAGE', checkCode: 'EC_INVALID_ONLY', sourceSystemId: source.id,
        title: `${e.code} events are only arriving invalid`, description: `${source.name} attempted ${e.invalidCount} ${e.code} event(s) but none passed validation. This is a confirmed delivery problem.`,
        severity: 'MEDIUM', recommendedAction: 'Inspect the rejected payloads in Integration Logs and correct the source system\'s event mapping.',
        fingerprint: `EC_INVALID_ONLY|${source.id}|${e.code}`
      });
    }
    for (const e of notObserved) {
      await ctx.finding({
        category: 'EVENT_COVERAGE', checkCode: 'EC_NOT_OBSERVED', sourceSystemId: source.id,
        title: `Expected event not yet observed: ${e.code}`,
        description: `${source.name} is expected to submit ${e.code}${e.module ? ` (${e.module})` : ''} but none has been received. This does NOT confirm an event was lost — the activity may simply not have occurred yet.`,
        severity: 'LOW', recommendedAction: 'Confirm with the source system team that this action is instrumented, then trigger it in a test environment to verify delivery.',
        fingerprint: `EC_NOT_OBSERVED|${source.id}|${e.code}`
      });
    }
  }
  const totalRequired = coverage.reduce((s, c) => s + c.required, 0);
  const totalVerified = coverage.reduce((s, c) => s + c.verified, 0);
  return totalRequired ? pct(totalVerified, totalRequired) : null;
};

const checkIntegrationQuality = async (ctx, sources, settings) => {
  const since = new Date(Date.now() - settings['qa.lookbackDays'] * 86400000);
  const maxDelayMs = settings['qa.maxDeliveryDelaySeconds'] * 1000;
  for (const source of sources) {
    // Availability
    const h = source.health;
    const availability = { HEALTHY: 'PASS', DEGRADED: 'WARNING', STALE: 'FAIL', NEVER_CONNECTED: 'NOT_TESTED', SUSPENDED: 'NOT_TESTED' }[h.status] || 'NOT_TESTED';
    await ctx.result('INTEGRATION_QUALITY', 'IQ_AVAILABILITY', 'Source system availability', availability, `${source.name}: ${h.label}. ${h.reason}`, { sourceSystemId: source.id, details: { health: h } });
    if (availability === 'FAIL' || availability === 'WARNING') {
      await ctx.finding({
        category: 'INTEGRATION_QUALITY', checkCode: 'IQ_AVAILABILITY', sourceSystemId: source.id,
        title: `${source.name} is ${h.label.toLowerCase()}`, description: h.reason,
        severity: availability === 'FAIL' ? 'HIGH' : 'MEDIUM',
        recommendedAction: 'Contact the source system team to confirm the integration client is running and can reach MediSentinel; review recent Integration Logs.',
        fingerprint: `IQ_AVAILABILITY|${source.id}`
      });
    }

    const logs = await IntegrationLog.findAll({
      where: { sourceSystemId: source.id, createdAt: { [Op.gte]: since } },
      attributes: ['outcome', 'deliveryAttempt', 'deliveryDelayMs', 'httpStatus'], raw: true
    });
    const requests = logs.filter((l) => !['CONNECTION_TEST_OK', 'CONNECTION_TEST_FAILED'].includes(l.outcome));
    const accepted = requests.filter((l) => l.outcome === 'ACCEPTED');

    // Delivery delay
    if (!accepted.length) {
      await ctx.result('INTEGRATION_QUALITY', 'IQ_DELIVERY_DELAY', 'Event delivery delay', 'NOT_TESTED', `No accepted events from ${source.name} in the lookback period.`, { sourceSystemId: source.id });
    } else {
      const delays = accepted.map((l) => Number(l.deliveryDelayMs || 0)).sort((a, b) => a - b);
      const late = delays.filter((d) => d > maxDelayMs).length;
      const p95 = delays[Math.min(delays.length - 1, Math.floor(delays.length * 0.95))];
      const latePct = pct(late, delays.length);
      const status = late === 0 ? 'PASS' : latePct <= 10 ? 'WARNING' : 'FAIL';
      await ctx.result('INTEGRATION_QUALITY', 'IQ_DELIVERY_DELAY', 'Event delivery delay', status,
        `${source.name}: ${late} of ${delays.length} event(s) arrived later than ${settings['qa.maxDeliveryDelaySeconds']}s (p95 ${Math.round(p95 / 1000)}s).`,
        { sourceSystemId: source.id, itemsChecked: delays.length, itemsFailed: late, details: { p95Ms: p95, maxMs: delays[delays.length - 1], avgMs: Math.round(delays.reduce((a, b) => a + b, 0) / delays.length) } });
      if (status !== 'PASS') {
        await ctx.finding({
          category: 'INTEGRATION_QUALITY', checkCode: 'IQ_DELIVERY_DELAY', sourceSystemId: source.id,
          title: `Delayed event delivery from ${source.name}`, description: `${latePct}% of events arrived later than the ${settings['qa.maxDeliveryDelaySeconds']}s target (p95 ${Math.round(p95 / 1000)}s).`,
          severity: status === 'FAIL' ? 'MEDIUM' : 'LOW', recommendedAction: 'Check the source system\'s outbound queue, retry back-off and clock synchronisation.',
          fingerprint: `IQ_DELIVERY_DELAY|${source.id}`
        });
      }
    }

    // API response status / failed submissions / retries
    if (!requests.length) {
      await ctx.result('INTEGRATION_QUALITY', 'IQ_API_RESPONSES', 'API response status', 'NOT_TESTED', `No API requests from ${source.name} in the lookback period.`, { sourceSystemId: source.id });
    } else {
      const failed = requests.filter((l) => ['ERROR', 'RATE_LIMITED', 'REJECTED_FORBIDDEN', 'CONFLICT'].includes(l.outcome));
      const failedRetries = requests.filter((l) => (l.deliveryAttempt || 1) > 1 && !['ACCEPTED', 'DUPLICATE', 'HEARTBEAT'].includes(l.outcome));
      const duplicates = requests.filter((l) => l.outcome === 'DUPLICATE');
      const failPct = pct(failed.length + failedRetries.length, requests.length);
      const status = failed.length + failedRetries.length === 0 ? 'PASS' : failPct <= 5 ? 'WARNING' : 'FAIL';
      const byStatus = requests.reduce((acc, l) => { acc[l.httpStatus] = (acc[l.httpStatus] || 0) + 1; return acc; }, {});
      await ctx.result('INTEGRATION_QUALITY', 'IQ_API_RESPONSES', 'API response status', status,
        `${source.name}: ${requests.length} request(s); ${failed.length} failed, ${failedRetries.length} failed retr${failedRetries.length === 1 ? 'y' : 'ies'}, ${duplicates.length} duplicate(s).`,
        { sourceSystemId: source.id, itemsChecked: requests.length, itemsFailed: failed.length + failedRetries.length, details: { httpStatus: byStatus, duplicates: duplicates.length, failedRetries: failedRetries.length } });
      if (status !== 'PASS') {
        await ctx.finding({
          category: 'INTEGRATION_QUALITY', checkCode: 'IQ_API_RESPONSES', sourceSystemId: source.id,
          title: `Failed API requests from ${source.name}`, description: `${failPct}% of requests failed or required unsuccessful retries in the lookback period.`,
          severity: status === 'FAIL' ? 'MEDIUM' : 'LOW', recommendedAction: 'Review the failed requests in Integration Logs (conflicts, rate limits, suspended source) and correct the client behaviour.',
          fingerprint: `IQ_API_RESPONSES|${source.id}`
        });
      }
      const dupPct = pct(duplicates.length, requests.length);
      await ctx.result('INTEGRATION_QUALITY', 'IQ_DUPLICATES', 'Duplicate submissions', dupPct > 20 ? 'WARNING' : 'PASS',
        `${duplicates.length} duplicate submission(s) (${dupPct}%) — duplicates are handled idempotently.`, { sourceSystemId: source.id, itemsChecked: requests.length, itemsFailed: duplicates.length });
    }

    // Pending deliveries reported by the source's heartbeat
    const hb = source.lastHeartbeatPayload;
    if (!hb) {
      await ctx.result('INTEGRATION_QUALITY', 'IQ_PENDING', 'Pending event deliveries', 'NOT_TESTED', `${source.name} has not reported a heartbeat with its delivery queue.`, { sourceSystemId: source.id });
    } else {
      const oldestAge = hb.oldestPendingAt ? Date.now() - new Date(hb.oldestPendingAt).getTime() : 0;
      const issue = (hb.failedDeliveries || 0) > 0 || ((hb.pendingEvents || 0) > 0 && oldestAge > maxDelayMs);
      await ctx.result('INTEGRATION_QUALITY', 'IQ_PENDING', 'Pending event deliveries', issue ? 'WARNING' : 'PASS',
        `${source.name} reported ${hb.pendingEvents ?? 'n/a'} pending and ${hb.failedDeliveries ?? 'n/a'} failed deliveries at ${hb.reportedAt}.`, { sourceSystemId: source.id, details: hb });
      if (issue) {
        await ctx.finding({
          category: 'INTEGRATION_QUALITY', checkCode: 'IQ_PENDING', sourceSystemId: source.id,
          title: `${source.name} reports undelivered events`, description: `Heartbeat reported ${hb.pendingEvents ?? 0} pending and ${hb.failedDeliveries ?? 0} failed deliveries${hb.oldestPendingAt ? ` (oldest pending since ${hb.oldestPendingAt})` : ''}.`,
          severity: 'MEDIUM', recommendedAction: 'Ask the source system team to inspect their outbound audit queue and retry failed deliveries.',
          fingerprint: `IQ_PENDING|${source.id}`
        });
      }
    }
  }
};

// ---------------------------------------------------------------------------
// Execution
// ---------------------------------------------------------------------------
export const executeVerification = async ({ user = null, trigger = 'MANUAL', req = null } = {}) => {
  const running = await QaRun.findOne({ where: { status: 'RUNNING', startedAt: { [Op.gte]: new Date(Date.now() - 10 * 60000) } } });
  if (running) throw Object.assign(new Error(`${formatRunId(running.id)} is still running.`), { status: 409 });

  const run = await QaRun.create({
    triggerType: trigger, executedByUserId: user?.id || null, executedByLabel: user ? `${user.fullName} (${user.username})` : 'Scheduler', startedAt: new Date(), status: 'RUNNING'
  });
  const ctx = new RunContext(run);
  try {
    const settings = await getSettingsMap(['qa.lookbackDays', 'qa.maxDeliveryDelaySeconds', 'qa.invalidRateWarningPercent']);
    const eventTypes = new Map((await AuditEventType.findAll({ raw: true })).map((t) => [t.code, t]));
    const allSources = await listSourcesWithHealth();
    const sourcesById = new Map(allSources.map((s) => [s.id, s]));
    const external = allSources.filter((s) => !s.isInternal && s.status !== 'RETIRED');

    const recordsVerified = await checkStoredRecords(ctx, eventTypes, sourcesById);
    await checkSubmissions(ctx, external, settings);
    const coveragePercent = await checkCoverage(ctx, external);
    await checkIntegrationQuality(ctx, external, settings);
    await runPosQualityChecks(ctx, { external, sourcesById, eventTypes, settings });

    // Resolved findings that were not re-detected are now verified as fixed.
    const resolved = await QaFinding.findAll({ where: { status: 'RESOLVED', category: { [Op.in]: [...ctx.executedCategories] } } });
    for (const finding of resolved) {
      if (!ctx.detected.has(finding.fingerprint)) {
        await finding.update({ status: 'VERIFIED', verifiedAt: new Date(), verificationNote: `Not re-detected by ${formatRunId(run.id)}.` });
        ctx.stats.verified += 1;
      }
    }

    const statuses = ctx.results.map((r) => r.status);
    const byCategory = {};
    ctx.results.forEach((r) => { (byCategory[r.category] ||= []).push(r.status); });
    const categoryStatus = Object.fromEntries(Object.keys(QA_CATEGORY_LABELS).map((c) => [c, overallStatus(byCategory[c] || [])]));
    await run.update({
      status: 'COMPLETED',
      completedAt: new Date(),
      totalChecks: statuses.length,
      passedChecks: statuses.filter((s) => s === 'PASS').length,
      failedChecks: statuses.filter((s) => s === 'FAIL').length,
      warningChecks: statuses.filter((s) => s === 'WARNING').length,
      notTestedChecks: statuses.filter((s) => s === 'NOT_TESTED').length,
      overallResult: overallStatus(statuses),
      recordsVerified,
      findingsSummary: {
        newFindings: ctx.stats.newFindings, reopened: ctx.stats.reopened, recurring: ctx.stats.recurring, verified: ctx.stats.verified,
        newBySeverity: ctx.stats.bySeverity, coveragePercent, categoryStatus
      }
    });

    await recordInternalEvent({
      user, req, action: 'QA_VERIFICATION_RUN', module: 'Quality Assurance', entity: { type: 'QaVerificationRun', id: formatRunId(run.id) },
      description: `${formatRunId(run.id)} (${trigger.toLowerCase()}) completed: ${run.overallResult} — ${run.passedChecks} pass, ${run.failedChecks} fail, ${run.warningChecks} warning, ${run.notTestedChecks} not tested.`,
      outcome: 'SUCCESS', severity: run.overallResult === 'FAIL' ? 'MEDIUM' : 'INFO',
      metadata: { recordsVerified, newFindings: ctx.stats.newFindings }
    });

    const integrityFindings = ctx.stats.newCritical.filter((f) => f.category === 'AUDIT_INTEGRITY');
    if (integrityFindings.length) {
      await notifyPermission('qa.view', {
        type: 'INTEGRITY_FAILURE', severity: 'CRITICAL',
        title: `Integrity verification failed (${integrityFindings.length} new finding${integrityFindings.length > 1 ? 's' : ''})`,
        message: integrityFindings.slice(0, 3).map((f) => f.description).join(' | '),
        link: `/qa/findings?category=AUDIT_INTEGRITY&status=OPEN`, relatedFindingId: integrityFindings[0].id, relatedAuditLogId: integrityFindings[0].relatedAuditLogId
      });
    }
    const otherNew = ctx.stats.newFindings - integrityFindings.length;
    if (otherNew > 0) {
      await notifyPermission('qa.view', {
        type: 'UNRESOLVED_QA_FINDING', severity: ctx.stats.newCritical.length > integrityFindings.length ? 'HIGH' : 'MEDIUM',
        title: `${formatRunId(run.id)}: ${otherNew} new QA finding(s)`,
        message: `Verification result ${run.overallResult}. Review the new findings and assign follow-up.`,
        link: `/qa/runs/${run.id}`
      });
    }
    return run;
  } catch (error) {
    await run.update({ status: 'ERROR', completedAt: new Date(), errorMessage: error.message.slice(0, 2000) });
    throw error;
  }
};

// ---------------------------------------------------------------------------
// Queries
// ---------------------------------------------------------------------------
export const qaDashboard = async () => {
  const [latest, runs, findingCounts, totals] = await Promise.all([
    QaRun.findOne({ where: { status: 'COMPLETED' }, order: [['id', 'DESC']], raw: true }),
    QaRun.findAll({ order: [['id', 'DESC']], limit: 10, raw: true }),
    QaFinding.findAll({ attributes: ['status', 'severity', [sequelize.fn('COUNT', sequelize.col('id')), 'n']], group: ['status', 'severity'], raw: true }),
    QaRun.findOne({ where: { status: 'COMPLETED' }, attributes: [[sequelize.fn('COUNT', sequelize.col('id')), 'runs'], [sequelize.fn('SUM', sequelize.col('totalChecks')), 'checks'], [sequelize.fn('SUM', sequelize.col('passedChecks')), 'passed'], [sequelize.fn('SUM', sequelize.col('failedChecks')), 'failed'], [sequelize.fn('SUM', sequelize.col('warningChecks')), 'warnings']], raw: true })
  ]);
  const latestResults = latest ? await QaResult.findAll({ where: { runId: latest.id }, include: [{ model: SourceSystem, as: 'sourceSystem', attributes: ['name'] }], order: [['category', 'ASC'], ['id', 'ASC']] }) : [];
  const openFindings = {};
  FINDING_SEVERITIES.forEach((s) => { openFindings[s] = 0; });
  let unresolved = 0;
  findingCounts.forEach((r) => { if (['OPEN', 'UNDER_INVESTIGATION'].includes(r.status)) { openFindings[r.severity] += Number(r.n); unresolved += Number(r.n); } });
  const categoryStatus = latest?.findingsSummary?.categoryStatus || {};
  return {
    latest: latest ? { ...latest, runCode: formatRunId(latest.id) } : null,
    runs: runs.map((r) => ({ ...r, runCode: formatRunId(r.id) })).reverse(),
    totals: { runs: Number(totals?.runs || 0), checks: Number(totals?.checks || 0), passed: Number(totals?.passed || 0), failed: Number(totals?.failed || 0), warnings: Number(totals?.warnings || 0) },
    openFindings, unresolved,
    categories: Object.entries(QA_CATEGORY_LABELS).map(([code, label]) => ({ code, label, status: categoryStatus[code] || 'NOT_TESTED' })),
    coveragePercent: latest?.findingsSummary?.coveragePercent ?? null,
    latestResults: latestResults.map((r) => r.get({ plain: true }))
  };
};

export const latestQaStatus = async () => {
  const latest = await QaRun.findOne({ where: { status: 'COMPLETED' }, order: [['id', 'DESC']], attributes: ['id', 'overallResult', 'completedAt'], raw: true });
  return latest ? { ...latest, runCode: formatRunId(latest.id) } : { overallResult: 'NOT_TESTED' };
};

export const listRuns = async ({ page = 1, limit = 25 }) => {
  const { rows, count } = await QaRun.findAndCountAll({ order: [['id', 'DESC']], limit, offset: (page - 1) * limit, raw: true });
  return { rows: rows.map((r) => ({ ...r, runCode: formatRunId(r.id) })), count };
};

export const getRun = async (id) => {
  const run = await QaRun.findByPk(id, { include: [{ model: User, as: 'executedBy', attributes: ['fullName', 'username'] }] });
  if (!run) return null;
  const results = await QaResult.findAll({ where: { runId: id }, include: [{ model: SourceSystem, as: 'sourceSystem', attributes: ['id', 'name'] }], order: [['category', 'ASC'], ['id', 'ASC']] });
  const findings = await QaFinding.findAll({ where: { [Op.or]: [{ runId: id }, { lastRunId: id }] }, include: [{ model: SourceSystem, as: 'sourceSystem', attributes: ['name'] }], order: [['severity', 'ASC'], ['id', 'ASC']], limit: 500 });
  const grouped = Object.entries(QA_CATEGORY_LABELS).map(([code, label]) => ({
    code, label, results: results.filter((r) => r.category === code).map((r) => r.get({ plain: true }))
  }));
  return { run: { ...run.get({ plain: true }), runCode: formatRunId(run.id) }, grouped, findings: findings.map((f) => ({ ...f.get({ plain: true }), findingCode: formatFindingId(f.id) })) };
};

export const coverageMatrix = async () => {
  const sources = (await listSourcesWithHealth({ includeInternal: false })).filter((s) => s.status !== 'RETIRED');
  const out = [];
  for (const source of sources) {
    const registry = await AuditEventRegistry.findAll({ where: { sourceSystemId: source.id, isActive: true }, include: [{ model: AuditEventType, as: 'eventType' }], order: [['id', 'ASC']] });
    const codes = registry.map((r) => r.eventType.code);
    const [received, invalid] = codes.length ? await Promise.all([
      AuditLog.findAll({ where: { sourceSystemId: source.id, actionType: { [Op.in]: codes } }, attributes: ['actionType', [sequelize.fn('COUNT', sequelize.col('id')), 'n'], [sequelize.fn('MAX', sequelize.col('receivedAt')), 'last']], group: ['actionType'], raw: true }),
      IntegrationLog.findAll({ where: { sourceSystemId: source.id, outcome: 'REJECTED_VALIDATION', actionCode: { [Op.in]: codes } }, attributes: ['actionCode', [sequelize.fn('COUNT', sequelize.col('id')), 'n']], group: ['actionCode'], raw: true })
    ]) : [[], []];
    const rec = Object.fromEntries(received.map((r) => [r.actionType, r]));
    const inv = Object.fromEntries(invalid.map((r) => [r.actionCode, Number(r.n)]));
    const entries = registry.map((r) => {
      const receivedCount = Number(rec[r.eventType.code]?.n || 0);
      const invalidCount = inv[r.eventType.code] || 0;
      return { id: r.id, code: r.eventType.code, name: r.eventType.name, module: r.sourceModule, isRequired: r.isRequired, receivedCount, invalidCount, lastReceivedAt: rec[r.eventType.code]?.last || null, status: coverageStatusFor({ receivedCount, invalidCount }) };
    });
    const required = entries.filter((e) => e.isRequired);
    const verified = required.filter((e) => e.status === 'VERIFIED').length;
    out.push({ source, entries, verified, required: required.length, percent: required.length ? pct(verified, required.length) : null });
  }
  return out;
};

// ---------------------------------------------------------------------------
// Findings management
// ---------------------------------------------------------------------------
export const listFindings = async ({ status, severity, category, sourceSystemId, search, page = 1, limit = 25 }) => {
  const where = {};
  if (status === 'unresolved') where.status = { [Op.in]: ['OPEN', 'UNDER_INVESTIGATION'] };
  else if (FINDING_STATUSES.includes(status)) where.status = status;
  if (FINDING_SEVERITIES.includes(severity)) where.severity = severity;
  if (QA_CATEGORY_LABELS[category]) where.category = category;
  if (sourceSystemId) where.sourceSystemId = Number(sourceSystemId);
  if (search) where[Op.or] = [{ title: { [Op.like]: `%${search}%` } }, { description: { [Op.like]: `%${search}%` } }, { relatedEventId: search }];
  const { rows, count } = await QaFinding.findAndCountAll({
    where, include: [{ model: SourceSystem, as: 'sourceSystem', attributes: ['id', 'name'] }, { model: User, as: 'assignedTo', attributes: ['fullName'] }],
    order: [[sequelize.literal("FIELD(`QaFinding`.`severity`,'CRITICAL','HIGH','MEDIUM','LOW','INFORMATIONAL')"), 'ASC'], ['lastDetectedAt', 'DESC']],
    limit, offset: (page - 1) * limit, distinct: true
  });
  return { rows: rows.map((f) => ({ ...f.get({ plain: true }), findingCode: formatFindingId(f.id), categoryLabel: QA_CATEGORY_LABELS[f.category] })), count };
};

export const getFinding = async (id) => {
  const f = await QaFinding.findByPk(id, {
    include: [
      { model: SourceSystem, as: 'sourceSystem', attributes: ['id', 'name'] },
      { model: QaRun, as: 'run', attributes: ['id'] },
      { model: User, as: 'assignedTo', attributes: ['id', 'fullName'] },
      { model: User, as: 'resolvedBy', attributes: ['fullName'] },
      { model: User, as: 'verifiedBy', attributes: ['fullName'] }
    ]
  });
  return f ? { ...f.get({ plain: true }), findingCode: formatFindingId(f.id), categoryLabel: QA_CATEGORY_LABELS[f.category] } : null;
};

export const updateFindingStatus = async (id, { status, notes, assignedToUserId }, user, req) => sequelize.transaction(async (transaction) => {
  const finding = await QaFinding.findByPk(id, { transaction, lock: transaction.LOCK.UPDATE });
  if (!finding) throw Object.assign(new Error('Finding not found.'), { status: 404 });
  if (!FINDING_STATUSES.includes(status)) throw Object.assign(new Error('Invalid status.'), { status: 400 });
  const text = String(notes || '').trim();
  if (status === 'RESOLVED' && !text) throw Object.assign(new Error('Resolution notes are required.'), { status: 400 });
  const before = { status: finding.status, assignedToUserId: finding.assignedToUserId };
  const update = { status };
  if (assignedToUserId !== undefined && assignedToUserId !== '') update.assignedToUserId = Number(assignedToUserId) || null;
  if (status === 'RESOLVED') Object.assign(update, { resolvedByUserId: user.id, resolvedAt: new Date(), resolutionNotes: text });
  if (status === 'VERIFIED') Object.assign(update, { verifiedByUserId: user.id, verifiedAt: new Date(), verificationNote: text.slice(0, 500) || 'Manually verified.' });
  if (status === 'OPEN' || status === 'UNDER_INVESTIGATION') { if (text) update.resolutionNotes = `${finding.resolutionNotes || ''}\n${text}`.trim(); }
  await finding.update(update, { transaction });
  await recordInternalEvent({
    user, req, action: 'QA_FINDING_UPDATED', module: 'Quality Assurance', entity: { type: 'QaFinding', id: formatFindingId(finding.id) },
    description: `${formatFindingId(finding.id)} status ${before.status} → ${status}`, before, after: { status, assignedToUserId: finding.assignedToUserId }, transaction
  });
  return finding;
});

// ---------------------------------------------------------------------------
// Scheduler
// ---------------------------------------------------------------------------
let schedulerTimer = null;
export const startQaScheduler = () => {
  if (schedulerTimer) return;
  schedulerTimer = setInterval(async () => {
    try {
      const { 'qa.scheduleIntervalMinutes': interval } = await getSettingsMap(['qa.scheduleIntervalMinutes']);
      if (!interval || interval <= 0) return;
      const last = await QaRun.findOne({ order: [['id', 'DESC']], attributes: ['startedAt'], raw: true });
      if (last && Date.now() - new Date(last.startedAt).getTime() < interval * 60000) return;
      await executeVerification({ trigger: 'SCHEDULED' });
    } catch (error) {
      if (error.status !== 409) console.error('[qa] scheduled verification failed:', error.message);
    }
  }, 60000);
  schedulerTimer.unref?.();
};
export const stopQaScheduler = () => { if (schedulerTimer) clearInterval(schedulerTimer); schedulerTimer = null; };
