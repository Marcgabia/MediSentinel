import { Op } from 'sequelize';
import {
  sequelize, AuditLog, Alert, InvestigationCase, IntegrationLog, QaRun, QaResult, QaFinding, SourceSystem, User
} from '../models/index.js';
import { buildAuditWhere } from './auditService.js';
import { listSourcesWithHealth } from './integrationService.js';
import { formatRunId } from './qaVerificationService.js';
import { localDate, ymd } from '../utils/sqlDates.js';

/**
 * Report definitions. Every report is computed from stored records; nothing is estimated.
 * Columns never include credentials, secrets, password hashes, session data or raw change payloads.
 */

const startOfDay = (d) => { const x = new Date(d); x.setHours(0, 0, 0, 0); return x; };

export const REPORTS = {
  DAILY_ACTIVITY: { name: 'Daily Audit Activity Report', description: 'Every audit event recorded on the selected day.', defaultDays: 0 },
  WEEKLY_ACTIVITY: { name: 'Weekly Audit Activity Report', description: 'Day-by-day activity totals for a seven-day period.', defaultDays: 6 },
  MONTHLY_ACTIVITY: { name: 'Monthly Audit Activity Report', description: 'Day-by-day activity totals for the month.', defaultDays: 'month' },
  SOURCE_SYSTEM_ACTIVITY: { name: 'Source System Activity Report', description: 'Activity volume and outcomes per connected system.', defaultDays: 29 },
  USER_ACTIVITY: { name: 'User Activity Report', description: 'Activity totals per user per source system.', defaultDays: 29 },
  AUTHENTICATION_ACTIVITY: { name: 'Authentication Activity Report', description: 'Logins, failed logins, logouts and password events.', defaultDays: 6 },
  FAILED_ACTIVITY: { name: 'Failed Activity Report', description: 'Events with FAILURE or DENIED outcomes.', defaultDays: 6 },
  SUSPICIOUS_ACTIVITY: { name: 'Suspicious Activity Report', description: 'Alerts raised by detection rules.', defaultDays: 29 },
  ADMINISTRATIVE_ACTIVITY: { name: 'Administrative Activity Report', description: 'Role, permission, account, settings and report events.', defaultDays: 29 },
  INVESTIGATION: { name: 'Audit Investigation Report', description: 'Investigation cases opened or updated in the period.', defaultDays: 89 },
  INTEGRATION_PERFORMANCE: { name: 'Integration Performance Report', description: 'API requests, failures and delivery delay per source system.', defaultDays: 6 },
  INTEGRITY_VERIFICATION: { name: 'Audit Integrity Verification Report', description: 'Results of integrity checks from QA verification runs.', defaultDays: 29 },
  QA_REPORT: { name: 'Quality Assurance Report', description: 'QA verification runs, outcomes and findings.', defaultDays: 29 }
};

export const resolvePeriod = (code, q = {}) => {
  const def = REPORTS[code];
  const today = new Date();
  let from = q.from ? new Date(`${q.from}T00:00:00`) : null;
  let to = q.to ? new Date(`${q.to}T23:59:59.999`) : null;
  if (from && Number.isNaN(from.getTime())) from = null;
  if (to && Number.isNaN(to.getTime())) to = null;
  if (!to) { to = new Date(today); to.setHours(23, 59, 59, 999); }
  if (!from) {
    if (def.defaultDays === 'month') from = new Date(to.getFullYear(), to.getMonth(), 1);
    else { from = startOfDay(to); from.setDate(from.getDate() - def.defaultDays); }
  }
  if (from > to) [from, to] = [startOfDay(to), new Date(from.getTime() + 86399999)];
  return { from, to, fromStr: ymd(from), toStr: ymd(to) };
};

const eventWhere = (q, period, extra = {}) => {
  const where = buildAuditWhere({ username: q.username, sourceSystemId: q.sourceSystemId, actionType: q.actionType, severity: q.severity });
  where.occurredAt = { [Op.between]: [period.from, period.to] };
  return { ...where, ...extra };
};

const EVENT_COLUMNS = [
  { key: 'occurredAt', label: 'Occurred At' }, { key: 'receivedAt', label: 'Received At' }, { key: 'auditId', label: 'Audit ID' },
  { key: 'eventId', label: 'Event ID' }, { key: 'sourceSystemName', label: 'Source System' }, { key: 'sourceModule', label: 'Module' },
  { key: 'actorUsername', label: 'User' }, { key: 'actorRole', label: 'Reported Role' }, { key: 'actionType', label: 'Action' },
  { key: 'entity', label: 'Affected Record' }, { key: 'description', label: 'Description' }, { key: 'outcome', label: 'Outcome' },
  { key: 'severity', label: 'Severity' }
];

const eventRows = async (where, limit) => {
  const rows = await AuditLog.findAll({
    where, order: [['occurredAt', 'DESC'], ['id', 'DESC']], limit,
    attributes: ['id', 'eventId', 'occurredAt', 'receivedAt', 'sourceSystemName', 'sourceModule', 'actorUsername', 'actorRole', 'actionType', 'entityType', 'entityId', 'description', 'outcome', 'severity'],
    raw: true
  });
  return rows.map((r) => ({ ...r, auditId: r.id, entity: r.entityType ? `${r.entityType} ${r.entityId || ''}`.trim() : '', link: `/audit/${r.id}` }));
};

const outcomeSummary = async (where) => {
  const rows = await AuditLog.findAll({ where, attributes: ['outcome', [sequelize.fn('COUNT', sequelize.col('id')), 'n']], group: ['outcome'], raw: true });
  const m = Object.fromEntries(rows.map((r) => [r.outcome, Number(r.n)]));
  const total = Object.values(m).reduce((a, b) => a + b, 0);
  const users = await AuditLog.count({ where, distinct: true, col: 'actorUsername' });
  return [
    { label: 'Total events', value: total }, { label: 'Successful', value: m.SUCCESS || 0 },
    { label: 'Failed', value: m.FAILURE || 0 }, { label: 'Denied', value: m.DENIED || 0 }, { label: 'Distinct users', value: users }
  ];
};

const dailyBreakdown = async (where, period) => {
  const rows = await AuditLog.findAll({
    where,
    attributes: [
      [localDate('occurredAt'), 'day'],
      [sequelize.fn('COUNT', sequelize.col('id')), 'total'],
      [sequelize.literal("SUM(outcome = 'SUCCESS')"), 'success'],
      [sequelize.literal("SUM(outcome = 'FAILURE')"), 'failure'],
      [sequelize.literal("SUM(outcome = 'DENIED')"), 'denied'],
      [sequelize.literal('COUNT(DISTINCT actorUsername)'), 'users']
    ],
    group: [localDate('occurredAt')], raw: true
  });
  const map = Object.fromEntries(rows.map((r) => [typeof r.day === 'string' ? r.day.slice(0, 10) : ymd(r.day), r]));
  const out = [];
  for (let d = startOfDay(period.from); d <= period.to; d.setDate(d.getDate() + 1)) {
    const key = ymd(d);
    const r = map[key];
    out.push({ day: key, total: Number(r?.total || 0), success: Number(r?.success || 0), failure: Number(r?.failure || 0), denied: Number(r?.denied || 0), users: Number(r?.users || 0) });
  }
  return out.reverse();
};

const DAILY_COLUMNS = [
  { key: 'day', label: 'Date' }, { key: 'total', label: 'Total Events' }, { key: 'success', label: 'Successful' },
  { key: 'failure', label: 'Failed' }, { key: 'denied', label: 'Denied' }, { key: 'users', label: 'Distinct Users' }
];

const builders = {
  async DAILY_ACTIVITY(q, period, limit) {
    const where = eventWhere(q, period);
    return { summary: await outcomeSummary(where), columns: EVENT_COLUMNS, rows: await eventRows(where, limit) };
  },
  async WEEKLY_ACTIVITY(q, period) {
    const where = eventWhere(q, period);
    return { summary: await outcomeSummary(where), columns: DAILY_COLUMNS, rows: await dailyBreakdown(where, period) };
  },
  async MONTHLY_ACTIVITY(q, period) {
    const where = eventWhere(q, period);
    return { summary: await outcomeSummary(where), columns: DAILY_COLUMNS, rows: await dailyBreakdown(where, period) };
  },
  async SOURCE_SYSTEM_ACTIVITY(q, period) {
    const where = eventWhere(q, period);
    const rows = await AuditLog.findAll({
      where,
      attributes: ['sourceSystemId', 'sourceSystemName',
        [sequelize.fn('COUNT', sequelize.col('id')), 'total'],
        [sequelize.literal("SUM(outcome = 'SUCCESS')"), 'success'], [sequelize.literal("SUM(outcome = 'FAILURE')"), 'failure'],
        [sequelize.literal("SUM(outcome = 'DENIED')"), 'denied'], [sequelize.literal('COUNT(DISTINCT actorUsername)'), 'users'],
        [sequelize.fn('MIN', sequelize.col('occurredAt')), 'firstEvent'], [sequelize.fn('MAX', sequelize.col('occurredAt')), 'lastEvent']],
      group: ['sourceSystemId', 'sourceSystemName'], order: [[sequelize.literal('total'), 'DESC']], raw: true
    });
    return {
      summary: [{ label: 'Source systems with activity', value: rows.length }, ...(await outcomeSummary(where)).slice(0, 1)],
      columns: [{ key: 'sourceSystemName', label: 'Source System' }, { key: 'total', label: 'Total' }, { key: 'success', label: 'Successful' }, { key: 'failure', label: 'Failed' }, { key: 'denied', label: 'Denied' }, { key: 'users', label: 'Distinct Users' }, { key: 'firstEvent', label: 'First Event' }, { key: 'lastEvent', label: 'Last Event' }],
      rows: rows.map((r) => ({ ...r, total: Number(r.total), success: Number(r.success), failure: Number(r.failure), denied: Number(r.denied), users: Number(r.users), link: `/audit?sourceSystemId=${r.sourceSystemId}&from=${period.fromStr}&to=${period.toStr}` }))
    };
  },
  async USER_ACTIVITY(q, period, limit) {
    const where = eventWhere(q, period);
    const rows = await AuditLog.findAll({
      where,
      attributes: ['sourceSystemId', 'sourceSystemName', 'actorUsername', 'actorUserId',
        [sequelize.fn('MAX', sequelize.col('actorRole')), 'role'],
        [sequelize.fn('COUNT', sequelize.col('id')), 'total'], [sequelize.literal("SUM(outcome = 'SUCCESS')"), 'success'],
        [sequelize.literal("SUM(outcome = 'FAILURE')"), 'failure'], [sequelize.literal("SUM(outcome = 'DENIED')"), 'denied'],
        [sequelize.fn('MAX', sequelize.col('occurredAt')), 'lastActivity']],
      group: ['sourceSystemId', 'sourceSystemName', 'actorUsername', 'actorUserId'], order: [[sequelize.literal('total'), 'DESC']], limit, raw: true
    });
    return {
      summary: [{ label: 'Users with activity', value: rows.length }, ...(await outcomeSummary(where)).slice(0, 4)],
      columns: [{ key: 'actorUsername', label: 'Username' }, { key: 'actorUserId', label: 'User ID' }, { key: 'role', label: 'Reported Role' }, { key: 'sourceSystemName', label: 'Source System' }, { key: 'total', label: 'Total' }, { key: 'success', label: 'Successful' }, { key: 'failure', label: 'Failed' }, { key: 'denied', label: 'Denied' }, { key: 'lastActivity', label: 'Last Activity' }],
      rows: rows.map((r) => ({ ...r, total: Number(r.total), success: Number(r.success), failure: Number(r.failure), denied: Number(r.denied), link: `/user-activity/profile?sourceSystemId=${r.sourceSystemId}&user=${encodeURIComponent(r.actorUserId || r.actorUsername || '')}` }))
    };
  },
  async AUTHENTICATION_ACTIVITY(q, period, limit) {
    const where = eventWhere(q, period, { actionCategory: 'AUTHENTICATION' });
    const counts = await AuditLog.findAll({ where, attributes: ['actionType', [sequelize.fn('COUNT', sequelize.col('id')), 'n']], group: ['actionType'], raw: true });
    const m = Object.fromEntries(counts.map((c) => [c.actionType, Number(c.n)]));
    return {
      summary: [{ label: 'Successful logins', value: m.LOGIN_SUCCESS || 0 }, { label: 'Failed logins', value: m.LOGIN_FAILED || 0 }, { label: 'Logouts', value: m.LOGOUT || 0 }, { label: 'Password changes', value: m.PASSWORD_CHANGED || 0 }, { label: 'Activations / deactivations', value: (m.ACCOUNT_ACTIVATED || 0) + (m.ACCOUNT_DEACTIVATED || 0) }],
      columns: EVENT_COLUMNS, rows: await eventRows(where, limit)
    };
  },
  async FAILED_ACTIVITY(q, period, limit) {
    const where = eventWhere(q, period, { outcome: { [Op.in]: ['FAILURE', 'DENIED'] } });
    return { summary: (await outcomeSummary(where)).filter((s) => s.label !== 'Successful'), columns: EVENT_COLUMNS, rows: await eventRows(where, limit) };
  },
  async SUSPICIOUS_ACTIVITY(q, period, limit) {
    const where = { firstDetectedAt: { [Op.between]: [period.from, period.to] } };
    if (q.sourceSystemId) where.sourceSystemId = Number(q.sourceSystemId);
    if (q.severity && ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].includes(q.severity)) where.severity = q.severity;
    if (q.username) where.actorUsername = { [Op.like]: `%${q.username}%` };
    const rows = await Alert.findAll({ where, include: [{ model: SourceSystem, as: 'sourceSystem', attributes: ['name'] }, { model: User, as: 'assignedTo', attributes: ['fullName'] }], order: [['firstDetectedAt', 'DESC']], limit });
    const plain = rows.map((a) => a.get({ plain: true }));
    const by = (k, v) => plain.filter((a) => a[k] === v).length;
    return {
      summary: [{ label: 'Alerts raised', value: plain.length }, { label: 'Critical', value: by('severity', 'CRITICAL') }, { label: 'High', value: by('severity', 'HIGH') }, { label: 'Still open', value: plain.filter((a) => ['OPEN', 'ACKNOWLEDGED', 'INVESTIGATING'].includes(a.status)).length }, { label: 'Resolved / dismissed', value: by('status', 'RESOLVED') + by('status', 'DISMISSED') }],
      columns: [{ key: 'alertCode', label: 'Alert ID' }, { key: 'firstDetectedAt', label: 'Detected' }, { key: 'alertType', label: 'Type' }, { key: 'severity', label: 'Severity' }, { key: 'source', label: 'Source System' }, { key: 'actorUsername', label: 'User' }, { key: 'occurrenceCount', label: 'Occurrences' }, { key: 'status', label: 'Status' }, { key: 'assignee', label: 'Assigned To' }, { key: 'title', label: 'Description' }],
      rows: plain.map((a) => ({ ...a, alertCode: `ALR-${String(a.id).padStart(6, '0')}`, source: a.sourceSystem?.name || '—', assignee: a.assignedTo?.fullName || '', link: `/alerts/${a.id}` }))
    };
  },
  async ADMINISTRATIVE_ACTIVITY(q, period, limit) {
    const where = eventWhere(q, period, { actionCategory: { [Op.in]: ['ADMINISTRATIVE', 'SYSTEM'] } });
    return { summary: await outcomeSummary(where), columns: EVENT_COLUMNS, rows: await eventRows(where, limit) };
  },
  async INVESTIGATION(q, period, limit) {
    const where = { [Op.or]: [{ createdAt: { [Op.between]: [period.from, period.to] } }, { updatedAt: { [Op.between]: [period.from, period.to] } }] };
    if (q.sourceSystemId) where.sourceSystemId = Number(q.sourceSystemId);
    if (q.severity && ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].includes(q.severity)) where.severity = q.severity;
    const rows = await InvestigationCase.findAll({ where, include: [{ model: User, as: 'assignedTo', attributes: ['fullName'] }, { model: SourceSystem, as: 'sourceSystem', attributes: ['name'] }], order: [['createdAt', 'DESC']], limit });
    const plain = rows.map((c) => c.get({ plain: true }));
    const by = (s) => plain.filter((c) => c.status === s).length;
    return {
      summary: [{ label: 'Cases', value: plain.length }, { label: 'Open', value: by('OPEN') }, { label: 'Under investigation', value: by('UNDER_INVESTIGATION') }, { label: 'Pending review', value: by('PENDING_REVIEW') }, { label: 'Resolved / closed', value: by('RESOLVED') + by('CLOSED') }],
      columns: [{ key: 'caseNumber', label: 'Case ID' }, { key: 'title', label: 'Title' }, { key: 'source', label: 'Source System' }, { key: 'severity', label: 'Severity' }, { key: 'status', label: 'Status' }, { key: 'assignee', label: 'Investigator' }, { key: 'createdAt', label: 'Created' }, { key: 'updatedAt', label: 'Last Updated' }, { key: 'findings', label: 'Findings' }, { key: 'resolutionNotes', label: 'Resolution Notes' }],
      rows: plain.map((c) => ({ ...c, source: c.sourceSystem?.name || '—', assignee: c.assignedTo?.fullName || 'Unassigned', link: `/investigations/${c.id}` }))
    };
  },
  async INTEGRATION_PERFORMANCE(q, period) {
    const where = { createdAt: { [Op.between]: [period.from, period.to] } };
    if (q.sourceSystemId) where.sourceSystemId = Number(q.sourceSystemId);
    const rows = await IntegrationLog.findAll({
      where,
      attributes: ['sourceSystemId',
        [sequelize.fn('COUNT', sequelize.col('id')), 'requests'],
        [sequelize.literal("SUM(outcome = 'ACCEPTED')"), 'accepted'], [sequelize.literal("SUM(outcome = 'DUPLICATE')"), 'duplicates'],
        [sequelize.literal("SUM(outcome = 'REJECTED_VALIDATION')"), 'invalid'], [sequelize.literal("SUM(outcome = 'REJECTED_AUTH')"), 'authFailures'],
        [sequelize.literal("SUM(outcome IN ('ERROR','RATE_LIMITED','REJECTED_FORBIDDEN','CONFLICT'))"), 'errors'],
        [sequelize.literal("SUM(outcome = 'HEARTBEAT')"), 'heartbeats'],
        [sequelize.literal("AVG(CASE WHEN outcome = 'ACCEPTED' THEN deliveryDelayMs END)"), 'avgDelay'],
        [sequelize.literal("MAX(CASE WHEN outcome = 'ACCEPTED' THEN deliveryDelayMs END)"), 'maxDelay'],
        [sequelize.fn('AVG', sequelize.col('processingMs')), 'avgProcessing']],
      group: ['sourceSystemId'], raw: true
    });
    const sources = new Map((await listSourcesWithHealth()).map((s) => [s.id, s]));
    const out = rows.map((r) => {
      const s = sources.get(r.sourceSystemId);
      return {
        source: s?.name || 'Unknown / unauthenticated caller', health: s?.health.label || '—',
        requests: Number(r.requests), accepted: Number(r.accepted || 0), duplicates: Number(r.duplicates || 0), invalid: Number(r.invalid || 0),
        authFailures: Number(r.authFailures || 0), errors: Number(r.errors || 0), heartbeats: Number(r.heartbeats || 0),
        avgDelaySec: r.avgDelay !== null ? Math.round(Number(r.avgDelay) / 100) / 10 : '', maxDelaySec: r.maxDelay !== null ? Math.round(Number(r.maxDelay) / 100) / 10 : '',
        avgProcessingMs: r.avgProcessing !== null ? Math.round(Number(r.avgProcessing)) : '',
        link: r.sourceSystemId ? `/integrations/${r.sourceSystemId}` : '/integrations/logs?sourceSystemId=unknown'
      };
    });
    const tot = (k) => out.reduce((s, r) => s + r[k], 0);
    return {
      summary: [{ label: 'API requests', value: tot('requests') }, { label: 'Accepted events', value: tot('accepted') }, { label: 'Invalid submissions', value: tot('invalid') }, { label: 'Auth failures', value: tot('authFailures') }, { label: 'Other errors', value: tot('errors') }],
      columns: [{ key: 'source', label: 'Source System' }, { key: 'health', label: 'Current Health' }, { key: 'requests', label: 'Requests' }, { key: 'accepted', label: 'Accepted' }, { key: 'duplicates', label: 'Duplicates' }, { key: 'invalid', label: 'Invalid' }, { key: 'authFailures', label: 'Auth Failures' }, { key: 'errors', label: 'Errors' }, { key: 'heartbeats', label: 'Heartbeats' }, { key: 'avgDelaySec', label: 'Avg Delay (s)' }, { key: 'maxDelaySec', label: 'Max Delay (s)' }, { key: 'avgProcessingMs', label: 'Avg Processing (ms)' }],
      rows: out
    };
  },
  async INTEGRITY_VERIFICATION(q, period, limit) {
    const runs = await QaRun.findAll({ where: { status: 'COMPLETED', startedAt: { [Op.between]: [period.from, period.to] } }, order: [['id', 'DESC']], limit, raw: true });
    const results = runs.length ? await QaResult.findAll({ where: { runId: { [Op.in]: runs.map((r) => r.id) }, category: 'AUDIT_INTEGRITY' }, raw: true }) : [];
    const rows = runs.map((run) => {
      const rs = results.filter((r) => r.runId === run.id);
      const get = (code) => rs.find((r) => r.checkCode === code)?.status || 'NOT_TESTED';
      const failures = rs.reduce((s, r) => s + r.itemsFailed, 0);
      return { runCode: formatRunId(run.id), startedAt: run.startedAt, recordsVerified: run.recordsVerified, signatures: get('AI_SIGNATURE'), chain: get('AI_CHAIN'), missing: get('AI_MISSING'), duplicates: get('AI_DUPLICATES'), appendOnly: get('AI_APPEND_ONLY'), failures, link: `/qa/runs/${run.id}` };
    });
    const openIntegrity = await QaFinding.count({ where: { category: 'AUDIT_INTEGRITY', status: { [Op.in]: ['OPEN', 'UNDER_INVESTIGATION'] } } });
    return {
      summary: [{ label: 'Verification runs', value: rows.length }, { label: 'Runs with integrity failures', value: rows.filter((r) => r.failures > 0).length }, { label: 'Latest records verified', value: rows[0]?.recordsVerified ?? 0 }, { label: 'Open integrity findings', value: openIntegrity }],
      columns: [{ key: 'runCode', label: 'Run ID' }, { key: 'startedAt', label: 'Executed' }, { key: 'recordsVerified', label: 'Records Verified' }, { key: 'signatures', label: 'Signatures' }, { key: 'chain', label: 'Hash Chain' }, { key: 'missing', label: 'Missing Integrity' }, { key: 'duplicates', label: 'Duplicate IDs' }, { key: 'appendOnly', label: 'Append-only Protection' }, { key: 'failures', label: 'Failed Items' }],
      rows
    };
  },
  async QA_REPORT(q, period, limit) {
    const runs = await QaRun.findAll({ where: { startedAt: { [Op.between]: [period.from, period.to] } }, order: [['id', 'DESC']], limit, raw: true });
    const findings = await QaFinding.findAll({ attributes: ['status', [sequelize.fn('COUNT', sequelize.col('id')), 'n']], group: ['status'], raw: true });
    const f = Object.fromEntries(findings.map((r) => [r.status, Number(r.n)]));
    return {
      summary: [{ label: 'Runs', value: runs.length }, { label: 'Passed runs', value: runs.filter((r) => r.overallResult === 'PASS').length }, { label: 'Open findings', value: (f.OPEN || 0) + (f.UNDER_INVESTIGATION || 0) }, { label: 'Resolved findings', value: f.RESOLVED || 0 }, { label: 'Verified findings', value: f.VERIFIED || 0 }],
      columns: [{ key: 'runCode', label: 'Run ID' }, { key: 'startedAt', label: 'Executed' }, { key: 'triggerType', label: 'Trigger' }, { key: 'executedByLabel', label: 'Executed By' }, { key: 'totalChecks', label: 'Total Checks' }, { key: 'passedChecks', label: 'Passed' }, { key: 'failedChecks', label: 'Failed' }, { key: 'warningChecks', label: 'Warnings' }, { key: 'overallResult', label: 'Overall Result' }, { key: 'newFindings', label: 'New Findings' }],
      rows: runs.map((r) => ({ ...r, runCode: formatRunId(r.id), newFindings: r.findingsSummary?.newFindings ?? 0, link: `/qa/runs/${r.id}` }))
    };
  }
};

export const generateReport = async (code, q = {}, { limit = 500 } = {}) => {
  const def = REPORTS[code];
  if (!def) throw Object.assign(new Error('Unknown report.'), { status: 404 });
  const period = resolvePeriod(code, q);
  const built = await builders[code](q, period, limit);
  return {
    code, ...def, period, generatedAt: new Date(),
    filters: { from: period.fromStr, to: period.toStr, username: q.username || '', sourceSystemId: q.sourceSystemId || '', actionType: q.actionType || '', severity: q.severity || '' },
    ...built,
    truncated: built.rows.length >= limit
  };
};
