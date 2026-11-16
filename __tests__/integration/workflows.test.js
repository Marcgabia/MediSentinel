import app from '../../index.js';
import { AuditLog, Alert, QaFinding, QaResult, Notification, InvestigationCase, sequelize } from '../../models/index.js';
import { dashboardSummary, dashboardCharts } from '../../services/dashboardService.js';
import { searchAuditLogs } from '../../services/auditService.js';
import { verifyChain } from '../../services/auditIntegrityService.js';
import { REPORTS } from '../../services/reportService.js';
import { freshDatabase, closeAll, createUser, createSourceWithCredential, makeEvent, signedPost, loginAgent, csrfFor } from '../helpers/testApp.js';

let pos;
let admin;
const ids = {};
const EVENTS = '/api/v1/audit-events';
const internal = (action) => AuditLog.findAll({ where: { sourceSystemCode: 'MEDISENTINEL', actionType: action }, order: [['id', 'ASC']], raw: true });
const post = async (agent, url, body, from) => {
  const csrf = await csrfFor(agent, from || url);
  return agent.post(url).type('form').set('Referer', from || url).send({ _csrf: csrf, ...body });
};

beforeAll(async () => {
  await freshDatabase();
  await createUser('INVESTIGATOR', 'inv1');
  pos = await createSourceWithCredential('WF_POS', 'Workflow POS');
  const update = await signedPost(app, EVENTS, makeEvent('WF_POS', {
    action: 'TRANSACTION_UPDATED', sourceModule: 'Sales Management', entity: { type: 'SalesTransaction', id: 'SALE-00025' },
    changes: { before: { transactionStatus: 'Pending', paymentStatus: 'Unpaid' }, after: { transactionStatus: 'Completed', paymentStatus: 'Paid' } }
  }), pos);
  ids.update = update.body.auditId;
  for (let i = 0; i < 5; i += 1) {
    await signedPost(app, EVENTS, makeEvent('WF_POS', { action: 'LOGIN_FAILED', outcome: 'FAILURE', sourceModule: 'Authentication', entity: undefined, changes: undefined, actor: { userId: 'USR-009', username: 'mallory', role: 'Cashier' }, description: 'Bad password' }), pos);
  }
  await signedPost(app, '/api/v1/heartbeat', { pendingEvents: 0 }, pos);
  admin = await loginAgent(app, 'admin', 'AdminPass123');
});
afterAll(closeAll);

describe('Dashboard & audit trail', () => {
  test('dashboard statistics come from the database', async () => {
    const s = await dashboardSummary();
    expect(s.totalEvents).toBe(await AuditLog.count());
    expect(s.todayEvents).toBeGreaterThanOrEqual(6);
    expect(s.failedToday).toBeGreaterThanOrEqual(5);
    expect(s.activeUsers).toBe(2);
    expect(s.connectedSystems).toBe(1);
    expect(s.registeredSystems).toBe(3); // WF_POS + the two seeded, never-connected integrations
    expect(s.neverConnected).toBe(2);
    expect(s.qa.overallResult).toBe('NOT_TESTED');
    const charts = await dashboardCharts();
    expect(charts.daily.values.reduce((a, b) => a + b, 0)).toBeGreaterThanOrEqual(6);
    expect(charts.outcomes.values[1]).toBeGreaterThanOrEqual(5);
    const page = await admin.get('/dashboard');
    expect(page.status).toBe(200);
    expect(page.text).toContain('Connected systems');
    expect(page.text).toMatch(/1<span[^>]*> \/ 3<\/span>/);
  });

  test('search and filters', async () => {
    const byUser = await searchAuditLogs({ username: 'mallory' }, { limit: 50, offset: 0 });
    expect(byUser.count).toBe(5);
    const byEntity = await searchAuditLogs({ entityId: 'SALE-00025', actionType: 'TRANSACTION_UPDATED' }, { limit: 50, offset: 0 });
    expect(byEntity.count).toBe(1);
    const failed = await searchAuditLogs({ outcome: 'FAILURE', sourceSystemId: String(pos.source.id) }, { limit: 50, offset: 0 });
    expect(failed.count).toBe(5);
    const oldest = await searchAuditLogs({ sort: 'oldest', sourceSystemId: String(pos.source.id) }, { limit: 1, offset: 0 });
    expect(oldest.rows[0].id).toBe(ids.update);
    const page = await admin.get('/audit?q=mallory');
    expect(page.text).toContain('mallory');
  });

  test('detail view shows before/after comparison and verified integrity', async () => {
    const page = await admin.get(`/audit/${ids.update}`);
    expect(page.status).toBe(200);
    expect(page.text).toContain('Transaction Status');
    expect(page.text).toContain('Completed');
    expect(page.text).toContain('data-diff-row="CHANGED"');
    expect(page.text).toContain('Verified');
  });

  test('CSV export of audit records is itself audited', async () => {
    const res = await admin.get('/audit/export?username=mallory');
    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toContain('text/csv');
    expect(res.text.split('\r\n').length).toBe(6);
    expect((await internal('REPORT_EXPORTED')).length).toBe(1);
  });
});

describe('Suspicious activity & alert management', () => {
  test('rule evaluation raised one de-duplicated alert', async () => {
    const alerts = await Alert.findAll({ where: { alertType: 'FAILED_LOGIN_BURST', actorUsername: 'mallory' } });
    expect(alerts).toHaveLength(1);
    expect(alerts[0].relatedEventIds).toHaveLength(5);
    ids.alert = alerts[0].id;
    expect(await Notification.count({ where: { relatedAlertId: ids.alert } })).toBeGreaterThan(0);
  });

  test('acknowledge → assign → note → resolve, each recorded in the audit trail', async () => {
    const [inv] = await sequelize.query("SELECT id FROM users WHERE username = 'inv1'", { type: sequelize.QueryTypes.SELECT });
    expect((await post(admin, `/alerts/${ids.alert}/action`, { action: 'acknowledge' }, `/alerts/${ids.alert}`)).status).toBe(302);
    await post(admin, `/alerts/${ids.alert}/action`, { action: 'assign', assigneeId: inv.id }, `/alerts/${ids.alert}`);
    await post(admin, `/alerts/${ids.alert}/action`, { action: 'note', note: 'Reviewed CCTV' }, `/alerts/${ids.alert}`);
    await post(admin, `/alerts/${ids.alert}/action`, { action: 'resolve', note: 'User forgot password' }, `/alerts/${ids.alert}`);
    const alert = await Alert.findByPk(ids.alert);
    expect(alert.status).toBe('RESOLVED');
    expect(alert.assignedToUserId).toBe(inv.id);
    expect((await internal('ALERT_UPDATED')).length).toBe(4);
    const page = await admin.get(`/alerts/${ids.alert}`);
    expect(page.text).toContain('Reviewed CCTV');
    expect(await Notification.count({ where: { userId: inv.id, relatedAlertId: ids.alert } })).toBeGreaterThan(0);
  });
});

describe('Investigation management', () => {
  test('cases reference audit records without modifying them and every change is audited', async () => {
    const original = await AuditLog.findByPk(ids.update, { raw: true });
    const [inv] = await sequelize.query("SELECT id FROM users WHERE username = 'inv1'", { type: sequelize.QueryTypes.SELECT });
    const created = await post(admin, '/investigations', { title: 'Review SALE-00025', description: 'Payment changed after hours', severity: 'HIGH', auditLogIds: ids.update, assignedToUserId: inv.id }, '/investigations/new');
    expect(created.status).toBe(302);
    const record = await InvestigationCase.findOne({ where: { title: 'Review SALE-00025' } });
    expect(record.caseNumber).toMatch(/^CASE-\d{4}-0001$/);

    await post(admin, `/investigations/${record.id}/status`, { status: 'UNDER_INVESTIGATION' }, `/investigations/${record.id}`);
    await post(admin, `/investigations/${record.id}/notes`, { content: 'Interviewed cashier', noteType: 'NOTE' }, `/investigations/${record.id}`);
    await post(admin, `/investigations/${record.id}/findings`, { findings: 'Legitimate correction', resolutionNotes: 'No action required' }, `/investigations/${record.id}`);
    const invalid = await post(admin, `/investigations/${record.id}/status`, { status: 'CLOSED' }, `/investigations/${record.id}`);
    expect(invalid.status).toBe(302);
    expect((await InvestigationCase.findByPk(record.id)).status).toBe('UNDER_INVESTIGATION');
    await post(admin, `/investigations/${record.id}/status`, { status: 'RESOLVED', note: 'Closed out' }, `/investigations/${record.id}`);

    const reloaded = await InvestigationCase.findByPk(record.id);
    expect(reloaded.status).toBe('RESOLVED');
    expect(reloaded.findings).toBe('Legitimate correction');
    expect((await internal('CASE_CREATED')).length).toBe(1);
    expect((await internal('CASE_ASSIGNED')).length).toBe(1);
    expect((await internal('CASE_STATUS_CHANGED')).length).toBe(2);
    expect((await internal('CASE_UPDATED')).length).toBe(2);
    expect(await AuditLog.findByPk(ids.update, { raw: true })).toEqual(original);

    const investigator = await loginAgent(app, 'inv1', 'Password123');
    expect((await investigator.get(`/investigations/${record.id}`)).status).toBe(200);
    expect(await Notification.count({ where: { userId: inv.id, relatedCaseId: record.id } })).toBe(1);
  });
});

describe('Reports', () => {
  test.each(Object.keys(REPORTS))('%s renders and is audited', async (code) => {
    const res = await admin.get(`/reports/${code}`);
    expect(res.status).toBe(200);
    expect(res.text).toContain(REPORTS[code].name);
  });

  test('report generation and CSV exports are recorded', async () => {
    const generated = await internal('REPORT_GENERATED');
    expect(generated.length).toBe(Object.keys(REPORTS).length);
    const csv = await admin.get(`/reports/USER_ACTIVITY/export?sourceSystemId=${pos.source.id}`);
    expect(csv.status).toBe(200);
    expect(csv.text).toContain('mallory');
    const exported = await internal('REPORT_EXPORTED');
    expect(exported.at(-1).entityId).toBe('USER_ACTIVITY');
  });
});

describe('Quality assurance verification', () => {
  test('a clean run passes integrity and reports coverage gaps honestly', async () => {
    const res = await post(admin, '/qa/run', {}, '/qa');
    expect(res.status).toBe(302);
    const [run] = await sequelize.query('SELECT * FROM qa_verification_runs ORDER BY id DESC LIMIT 1', { type: sequelize.QueryTypes.SELECT });
    expect(run.status).toBe('COMPLETED');
    const results = await QaResult.findAll({ where: { runId: run.id }, raw: true });
    const status = (code) => results.filter((r) => r.checkCode === code).map((r) => r.status);
    expect(status('AI_SIGNATURE')).toEqual(['PASS']);
    expect(status('AI_CHAIN')).toEqual(['PASS']);
    expect(status('AI_APPEND_ONLY')).toEqual(['PASS']);
    // Seeded integrations never connected → NOT_TESTED, not "lost"
    expect(status('EC_COVERAGE')).toContain('NOT_TESTED');
    expect(await QaFinding.count({ where: { category: 'AUDIT_INTEGRITY' } })).toBe(0);
    expect((await internal('QA_VERIFICATION_RUN')).length).toBe(1);
    expect((await admin.get(`/qa/runs/${run.id}`)).status).toBe(200);
  });

  test('detects modified, deleted and corrupted records even when the database protection is bypassed', async () => {
    await sequelize.query('DROP TRIGGER trg_audit_logs_no_update');
    await sequelize.query('DROP TRIGGER trg_audit_logs_no_delete');
    const [victim, , toDelete] = await AuditLog.findAll({ where: { sourceSystemId: pos.source.id }, order: [['id', 'ASC']], limit: 3, raw: true });
    await sequelize.query('UPDATE audit_logs SET newValues = JSON_OBJECT("paymentStatus", "Refunded") WHERE id = ?', { replacements: [victim.id] });
    await sequelize.query('DELETE FROM audit_logs WHERE id = ?', { replacements: [toDelete.id] });

    const chain = await verifyChain();
    expect(chain.issueCounts.SIGNATURE_MISMATCH).toBe(1);
    expect(chain.issueCounts.CHAIN_BROKEN).toBe(1);

    await post(admin, '/qa/run', {}, '/qa');
    const [run] = await sequelize.query('SELECT * FROM qa_verification_runs ORDER BY id DESC LIMIT 1', { type: sequelize.QueryTypes.SELECT });
    expect(run.overallResult).toBe('FAIL');
    const findings = await QaFinding.findAll({ where: { category: 'AUDIT_INTEGRITY' }, raw: true });
    const codes = findings.map((f) => f.checkCode);
    expect(codes).toEqual(expect.arrayContaining(['AI_SIGNATURE', 'AI_CHAIN', 'AI_APPEND_ONLY']));
    expect(findings.find((f) => f.checkCode === 'AI_SIGNATURE')).toMatchObject({ severity: 'CRITICAL', relatedAuditLogId: victim.id, status: 'OPEN' });
    expect(await Notification.count({ where: { type: 'INTEGRITY_FAILURE' } })).toBeGreaterThan(0);

    const detail = await admin.get(`/audit/${victim.id}`);
    expect(detail.text).toContain('SIGNATURE_MISMATCH');

    // Restore protection for the remaining tests
    await sequelize.query("CREATE TRIGGER trg_audit_logs_no_update BEFORE UPDATE ON audit_logs FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'audit_logs is append-only: UPDATE is not permitted'");
    await sequelize.query("CREATE TRIGGER trg_audit_logs_no_delete BEFORE DELETE ON audit_logs FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'audit_logs is append-only: DELETE is not permitted'");
  });

  test('resolved findings are verified by the next run when no longer detected', async () => {
    const appendOnly = await QaFinding.findOne({ where: { checkCode: 'AI_APPEND_ONLY' } });
    const res = await post(admin, `/qa/findings/${appendOnly.id}`, { status: 'RESOLVED', notes: 'Triggers reinstalled' }, `/qa/findings/${appendOnly.id}`);
    expect(res.status).toBe(302);
    expect((await QaFinding.findByPk(appendOnly.id)).status).toBe('RESOLVED');
    await post(admin, '/qa/run', {}, '/qa');
    expect((await QaFinding.findByPk(appendOnly.id)).status).toBe('VERIFIED');
    // A still-tampered record is NOT verified: resolving it and re-running reopens it.
    const signature = await QaFinding.findOne({ where: { checkCode: 'AI_SIGNATURE' } });
    await post(admin, `/qa/findings/${signature.id}`, { status: 'RESOLVED', notes: 'Claimed fixed' }, `/qa/findings/${signature.id}`);
    await post(admin, '/qa/run', {}, '/qa');
    expect((await QaFinding.findByPk(signature.id)).status).toBe('OPEN');
    expect((await internal('QA_FINDING_UPDATED')).length).toBe(2);
  });

  test('QA pages render', async () => {
    for (const url of ['/qa', '/qa/runs', '/qa/coverage', '/qa/findings', '/qa/findings?status=VERIFIED']) {
      expect((await admin.get(url)).status).toBe(200);
    }
  });
});

describe('Notification center', () => {
  test('notifications can be read, unread and bulk-marked', async () => {
    const [n] = await sequelize.query("SELECT n.id FROM notifications n JOIN users u ON u.id = n.userId WHERE u.username = 'admin' ORDER BY n.id LIMIT 1", { type: sequelize.QueryTypes.SELECT });
    const open = await admin.get(`/notifications/${n.id}/open`);
    expect(open.status).toBe(302);
    expect((await Notification.findByPk(n.id)).isRead).toBe(true);
    await post(admin, `/notifications/${n.id}/read`, { state: 'unread' }, '/notifications');
    expect((await Notification.findByPk(n.id)).isRead).toBe(false);
    await post(admin, '/notifications/read-all', {}, '/notifications');
    const feed = await admin.get('/notifications/feed.json').set('Accept', 'application/json');
    expect(feed.body.unread).toBe(0);
  });
});
