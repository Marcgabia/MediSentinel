import app from '../../index.js';
import { AuditLog, SourceSystem, AuditEventRegistry, AuditEventType, User, Role, AlertRule, SystemSetting, IntegrationLog } from '../../models/index.js';
import { freshDatabase, closeAll, loginAgent, csrfFor, createSourceWithCredential, makeEvent, signedPost } from '../helpers/testApp.js';
import { invalidateSettingsCache } from '../../services/settingsService.js';

let admin;
let server;
let baseUrl;
const internal = (action) => AuditLog.findAll({ where: { sourceSystemCode: 'MEDISENTINEL', actionType: action }, order: [['id', 'ASC']], raw: true });
const post = async (agent, url, body, from) => {
  const csrf = await csrfFor(agent, from || url);
  return agent.post(url).type('form').set('Referer', from || url).send({ _csrf: csrf, ...body });
};

beforeAll(async () => {
  await freshDatabase();
  admin = await loginAgent(app, 'admin', 'AdminPass123');
  server = app.listen(0);
  await new Promise((r) => server.once('listening', r));
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});
afterAll(async () => {
  await new Promise((r) => server.close(r));
  await closeAll();
});

describe('Source system registration & integration management', () => {
  let sourceId;
  test('registers a system through the form (audited, initially never connected)', async () => {
    const res = await post(admin, '/integrations', { systemCode: 'pharma_lab', name: 'Pharmacy Lab System', environment: 'TEST', healthCheckUrl: `${baseUrl}/api/v1/health` }, '/integrations/new');
    expect(res.status).toBe(302);
    const source = await SourceSystem.findOne({ where: { systemCode: 'PHARMA_LAB' } });
    sourceId = source.id;
    expect(source.status).toBe('PENDING');
    expect((await internal('SOURCE_SYSTEM_REGISTERED')).at(-1).entityId).toBe('PHARMA_LAB');
    const page = await admin.get('/integrations');
    expect(page.text).toContain('Never connected');
  });

  test('rejects duplicate codes and invalid URLs', async () => {
    await post(admin, '/integrations', { systemCode: 'PHARMA_LAB', name: 'Dup' }, '/integrations/new');
    await post(admin, '/integrations', { systemCode: 'BAD_URL', name: 'Bad', apiEndpoint: 'javascript:alert(1)' }, '/integrations/new');
    expect(await SourceSystem.count({ where: { systemCode: ['PHARMA_LAB', 'BAD_URL'] } })).toBe(1);
  });

  test('connection test probes the registered health URL and logs the result', async () => {
    await post(admin, `/integrations/${sourceId}/test`, {}, `/integrations/${sourceId}`);
    const source = await SourceSystem.findByPk(sourceId);
    expect(source.lastConnectionTestResult).toMatchObject({ ok: true, status: 'REACHABLE', httpStatus: 200 });
    expect(await IntegrationLog.count({ where: { sourceSystemId: sourceId, outcome: 'CONNECTION_TEST_OK' } })).toBe(1);
    // A successful outbound probe does NOT mark the integration as connected.
    expect(source.lastSuccessfulConnectionAt).toBeNull();

    await post(admin, `/integrations/${sourceId}`, { name: 'Pharmacy Lab System', environment: 'TEST', healthCheckUrl: 'http://127.0.0.1:9/health' }, `/integrations/${sourceId}/edit`);
    await post(admin, `/integrations/${sourceId}/test`, {}, `/integrations/${sourceId}`);
    expect((await SourceSystem.findByPk(sourceId)).lastConnectionTestResult.ok).toBe(false);
  });

  test('status changes are audited with before/after values', async () => {
    await post(admin, `/integrations/${sourceId}`, { name: 'Pharmacy Lab System', environment: 'TEST', status: 'SUSPENDED' }, `/integrations/${sourceId}/edit`);
    const update = (await internal('SOURCE_SYSTEM_UPDATED')).at(-1);
    expect(update.previousValues.status).toBe('PENDING');
    expect(update.newValues.status).toBe('SUSPENDED');
  });

  test('event registry entries can be added and removed (audited)', async () => {
    const type = await AuditEventType.findOne({ where: { code: 'STOCK_IN' } });
    await post(admin, `/integrations/${sourceId}/registry`, { eventTypeId: type.id, sourceModule: 'Stock', isRequired: 'on' }, `/integrations/${sourceId}`);
    const entry = await AuditEventRegistry.findOne({ where: { sourceSystemId: sourceId, eventTypeId: type.id } });
    expect(entry).not.toBeNull();
    await post(admin, `/integrations/${sourceId}/registry/${entry.id}/delete`, {}, `/integrations/${sourceId}`);
    expect(await AuditEventRegistry.count({ where: { sourceSystemId: sourceId } })).toBe(0);
    expect((await internal('EVENT_REGISTRY_CHANGED')).length).toBe(2);
  });

  test('integration health reflects actual communication', async () => {
    const { listSourcesWithHealth } = await import('../../services/integrationService.js');
    const healthOf = async () => (await listSourcesWithHealth()).find((s) => s.systemCode === 'LIVE_SRC').health.status;
    const live = await createSourceWithCredential('LIVE_SRC', 'Live Source');
    expect(await healthOf()).toBe('NEVER_CONNECTED');
    // Rejected traffic is not "communication" — health must not flip to connected.
    await signedPost(app, '/api/v1/audit-events', makeEvent('LIVE_SRC'), { ...live, secret: 'wrong' });
    expect(await healthOf()).toBe('NEVER_CONNECTED');
    await signedPost(app, '/api/v1/audit-events', makeEvent('LIVE_SRC'), live);
    expect(await healthOf()).toBe('HEALTHY');
    expect((await admin.get('/integrations/monitor')).status).toBe(200);
  });
});

describe('Internal user & permission management', () => {
  test('create, modify, change role, deactivate, reset password — each audited', async () => {
    const auditor = await Role.findOne({ where: { code: 'AUDITOR' } });
    const investigator = await Role.findOne({ where: { code: 'INVESTIGATOR' } });
    await post(admin, '/users', { fullName: 'Ana Reyes', username: 'areyes', email: 'ana@test.local', roleId: auditor.id, password: 'weak' }, '/users/new');
    expect(await User.count({ where: { username: 'areyes' } })).toBe(0);
    await post(admin, '/users', { fullName: 'Ana Reyes', username: 'areyes', email: 'ana@test.local', roleId: auditor.id, password: 'StrongPass123' }, '/users/new');
    const user = await User.findOne({ where: { username: 'areyes' } });
    expect(user).not.toBeNull();

    await post(admin, `/users/${user.id}`, { fullName: 'Ana R. Reyes', email: 'ana@test.local', roleId: investigator.id }, `/users/${user.id}/edit`);
    const role = (await internal('ROLE_CHANGED')).at(-1);
    expect(role).toMatchObject({ entityId: 'areyes' });
    expect(role.previousValues).toEqual({ role: 'AUDITOR' });
    expect(role.newValues).toEqual({ role: 'INVESTIGATOR' });
    expect((await internal('ACCOUNT_MODIFIED')).at(-1).newValues.fullName).toBe('Ana R. Reyes');

    await post(admin, `/users/${user.id}/active`, { active: 'false' }, '/users');
    expect((await User.findByPk(user.id)).isActive).toBe(false);
    await post(admin, `/users/${user.id}/password`, { password: 'NewStrong456' }, `/users/${user.id}/edit`);
    expect((await internal('ACCOUNT_CREATED')).length).toBe(1);
    expect((await internal('ACCOUNT_DEACTIVATED')).length).toBe(1);
    expect((await internal('PASSWORD_CHANGED')).some((e) => e.entityId === 'areyes')).toBe(true);
  });

  test('the last administrator cannot be demoted or deactivated', async () => {
    const me = await User.findOne({ where: { username: 'admin' } });
    const viewer = await Role.findOne({ where: { code: 'VIEWER' } });
    await post(admin, `/users/${me.id}`, { fullName: me.fullName, email: me.email, roleId: viewer.id }, `/users/${me.id}/edit`);
    await post(admin, `/users/${me.id}/active`, { active: 'false' }, '/users');
    const reloaded = await User.findByPk(me.id, { include: [{ model: Role, as: 'role' }] });
    expect(reloaded.role.code).toBe('SYSTEM_ADMIN');
    expect(reloaded.isActive).toBe(true);
  });

  test('role permissions can be edited (audited) except for the administrator role', async () => {
    const viewer = await Role.findOne({ where: { code: 'VIEWER' } });
    await post(admin, `/users/roles/${viewer.id}`, { permissions: ['dashboard.view', 'audit.view', 'notifications.view', 'reports.view'] }, '/users/roles');
    expect((await Role.findByPk(viewer.id)).permissions).toContain('reports.view');
    const event = (await internal('PERMISSION_CHANGED')).at(-1);
    expect(event.newValues.permissions).toContain('reports.view');
    const adminRole = await Role.findOne({ where: { code: 'SYSTEM_ADMIN' } });
    await post(admin, `/users/roles/${adminRole.id}`, { permissions: ['dashboard.view'] }, '/users/roles');
    expect((await Role.findByPk(adminRole.id)).permissions.length).toBeGreaterThan(10);
  });
});

describe('Settings, rules and event types', () => {
  test('system settings are validated and changes audited', async () => {
    await post(admin, '/settings/system', { 'integration.staleAfterMinutes': '45', 'qa.lookbackDays': '14' }, '/settings?tab=system');
    invalidateSettingsCache();
    expect((await SystemSetting.findByPk('integration.staleAfterMinutes')).value).toBe(45);
    const event = (await internal('SETTINGS_MODIFIED')).at(-1);
    expect(event.previousValues['integration.staleAfterMinutes']).toBe(30);
    expect(event.newValues['integration.staleAfterMinutes']).toBe(45);
    await post(admin, '/settings/system', { 'qa.lookbackDays': '-5' }, '/settings?tab=system');
    expect((await SystemSetting.findByPk('qa.lookbackDays')).value).toBe(14);
  });

  test('alert rules can be tuned and disabled (audited)', async () => {
    const rule = await AlertRule.findOne({ where: { code: 'FREQUENT_VOIDS' } });
    await post(admin, `/alerts/rules/${rule.id}`, { threshold: '7', windowMinutes: '120', severity: 'CRITICAL' }, '/alerts/rules');
    const updated = await AlertRule.findByPk(rule.id);
    expect(updated).toMatchObject({ threshold: 7, windowMinutes: 120, severity: 'CRITICAL', isEnabled: false });
    expect((await internal('ALERT_RULE_CHANGED')).at(-1).newValues.threshold).toBe(7);
  });

  test('custom event types can be registered and then submitted by sources', async () => {
    await post(admin, '/settings/event-types', { code: 'prescription_verified', name: 'Prescription Verified', category: 'OPERATIONAL', requiresEntity: 'on' }, '/settings?tab=events');
    expect(await AuditEventType.findOne({ where: { code: 'PRESCRIPTION_VERIFIED' } })).not.toBeNull();
    const src = await createSourceWithCredential('RX_SYS', 'Prescription System');
    await new Promise((r) => setTimeout(r, 50));
    const { invalidateEventTypeCache } = await import('../../services/auditIngestionService.js');
    invalidateEventTypeCache();
    const res = await signedPost(app, '/api/v1/audit-events', makeEvent('RX_SYS', { action: 'PRESCRIPTION_VERIFIED', changes: undefined }), src);
    expect(res.status).toBe(201);
  });

  test('users can change their own password (audited)', async () => {
    const csrf = await csrfFor(admin, '/settings?tab=password');
    await admin.post('/settings/password').type('form').send({ _csrf: csrf, currentPassword: 'AdminPass123', newPassword: 'EvenBetter789', confirmPassword: 'EvenBetter789' });
    const relogin = await loginAgent(app, 'admin', 'EvenBetter789');
    expect(relogin.loginResponse.headers.location).toBe('/dashboard');
    expect((await internal('PASSWORD_CHANGED')).some((e) => e.actorUsername === 'admin' && e.outcome === 'SUCCESS')).toBe(true);
  });
});
