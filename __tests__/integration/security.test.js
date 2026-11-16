import request from 'supertest';
import app from '../../index.js';
import { AuditLog, Alert, User, Session, sequelize } from '../../models/index.js';
import { freshDatabase, closeAll, createUser, createSourceWithCredential, makeEvent, signedPost, loginAgent, csrfFor } from '../helpers/testApp.js';

let pos;
beforeAll(async () => {
  await freshDatabase();
  await createUser('VIEWER', 'viewer1');
  await createUser('AUDITOR', 'auditor1');
  await createUser('INVESTIGATOR', 'investigator1');
  pos = await createSourceWithCredential('SEC_POS', 'Security POS');
});
afterAll(closeAll);

const internalEvents = (action) => AuditLog.findAll({ where: { sourceSystemCode: 'MEDISENTINEL', actionType: action }, raw: true });

describe('Authentication & sessions', () => {
  test('anonymous users are redirected to the login page', async () => {
    const res = await request(app).get('/dashboard');
    expect(res.status).toBe(302);
    expect(res.headers.location).toBe('/login');
  });

  test('successful login is audited and rotates the session', async () => {
    const agent = await loginAgent(app, 'admin', 'AdminPass123');
    expect(agent.loginResponse.headers.location).toBe('/dashboard');
    expect((await agent.get('/dashboard')).status).toBe(200);
    const events = await internalEvents('LOGIN_SUCCESS');
    expect(events.some((e) => e.actorUsername === 'admin')).toBe(true);
  });

  test('repeated failed logins lock the account, are audited and raise an alert', async () => {
    await createUser('VIEWER', 'victim');
    for (let i = 0; i < 5; i += 1) await loginAgent(app, 'victim', 'wrong-password');
    const user = await User.findOne({ where: { username: 'victim' } });
    expect(user.lockedUntil.getTime()).toBeGreaterThan(Date.now());
    const locked = await loginAgent(app, 'victim', 'Password123');
    expect(locked.loginResponse.headers.location).toBe('/login');
    const failures = (await internalEvents('LOGIN_FAILED')).filter((e) => e.actorUsername === 'victim');
    expect(failures.length).toBe(6);
    await new Promise((r) => setTimeout(r, 300));
    expect(await Alert.count({ where: { alertType: 'FAILED_LOGIN_BURST', actorUsername: 'victim' } })).toBe(1);
  });

  test('unknown usernames are rejected with a generic message and audited', async () => {
    const agent = await loginAgent(app, 'ghost', 'whatever123');
    const page = await agent.get('/login');
    expect(page.text).toContain('Invalid username or password.');
    expect((await internalEvents('LOGIN_FAILED')).some((e) => e.actorUsername === 'ghost')).toBe(true);
  });

  test('sessions expire after the idle timeout', async () => {
    const agent = await loginAgent(app, 'auditor1', 'Password123');
    expect((await agent.get('/audit')).status).toBe(200);
    const sessions = await Session.findAll();
    for (const s of sessions) {
      const data = JSON.parse(s.data);
      if (data.userId) { data.lastActivity = Date.now() - 2 * 3600000; await s.update({ data: JSON.stringify(data) }); }
    }
    const res = await agent.get('/audit');
    expect(res.status).toBe(302);
    expect(res.headers.location).toBe('/login');
    const logouts = await internalEvents('LOGOUT');
    expect(logouts.some((e) => e.metadata?.reason === 'IDLE_TIMEOUT')).toBe(true);
  });

  test('deactivated accounts lose access immediately', async () => {
    const temp = await createUser('AUDITOR', 'tempauditor');
    const agent = await loginAgent(app, 'tempauditor', 'Password123');
    expect((await agent.get('/audit')).status).toBe(200);
    await temp.update({ isActive: false });
    expect((await agent.get('/audit')).headers.location).toBe('/login');
  });

  test('state-changing requests require a CSRF token', async () => {
    const agent = await loginAgent(app, 'admin', 'AdminPass123');
    const res = await agent.post('/qa/run').type('form').send({});
    expect(res.status).toBe(403);
  });
});

describe('Role-based access control', () => {
  test('a read-only viewer cannot reach administrative pages; attempts are audited', async () => {
    const agent = await loginAgent(app, 'viewer1', 'Password123');
    expect((await agent.get('/audit')).status).toBe(200);
    expect((await agent.get('/users')).status).toBe(403);
    expect((await agent.get('/integrations')).status).toBe(403);
    expect((await agent.get('/reports')).status).toBe(403);
    const csrf = await csrfFor(agent);
    expect((await agent.post('/integrations').type('form').send({ _csrf: csrf, systemCode: 'HACK', name: 'x' })).status).toBe(403);
    const denied = (await internalEvents('ACCESS_DENIED')).filter((e) => e.actorUsername === 'viewer1');
    expect(denied.length).toBeGreaterThanOrEqual(4);
    expect(denied.every((e) => e.outcome === 'DENIED')).toBe(true);
  });

  test('auditors are read-only: reports yes, configuration no', async () => {
    const agent = await loginAgent(app, 'auditor1', 'Password123');
    expect((await agent.get('/reports')).status).toBe(200);
    expect((await agent.get('/qa')).status).toBe(200);
    expect((await agent.get('/alerts/rules')).status).toBe(403);
    const csrf = await csrfFor(agent);
    expect((await agent.post('/qa/run').type('form').send({ _csrf: csrf })).status).toBe(403);
  });

  test('investigators cannot manage users or integrations', async () => {
    const agent = await loginAgent(app, 'investigator1', 'Password123');
    expect((await agent.get('/investigations')).status).toBe(200);
    expect((await agent.get('/users')).status).toBe(403);
    expect((await agent.get('/integrations/new')).status).toBe(403);
  });

  test('integration service accounts cannot be assigned to people', async () => {
    const agent = await loginAgent(app, 'admin', 'AdminPass123');
    const csrf = await csrfFor(agent, '/users/new');
    const [[role]] = await sequelize.query("SELECT id FROM roles WHERE code = 'INTEGRATION_SERVICE'");
    const res = await agent.post('/users').type('form').set('Referer', '/users/new').send({ _csrf: csrf, fullName: 'Bot', username: 'bot', email: 'bot@test.local', roleId: role.id, password: 'Password123' });
    expect(res.status).toBe(302);
    expect(await User.count({ where: { username: 'bot' } })).toBe(0);
  });
});

describe('Audit record protection', () => {
  test('there are no routes that modify or delete audit records', async () => {
    const agent = await loginAgent(app, 'admin', 'AdminPass123');
    const csrf = await csrfFor(agent);
    const [log] = await AuditLog.findAll({ limit: 1, raw: true });
    expect((await agent.post(`/audit/${log.id}`).type('form').send({ _csrf: csrf, description: 'x' })).status).toBe(404);
    expect((await agent.delete(`/audit/${log.id}`).set('X-CSRF-Token', csrf)).status).toBe(404);
  });

  test('the database rejects UPDATE and DELETE on audit_logs', async () => {
    const [log] = await AuditLog.findAll({ limit: 1 });
    await expect(sequelize.query('UPDATE audit_logs SET description = ? WHERE id = ?', { replacements: ['tampered', log.id] })).rejects.toThrow(/append-only/);
    await expect(sequelize.query('DELETE FROM audit_logs WHERE id = ?', { replacements: [log.id] })).rejects.toThrow(/append-only/);
  });
});

describe('Sensitive information exposure', () => {
  test('issued secrets are shown once and never again', async () => {
    const agent = await loginAgent(app, 'admin', 'AdminPass123');
    const csrf = await csrfFor(agent, `/integrations/${pos.source.id}`);
    const issued = await agent.post(`/integrations/${pos.source.id}/credentials`).type('form').send({ _csrf: csrf, label: 'UI test' });
    expect(issued.status).toBe(200);
    expect(issued.headers['cache-control']).toBe('no-store');
    const secret = issued.text.match(/id="secret" class="input mono" value="([^"]+)"/)[1];
    expect(secret).toMatch(/^mss_/);
    const detail = await agent.get(`/integrations/${pos.source.id}`);
    expect(detail.text).not.toContain(secret);
    expect(detail.text).not.toContain(pos.secret);
    const exportCsv = await agent.get('/audit/export');
    expect(exportCsv.text).not.toContain(secret);
    expect(exportCsv.text).not.toMatch(/passwordHash|\$2b\$/);
    const issuedEvent = (await internalEvents('CREDENTIAL_ISSUED')).at(-1);
    expect(JSON.stringify(issuedEvent)).not.toContain(secret);
  });

  test('manipulated payloads are stored verbatim but rendered escaped', async () => {
    const event = makeEvent('SEC_POS', { description: '<script>alert("x")</script>', entity: { type: '<img src=x onerror=alert(1)>', id: 'X-1' } });
    const res = await signedPost(app, '/api/v1/audit-events', event, pos);
    expect(res.status).toBe(201);
    const agent = await loginAgent(app, 'admin', 'AdminPass123');
    const page = await agent.get(`/audit/${res.body.auditId}`);
    expect(page.text).not.toContain('<script>alert("x")</script>');
    expect(page.text).toContain('&lt;script&gt;');
    expect(page.text).not.toContain('<img src=x');
  });

  test('security headers are present', async () => {
    const res = await request(app).get('/login');
    expect(res.headers['content-security-policy']).toContain("script-src 'self'");
    expect(res.headers['x-frame-options']).toBe('DENY');
    expect(res.headers['x-powered-by']).toBeUndefined();
  });
});
