import request from 'supertest';
import app from '../../index.js';
import { AuditLog, Notification, User, Role, SystemSetting } from '../../models/index.js';
import { invalidateSettingsCache } from '../../services/settingsService.js';
import { freshDatabase, closeAll, loginAgent, csrfFor } from '../helpers/testApp.js';

beforeAll(freshDatabase);
afterAll(closeAll);

const signUp = async (fields) => {
  const agent = request.agent(app);
  const page = await agent.get('/register');
  const csrf = page.text.match(/name="_csrf" value="([^"]+)"/)[1];
  const res = await agent.post('/register').type('form').send({ _csrf: csrf, ...fields });
  return { agent, res };
};

const valid = {
  fullName: 'Ana Santos', username: 'ana.santos', email: 'ana.santos@pharmacy.local',
  password: 'Str0ngPassword', confirmPassword: 'Str0ngPassword'
};

describe('Self-registration', () => {
  test('the sign-in page links to account creation', async () => {
    const res = await request(app).get('/login');
    expect(res.status).toBe(200);
    expect(res.text).toContain('href="/register"');
    expect(res.text).toContain('Create an account');
  });

  test('rejects weak passwords, mismatched confirmation and bad usernames without creating an account', async () => {
    expect((await signUp({ ...valid, password: 'weak', confirmPassword: 'weak' })).res.text).toContain('Password must contain');
    expect((await signUp({ ...valid, confirmPassword: 'Str0ngPassword!' })).res.text).toContain('Passwords do not match');
    expect((await signUp({ ...valid, username: 'a b' })).res.status).toBe(400);
    expect(await User.count({ where: { username: 'ana.santos' } })).toBe(0);
  });

  test('creates an inactive read-only account, audits it and notifies administrators', async () => {
    const { agent, res } = await signUp(valid);
    expect(res.status).toBe(302);
    expect(res.headers.location).toBe('/register');
    expect((await agent.get('/register')).text).toContain('Request submitted');

    const user = await User.findOne({ where: { username: 'ana.santos' }, include: [{ model: Role, as: 'role' }] });
    expect(user.isActive).toBe(false);
    expect(user.role.code).toBe('VIEWER');

    const event = await AuditLog.findOne({ where: { sourceSystemCode: 'MEDISENTINEL', actionType: 'ACCOUNT_CREATED', entityId: 'ana.santos' } });
    expect(event).not.toBeNull();
    const admin = await User.findOne({ where: { username: 'admin' } });
    expect(await Notification.count({ where: { userId: admin.id, type: 'ACCOUNT_REQUEST' } })).toBe(1);
  });

  test('ignores attempts to choose a role and refuses duplicates', async () => {
    const adminRole = await Role.findOne({ where: { code: 'SYSTEM_ADMIN' } });
    await signUp({ ...valid, username: 'sneaky', email: 'sneaky@pharmacy.local', roleId: adminRole.id, isActive: 'true' });
    const sneaky = await User.findOne({ where: { username: 'sneaky' }, include: [{ model: Role, as: 'role' }] });
    expect(sneaky.role.code).toBe('VIEWER');
    expect(sneaky.isActive).toBe(false);

    const { res } = await signUp(valid);
    expect(res.status).toBe(409);
    expect(res.text).toContain('already registered');
  });

  test('a pending account cannot sign in until an administrator approves it', async () => {
    const before = await loginAgent(app, 'ana.santos', 'Str0ngPassword');
    expect(before.loginResponse.headers.location).toBe('/login');
    expect((await before.get('/login')).text).toContain('waiting for administrator approval');

    const admin = await loginAgent(app, 'admin', 'AdminPass123');
    const list = await admin.get('/users?status=pending');
    expect(list.text).toContain('Pending approval');
    expect(list.text).toContain('>Approve<');
    const user = await User.findOne({ where: { username: 'ana.santos' } });
    const csrf = await csrfFor(admin, '/users');
    await admin.post(`/users/${user.id}/active`).type('form').send({ _csrf: csrf, active: 'true' }).expect(302);

    const after = await loginAgent(app, 'ana.santos', 'Str0ngPassword');
    expect(after.loginResponse.headers.location).toBe('/dashboard');
    expect((await after.get('/users')).status).toBe(403);
  });

  test('administrators can turn self-registration off', async () => {
    await SystemSetting.update({ value: 0 }, { where: { key: 'security.allowSelfRegistration' } });
    invalidateSettingsCache();
    const login = await request(app).get('/login');
    expect(login.text).not.toContain('href="/register"');
    const res = await request(app).get('/register');
    expect(res.status).toBe(302);
    expect(res.headers.location).toBe('/login');
    await SystemSetting.update({ value: 1 }, { where: { key: 'security.allowSelfRegistration' } });
    invalidateSettingsCache();
  });
});
