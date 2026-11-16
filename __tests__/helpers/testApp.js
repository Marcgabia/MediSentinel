import crypto from 'crypto';
import bcrypt from 'bcrypt';
import request from 'supertest';
import { resetTestDatabase, runMigrations } from '../../utils/migrator.js';
import { seedReferenceData } from '../../utils/seedReferenceData.js';
import { sequelize, User, Role } from '../../models/index.js';
import { registerSource, issueCredential } from '../../services/integrationService.js';
import { signRequest } from '../../utils/secretBox.js';
import { resetInternalSourceCache } from '../../services/auditService.js';
import { invalidateSettingsCache } from '../../services/settingsService.js';
import { invalidateEventTypeCache } from '../../services/auditIngestionService.js';
import { invalidateRuleCache } from '../../services/alertService.js';
import { getSessionStore } from '../../middleware/session.js';

export const silent = { log: () => {} };

/** Fresh test database (drop → create → migrate → seed). */
export const freshDatabase = async () => {
  await resetTestDatabase();
  await runMigrations(silent);
  await seedReferenceData(silent);
  resetInternalSourceCache();
  invalidateSettingsCache();
  invalidateEventTypeCache();
  invalidateRuleCache();
};

export const closeAll = async () => {
  getSessionStore().close();
  await sequelize.close();
};

export const createUser = async (roleCode, username, password = 'Password123') => {
  const role = await Role.findOne({ where: { code: roleCode } });
  return User.create({ fullName: `${username} Test`, username, email: `${username}@test.local`, passwordHash: await bcrypt.hash(password, 4), roleId: role.id, isActive: true });
};

export const createSourceWithCredential = async (code = 'TEST_POS', name = 'Test POS') => {
  const source = await sequelize.transaction((t) => registerSource({ systemCode: code, name, environment: 'TEST' }, null, t));
  const { credential, secret } = await sequelize.transaction((t) => issueCredential(source.id, 'jest', null, t));
  return { source, credential, secret, keyId: credential.keyId };
};

export const makeEvent = (sourceSystem, overrides = {}) => ({
  eventId: `EVT-${crypto.randomUUID()}`,
  occurredAt: new Date().toISOString(),
  sourceSystem,
  sourceModule: 'Sales',
  actor: { userId: 'USR-001', username: 'cashier01', role: 'Cashier' },
  action: 'TRANSACTION_CREATED',
  entity: { type: 'SalesTransaction', id: 'SALE-00025' },
  description: 'Created a new sales transaction',
  changes: { before: null, after: { transactionStatus: 'Pending' } },
  outcome: 'SUCCESS',
  severity: 'INFO',
  correlationId: 'REQ-12345',
  ...overrides
});

/** Signed API call via supertest. */
export const signedPost = (app, path, payload, { keyId, secret, timestamp, attempt, rawBody } = {}) => {
  const body = rawBody !== undefined ? rawBody : JSON.stringify(payload);
  const ts = String(timestamp ?? Math.floor(Date.now() / 1000));
  const req = request(app).post(path)
    .set('Content-Type', 'application/json')
    .set('X-MediSentinel-Key', keyId)
    .set('X-MediSentinel-Timestamp', ts)
    .set('X-MediSentinel-Signature', signRequest({ secret, timestamp: ts, method: 'POST', path, body }));
  if (attempt) req.set('X-MediSentinel-Delivery-Attempt', String(attempt));
  return req.send(body);
};

/** Log in through the real form (CSRF included) and return a supertest agent. */
export const loginAgent = async (app, username, password) => {
  const agent = request.agent(app);
  const page = await agent.get('/login');
  const csrf = page.text.match(/name="_csrf" value="([^"]+)"/)[1];
  const res = await agent.post('/login').type('form').send({ _csrf: csrf, username, password });
  agent.csrf = csrf;
  agent.loginResponse = res;
  return agent;
};

/** Fetch a fresh CSRF token for an authenticated agent. */
export const csrfFor = async (agent, path = '/settings?tab=password') => {
  const page = await agent.get(path);
  const match = page.text.match(/name="_csrf" value="([^"]+)"/);
  return match ? match[1] : agent.csrf;
};
