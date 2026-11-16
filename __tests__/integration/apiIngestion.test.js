import os from 'os';
import path from 'path';
import fs from 'fs';
import request from 'supertest';
import app from '../../index.js';
import { AuditLog, IntegrationLog, SourceSystem, IntegrationCredential, sequelize } from '../../models/index.js';
import { verifyStoredRecord } from '../../services/auditIntegrityService.js';
import { revokeCredential } from '../../services/integrationService.js';
import { MediSentinelClient } from '../../clients/medisentinel-client.js';
import { freshDatabase, closeAll, createSourceWithCredential, makeEvent, signedPost } from '../helpers/testApp.js';

let pos;
const EVENTS = '/api/v1/audit-events';

beforeAll(async () => {
  await freshDatabase();
  pos = await createSourceWithCredential('TEST_POS', 'Test POS');
});
afterAll(closeAll);

const lastLog = () => IntegrationLog.findOne({ order: [['id', 'DESC']], raw: true });

describe('Secure API integration — authentication', () => {
  test('rejects requests without authentication headers and records the attempt', async () => {
    const res = await request(app).post(EVENTS).send(makeEvent('TEST_POS'));
    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe('MISSING_AUTHENTICATION');
    expect(await lastLog()).toMatchObject({ outcome: 'REJECTED_AUTH', errorCode: 'MISSING_AUTHENTICATION', httpStatus: 401 });
  });

  test('rejects unknown credentials', async () => {
    const res = await signedPost(app, EVENTS, makeEvent('TEST_POS'), { keyId: 'msk_doesnotexist', secret: pos.secret });
    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe('INVALID_CREDENTIALS');
  });

  test('rejects an invalid signature', async () => {
    const res = await signedPost(app, EVENTS, makeEvent('TEST_POS'), { keyId: pos.keyId, secret: 'wrong-secret' });
    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe('INVALID_SIGNATURE');
    expect(await lastLog()).toMatchObject({ sourceSystemId: pos.source.id, keyId: pos.keyId, outcome: 'REJECTED_AUTH' });
  });

  test('rejects stale timestamps (replay protection)', async () => {
    const res = await signedPost(app, EVENTS, makeEvent('TEST_POS'), { ...pos, timestamp: Math.floor(Date.now() / 1000) - 3600 });
    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe('TIMESTAMP_OUT_OF_RANGE');
  });

  test('rejects a tampered body even with valid headers', async () => {
    const event = makeEvent('TEST_POS');
    const ts = String(Math.floor(Date.now() / 1000));
    const { signRequest } = await import('../../utils/secretBox.js');
    const signature = signRequest({ secret: pos.secret, timestamp: ts, method: 'POST', path: EVENTS, body: JSON.stringify(event) });
    const res = await request(app).post(EVENTS).set('Content-Type', 'application/json')
      .set('X-MediSentinel-Key', pos.keyId).set('X-MediSentinel-Timestamp', ts).set('X-MediSentinel-Signature', signature)
      .send(JSON.stringify({ ...event, description: 'manipulated in transit' }));
    expect(res.status).toBe(401);
  });

  test('repeated failures raise an API_AUTH_FAILURE alert', async () => {
    for (let i = 0; i < 5; i += 1) await signedPost(app, EVENTS, makeEvent('TEST_POS'), { keyId: pos.keyId, secret: 'nope' });
    await new Promise((r) => setTimeout(r, 300));
    const [rows] = await sequelize.query("SELECT alertType, occurrenceCount FROM audit_alerts WHERE alertType = 'API_AUTH_FAILURE'");
    expect(rows.length).toBe(1);
  });

  test('revoked credentials and suspended sources are refused', async () => {
    const extra = await createSourceWithCredential('TEST_REVOKE', 'Revocation Test');
    await sequelize.transaction((t) => revokeCredential(extra.credential.id, null, t));
    const revoked = await signedPost(app, EVENTS, makeEvent('TEST_REVOKE'), extra);
    expect(revoked.status).toBe(401);
    expect(revoked.body.error.code).toBe('CREDENTIAL_REVOKED');

    const suspended = await createSourceWithCredential('TEST_SUSPENDED', 'Suspended Test');
    await SourceSystem.update({ status: 'SUSPENDED' }, { where: { id: suspended.source.id } });
    const res = await signedPost(app, EVENTS, makeEvent('TEST_SUSPENDED'), suspended);
    expect(res.status).toBe(403);
    expect(res.body.error.code).toBe('SOURCE_SUSPENDED');
  });
});

describe('Secure API integration — event submission', () => {
  test('accepts, validates and stores a valid event with integrity protection', async () => {
    const before = await SourceSystem.findByPk(pos.source.id);
    expect(before.status).toBe('PENDING');
    const event = makeEvent('TEST_POS', { changes: { before: { transactionStatus: 'Pending', password: 'hunter2' }, after: { transactionStatus: 'Completed' } }, action: 'TRANSACTION_UPDATED' });
    const res = await signedPost(app, EVENTS, event, pos);
    expect(res.status).toBe(201);
    expect(res.body).toMatchObject({ status: 'accepted', eventId: event.eventId });

    const stored = await AuditLog.findByPk(res.body.auditId);
    expect(stored).toMatchObject({ eventId: event.eventId, sourceSystemCode: 'TEST_POS', actorUsername: 'cashier01', actorRole: 'Cashier', actionType: 'TRANSACTION_UPDATED', entityId: 'SALE-00025', outcome: 'SUCCESS' });
    expect(stored.previousValues.password).toBe('[REDACTED]');
    expect(stored.receivedAt.getTime()).toBeGreaterThanOrEqual(new Date(event.occurredAt).getTime());
    expect(stored.integrityHash).toMatch(/^[a-f0-9]{64}$/);
    expect((await verifyStoredRecord(stored)).valid).toBe(true);

    const after = await SourceSystem.findByPk(pos.source.id);
    expect(after.status).toBe('ACTIVE');
    expect(after.lastEventReceivedAt).not.toBeNull();
    expect(await lastLog()).toMatchObject({ outcome: 'ACCEPTED', httpStatus: 201, eventId: event.eventId });
  });

  test('handles duplicate submissions idempotently and detects eventId conflicts', async () => {
    const event = makeEvent('TEST_POS');
    const first = await signedPost(app, EVENTS, event, pos);
    const retry = await signedPost(app, EVENTS, event, pos);
    expect(first.status).toBe(201);
    expect(retry.status).toBe(200);
    expect(retry.body).toMatchObject({ status: 'duplicate', auditId: first.body.auditId });
    expect(await AuditLog.count({ where: { eventId: event.eventId } })).toBe(1);

    const conflict = await signedPost(app, EVENTS, { ...event, description: 'Different content' }, pos);
    expect(conflict.status).toBe(409);
    expect(conflict.body.error.code).toBe('EVENT_ID_CONFLICT');
    expect(await lastLog()).toMatchObject({ outcome: 'CONFLICT' });
  });

  test('records invalid submissions in the integration logs', async () => {
    const res = await signedPost(app, EVENTS, makeEvent('TEST_POS', { action: 'TELEPORT', description: '' }), pos);
    expect(res.status).toBe(422);
    expect(res.body.error.details.map((d) => d.code)).toEqual(expect.arrayContaining(['UNKNOWN_ACTION', 'REQUIRED']));
    const log = await lastLog();
    expect(log).toMatchObject({ outcome: 'REJECTED_VALIDATION', httpStatus: 422, actionCode: 'TELEPORT' });
    expect(log.errorDetails.length).toBeGreaterThan(0);
  });

  test('rejects events that impersonate another source system', async () => {
    const res = await signedPost(app, EVENTS, makeEvent('OTHER_SYSTEM'), pos);
    expect(res.status).toBe(422);
    expect(res.body.error.details[0].code).toBe('SOURCE_MISMATCH');
  });

  test('rejects malformed JSON after authentication and logs it', async () => {
    const res = await signedPost(app, EVENTS, null, { ...pos, rawBody: '{"eventId": "broken"' });
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('INVALID_JSON');
    expect(await lastLog()).toMatchObject({ outcome: 'REJECTED_VALIDATION', errorCode: 'INVALID_JSON', sourceSystemId: pos.source.id });
  });

  test('batch submission processes each event independently', async () => {
    const good = makeEvent('TEST_POS');
    const res = await signedPost(app, `${EVENTS}/batch`, { events: [good, makeEvent('TEST_POS'), { eventId: 'bad' }, good] }, pos);
    expect(res.status).toBe(200);
    expect(res.body.summary).toEqual({ accepted: 2, rejected: 1, duplicate: 1 });
    expect(res.body.results.map((r) => r.status)).toEqual(['accepted', 'accepted', 'rejected', 'duplicate']);
    const batchLogs = await IntegrationLog.count({ where: { endpoint: `${EVENTS}/batch` } });
    expect(batchLogs).toBe(4);
  });

  test('rejects oversized and malformed batches', async () => {
    expect((await signedPost(app, `${EVENTS}/batch`, { nope: [] }, pos)).body.error.code).toBe('INVALID_BATCH');
    const big = Array.from({ length: 101 }, () => makeEvent('TEST_POS'));
    expect((await signedPost(app, `${EVENTS}/batch`, { events: big }, pos)).body.error.code).toBe('BATCH_TOO_LARGE');
  });

  test('a failed delivery can be retried with the same eventId and is recorded as a retry', async () => {
    const event = makeEvent('TEST_POS');
    const failed = await signedPost(app, EVENTS, event, { ...pos, timestamp: 1000000000 });
    expect(failed.status).toBe(401);
    const retried = await signedPost(app, EVENTS, event, { ...pos, attempt: 2 });
    expect(retried.status).toBe(201);
    expect(await lastLog()).toMatchObject({ outcome: 'ACCEPTED', deliveryAttempt: 2 });
  });

  test('heartbeats update communication health and pending deliveries', async () => {
    const res = await signedPost(app, '/api/v1/heartbeat', { pendingEvents: 3, failedDeliveries: 1, version: 'pos-2.1' }, pos);
    expect(res.status).toBe(200);
    const src = await SourceSystem.findByPk(pos.source.id);
    expect(src.lastHeartbeatAt).not.toBeNull();
    expect(src.lastHeartbeatPayload).toMatchObject({ pendingEvents: 3, failedDeliveries: 1, version: 'pos-2.1' });
  });

  test('never exposes integration secrets', async () => {
    const credential = await IntegrationCredential.findByPk(pos.credential.id);
    expect(credential.secretCiphertext).toBeUndefined();
    const withSecret = await IntegrationCredential.scope('withSecret').findByPk(pos.credential.id);
    expect(withSecret.secretCiphertext).not.toContain(pos.secret);
    const res = await signedPost(app, EVENTS, makeEvent('TEST_POS'), pos);
    expect(JSON.stringify(res.body)).not.toContain(pos.secret);
  });
});

describe('Reference client SDK', () => {
  let server;
  let baseUrl;
  beforeAll(async () => {
    server = app.listen(0);
    await new Promise((r) => server.once('listening', r));
    baseUrl = `http://127.0.0.1:${server.address().port}/api/v1`;
  });
  afterAll(() => new Promise((r) => server.close(r)));

  test('sends signed events end-to-end', async () => {
    const client = new MediSentinelClient({ baseUrl, keyId: pos.keyId, secret: pos.secret, sourceSystem: 'TEST_POS', maxAttempts: 1 });
    const result = await client.send({ sourceModule: 'Auth', actor: { username: 'cashier01' }, action: 'LOGIN_SUCCESS', description: 'Signed in' });
    expect(result.status).toBe(201);
  });

  test('queues events while MediSentinel is unreachable and delivers them on retry', async () => {
    const outbox = path.join(os.tmpdir(), `ms-outbox-${Date.now()}.jsonl`);
    const offline = new MediSentinelClient({ baseUrl: 'http://127.0.0.1:9/api/v1', keyId: pos.keyId, secret: pos.secret, sourceSystem: 'TEST_POS', outboxFile: outbox, maxAttempts: 1, timeoutMs: 1000 });
    await offline.record({ sourceModule: 'Auth', actor: { username: 'cashier02' }, action: 'LOGOUT', description: 'Signed out' });
    expect(offline.readOutbox()).toHaveLength(1);

    const online = new MediSentinelClient({ baseUrl, keyId: pos.keyId, secret: pos.secret, sourceSystem: 'TEST_POS', outboxFile: outbox, maxAttempts: 2 });
    const flushed = await online.flush();
    expect(flushed).toEqual({ delivered: 1, pending: 0 });
    const queuedId = JSON.parse(fs.readFileSync(outbox, 'utf8') || '{}').eventId;
    expect(queuedId).toBeUndefined();
    fs.rmSync(outbox, { force: true });
  });
});
