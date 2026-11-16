import { Op } from 'sequelize';
import { normalizeEvent, redactSensitive } from '../../utils/eventNormalizer.js';
import { diffChanges, summarizeDiff } from '../../utils/changeDiff.js';
import { toCsv, escapeCsvCell } from '../../utils/csv.js';
import { computeHealth } from '../../utils/integrationHealth.js';
import { buildPagination, parsePagination } from '../../utils/pagination.js';
import { encryptSecret, decryptSecret, signRequest, verifyRequestSignature, fingerprintSecret } from '../../utils/secretBox.js';
import { buildAuditWhere } from '../../services/auditService.js';
import { resolvePeriod } from '../../services/reportService.js';
import { validateStoredRecord, overallStatus, coverageStatusFor } from '../../services/qaVerificationService.js';
import { DEFAULT_EVENT_TYPES } from '../../utils/auditConstants.js';
import { sequelize } from '../../models/index.js';

afterAll(() => sequelize.close());

describe('event normalisation', () => {
  const source = { id: 7, systemCode: 'PHARMACORE_POS', name: 'PharmaCore POS' };
  const type = DEFAULT_EVENT_TYPES.find((t) => t.code === 'TRANSACTION_VOIDED');
  test('snapshots identity, separates occurrence/receipt time, applies defaults and aliases', () => {
    const receivedAt = new Date('2026-11-12T10:30:05Z');
    const out = normalizeEvent({
      eventId: ' E1 ', occurredAt: '2026-11-12T18:30:00+08:00', sourceSystem: 'PHARMACORE_POS', sourceModule: 'Sales',
      actor: { userId: 42, username: 'cashier01', role: 'Cashier' }, action: 'TRANSACTION_VOIDED', entity: { type: 'Sale', id: 99 },
      description: ' Voided ', outcome: 'failed', context: { ipAddress: '10.0.0.1' }
    }, { sourceSystem: source, eventType: type, receivedAt, payloadHash: 'h' });
    expect(out).toMatchObject({
      eventId: 'E1', sourceSystemId: 7, sourceSystemName: 'PharmaCore POS', actorUserId: '42', actorRole: 'Cashier',
      entityId: '99', outcome: 'FAILURE', severity: 'MEDIUM', actionCategory: 'OPERATIONAL', ipAddress: '10.0.0.1', description: 'Voided'
    });
    expect(out.occurredAt.toISOString()).toBe('2026-11-12T10:30:00.000Z');
    expect(out.receivedAt).toBe(receivedAt);
  });
  test('redacts passwords, tokens and secrets from change payloads', () => {
    const { value, redacted } = redactSensitive({ username: 'a', password: 'x', nested: { apiKey: 'k', ok: 1 }, list: [{ token: 't' }] });
    expect(value).toEqual({ username: 'a', password: '[REDACTED]', nested: { apiKey: '[REDACTED]', ok: 1 }, list: [{ token: '[REDACTED]' }] });
    expect(redacted).toEqual(['password', 'nested.apiKey', 'list[0].token']);
  });
});

describe('before/after comparison', () => {
  test('highlights changed, added, removed and unchanged fields', () => {
    const rows = diffChanges(
      { transactionStatus: 'Pending', paymentStatus: 'Unpaid', cashier: 'a', meta: { till: 1 } },
      { transactionStatus: 'Completed', paymentStatus: 'Paid', cashier: 'a', receipt: 'R-1', meta: { till: 2 } }
    );
    const byField = Object.fromEntries(rows.map((r) => [r.field, r.change]));
    expect(byField).toEqual({ cashier: 'UNCHANGED', 'meta.till': 'CHANGED', paymentStatus: 'CHANGED', receipt: 'ADDED', transactionStatus: 'CHANGED' });
    expect(summarizeDiff(rows)).toEqual({ changed: 3, added: 1, removed: 0, unchanged: 1 });
    expect(rows.find((r) => r.field === 'transactionStatus').label).toBe('Transaction Status');
  });
  test('handles creation (no before) and deletion (no after)', () => {
    expect(diffChanges(null, { a: 1 })[0].change).toBe('ADDED');
    expect(diffChanges({ a: 1 }, null)[0].change).toBe('REMOVED');
  });
});

describe('CSV export', () => {
  test('escapes quotes/newlines and neutralises spreadsheet formulas', () => {
    expect(escapeCsvCell('=HYPERLINK("x")')).toBe('"\'=HYPERLINK(""x"")"');
    expect(escapeCsvCell('a\nb')).toBe('"a b"');
    const csv = toCsv([{ key: 'a', label: 'A' }], [{ a: '+1' }, { a: null }]);
    expect(csv.split('\r\n')).toEqual(['﻿"A"', '"\'+1"', '""']);
  });
});

describe('integration health', () => {
  const now = new Date('2026-11-12T12:00:00Z');
  const cfg = { staleAfterMinutes: 30, degradedErrorRate: 25, now };
  test('never claims a connection without real communication', () => {
    expect(computeHealth({ status: 'ACTIVE' }, {}, cfg).status).toBe('NEVER_CONNECTED');
  });
  test('derives HEALTHY / STALE / DEGRADED / SUSPENDED / INTERNAL', () => {
    expect(computeHealth({ status: 'ACTIVE', lastSuccessfulConnectionAt: '2026-11-12T11:55:00Z' }, {}, cfg).status).toBe('HEALTHY');
    expect(computeHealth({ status: 'ACTIVE', lastHeartbeatAt: '2026-11-12T10:00:00Z' }, {}, cfg).status).toBe('STALE');
    expect(computeHealth({ status: 'ACTIVE', lastSuccessfulConnectionAt: '2026-11-12T11:59:00Z' }, { requestsLastHour: 10, failuresLastHour: 6 }, cfg).status).toBe('DEGRADED');
    expect(computeHealth({ status: 'SUSPENDED', lastSuccessfulConnectionAt: '2026-11-12T11:59:00Z' }, {}, cfg).status).toBe('SUSPENDED');
    expect(computeHealth({ isInternal: true }, {}, cfg).status).toBe('INTERNAL');
  });
});

describe('pagination', () => {
  test('parses bounds and preserves filters in links', () => {
    expect(parsePagination({ page: '-3', limit: '1000' })).toEqual({ page: 1, limit: 100, offset: 0 });
    const p = buildPagination({ page: 2, limit: 10, total: 45, query: { q: 'abc', page: 2 }, basePath: '/audit' });
    expect(p).toMatchObject({ totalPages: 5, from: 11, to: 20, hasPrev: true, hasNext: true });
    expect(p.nextUrl).toBe('/audit?q=abc&page=3');
  });
});

describe('credential protection and request signing', () => {
  test('secrets are encrypted (AES-GCM) and decrypt only with the key', () => {
    const cipher = encryptSecret('mss_super_secret');
    expect(cipher).not.toContain('mss_super_secret');
    expect(decryptSecret(cipher)).toBe('mss_super_secret');
    const tampered = cipher.slice(0, -4) + (cipher.endsWith('AAAA') ? 'BBBB' : 'AAAA');
    expect(() => decryptSecret(tampered)).toThrow();
    expect(fingerprintSecret('a')).toHaveLength(64);
  });
  test('signature covers timestamp, method, path and body', () => {
    const base = { secret: 's', timestamp: '1700000000', method: 'POST', path: '/api/v1/audit-events', body: '{"a":1}' };
    const signature = signRequest(base);
    expect(verifyRequestSignature({ ...base, signature })).toBe(true);
    expect(verifyRequestSignature({ ...base, body: '{"a":2}', signature })).toBe(false);
    expect(verifyRequestSignature({ ...base, path: '/api/v1/audit-events/batch', signature })).toBe(false);
    expect(verifyRequestSignature({ ...base, timestamp: '1700000001', signature })).toBe(false);
    expect(verifyRequestSignature({ ...base, signature: 'v1=deadbeef' })).toBe(false);
  });
});

describe('report filtering', () => {
  test('builds WHERE clauses from search filters', () => {
    const where = buildAuditWhere({ username: 'cash', eventId: 'E1', entityId: 'SALE-1', sourceSystemId: '3', actionType: 'UPDATE', severity: 'HIGH', outcome: 'FAILURE', actorRole: 'Cashier', from: '2026-11-01', to: '2026-11-02' });
    expect(where.actorUsername).toEqual({ [Op.like]: '%cash%' });
    expect(where).toMatchObject({ eventId: 'E1', entityId: 'SALE-1', sourceSystemId: 3, actionType: 'UPDATE', severity: 'HIGH', outcome: 'FAILURE', actorRole: 'Cashier' });
    expect(where.occurredAt[Op.gte].getHours()).toBe(0);
    expect(where.occurredAt[Op.lte].getMinutes()).toBe(59);
  });
  test('ignores invalid enum values', () => {
    expect(buildAuditWhere({ severity: 'EXTREME', outcome: 'MAYBE' })).toEqual({});
  });
  test('resolves default report periods', () => {
    const daily = resolvePeriod('DAILY_ACTIVITY', {});
    expect(daily.fromStr).toBe(daily.toStr);
    const weekly = resolvePeriod('WEEKLY_ACTIVITY', { to: '2026-11-12' });
    expect(weekly.fromStr).toBe('2026-11-06');
    const monthly = resolvePeriod('MONTHLY_ACTIVITY', { to: '2026-11-12' });
    expect(monthly.fromStr).toBe('2026-11-01');
    const swapped = resolvePeriod('USER_ACTIVITY', { from: '2026-11-12', to: '2026-11-01' });
    expect(swapped.from <= swapped.to).toBe(true);
  });
});

describe('QA check helpers', () => {
  const types = new Map(DEFAULT_EVENT_TYPES.map((t) => [t.code, t]));
  const record = { eventId: 'E', sourceSystemId: 1, sourceSystemCode: 'X', sourceModule: 'M', actionType: 'UPDATE', outcome: 'SUCCESS', severity: 'INFO', occurredAt: '2026-11-12T10:00:00Z', receivedAt: '2026-11-12T10:00:01Z', actorUsername: 'u', entityType: 'T', entityId: '1', previousValues: { a: 1 }, newValues: { a: 2 } };
  test('stored record validation', () => {
    expect(validateStoredRecord(record, types)).toEqual([]);
    expect(validateStoredRecord({ ...record, actionType: 'NOPE', outcome: 'X', actorUsername: null, newValues: [1] }, types).length).toBeGreaterThanOrEqual(4);
    expect(validateStoredRecord({ ...record, occurredAt: '2026-11-12T12:00:00Z' }, types)).toContain('Event occurrence time is later than server receipt time.');
  });
  test('overall status and coverage classification', () => {
    expect(overallStatus(['PASS', 'WARNING', 'FAIL'])).toBe('FAIL');
    expect(overallStatus(['PASS', 'WARNING'])).toBe('WARNING');
    expect(overallStatus(['PASS', 'NOT_TESTED'])).toBe('PASS');
    expect(overallStatus(['NOT_TESTED'])).toBe('NOT_TESTED');
    expect(coverageStatusFor({ receivedCount: 2, invalidCount: 5 })).toBe('VERIFIED');
    expect(coverageStatusFor({ receivedCount: 0, invalidCount: 1 })).toBe('INVALID_ONLY');
    expect(coverageStatusFor({ receivedCount: 0, invalidCount: 0 })).toBe('NOT_OBSERVED');
  });
});
