import {
  canonicalize, computePayloadHash, sealRecord, verifyRecord, GENESIS_HASH, computeIntegrityHash
} from '../../utils/integrityHelper.js';

const baseRecord = () => ({
  eventId: 'EVT-1', sourceSystemId: 2, sourceSystemCode: 'PHARMACORE_POS', sourceSystemName: 'PharmaCore POS', sourceModule: 'Sales',
  actorUserId: 'USR-001', actorUsername: 'cashier01', actorRole: 'Cashier', actionType: 'TRANSACTION_UPDATED', actionCategory: 'OPERATIONAL',
  entityType: 'SalesTransaction', entityId: 'SALE-00025', description: 'Completed sale',
  previousValues: { transactionStatus: 'Pending', paymentStatus: 'Unpaid' }, newValues: { paymentStatus: 'Paid', transactionStatus: 'Completed' },
  outcome: 'SUCCESS', severity: 'INFO', occurredAt: new Date('2026-11-12T10:30:00.123Z'), receivedAt: new Date('2026-11-12T10:30:01.456Z'),
  ipAddress: '10.0.0.5', userAgent: 'Terminal', correlationId: 'REQ-1', metadata: null, payloadHash: 'f'.repeat(64), ingestionChannel: 'API'
});

describe('canonicalisation', () => {
  test('is independent of key order (MySQL JSON reorders keys)', () => {
    expect(canonicalize({ b: 1, a: { d: 2, c: 3 } })).toBe(canonicalize({ a: { c: 3, d: 2 }, b: 1 }));
    expect(computePayloadHash({ x: 1, y: [1, 2] })).toBe(computePayloadHash({ y: [1, 2], x: 1 }));
  });
  test('distinguishes array order and values', () => {
    expect(canonicalize([1, 2])).not.toBe(canonicalize([2, 1]));
    expect(computePayloadHash({ a: 1 })).not.toBe(computePayloadHash({ a: '1' }));
  });
  test('serialises dates as ISO strings', () => {
    expect(canonicalize(new Date('2026-01-01T00:00:00Z'))).toBe('"2026-01-01T00:00:00.000Z"');
  });
});

describe('integrity generation and verification', () => {
  test('a sealed record verifies, including its chain link', () => {
    const sealed = sealRecord(baseRecord(), GENESIS_HASH);
    expect(sealed.integrityHash).toMatch(/^[a-f0-9]{64}$/);
    expect(sealed.signingKeyId).toBe('ktest');
    expect(verifyRecord(sealed, GENESIS_HASH)).toEqual({ valid: true, issues: [] });
  });

  test('round-tripping dates as strings and reordered JSON still verifies', () => {
    const sealed = sealRecord(baseRecord());
    const fromDb = { ...sealed, occurredAt: sealed.occurredAt.toISOString(), newValues: { transactionStatus: 'Completed', paymentStatus: 'Paid' }, sourceSystemId: '2' };
    expect(verifyRecord(fromDb, GENESIS_HASH).valid).toBe(true);
  });

  test.each([
    ['description', 'Nothing to see here'],
    ['actorUsername', 'someone-else'],
    ['outcome', 'FAILURE'],
    ['newValues', { paymentStatus: 'Unpaid', transactionStatus: 'Completed' }],
    ['occurredAt', new Date('2026-11-12T10:30:00.124Z')]
  ])('detects modification of %s', (field, value) => {
    const sealed = sealRecord(baseRecord());
    const result = verifyRecord({ ...sealed, [field]: value });
    expect(result.valid).toBe(false);
    expect(result.issues.map((i) => i.code)).toContain('SIGNATURE_MISMATCH');
  });

  test('detects a broken chain (deleted / reordered records)', () => {
    const first = sealRecord(baseRecord(), GENESIS_HASH);
    const second = sealRecord({ ...baseRecord(), eventId: 'EVT-2' }, first.integrityHash);
    expect(verifyRecord(second, first.integrityHash).valid).toBe(true);
    const result = verifyRecord(second, GENESIS_HASH);
    expect(result.issues.map((i) => i.code)).toEqual(['CHAIN_BROKEN']);
  });

  test('reports missing, malformed and unverifiable integrity values', () => {
    const sealed = sealRecord(baseRecord());
    expect(verifyRecord({ ...sealed, integrityHash: null }).issues[0].code).toBe('MISSING_INTEGRITY');
    expect(verifyRecord({ ...sealed, integrityHash: 'abc' }).issues.map((i) => i.code)).toContain('INVALID_HASH_FORMAT');
    expect(verifyRecord({ ...sealed, signingKeyId: 'unknown' }).issues.map((i) => i.code)).toContain('UNKNOWN_SIGNING_KEY');
  });

  test('records signed with a retired key remain verifiable', () => {
    const record = { ...baseRecord(), previousHash: GENESIS_HASH, signingKeyId: 'kold' };
    record.integrityHash = computeIntegrityHash(record, 'b'.repeat(64));
    expect(verifyRecord(record, GENESIS_HASH).valid).toBe(true);
  });

  test('a forged value computed with the wrong key is rejected', () => {
    const record = { ...baseRecord(), previousHash: GENESIS_HASH, signingKeyId: 'ktest' };
    record.integrityHash = computeIntegrityHash(record, 'z'.repeat(64));
    expect(verifyRecord(record).issues.map((i) => i.code)).toContain('SIGNATURE_MISMATCH');
  });
});
