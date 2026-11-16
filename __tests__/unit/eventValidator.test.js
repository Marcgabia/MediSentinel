import { validateEvent } from '../../utils/eventValidator.js';
import { DEFAULT_EVENT_TYPES } from '../../utils/auditConstants.js';

const eventTypes = new Map(DEFAULT_EVENT_TYPES.map((t) => [t.code, t]));
const now = new Date('2026-11-12T10:35:00Z');
const ctx = { eventTypes, sourceSystemCode: 'PHARMACORE_POS', now };

const valid = () => ({
  eventId: 'UUID-12345',
  occurredAt: '2026-11-12T10:30:00Z',
  sourceSystem: 'PHARMACORE_POS',
  sourceModule: 'Sales',
  actor: { userId: 'USR-001', username: 'cashier01', role: 'Cashier' },
  action: 'CREATE',
  entity: { type: 'SalesTransaction', id: 'SALE-00025' },
  description: 'Created a new sales transaction',
  changes: { before: null, after: { transactionStatus: 'Pending' } },
  outcome: 'SUCCESS',
  severity: 'INFO',
  correlationId: 'REQ-12345'
});

const codes = (result) => result.errors.map((e) => `${e.field}:${e.code}`);

describe('eventValidator', () => {
  test('accepts the standardized example payload', () => {
    const result = validateEvent(valid(), ctx);
    expect(result.errors).toEqual([]);
    expect(result.valid).toBe(true);
    expect(result.eventType.code).toBe('CREATE');
  });

  test('rejects non-object payloads', () => {
    expect(validateEvent(null, ctx).errors[0].code).toBe('INVALID_JSON');
    expect(validateEvent([1, 2], ctx).errors[0].code).toBe('INVALID_JSON');
  });

  test('requires eventId, occurredAt, sourceModule, action, description and outcome', () => {
    const result = validateEvent({ sourceSystem: 'PHARMACORE_POS', actor: { username: 'x' } }, ctx);
    expect(codes(result)).toEqual(expect.arrayContaining([
      'eventId:REQUIRED', 'occurredAt:REQUIRED', 'sourceModule:REQUIRED', 'action:REQUIRED', 'description:REQUIRED', 'outcome:REQUIRED'
    ]));
  });

  test('rejects malformed event identifiers', () => {
    expect(codes(validateEvent({ ...valid(), eventId: 'has spaces!' }, ctx))).toContain('eventId:INVALID_FORMAT');
  });

  test('rejects unregistered action types', () => {
    expect(codes(validateEvent({ ...valid(), action: 'TELEPORT' }, ctx))).toContain('action:UNKNOWN_ACTION');
  });

  test('validates timestamps: format, timezone, future and age limits', () => {
    expect(codes(validateEvent({ ...valid(), occurredAt: 'yesterday' }, ctx))).toContain('occurredAt:INVALID_TIMESTAMP');
    expect(codes(validateEvent({ ...valid(), occurredAt: '2026-11-12T10:30:00' }, ctx))).toContain('occurredAt:INVALID_TIMESTAMP');
    expect(codes(validateEvent({ ...valid(), occurredAt: '2026-11-12T11:30:00Z' }, ctx))).toContain('occurredAt:TIMESTAMP_IN_FUTURE');
    expect(codes(validateEvent({ ...valid(), occurredAt: '2026-01-01T00:00:00Z' }, ctx))).toContain('occurredAt:TIMESTAMP_TOO_OLD');
    expect(validateEvent({ ...valid(), occurredAt: '2026-11-12T18:30:00+08:00' }, ctx).valid).toBe(true);
  });

  test('rejects events claiming to come from another source system', () => {
    expect(codes(validateEvent({ ...valid(), sourceSystem: 'OTHER_SYSTEM' }, ctx))).toContain('sourceSystem:SOURCE_MISMATCH');
  });

  test('requires user identity unless the actor is a SYSTEM process', () => {
    expect(codes(validateEvent({ ...valid(), actor: { role: 'Cashier' } }, ctx))).toContain('actor.username:REQUIRED');
    expect(validateEvent({ ...valid(), actor: { type: 'SYSTEM' } }, ctx).valid).toBe(true);
  });

  test('requires entity type and id for record actions', () => {
    expect(codes(validateEvent({ ...valid(), entity: undefined }, ctx))).toEqual(expect.arrayContaining(['entity.type:REQUIRED', 'entity.id:REQUIRED']));
    expect(validateEvent({ ...valid(), action: 'LOGIN_SUCCESS', entity: undefined, changes: undefined }, ctx).valid).toBe(true);
  });

  test('UPDATE events must include after values; changes must be well-formed objects', () => {
    expect(codes(validateEvent({ ...valid(), action: 'UPDATE', changes: undefined }, ctx))).toContain('changes.after:REQUIRED');
    expect(codes(validateEvent({ ...valid(), changes: { before: 'x', after: {} } }, ctx))).toContain('changes.before:INVALID_TYPE');
    expect(codes(validateEvent({ ...valid(), changes: { previous: {} } }, ctx))).toContain('changes:INVALID_FORMAT');
  });

  test('validates outcome (with aliases), severity and IP address', () => {
    expect(validateEvent({ ...valid(), outcome: 'failed' }, ctx).valid).toBe(true);
    expect(codes(validateEvent({ ...valid(), outcome: 'MAYBE' }, ctx))).toContain('outcome:INVALID_VALUE');
    expect(codes(validateEvent({ ...valid(), severity: 'APOCALYPTIC' }, ctx))).toContain('severity:INVALID_VALUE');
    expect(codes(validateEvent({ ...valid(), context: { ipAddress: '999.1.1.1' } }, ctx))).toContain('context.ipAddress:INVALID_FORMAT');
    expect(validateEvent({ ...valid(), context: { ipAddress: '2001:db8::1' } }, ctx).valid).toBe(true);
  });

  test('enforces size limits', () => {
    expect(codes(validateEvent({ ...valid(), description: 'x'.repeat(2001) }, ctx))).toContain('description:TOO_LONG');
    expect(codes(validateEvent({ ...valid(), metadata: { blob: 'x'.repeat(20000) } }, ctx))).toContain('metadata:PAYLOAD_TOO_LARGE');
  });
});
