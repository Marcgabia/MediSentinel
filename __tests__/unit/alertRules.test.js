import { eventMatchesRule, groupKeyFor, thresholdReached, isOutsideBusinessHours, fingerprintFor, describeAlert } from '../../utils/alertRuleEngine.js';
import { DEFAULT_ALERT_RULES } from '../../utils/auditConstants.js';

const rule = (code) => ({ id: 1, isEnabled: true, ...DEFAULT_ALERT_RULES.find((r) => r.code === code) });
const event = (overrides = {}) => ({
  id: 10, sourceSystemId: 2, sourceSystemName: 'PharmaCore POS', actorUserId: 'USR-002', actorUsername: 'cashier02',
  actionType: 'LOGIN_FAILED', actionCategory: 'AUTHENTICATION', outcome: 'FAILURE', severity: 'LOW',
  occurredAt: '2026-11-12T03:00:00Z', ...overrides
});

describe('alert rule evaluation', () => {
  test('matches only the configured actions', () => {
    expect(eventMatchesRule(rule('FAILED_LOGIN_BURST'), event())).toBe(true);
    expect(eventMatchesRule(rule('FAILED_LOGIN_BURST'), event({ actionType: 'LOGIN_SUCCESS' }))).toBe(false);
    expect(eventMatchesRule(rule('MASS_DELETION'), event({ actionType: 'DELETE' }))).toBe(true);
    expect(eventMatchesRule(rule('FREQUENT_VOIDS'), event({ actionType: 'TRANSACTION_VOIDED' }))).toBe(true);
  });

  test('"any" match mode: denied outcome OR ACCESS_DENIED action', () => {
    const r = rule('UNAUTHORIZED_ACCESS_REPEAT');
    expect(eventMatchesRule(r, event({ actionType: 'ACCESS_DENIED', outcome: 'DENIED' }))).toBe(true);
    expect(eventMatchesRule(r, event({ actionType: 'UPDATE', outcome: 'DENIED' }))).toBe(true);
    expect(eventMatchesRule(r, event({ actionType: 'UPDATE', outcome: 'SUCCESS' }))).toBe(false);
  });

  test('minimum severity rule', () => {
    const r = rule('CRITICAL_EVENT');
    expect(eventMatchesRule(r, event({ severity: 'CRITICAL' }))).toBe(true);
    expect(eventMatchesRule(r, event({ severity: 'HIGH' }))).toBe(false);
  });

  test('disabled rules and API rules never match stored events', () => {
    expect(eventMatchesRule({ ...rule('FAILED_LOGIN_BURST'), isEnabled: false }, event())).toBe(false);
    expect(eventMatchesRule(rule('API_AUTH_FAILURE'), event())).toBe(false);
  });

  test('off-hours detection honours timezone', () => {
    const r = rule('OFF_HOURS_ADMIN');
    // 03:00Z = 11:00 Manila → within business hours
    expect(eventMatchesRule(r, event({ actionCategory: 'ADMINISTRATIVE', occurredAt: '2026-11-12T03:00:00Z' }))).toBe(false);
    // 16:00Z = 00:00 Manila → outside
    expect(eventMatchesRule(r, event({ actionCategory: 'ADMINISTRATIVE', occurredAt: '2026-11-12T16:00:00Z' }))).toBe(true);
    expect(isOutsideBusinessHours(new Date('2026-11-12T23:30:00Z'), { startHour: 7, endHour: 21, timezone: 'UTC' })).toBe(true);
  });

  test('groups by actor within a source system (same username on another system is a different group)', () => {
    const r = rule('FAILED_LOGIN_BURST');
    expect(groupKeyFor(r, event())).toBe('actor:2:usr-002');
    expect(groupKeyFor(r, event({ sourceSystemId: 3 }))).not.toBe(groupKeyFor(r, event()));
    expect(groupKeyFor(rule('EVENT_VOLUME_SPIKE'), event())).toBe('source:2');
    expect(fingerprintFor(r, event())).toBe('FAILED_LOGIN_BURST|actor:2:usr-002');
  });

  test('threshold evaluation', () => {
    const r = rule('FAILED_LOGIN_BURST');
    expect(thresholdReached(r, 4)).toBe(false);
    expect(thresholdReached(r, 5)).toBe(true);
    expect(thresholdReached({ threshold: 0 }, 1)).toBe(true);
  });

  test('descriptions are short and factual', () => {
    expect(describeAlert(rule('FAILED_LOGIN_BURST'), event(), 5)).toBe('5 events by cashier02 on PharmaCore POS within 15 min (limit 5).');
  });
});
