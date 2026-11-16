import { validateEvent } from '../../utils/eventValidator.js';
import { normalizeEvent, maskValue, buildTrace } from '../../utils/eventNormalizer.js';
import { DEFAULT_EVENT_TYPES } from '../../utils/auditConstants.js';
import {
  validatePosRecord, analyzeTransaction, voidIndicators, configurationGaps, requesterKey
} from '../../utils/posAuditRules.js';
import { isAllowedTransition, normalizeStatus, POS_EVENT_CODES, ROUTINE_CODES, POS_REGISTRY_TEMPLATE } from '../../utils/posEventCatalog.js';

const eventTypes = new Map(DEFAULT_EVENT_TYPES.map((t) => [t.code, t]));
const now = new Date('2026-11-12T12:00:00Z');
const ctx = { eventTypes, sourceSystemCode: 'TEST_POS', now };
const source = { id: 7, systemCode: 'TEST_POS', name: 'Test POS', isInternal: false };

const payload = (overrides = {}) => ({
  eventId: 'EVT-1',
  occurredAt: '2026-11-12T10:30:00Z',
  sourceSystem: 'TEST_POS',
  sourceModule: 'Sales',
  actor: { userId: 'USR-001', username: 'cashier01', role: 'Cashier' },
  action: 'TRANSACTION_VOID_REQUESTED',
  entity: { type: 'Transaction', id: 'SALE-00025' },
  description: 'Void requested',
  outcome: 'SUCCESS',
  correlationId: 'SALE-00025',
  branch: { id: 'BR-MAIN', name: 'Main Branch' },
  reason: 'Customer changed mind',
  ...overrides
});
const errorCodes = (result) => result.errors.map((e) => `${e.field}:${e.code}`);

// Builds a stored-record shape the way the ingestion pipeline does.
let seq = 0;
const stored = (overrides = {}, minutes = 0) => {
  const p = payload({ eventId: `EVT-${++seq}`, occurredAt: new Date(Date.parse('2026-11-12T10:00:00Z') + minutes * 60000).toISOString(), ...overrides });
  const type = eventTypes.get(p.action);
  return { id: seq, ...normalizeEvent(p, { sourceSystem: source, eventType: type, receivedAt: new Date(Date.parse(p.occurredAt) + 1000), payloadHash: 'x' }) };
};

describe('POS event catalogue', () => {
  test('registers every event in the specification', () => {
    const required = [
      'CUSTOMER_LOOKUP', 'CUSTOMER_CREATED', 'CUSTOMER_INFORMATION_UPDATED',
      'STORE_SETTINGS_VIEWED', 'STORE_SETTINGS_UPDATED', 'STORE_LOGO_UPDATED', 'DEFAULT_BRANCH_CHANGED', 'RECEIPT_SETTING_CHANGED', 'PRODUCT_DISPLAY_SETTING_CHANGED',
      'BRANCH_CREATED', 'BRANCH_UPDATED', 'BRANCH_DEACTIVATED', 'BRANCH_SETTINGS_UPDATED',
      'PRODUCT_CREATED', 'PRODUCT_UPDATED', 'PRODUCT_ARCHIVED', 'PRODUCT_DELETED', 'PRODUCT_PRICE_UPDATED',
      'TRANSACTION_CREATED', 'TRANSACTION_UPDATED', 'CHECKOUT_COMPLETED', 'PAYMENT_RECORDED', 'TRANSACTION_CANCELLED', 'TRANSACTION_VOIDED', 'TRANSACTION_STATUS_CHANGED',
      'TRANSACTION_VOID_REQUESTED', 'TRANSACTION_VOID_APPROVED', 'TRANSACTION_VOID_REJECTED',
      'TRANSACTION_HISTORY_ACCESSED', 'TRANSACTION_DETAILS_VIEWED', 'SALES_REPORT_ACCESSED', 'DAILY_REPORT_GENERATED', 'MONTHLY_REPORT_GENERATED', 'YEARLY_REPORT_GENERATED', 'SALES_REPORT_EXPORTED',
      'PRICE_CHECK_PERFORMED'
    ];
    required.forEach((code) => {
      expect(POS_EVENT_CODES).toContain(code);
      expect(eventTypes.get(code)).toBeDefined();
    });
    expect(new Set(DEFAULT_EVENT_TYPES.map((t) => t.code)).size).toBe(DEFAULT_EVENT_TYPES.length);
  });

  test('routine access events are optional in the expected-event template', () => {
    ROUTINE_CODES.forEach((code) => {
      expect(POS_REGISTRY_TEMPLATE.find(([c]) => c === code)[2]).toBe(false);
    });
    expect(POS_REGISTRY_TEMPLATE.find(([c]) => c === 'TRANSACTION_VOIDED')[2]).toBe(true);
  });

  test('status transitions are case-insensitive and unknown vocabularies are not judged', () => {
    expect(normalizeStatus(' Completed ')).toBe('completed');
    expect(isAllowedTransition('completed', 'voided')).toBe(true);
    expect(isAllowedTransition('Completed', 'Pending')).toBe(false);
    expect(isAllowedTransition('voided', 'completed')).toBe(false);
    expect(isAllowedTransition('on-hold', 'whatever')).toBe(true);
  });
});

describe('payload validation for traceability fields', () => {
  test('accepts a complete void request', () => {
    expect(validateEvent(payload(), ctx).errors).toEqual([]);
  });

  test('rejects authorization secrets and never stores them', () => {
    const result = validateEvent(payload({
      action: 'TRANSACTION_VOID_APPROVED',
      authorization: { outcome: 'APPROVED', authorizedBy: { userId: 'OWN-1', username: 'owner' }, ownerPassword: 'hunter2' }
    }), ctx);
    expect(errorCodes(result)).toContain('authorization:SECRET_NOT_ALLOWED');
    const nested = validateEvent(payload({ authorization: { outcome: 'APPROVED', authorizedBy: { userId: 'OWN-1', pin: '1234' } } }), ctx);
    expect(errorCodes(nested)).toContain('authorization:SECRET_NOT_ALLOWED');
  });

  test('validates structure of branch, authorization, references, report and lookup', () => {
    const result = validateEvent(payload({
      branch: { name: 'No id' },
      authorization: { outcome: 'MAYBE', authorizedBy: {} },
      references: { transactionId: 'bad id with spaces', extra: 1 },
      report: { exportFormat: 'DOCX', dateFrom: '2026-11-30', dateTo: '2026-11-01', resultCount: -1 },
      lookup: { resultStatus: 'SOMETHING', query: 'Juan dela Cruz' },
      metadata: { trace: {} }
    }), ctx);
    expect(errorCodes(result)).toEqual(expect.arrayContaining([
      'branch.id:REQUIRED', 'authorization.outcome:INVALID_VALUE', 'authorization.authorizedBy.userId:REQUIRED',
      'references:INVALID_FORMAT', 'references.transactionId:INVALID_FORMAT', 'report.exportFormat:INVALID_VALUE',
      'report.dateTo:INVALID_VALUE', 'report.resultCount:INVALID_VALUE', 'lookup:INVALID_FORMAT', 'lookup.resultStatus:INVALID_VALUE',
      'metadata.trace:RESERVED_FIELD'
    ]));
  });

  test('missing reason or authorization is NOT a rejection (accepted and flagged by QA)', () => {
    expect(validateEvent(payload({ reason: undefined }), ctx).valid).toBe(true);
    expect(validateEvent(payload({ action: 'TRANSACTION_VOIDED', reason: undefined }), ctx).valid).toBe(true);
  });

  test('configuration updates still require after values', () => {
    const result = validateEvent(payload({ action: 'STORE_SETTINGS_UPDATED', entity: { type: 'StoreSettings', id: 'STORE' }, changes: undefined }), ctx);
    expect(errorCodes(result)).toContain('changes.after:REQUIRED');
  });
});

describe('normalization', () => {
  test('builds metadata.trace and derives the transaction reference from the entity', () => {
    const record = stored({ authorization: { requestedBy: { userId: 'USR-001', username: 'cashier01' }, outcome: 'PENDING' } });
    expect(record.metadata.trace).toEqual({
      branchId: 'BR-MAIN', branchName: 'Main Branch', reason: 'Customer changed mind',
      authorization: { requestedBy: { userId: 'USR-001', username: 'cashier01' }, outcome: 'PENDING' },
      references: { transactionId: 'SALE-00025' }
    });
  });

  test('masks customer personal data while keeping identifiers and change detection', () => {
    const record = stored({
      action: 'CUSTOMER_INFORMATION_UPDATED', sourceModule: 'Customers', entity: { type: 'Customer', id: 'CUST-0042' },
      changes: { before: { name: 'Juan Dela Cruz', phone: '09171234567', loyaltyTier: 'Silver' }, after: { name: 'Juan Dela Cruz', phone: '09998887777', loyaltyTier: 'Gold' } }
    });
    expect(JSON.stringify(record)).not.toContain('Juan');
    expect(JSON.stringify(record)).not.toContain('0917');
    expect(record.previousValues.name).toBe(record.newValues.name);
    expect(record.previousValues.phone).not.toBe(record.newValues.phone);
    expect(record.newValues.loyaltyTier).toBe('Gold');
    expect(record.entityId).toBe('CUST-0042');
    expect(record.metadata.maskedFields).toEqual(expect.arrayContaining(['before.name', 'after.phone']));
    expect(record.metadata.trace.references.customerId).toBe('CUST-0042');
    expect(maskValue('abc')).toMatch(/^\[MASKED:[a-f0-9]{10}\]$/);
  });

  test('customer-specific keys are masked on any event; product names are not', () => {
    const record = stored({ action: 'CHECKOUT_COMPLETED', changes: { before: null, after: { transactionStatus: 'Completed', customerName: 'Maria Santos', productName: 'Paracetamol 500mg' } } });
    expect(record.newValues.customerName).toMatch(/^\[MASKED:/);
    expect(record.newValues.productName).toBe('Paracetamol 500mg');
  });

  test('trace stays empty for events without traceability fields', () => {
    expect(buildTrace({ actor: { userId: 'x' } }, {})).toEqual({});
  });
});

describe('record-level POS validation', () => {
  test('flags missing reason, before values, branch and correlation', () => {
    const record = stored({ reason: undefined, branch: undefined, correlationId: undefined });
    const codes = validatePosRecord(record, { eventType: eventTypes.get(record.actionType), source }).map((p) => p.code);
    expect(codes).toEqual(expect.arrayContaining(['PV_REASON', 'PV_BRANCH', 'PV_CORRELATION']));
    const settings = stored({ action: 'STORE_SETTINGS_UPDATED', entity: { type: 'StoreSettings', id: 'STORE' }, changes: { before: null, after: { storeName: 'XIAN Pharmacy' } } });
    expect(validatePosRecord(settings, { eventType: eventTypes.get('STORE_SETTINGS_UPDATED'), source }).map((p) => p.code)).toContain('PV_BEFORE_VALUES');
  });

  test('flags approvals without authorizer and unexpected authorization outcomes', () => {
    const noAuth = stored({ action: 'TRANSACTION_VOID_APPROVED', authorization: { outcome: 'APPROVED' } });
    expect(validatePosRecord(noAuth, { eventType: eventTypes.get('TRANSACTION_VOID_APPROVED'), source }).map((p) => p.code)).toContain('PV_AUTHORIZATION');
    const wrong = stored({ action: 'TRANSACTION_VOID_APPROVED', authorization: { outcome: 'REJECTED', authorizedBy: { userId: 'OWN-1' } } });
    expect(validatePosRecord(wrong, { eventType: eventTypes.get('TRANSACTION_VOID_APPROVED'), source }).map((p) => p.message).join(' ')).toMatch(/REJECTED/);
    const ok = stored({ action: 'TRANSACTION_VOID_APPROVED', authorization: { outcome: 'APPROVED', reference: 'OWNER-VERIFY-8842' } });
    expect(validatePosRecord(ok, { eventType: eventTypes.get('TRANSACTION_VOID_APPROVED'), source })).toEqual([]);
  });

  test('flags unregistered sources, username-only actors and events outside the registry', () => {
    const record = stored({ actor: { username: 'cashier01' } });
    const codes = validatePosRecord(record, { eventType: eventTypes.get(record.actionType), source: null, registryCodes: new Set(['TRANSACTION_CREATED']) }).map((p) => p.code);
    expect(codes).toEqual(expect.arrayContaining(['PV_SOURCE', 'PV_USER_REFERENCE', 'PV_UNREGISTERED_EVENT']));
  });
});

describe('transaction timeline analysis', () => {
  const expected = new Set(['TRANSACTION_CREATED', 'CHECKOUT_COMPLETED', 'TRANSACTION_VOID_REQUESTED', 'TRANSACTION_VOID_APPROVED', 'TRANSACTION_VOIDED']);
  const approve = (m, extra = {}) => stored({ action: 'TRANSACTION_VOID_APPROVED', reason: undefined, authorization: { outcome: 'APPROVED', authorizedBy: { userId: 'OWN-1', username: 'owner' } }, ...extra }, m);
  const reject = (m) => stored({ action: 'TRANSACTION_VOID_REJECTED', reason: undefined, outcome: 'DENIED', authorization: { outcome: 'REJECTED', authorizedBy: { userId: 'OWN-1', username: 'owner' } } }, m);
  const created = (m = 0) => stored({ action: 'TRANSACTION_CREATED', reason: undefined, changes: { before: null, after: { transactionStatus: 'Pending' } } }, m);
  const checkout = (m = 1) => stored({ action: 'CHECKOUT_COMPLETED', reason: undefined, changes: { before: { transactionStatus: 'Pending' }, after: { transactionStatus: 'Completed', paymentStatus: 'Paid' } } }, m);
  const voided = (m, extra = {}) => stored({ action: 'TRANSACTION_VOIDED', changes: { before: { transactionStatus: 'Completed' }, after: { transactionStatus: 'Voided' } }, ...extra }, m);

  test('a complete authorized void has no issues and a full summary', () => {
    const { summary, issues } = analyzeTransaction([voided(5), created(), checkout(), stored({}, 3), approve(4)], { expectedCodes: expected, now });
    expect(issues).toEqual([]);
    expect(summary).toMatchObject({
      transactionRef: 'SALE-00025', initialStatus: 'pending', statusBeforeVoid: 'completed', currentStatus: 'voided', paymentStatus: 'paid',
      voidReason: 'Customer changed mind', authorizedBy: { userId: 'OWN-1', username: 'owner' }, branchId: 'BR-MAIN'
    });
    expect(summary.processedBy.username).toBe('cashier01');
    expect(summary.statusHistory.map((h) => h.to)).toEqual(['pending', 'completed', 'voided']);
  });

  test('detects missing completion and void events only when registered and settled', () => {
    const completedByUpdate = [created(), stored({ action: 'TRANSACTION_UPDATED', reason: undefined, changes: { before: { transactionStatus: 'Pending' }, after: { transactionStatus: 'Completed' } } }, 1)];
    expect(analyzeTransaction(completedByUpdate, { expectedCodes: expected, now }).issues.map((i) => i.code)).toContain('TC_COMPLETION_MISSING');
    // Not registered → not judged
    expect(analyzeTransaction(completedByUpdate, { expectedCodes: new Set(), now }).issues).toEqual([]);
    // Inside the observation window → not judged yet
    expect(analyzeTransaction(completedByUpdate, { expectedCodes: expected, now: new Date('2026-11-12T10:05:00Z') }).issues).toEqual([]);

    const voidedByStatus = [created(), checkout(), stored({ action: 'TRANSACTION_STATUS_CHANGED', reason: undefined, changes: { before: { transactionStatus: 'Completed' }, after: { transactionStatus: 'Voided' } } }, 2)];
    expect(analyzeTransaction(voidedByStatus, { expectedCodes: expected, now }).issues.map((i) => i.code)).toContain('TC_VOID_EVENT_MISSING');
  });

  test('detects approved voids without a final outcome, voids after rejection and missing authorization', () => {
    expect(analyzeTransaction([created(), checkout(), stored({}, 2), approve(3)], { expectedCodes: expected, now }).issues.map((i) => i.code)).toContain('TC_APPROVED_NOT_FINALIZED');
    const afterRejection = analyzeTransaction([created(), checkout(), stored({}, 2), reject(3), voided(4)], { expectedCodes: expected, now });
    expect(afterRejection.issues.map((i) => i.code)).toEqual(expect.arrayContaining(['TC_VOID_AFTER_REJECTION', 'TC_VOID_AUTHORIZATION_MISSING']));
    expect(afterRejection.summary.voidDecisions[0].outcome).toBe('REJECTED');
    const authorizedOnVoid = analyzeTransaction([created(), checkout(), voided(4, { authorization: { outcome: 'APPROVED', reference: 'OWNER-VERIFY-1' } })], { expectedCodes: expected, now });
    expect(authorizedOnVoid.issues.map((i) => i.code)).toEqual(['TC_VOID_REQUEST_MISSING']);
    expect(analyzeTransaction([created(), checkout(), stored({}, 2), voided(4)], { expectedCodes: expected, now, voidAuthorizationRequired: false }).issues).toEqual([]);
  });

  test('detects invalid transitions, status gaps, activity after void and duplicates', () => {
    const events = [
      created(),
      checkout(1),
      checkout(2),
      stored({ action: 'TRANSACTION_STATUS_CHANGED', reason: undefined, changes: { before: { transactionStatus: 'Completed' }, after: { transactionStatus: 'Pending' } } }, 3),
      stored({ action: 'TRANSACTION_STATUS_CHANGED', reason: undefined, changes: { before: { transactionStatus: 'Pending' }, after: { transactionStatus: 'Cancelled' } } }, 4),
      stored({ action: 'PAYMENT_RECORDED', reason: undefined, changes: { before: null, after: { paymentStatus: 'Paid' } } }, 5)
    ];
    const codes = analyzeTransaction(events, { expectedCodes: expected, now }).issues.map((i) => i.code);
    expect(codes).toEqual(expect.arrayContaining(['TC_DUPLICATE_EVENT', 'TC_STATUS_GAP', 'TC_STATUS_TRANSITION', 'TC_EVENT_AFTER_TERMINAL']));
  });

  test('missing creation is only reported once instrumentation was live', () => {
    const events = [checkout(1)];
    expect(analyzeTransaction(events, { expectedCodes: expected, now }).issues.map((i) => i.code)).not.toContain('TC_CREATION_MISSING');
    expect(analyzeTransaction(events, { expectedCodes: expected, now, instrumentationStart: new Date('2026-11-01T00:00:00Z') }).issues.map((i) => i.code)).toContain('TC_CREATION_MISSING');
  });
});

describe('void indicators', () => {
  test('reports reason, authorization, repeated, failed and self-authorization indicators', () => {
    const events = [
      stored({ reason: undefined }, 0),
      stored({ action: 'TRANSACTION_VOID_REJECTED', reason: undefined, authorization: { outcome: 'REJECTED', authorizedBy: { userId: 'OWN-1' } } }, 1),
      stored({ action: 'TRANSACTION_VOID_APPROVED', reason: undefined, authorization: { outcome: 'APPROVED', authorizedBy: { userId: 'USR-001', username: 'cashier01' } } }, 2),
      stored({ action: 'TRANSACTION_VOIDED', reason: undefined, changes: { before: { transactionStatus: 'Completed' }, after: { transactionStatus: 'Voided' } } }, 3)
    ];
    const analysis = analyzeTransaction(events, { now });
    const counts = new Map([[requesterKey(source.id, { userId: 'USR-001' }), 4]]);
    const codes = voidIndicators(analysis, { repeatedVoidCounts: counts, threshold: 3 }).map((i) => i.code);
    expect(codes).toEqual(expect.arrayContaining(['MISSING_REASON', 'FAILED_AUTHORIZATION', 'REPEATED_VOIDS', 'SELF_AUTHORIZED']));
    expect(codes).not.toContain('MISSING_AUTHORIZATION');
  });
});

describe('configuration continuity', () => {
  test('a before value that differs from the last recorded after value reveals an unaudited change', () => {
    const settings = (before, after, m) => stored({ action: 'STORE_SETTINGS_UPDATED', reason: undefined, entity: { type: 'StoreSettings', id: 'STORE' }, changes: { before, after } }, m);
    const gaps = configurationGaps([
      settings({ storeName: 'XIAN Store', printReceipt: false }, { storeName: 'XIAN Pharmacy', printReceipt: true }, 0),
      settings({ storeName: 'XIAN Pharmacy', printReceipt: false }, { storeName: 'XIAN Pharmacy', printReceipt: false }, 5)
    ]);
    expect(gaps).toHaveLength(1);
    expect(gaps[0]).toMatchObject({ field: 'printReceipt', recordedAfter: true, reportedBefore: false });
  });
});
