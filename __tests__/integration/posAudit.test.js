// Acceptance tests for pharmacy (POS) audit monitoring. Every event travels through the real
// signed API (authentication → validation → idempotency → normalization → sealing) using
// isolated TEST source systems in the dedicated medisentinel_test database.
import crypto from 'crypto';
import { Op } from 'sequelize';
import app from '../../index.js';
import { AuditLog, QaFinding, QaResult, IntegrationLog, IdentityMapping, sequelize } from '../../models/index.js';
import { applyPosRegistryTemplate } from '../../utils/seedReferenceData.js';
import { executeVerification } from '../../services/qaVerificationService.js';
import { posDashboard, getTransactionTimeline, listVoidInvestigations, searchCrossSystem } from '../../services/posAuditService.js';
import { verifyChain } from '../../services/auditIntegrityService.js';
import { freshDatabase, closeAll, createUser, createSourceWithCredential, signedPost, loginAgent, csrfFor } from '../helpers/testApp.js';

const EVENTS = '/api/v1/audit-events';
const BATCH = '/api/v1/audit-events/batch';
let pos;
let inventory;
let admin;
const ids = {};

const ago = (minutes) => new Date(Date.now() - minutes * 60000).toISOString();
const cashier = { userId: 'USR-001', username: 'cashier01', role: 'Cashier' };
const owner = { userId: 'USR-900', username: 'owner', role: 'Owner' };
const posAdmin = { userId: 'USR-010', username: 'posadmin', role: 'Administrator' };

const event = (fields) => ({
  eventId: `EVT-${crypto.randomUUID()}`,
  occurredAt: ago(120),
  sourceSystem: 'TEST_PHARMACORE',
  sourceModule: 'Sales',
  actor: cashier,
  outcome: 'SUCCESS',
  branch: { id: 'BR-MAIN', name: 'Main Branch' },
  ...fields
});
const send = (fields, source = pos) => signedPost(app, EVENTS, fields.sourceSystem ? fields : event(fields), source);
const sale = (id, action, fields = {}) => send({ action, entity: { type: 'Transaction', id }, correlationId: `CORR-${id}`, description: `${action} ${id}`, ...fields });
const stored = (eventId) => AuditLog.findOne({ where: { eventId }, raw: true });
const post = async (agent, url, body, from) => {
  const csrf = await csrfFor(agent, from || url);
  return agent.post(url).type('form').set('Referer', from || url).send({ _csrf: csrf, ...body });
};

beforeAll(async () => {
  await freshDatabase();
  pos = await createSourceWithCredential('TEST_PHARMACORE', 'Test PharmaCore POS');
  inventory = await createSourceWithCredential('TEST_INVENTORY', 'Test Inventory');
  await applyPosRegistryTemplate(pos.source.id);
  await createUser('AUDITOR', 'auditor1');
  await createUser('VIEWER', 'viewer1');
  admin = await loginAgent(app, 'admin', 'AdminPass123');
});
afterAll(closeAll);

describe('1. Customer management', () => {
  test('customer creation is recorded with identifiers and without personal data', async () => {
    const payload = event({
      action: 'CUSTOMER_CREATED', sourceModule: 'Customers', entity: { type: 'Customer', id: 'CUST-0001' }, correlationId: 'REQ-C1',
      description: 'Registered a new customer', changes: { before: null, after: { name: 'Juan Dela Cruz', phone: '09171234567', loyaltyTier: 'Regular', seniorCitizen: true } }
    });
    const res = await send(payload);
    expect(res.status).toBe(201);
    const record = await stored(payload.eventId);
    expect(record).toMatchObject({ actionType: 'CUSTOMER_CREATED', sourceSystemCode: 'TEST_PHARMACORE', sourceModule: 'Customers', actorUserId: 'USR-001', actorUsername: 'cashier01', entityId: 'CUST-0001', outcome: 'SUCCESS', correlationId: 'REQ-C1' });
    expect(record.newValues.loyaltyTier).toBe('Regular');
    expect(record.newValues.name).toMatch(/^\[MASKED:/);
    expect(JSON.stringify(record)).not.toMatch(/Juan|0917/);
    expect(record.metadata.trace.references.customerId).toBe('CUST-0001');

    const lookup = await send({ action: 'CUSTOMER_LOOKUP', sourceModule: 'Customers', description: 'Customer search', lookup: { resultStatus: 'FOUND', resultCount: 1 } });
    expect(lookup.status).toBe(201);
    const update = await send({ action: 'CUSTOMER_INFORMATION_UPDATED', sourceModule: 'Customers', entity: { type: 'Customer', id: 'CUST-0001' }, description: 'Updated phone', changes: { before: { phone: '09171234567' }, after: { phone: '09998887777' } } });
    expect(update.status).toBe(201);
  });
});

describe('2–3. Store configuration and branches', () => {
  test('store settings changes keep before-and-after values and the administrator', async () => {
    const payload = event({
      action: 'STORE_SETTINGS_UPDATED', sourceModule: 'Store Settings', actor: posAdmin, entity: { type: 'StoreSettings', id: 'STORE' }, correlationId: 'REQ-S1',
      description: 'Updated store settings',
      changes: { before: { storeName: 'XIAN Store', defaultBranch: 'Main Branch', printReceipt: false }, after: { storeName: 'XIAN Pharmacy', defaultBranch: 'Main Branch', printReceipt: true } }
    });
    expect((await send(payload)).status).toBe(201);
    ids.settings = payload.eventId;
    const record = await stored(payload.eventId);
    expect(record.previousValues).toEqual({ storeName: 'XIAN Store', defaultBranch: 'Main Branch', printReceipt: false });
    expect(record.newValues).toEqual({ storeName: 'XIAN Pharmacy', defaultBranch: 'Main Branch', printReceipt: true });
    expect(record.actorUsername).toBe('posadmin');

    const page = await admin.get('/audit/configuration');
    expect(page.status).toBe(200);
    expect(page.text).toContain('Store Settings Updated');
    expect(page.text).toContain('XIAN Store');
    expect(page.text).toContain('XIAN Pharmacy');
    expect(page.text).toContain('posadmin');
  });

  test('a configuration update without after values is rejected', async () => {
    const res = await send({ action: 'RECEIPT_SETTING_CHANGED', sourceModule: 'Store Settings', actor: posAdmin, entity: { type: 'StoreSettings', id: 'STORE' }, description: 'Receipt change' });
    expect(res.status).toBe(422);
    expect(res.body.error.details.map((d) => d.field)).toContain('changes.after');
  });

  test('branch creation and modification are recorded and filterable by branch', async () => {
    const created = event({ action: 'BRANCH_CREATED', sourceModule: 'Branches', actor: posAdmin, entity: { type: 'Branch', id: 'BR-CAL' }, branch: { id: 'BR-CAL', name: 'Calapan' }, description: 'Created branch Calapan', changes: { before: null, after: { name: 'Calapan', status: 'Active' } } });
    const updated = event({ action: 'BRANCH_UPDATED', sourceModule: 'Branches', actor: posAdmin, entity: { type: 'Branch', id: 'BR-CAL' }, branch: { id: 'BR-CAL', name: 'Calapan' }, occurredAt: ago(110), description: 'Renamed branch', changes: { before: { name: 'Calapan' }, after: { name: 'Calapan City' } } });
    expect((await send(created)).status).toBe(201);
    expect((await send(updated)).status).toBe(201);
    const page = await admin.get('/audit/configuration?branchId=BR-CAL');
    expect(page.text).toContain('Branch Created');
    expect(page.text).toContain('Calapan City');
    expect(page.text).not.toContain('XIAN Pharmacy');
  });

  test('an unaudited configuration change between two recorded changes is detectable', async () => {
    // printReceipt was recorded as true; the next change reports it was false before.
    const gap = event({
      action: 'STORE_SETTINGS_UPDATED', sourceModule: 'Store Settings', actor: posAdmin, entity: { type: 'StoreSettings', id: 'STORE' }, occurredAt: ago(100),
      description: 'Updated store settings again', changes: { before: { printReceipt: false }, after: { printReceipt: true } }
    });
    expect((await send(gap)).status).toBe(201);
    ids.gap = gap.eventId;
  });
});

describe('4. Products', () => {
  test('product changes are traceable to the responsible user', async () => {
    const payload = event({
      action: 'PRODUCT_PRICE_UPDATED', sourceModule: 'Products', actor: posAdmin, entity: { type: 'Product', id: 'PRD-0101' }, references: { productCode: 'PARA-500' },
      description: 'Updated price of Paracetamol 500mg', changes: { before: { price: 5.5 }, after: { price: 6.0 } }
    });
    expect((await send(payload)).status).toBe(201);
    const { rows } = await searchCrossSystem({ sourceSystemId: pos.source.id, userId: 'USR-010', activity: 'PRODUCT' });
    expect(rows.map((r) => r.eventId)).toContain(payload.eventId);
    const detail = await admin.get(`/audit/${(await stored(payload.eventId)).id}`);
    expect(detail.text).toContain('posadmin');
    expect(detail.text).toContain('PARA-500');
  });
});

describe('5–7. Transactions, voids and timeline reconstruction', () => {
  test('completed POS transactions have corresponding audit events', async () => {
    expect((await sale('SALE-00025', 'TRANSACTION_CREATED', { occurredAt: ago(130), changes: { before: null, after: { transactionStatus: 'Pending' } } })).status).toBe(201);
    expect((await sale('SALE-00025', 'TRANSACTION_UPDATED', { occurredAt: ago(128), references: { customerId: 'CUST-0001' }, changes: { before: { items: 1 }, after: { items: 2 } } })).status).toBe(201);
    expect((await sale('SALE-00025', 'CHECKOUT_COMPLETED', { occurredAt: ago(125), changes: { before: { transactionStatus: 'Pending' }, after: { transactionStatus: 'Completed' } } })).status).toBe(201);
    expect((await sale('SALE-00025', 'PAYMENT_RECORDED', { occurredAt: ago(124), changes: { before: { paymentStatus: 'Unpaid' }, after: { paymentStatus: 'Paid', method: 'Cash' } } })).status).toBe(201);

    const timeline = await getTransactionTimeline('SALE-00025');
    expect(timeline.events.map((e) => e.actionType)).toEqual(['TRANSACTION_CREATED', 'TRANSACTION_UPDATED', 'CHECKOUT_COMPLETED', 'PAYMENT_RECORDED']);
    expect(timeline.analyses[0].summary).toMatchObject({ currentStatus: 'completed', paymentStatus: 'paid', customerRef: 'CUST-0001', branchId: 'BR-MAIN' });
    expect(timeline.analyses[0].issues).toEqual([]);
  });

  test('void requests and authorization results are recorded; secrets are refused', async () => {
    await sale('SALE-00030', 'TRANSACTION_CREATED', { occurredAt: ago(118), changes: { before: null, after: { transactionStatus: 'Pending' } } });
    await sale('SALE-00030', 'CHECKOUT_COMPLETED', { occurredAt: ago(117), changes: { before: { transactionStatus: 'Pending' }, after: { transactionStatus: 'Completed' } } });

    const secret = await sale('SALE-00030', 'TRANSACTION_VOID_APPROVED', { occurredAt: ago(115), authorization: { outcome: 'APPROVED', authorizedBy: owner, ownerPassword: 'owner-secret' } });
    expect(secret.status).toBe(422);
    expect(secret.body.error.details[0].code).toBe('SECRET_NOT_ALLOWED');
    const [[leak]] = await sequelize.query("SELECT COUNT(*) AS n FROM audit_logs WHERE CAST(metadata AS CHAR) LIKE '%owner-secret%'");
    expect(Number(leak.n)).toBe(0);
    expect((await IntegrationLog.findOne({ order: [['id', 'DESC']], raw: true })).outcome).toBe('REJECTED_VALIDATION');

    expect((await sale('SALE-00030', 'TRANSACTION_VOID_REQUESTED', { occurredAt: ago(116), reason: 'Wrong item scanned', authorization: { requestedBy: cashier, outcome: 'PENDING' } })).status).toBe(201);
    expect((await sale('SALE-00030', 'TRANSACTION_VOID_APPROVED', { occurredAt: ago(115), actor: owner, authorization: { requestedBy: cashier, authorizedBy: owner, outcome: 'APPROVED', method: 'OWNER_PASSWORD', reference: 'AUTH-77812' } })).status).toBe(201);
    expect((await sale('SALE-00030', 'TRANSACTION_VOIDED', { occurredAt: ago(114), reason: 'Wrong item scanned', authorization: { requestedBy: cashier, authorizedBy: owner, outcome: 'APPROVED', reference: 'AUTH-77812' }, changes: { before: { transactionStatus: 'Completed' }, after: { transactionStatus: 'Voided' } } })).status).toBe(201);

    const { summary, issues } = (await getTransactionTimeline('SALE-00030')).analyses[0];
    expect(issues).toEqual([]);
    expect(summary).toMatchObject({ currentStatus: 'voided', statusBeforeVoid: 'completed', voidReason: 'Wrong item scanned', authorizedBy: { userId: 'USR-900', username: 'owner', role: 'Owner' }, authorizationReference: 'AUTH-77812' });
    expect(summary.voidRequest.by.username).toBe('cashier01');
    expect(summary.processedBy.username).toBe('cashier01');

    // A void without reason or authorization is ACCEPTED (evidence is kept) and highlighted.
    await sale('SALE-00031', 'TRANSACTION_CREATED', { occurredAt: ago(112), changes: { before: null, after: { transactionStatus: 'Pending' } } });
    await sale('SALE-00031', 'CHECKOUT_COMPLETED', { occurredAt: ago(111), changes: { before: { transactionStatus: 'Pending' }, after: { transactionStatus: 'Completed' } } });
    const bare = await sale('SALE-00031', 'TRANSACTION_VOIDED', { occurredAt: ago(110), changes: { before: { transactionStatus: 'Completed' }, after: { transactionStatus: 'Voided' } } });
    expect(bare.status).toBe(201);
    ids.bareVoid = bare.body.auditId;

    const { rows } = await listVoidInvestigations({});
    const authorized = rows.find((r) => r.transactionRef === 'SALE-00030');
    const flagged = rows.find((r) => r.transactionRef === 'SALE-00031');
    expect(authorized.indicatorCodes).toEqual([]);
    expect(flagged.indicatorCodes).toEqual(expect.arrayContaining(['MISSING_REASON', 'MISSING_AUTHORIZATION']));

    const page = await admin.get('/audit/voids');
    expect(page.status).toBe(200);
    expect(page.text).toContain('SALE-00031');
    expect(page.text).toContain('Missing void reason');
    expect(page.text).toContain('do not by themselves imply wrongdoing');
  });

  test('transaction history is reconstructed through references and correlation IDs across systems', async () => {
    const stock = await send(event({
      sourceSystem: 'TEST_INVENTORY', sourceModule: 'Stock', action: 'STOCK_OUT', actor: { userId: 'INV-7', username: 'cashier01', role: 'Clerk' },
      entity: { type: 'InventoryItem', id: 'PARA-500' }, references: { transactionId: 'SALE-00025' }, correlationId: 'CORR-SALE-00025',
      occurredAt: ago(124), description: 'Dispensed 2 units for SALE-00025', changes: { before: { quantity: 40 }, after: { quantity: 38 } }
    }), inventory);
    expect(stock.status).toBe(201);
    const timeline = await getTransactionTimeline('SALE-00025');
    expect(timeline.events.map((e) => e.sourceSystemName)).toEqual(expect.arrayContaining(['Test PharmaCore POS', 'Test Inventory']));
    expect(timeline.analyses).toHaveLength(2);

    const page = await admin.get('/audit/transactions/SALE-00025');
    expect(page.status).toBe(200);
    expect(page.text).toContain('Checkout Completed');
    expect(page.text).toContain('Payment Recorded');
    expect(page.text).toContain('Test Inventory');
    const order = ['Transaction Created', 'Checkout Completed', 'Payment Recorded'].map((s) => page.text.indexOf(s));
    expect(order).toEqual([...order].sort((a, b) => a - b));
    // Viewing transaction details is itself audited
    expect(await AuditLog.count({ where: { sourceSystemCode: 'MEDISENTINEL', actionType: 'READ', entityId: 'SALE-00025' } })).toBeGreaterThan(0);
  });
});

describe('8. Reports', () => {
  test('sales report exports are traceable', async () => {
    const payload = event({
      action: 'SALES_REPORT_EXPORTED', sourceModule: 'Reports', actor: posAdmin, description: 'Exported monthly sales report',
      report: { reportType: 'MONTHLY_SALES', dateFrom: '2026-10-01', dateTo: '2026-10-31', branchFilter: 'BR-MAIN', exportFormat: 'csv', resultCount: 412 }
    });
    expect((await send(payload)).status).toBe(201);
    const record = await stored(payload.eventId);
    expect(record.metadata.trace.report).toEqual({ reportType: 'MONTHLY_SALES', dateFrom: '2026-10-01', dateTo: '2026-10-31', branchFilter: 'BR-MAIN', exportFormat: 'CSV', resultCount: 412 });
    const { rows } = await searchCrossSystem({ activity: 'REPORT', userId: 'USR-010' });
    expect(rows.map((r) => r.eventId)).toContain(payload.eventId);
  });
});

describe('9. Duplicate submissions', () => {
  test('re-sent events are idempotent (single and batch)', async () => {
    const payload = event({ action: 'PRICE_CHECK_PERFORMED', sourceModule: 'Price Check', entity: { type: 'Product', id: 'PRD-0101' }, references: { productCode: 'PARA-500' }, description: 'Price check', lookup: { resultStatus: 'FOUND' } });
    const first = await send(payload);
    expect(first.status).toBe(201);
    const before = await AuditLog.count({ where: { sourceSystemId: pos.source.id } });
    const again = await send(payload);
    expect(again.status).toBe(200);
    expect(again.body).toMatchObject({ status: 'duplicate', auditId: first.body.auditId });
    const batch = await signedPost(app, BATCH, { events: [payload, event({ action: 'PRICE_CHECK_PERFORMED', sourceModule: 'Price Check', description: 'Price check', lookup: { resultStatus: 'NOT_FOUND' } })] }, pos);
    expect(batch.body.summary).toEqual({ duplicate: 1, accepted: 1 });
    expect(await AuditLog.count({ where: { sourceSystemId: pos.source.id } })).toBe(before + 1);
    const conflict = await send({ ...payload, description: 'changed' });
    expect(conflict.status).toBe(409);
  });
});

describe('10. Quality assurance of POS events', () => {
  test('QA identifies invalid or incomplete POS audit events', async () => {
    // Completed through a generic update with no CHECKOUT_COMPLETED event (registered as expected).
    await sale('SALE-00040', 'TRANSACTION_CREATED', { occurredAt: ago(100), changes: { before: null, after: { transactionStatus: 'Pending' } } });
    await sale('SALE-00040', 'TRANSACTION_UPDATED', { occurredAt: ago(99), changes: { before: { transactionStatus: 'Pending' }, after: { transactionStatus: 'Completed' } } });
    // Approval with no authorizer identity and no final void outcome.
    await sale('SALE-00041', 'TRANSACTION_CREATED', { occurredAt: ago(98), changes: { before: null, after: { transactionStatus: 'Pending' } } });
    await sale('SALE-00041', 'TRANSACTION_VOID_APPROVED', { occurredAt: ago(97), actor: owner, authorization: { outcome: 'APPROVED' } });

    const run = await executeVerification({ trigger: 'MANUAL' });
    expect(run.status).toBe('COMPLETED');
    const results = await QaResult.findAll({ where: { runId: run.id }, raw: true });
    const categories = new Set(results.map((r) => r.category));
    ['POS_EVENT_VALIDATION', 'TRANSACTION_CONSISTENCY', 'CONFIGURATION_AUDIT', 'CROSS_SYSTEM_CONSISTENCY'].forEach((c) => expect(categories.has(c)).toBe(true));

    const findings = await QaFinding.findAll({ raw: true });
    const has = (checkCode, text) => findings.some((f) => f.checkCode === checkCode && (!text || f.description.includes(text) || f.title.includes(text)));
    expect(has('PV_REASON')).toBe(true); // SALE-00031 voided without a reason
    expect(has('PV_AUTHORIZATION', 'TRANSACTION_VOID_APPROVED')).toBe(true); // SALE-00041
    expect(has('TC_VOID_EVENTS', 'SALE-00031')).toBe(true); // void without authorization
    expect(has('TC_VOID_FINAL', 'SALE-00041')).toBe(true); // approved but never voided
    expect(has('TC_COMPLETION', 'SALE-00040')).toBe(true);
    expect(has('CA_CONTINUITY', 'printReceipt')).toBe(true);
    expect(findings.some((f) => f.description.includes('SALE-00025') && f.category === 'TRANSACTION_CONSISTENCY')).toBe(false);
    expect(findings.some((f) => f.description.includes('SALE-00030') && f.category === 'TRANSACTION_CONSISTENCY')).toBe(false);
    const idempotency = results.find((r) => r.checkCode === 'CS_IDEMPOTENCY');
    expect(idempotency.status).toBe('WARNING'); // the deliberate 409 conflict above
    expect(results.find((r) => r.checkCode === 'CS_SOURCE_IDENTITY').status).toBe('PASS');

    const qaPage = await admin.get('/qa');
    expect(qaPage.text).toContain('Transaction Audit Consistency');
  });

  test('pharmacy dashboard figures come from stored audit records', async () => {
    const data = await posDashboard({});
    expect(data.cards.completedTransactions).toBe(3); // SALE-00025, SALE-00030 and SALE-00031 completed checkout
    expect(data.cards.voidedTransactions).toBe(2);
    expect(data.cards.configurationChanges).toBe(4);
    expect(data.cards.customerActivities).toBe(3);
    expect(data.cards.totalPosEvents).toBe(await AuditLog.count({ where: { sourceSystemId: pos.source.id } }));
    expect(data.cards.pendingFindings).toBeGreaterThan(0);
    expect(data.charts.posBranch.labels).toEqual(expect.arrayContaining(['BR-MAIN', 'BR-CAL']));
    const byBranch = await posDashboard({ branchId: 'BR-CAL' });
    expect(byBranch.cards.totalPosEvents).toBe(2);
    const page = await admin.get('/dashboard/pharmacy');
    expect(page.status).toBe(200);
    expect(page.text).toContain('Voided transactions');
  });
});

describe('11. Original audit records are protected', () => {
  test('no ordinary route can modify audit records and the chain stays intact', async () => {
    const id = ids.bareVoid;
    for (const method of ['post', 'put', 'patch', 'delete']) {
      const res = await admin[method](`/audit/${id}`).send({});
      expect([403, 404]).toContain(res.status);
    }
    expect((await admin.post('/audit/transactions/SALE-00031').send({})).status).toBe(403); // CSRF / no route
    await expect(sequelize.query(`UPDATE audit_logs SET description = 'x' WHERE id = ${Number(id)}`)).rejects.toThrow(/append-only/);
    await expect(sequelize.query(`DELETE FROM audit_logs WHERE id = ${Number(id)}`)).rejects.toThrow(/append-only/);
    const chain = await verifyChain();
    expect(chain.checked).toBeGreaterThan(30);
    expect(chain.failures).toEqual([]);
  });

  test('transaction details are restricted to authorized roles', async () => {
    const viewer = await loginAgent(app, 'viewer1', 'Password123');
    expect((await viewer.get('/audit/transactions/SALE-00030')).status).toBe(403);
    expect((await viewer.get('/audit/voids')).status).toBe(403);
    const auditor = await loginAgent(app, 'auditor1', 'Password123');
    expect((await auditor.get('/audit/transactions/SALE-00030')).status).toBe(200);
    expect((await auditor.get('/audit/identities')).status).toBe(403);
  });
});

describe('Pages', () => {
  test('every pharmacy audit page renders for an administrator', async () => {
    const detailId = (await AuditLog.findOne({ where: { actionType: 'TRANSACTION_VOIDED', entityId: 'SALE-00030' }, raw: true })).id;
    const pages = [
      '/audit/transactions', '/audit/transactions?q=SALE', '/audit/transactions/SALE-00030', '/audit/transactions/UNKNOWN-REF',
      '/audit/voids?flagged=true', '/audit/voids?indicator=MISSING_REASON', '/audit/configuration?field=printReceipt',
      '/audit/cross-system', '/audit/cross-system?activity=VOID&hideRoutine=true', '/audit/cross-system?transactionRef=SALE-00025',
      '/audit/identities', '/audit?branchId=BR-MAIN&hideRoutine=true', `/audit/${detailId}`,
      '/dashboard', '/dashboard/pharmacy?branchId=BR-MAIN&from=2026-01-01', `/integrations/${pos.source.id}`, '/qa/coverage', '/settings?tab=system'
    ];
    for (const url of pages) {
      const res = await admin.get(url);
      expect([url, res.status]).toEqual([url, 200]);
    }
    const detail = await admin.get(`/audit/${detailId}`);
    expect(detail.text).toContain('AUTH-77812');
    expect(detail.text).toContain('Transaction timeline');
  });

  test('the POS event template can be applied to a source system', async () => {
    const res = await post(admin, `/integrations/${inventory.source.id}/registry/pos-template`, {}, `/integrations/${inventory.source.id}`);
    expect(res.status).toBe(302);
    const [[row]] = await sequelize.query('SELECT COUNT(*) AS n FROM audit_event_registry WHERE sourceSystemId = ?', { replacements: [inventory.source.id] });
    expect(Number(row.n)).toBeGreaterThan(30);
    expect(await AuditLog.count({ where: { actionType: 'EVENT_REGISTRY_CHANGED', entityId: 'TEST_INVENTORY:POS_TEMPLATE' } })).toBe(1);
  });
});

describe('12. Source systems and cross-system identity', () => {
  test('events are attributed only to the authenticated, registered source', async () => {
    const spoof = await send(event({ sourceSystem: 'TEST_INVENTORY', action: 'PRICE_CHECK_PERFORMED', sourceModule: 'Price Check', description: 'spoof', lookup: { resultStatus: 'FOUND' } }), pos);
    expect(spoof.status).toBe(422);
    expect(spoof.body.error.details[0].code).toBe('SOURCE_MISMATCH');
    const [codes] = await sequelize.query(`SELECT DISTINCT a.sourceSystemCode, s.systemCode FROM audit_logs a JOIN source_systems s ON s.id = a.sourceSystemId WHERE s.isInternal = 0`);
    codes.forEach((row) => expect(row.sourceSystemCode).toBe(row.systemCode));
    expect(codes.map((r) => r.systemCode).sort()).toEqual(['TEST_INVENTORY', 'TEST_PHARMACORE']);
  });

  test('identical usernames are not merged; explicit mappings link identities', async () => {
    const page = await admin.get('/audit/cross-system?username=cashier01');
    expect(page.status).toBe(200);
    expect(page.text).toContain('separate identities');
    const { identities } = await searchCrossSystem({ username: 'cashier01' });
    expect(new Set(identities.map((i) => i.sourceSystemId)).size).toBe(2);

    for (const [sourceSystemId, actorUserId] of [[pos.source.id, 'USR-001'], [inventory.source.id, 'INV-7']]) {
      const res = await post(admin, '/audit/identities', { personKey: 'EMP-0001', displayName: 'Cashier One', sourceSystemId, actorUserId, verificationNote: 'Checked against HR employee record' }, '/audit/identities');
      expect(res.status).toBe(302);
    }
    expect(await IdentityMapping.count({ where: { personKey: 'EMP-0001', isActive: true } })).toBe(2);
    const linked = await searchCrossSystem({ person: 'EMP-0001' });
    expect(new Set(linked.rows.map((r) => r.sourceSystemCode))).toEqual(new Set(['TEST_PHARMACORE', 'TEST_INVENTORY']));
    expect(await AuditLog.count({ where: { actionType: 'IDENTITY_MAPPING_CHANGED' } })).toBe(2);

    const duplicate = await post(admin, '/audit/identities', { personKey: 'EMP-0099', sourceSystemId: pos.source.id, actorUserId: 'USR-001', verificationNote: 'Second mapping attempt' }, '/audit/identities');
    expect(duplicate.status).toBe(302);
    expect(await IdentityMapping.count({ where: { personKey: 'EMP-0099' } })).toBe(0);
  });
});
