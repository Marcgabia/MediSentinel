// Sends REAL signed requests to a running MediSentinel instance, acting as a test source system.
// Every event travels through authentication, validation, idempotency, sealing and alert rules.
//
//   MEDISENTINEL_URL=http://localhost:3000/api/v1 MEDISENTINEL_SOURCE=DEV_SIMULATOR \
//   MEDISENTINEL_KEY_ID=msk_... MEDISENTINEL_SECRET=mss_... \
//   node scripts/simulate-source.js --scenario all --profile pos
//
// Scenarios: normal | pos-flows | failed-logins | voids | mass-delete | privilege | invalid | duplicate |
//            bad-signature | batch | heartbeat | all
import crypto from 'crypto';
import { MediSentinelClient } from '../clients/medisentinel-client.js';

const arg = (name, fallback) => {
  const i = process.argv.indexOf(`--${name}`);
  return i > -1 ? process.argv[i + 1] : fallback;
};

const client = new MediSentinelClient({
  baseUrl: arg('url', process.env.MEDISENTINEL_URL || 'http://localhost:3000/api/v1'),
  keyId: arg('key', process.env.MEDISENTINEL_KEY_ID),
  secret: arg('secret', process.env.MEDISENTINEL_SECRET),
  sourceSystem: arg('source', process.env.MEDISENTINEL_SOURCE),
  maxAttempts: 3,
  clientVersion: 'medisentinel-simulator/1.0'
});
const scenario = arg('scenario', 'normal');
const profile = arg('profile', 'pos');
const count = Number(arg('count', 5));

const users = profile === 'inventory'
  ? [{ userId: 'INV-U01', username: 'stockclerk01', role: 'Inventory Clerk' }, { userId: 'INV-U02', username: 'invmanager', role: 'Inventory Manager' }]
  : [{ userId: 'USR-001', username: 'cashier01', role: 'Cashier' }, { userId: 'USR-002', username: 'cashier02', role: 'Cashier' }, { userId: 'USR-010', username: 'posadmin', role: 'Administrator' }];
const pick = (list) => list[Math.floor(Math.random() * list.length)];
const ctx = () => ({ ipAddress: `10.0.0.${10 + Math.floor(Math.random() * 40)}`, userAgent: 'Mozilla/5.0 (Windows NT 10.0) PharmacyTerminal/2.3' });
const tally = {};
const log = (label, result) => {
  const status = result.body?.status || result.status;
  tally[status] = (tally[status] || 0) + 1;
  console.log(`${String(result.status).padEnd(4)} ${String(status).padEnd(10)} ${label}${result.body?.error ? `  → ${result.body.error.code}: ${result.body.error.message}` : ''}`);
};

const send = async (label, fields) => log(label, await client.send({ context: ctx(), correlationId: `REQ-${crypto.randomBytes(4).toString('hex')}`, ...fields }));

const scenarios = {
  async normal() {
    for (let i = 0; i < count; i += 1) {
      const actor = pick(users);
      const session = `REQ-${crypto.randomBytes(4).toString('hex')}`;
      await send(`${actor.username} login`, { sourceModule: 'Authentication', actor, action: 'LOGIN_SUCCESS', description: `${actor.username} signed in`, correlationId: session });
      if (profile === 'inventory') {
        const sku = `MED-${100 + Math.floor(Math.random() * 50)}`;
        await send(`stock-in ${sku}`, { sourceModule: 'Stock', actor, action: 'STOCK_IN', entity: { type: 'InventoryItem', id: sku }, description: `Received 50 units of ${sku}`, changes: { before: { quantity: 20 }, after: { quantity: 70 } }, correlationId: session });
        await send(`stock-out ${sku}`, { sourceModule: 'Stock', actor, action: 'STOCK_OUT', entity: { type: 'InventoryItem', id: sku }, description: `Dispensed 5 units of ${sku}`, changes: { before: { quantity: 70 }, after: { quantity: 65 } }, correlationId: session });
        await send(`adjust ${sku}`, { sourceModule: 'Stock', actor, action: 'INVENTORY_ADJUSTMENT', entity: { type: 'InventoryItem', id: sku }, description: `Cycle-count adjustment for ${sku}`, changes: { before: { quantity: 65, reason: null }, after: { quantity: 63, reason: 'Damaged packaging' } }, correlationId: session });
        await send(`update ${sku}`, { sourceModule: 'Inventory', actor, action: 'INVENTORY_UPDATED', entity: { type: 'InventoryItem', id: sku }, description: `Updated reorder level for ${sku}`, changes: { before: { reorderLevel: 10 }, after: { reorderLevel: 25 } }, correlationId: session });
      } else {
        const sale = `SALE-${String(Math.floor(Math.random() * 99999)).padStart(5, '0')}`;
        await send(`create ${sale}`, { sourceModule: 'Sales', actor, action: 'TRANSACTION_CREATED', entity: { type: 'SalesTransaction', id: sale }, description: 'Created a new sales transaction', changes: { before: null, after: { transactionStatus: 'Pending', total: 845.5 } }, correlationId: session });
        await send(`update ${sale}`, { sourceModule: 'Sales', actor, action: 'TRANSACTION_UPDATED', entity: { type: 'SalesTransaction', id: sale }, description: 'Completed sales transaction', changes: { before: { transactionStatus: 'Pending', paymentStatus: 'Unpaid' }, after: { transactionStatus: 'Completed', paymentStatus: 'Paid' } }, correlationId: session });
        await send(`payment ${sale}`, { sourceModule: 'Payments', actor, action: 'PAYMENT_STATUS_CHANGED', entity: { type: 'Payment', id: `PAY-${sale}` }, description: 'Payment captured (cash)', changes: { before: { paymentStatus: 'Unpaid' }, after: { paymentStatus: 'Paid', method: 'Cash' } }, correlationId: session });
      }
      if (i === 0) await send('report export', { sourceModule: 'Reports', actor, action: 'REPORT_EXPORTED', entity: { type: 'Report', id: 'daily-sales' }, description: 'Exported daily sales report', correlationId: session });
      await send(`${actor.username} logout`, { sourceModule: 'Authentication', actor, action: 'LOGOUT', description: `${actor.username} signed out`, correlationId: session });
    }
  },
  // Complete pharmacy flows using the POS Audit Event Registry (customers, settings, branches,
  // products, checkout, authorized and unauthorized voids, reports, price checks).
  async 'pos-flows'() {
    const cashier = users[0];
    const owner = { userId: 'USR-900', username: 'owner', role: 'Owner' };
    const admin = users[2];
    const branch = { id: 'BR-MAIN', name: 'Main Branch' };
    const tag = crypto.randomBytes(3).toString('hex').toUpperCase();
    const cust = `CUST-${tag}`;
    await send('customer lookup', { sourceModule: 'Customers', actor: cashier, action: 'CUSTOMER_LOOKUP', description: 'Searched customers', lookup: { resultStatus: 'NOT_FOUND', resultCount: 0 }, branch });
    await send(`create ${cust}`, { sourceModule: 'Customers', actor: cashier, action: 'CUSTOMER_CREATED', entity: { type: 'Customer', id: cust }, description: 'Registered customer', changes: { before: null, after: { name: 'Sample Customer', phone: '09170000000', loyaltyTier: 'Regular' } }, branch });
    await send('store settings', { sourceModule: 'Store Settings', actor: admin, action: 'STORE_SETTINGS_UPDATED', entity: { type: 'StoreSettings', id: 'STORE' }, description: 'Updated store settings', changes: { before: { storeName: 'XIAN Store', defaultBranch: 'Main Branch', printReceipt: false }, after: { storeName: 'XIAN Pharmacy', defaultBranch: 'Main Branch', printReceipt: true } } });
    await send('branch update', { sourceModule: 'Branches', actor: admin, action: 'BRANCH_UPDATED', entity: { type: 'Branch', id: 'BR-MAIN' }, description: 'Updated branch hours', changes: { before: { openingTime: '08:00' }, after: { openingTime: '07:30' } }, branch });
    await send('price update', { sourceModule: 'Products', actor: admin, action: 'PRODUCT_PRICE_UPDATED', entity: { type: 'Product', id: 'PRD-0101' }, references: { productCode: 'PARA-500' }, description: 'Updated price', changes: { before: { price: 5.5 }, after: { price: 6 } } });
    for (const [n, voidIt, authorized] of [[1, false, false], [2, true, true], [3, true, false]]) {
      const sale = `SALE-${tag}${n}`;
      const authRef = `AUTH-${tag}${n}`;
      const base = { sourceModule: 'Sales', entity: { type: 'Transaction', id: sale }, correlationId: sale, branch };
      await send(`create ${sale}`, { ...base, actor: cashier, action: 'TRANSACTION_CREATED', description: 'Created sale', references: { customerId: cust }, changes: { before: null, after: { transactionStatus: 'Pending' } } });
      await send(`checkout ${sale}`, { ...base, actor: cashier, action: 'CHECKOUT_COMPLETED', description: 'Checkout completed', changes: { before: { transactionStatus: 'Pending' }, after: { transactionStatus: 'Completed', paymentStatus: 'Paid' } } });
      await send(`payment ${sale}`, { ...base, actor: cashier, action: 'PAYMENT_RECORDED', description: 'Cash payment recorded', changes: { before: { paymentStatus: 'Unpaid' }, after: { paymentStatus: 'Paid', method: 'Cash' } } });
      if (!voidIt) continue;
      await send(`void request ${sale}`, { ...base, actor: cashier, action: 'TRANSACTION_VOID_REQUESTED', description: 'Void requested', reason: authorized ? 'Wrong item scanned' : undefined, authorization: { requestedBy: cashier, outcome: 'PENDING' } });
      if (authorized) {
        await send(`void approved ${sale}`, { ...base, actor: owner, action: 'TRANSACTION_VOID_APPROVED', description: 'Owner approved void', authorization: { requestedBy: cashier, authorizedBy: owner, outcome: 'APPROVED', method: 'OWNER_PASSWORD', reference: authRef } });
      }
      await send(`voided ${sale}`, { ...base, actor: cashier, action: 'TRANSACTION_VOIDED', description: 'Transaction voided', reason: authorized ? 'Wrong item scanned' : undefined, authorization: authorized ? { requestedBy: cashier, authorizedBy: owner, outcome: 'APPROVED', reference: authRef } : undefined, changes: { before: { transactionStatus: 'Completed' }, after: { transactionStatus: 'Voided' } } });
    }
    await send('void with password (must be rejected)', { sourceModule: 'Sales', actor: owner, action: 'TRANSACTION_VOID_APPROVED', entity: { type: 'Transaction', id: `SALE-${tag}1` }, description: 'Should be refused', authorization: { outcome: 'APPROVED', authorizedBy: owner, ownerPassword: 'never-send-this' } });
    await send('report export', { sourceModule: 'Reports', actor: admin, action: 'SALES_REPORT_EXPORTED', description: 'Exported monthly sales', report: { reportType: 'MONTHLY_SALES', dateFrom: '2026-10-01', dateTo: '2026-10-31', branchFilter: 'BR-MAIN', exportFormat: 'CSV' } });
    await send('price check', { sourceModule: 'Price Check', actor: cashier, action: 'PRICE_CHECK_PERFORMED', entity: { type: 'Product', id: 'PRD-0101' }, references: { productCode: 'PARA-500' }, description: 'Price check', lookup: { resultStatus: 'FOUND' }, branch });
  },
  async 'failed-logins'() {
    const actor = { userId: 'USR-002', username: 'cashier02', role: 'Cashier' };
    for (let i = 0; i < Math.max(6, count); i += 1) {
      await send(`failed login #${i + 1}`, { sourceModule: 'Authentication', actor, action: 'LOGIN_FAILED', outcome: 'FAILURE', description: 'Invalid password', metadata: { reason: 'BAD_PASSWORD' } });
    }
  },
  async voids() {
    const actor = { userId: 'USR-001', username: 'cashier01', role: 'Cashier' };
    for (let i = 0; i < Math.max(4, count); i += 1) {
      const sale = `SALE-9${String(i).padStart(4, '0')}`;
      await send(`void ${sale}`, { sourceModule: 'Sales', actor, action: 'TRANSACTION_VOIDED', entity: { type: 'SalesTransaction', id: sale }, description: `Voided transaction ${sale}`, changes: { before: { transactionStatus: 'Completed' }, after: { transactionStatus: 'Voided', voidReason: 'Customer request' } }, severity: 'MEDIUM' });
    }
  },
  async 'mass-delete'() {
    const actor = { userId: 'USR-010', username: 'posadmin', role: 'Administrator' };
    for (let i = 0; i < Math.max(6, count); i += 1) {
      await send(`delete PRD-${i}`, { sourceModule: 'Products', actor, action: 'DELETE', entity: { type: 'Product', id: `PRD-${700 + i}` }, description: `Deleted product PRD-${700 + i}`, changes: { before: { name: `Product ${i}`, price: 99 }, after: null }, severity: 'HIGH' });
    }
  },
  async privilege() {
    const actor = { userId: 'USR-010', username: 'posadmin', role: 'Administrator' };
    for (let i = 0; i < 3; i += 1) {
      await send(`role change #${i + 1}`, { sourceModule: 'User Management', actor, action: 'ROLE_CHANGED', entity: { type: 'User', id: `USR-00${i + 3}` }, description: 'Changed user role', changes: { before: { role: 'Cashier' }, after: { role: 'Supervisor' } } });
    }
    await send('access denied', { sourceModule: 'Settings', actor: users[0], action: 'ACCESS_DENIED', outcome: 'DENIED', description: 'Attempted to open system settings without permission' });
  },
  async invalid() {
    await send('missing fields', { sourceModule: '', actor: {}, action: 'UPDATE', description: '' });
    await send('unknown action', { sourceModule: 'Sales', actor: users[0], action: 'TELEPORT', description: 'Not a registered action' });
    await send('bad timestamp', { occurredAt: 'yesterday', sourceModule: 'Sales', actor: users[0], action: 'TRANSACTION_CREATED', entity: { type: 'SalesTransaction', id: 'SALE-1' }, description: 'Bad timestamp' });
    await send('update without changes', { sourceModule: 'Sales', actor: users[0], action: 'TRANSACTION_UPDATED', entity: { type: 'SalesTransaction', id: 'SALE-2' }, description: 'Missing after values' });
  },
  async duplicate() {
    const event = client.buildEvent({ sourceModule: 'Sales', actor: users[0], action: 'TRANSACTION_CREATED', entity: { type: 'SalesTransaction', id: 'SALE-DUP' }, description: 'Idempotency test' });
    log('first delivery', await client.send(event));
    log('retry (same payload)', await client.send(event));
    log('same eventId, different payload', await client.send({ ...event, description: 'Tampered resend' }));
  },
  async 'bad-signature'() {
    const rogue = new MediSentinelClient({ baseUrl: client.baseUrl, keyId: client.keyId, secret: 'wrong-secret', sourceSystem: client.sourceSystem, maxAttempts: 1 });
    for (let i = 0; i < Math.max(5, count); i += 1) log(`bad signature #${i + 1}`, await rogue.send({ sourceModule: 'Sales', actor: users[0], action: 'LOGIN_SUCCESS', description: 'forged' }));
  },
  async batch() {
    const events = Array.from({ length: Math.max(3, count) }, (_, i) => client.buildEvent({ sourceModule: 'Authentication', actor: pick(users), action: i % 2 ? 'LOGOUT' : 'LOGIN_SUCCESS', description: `Batch event ${i + 1}`, context: ctx() }));
    events.push({ eventId: 'BATCH-INVALID', sourceModule: 'X', action: 'NOPE' });
    const result = await client.sendBatch(events);
    console.log(`${result.status} batch → ${JSON.stringify(result.body.summary)}`);
  },
  async heartbeat() {
    const result = await client.heartbeat({ status: 'running' });
    console.log(`${result.status} heartbeat → ${JSON.stringify(result.body)}`);
  }
};

const order = scenario === 'all' ? ['heartbeat', 'normal', 'pos-flows', 'failed-logins', 'voids', 'mass-delete', 'privilege', 'invalid', 'duplicate', 'batch', 'bad-signature', 'heartbeat'] : [scenario];
for (const name of order) {
  if (!scenarios[name]) { console.error(`Unknown scenario "${name}"`); process.exit(1); }
  console.log(`\n=== ${name} ===`);
  await scenarios[name]();
}
console.log(`\nSummary: ${JSON.stringify(tally)}`);
