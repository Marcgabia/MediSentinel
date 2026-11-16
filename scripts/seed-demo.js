// Sample dataset: two DEMO source systems with 14 days of activity, incidents, alerts,
// investigations, a QA run and staff accounts. Everything flows through the real services
// (validation → hash chain → alert rules), so all figures are computed, not hard-coded.
//
//   npm run seed:demo
//
// Existing accounts are never modified. Running it twice is refused.
import crypto from 'crypto';
import { sequelize, SourceSystem, User, Role, AuditEventType, AuditEventRegistry, Alert } from '../models/index.js';
import { runMigrations } from '../utils/migrator.js';
import { seedReferenceData } from '../utils/seedReferenceData.js';
import { registerSource, issueCredential, recordHeartbeat } from '../services/integrationService.js';
import { ingestEvent, logIntegration } from '../services/auditIngestionService.js';
import { recordInternalEvent } from '../services/auditService.js';
import { applyAlertAction, evaluateApiAuthFailure, formatAlertId } from '../services/alertService.js';
import { createCase, assignCase, changeStatus, addNote, updateFindings } from '../services/investigationService.js';
import { createUser } from '../services/userService.js';
import { executeVerification } from '../services/qaVerificationService.js';
import { sessionIdentity } from '../middleware/auth.js';
import { saveDemoCredentials } from '../services/demoTrafficService.js';

const DEMO_PASSWORD = 'Demo@12345';

// Deterministic pseudo-random numbers so the dataset looks the same on every machine.
let seed = 20261113;
const rand = () => { seed |= 0; seed = (seed + 0x6D2B79F5) | 0; let t = Math.imul(seed ^ (seed >>> 15), 1 | seed); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
const between = (a, b) => a + Math.floor(rand() * (b - a + 1));
const pick = (list) => list[Math.floor(rand() * list.length)];

const now = new Date();
const at = (daysAgo, hour, minute = 0) => {
  const d = new Date(now);
  d.setDate(d.getDate() - daysAgo);
  d.setHours(hour, minute, between(0, 59), between(0, 999));
  return d;
};

const POS_USERS = [
  { userId: 'POS-101', username: 'msantos', role: 'Cashier', ip: '10.10.1.21' },
  { userId: 'POS-102', username: 'jreyes', role: 'Cashier', ip: '10.10.1.22' },
  { userId: 'POS-201', username: 'agarcia', role: 'Pharmacist', ip: '10.10.1.30' },
  { userId: 'POS-900', username: 'posadmin', role: 'Store Manager', ip: '10.10.1.5' }
];
const INV_USERS = [
  { userId: 'INV-11', username: 'rlopez', role: 'Stock Clerk', ip: '10.10.2.14' },
  { userId: 'INV-20', username: 'dmendoza', role: 'Inventory Manager', ip: '10.10.2.15' }
];
const MEDICINES = ['Amoxicillin 500mg', 'Paracetamol 500mg', 'Losartan 50mg', 'Metformin 500mg', 'Cetirizine 10mg', 'Omeprazole 20mg', 'Salbutamol Inhaler', 'Ascorbic Acid 500mg'];
const UA = 'PharmaTerminal/3.2 (Windows 10)';

const run = async () => {
  await runMigrations({ log: () => {} });
  await seedReferenceData({ log: () => {} });
  if (await SourceSystem.findOne({ where: { systemCode: 'DEMO_POS' } })) {
    console.log('Sample data already exists (DEMO_POS). Nothing changed.');
    return;
  }
  await SourceSystem.update({ name: 'MediSentinel' }, { where: { systemCode: 'MEDISENTINEL' } });

  const admin = await User.findOne({ include: [{ model: Role, as: 'role', where: { code: 'SYSTEM_ADMIN' } }], order: [['id', 'ASC']] });
  if (!admin) throw new Error('No administrator account found. Run npm run migrate first.');
  const adminId = sessionIdentity(admin);

  // 1. Staff accounts -------------------------------------------------------
  const roles = Object.fromEntries((await Role.findAll({ raw: true })).map((r) => [r.code, r.id]));
  const staff = [
    { fullName: 'Rhea Dela Cruz', username: 'rhea.auditor', email: 'rhea.auditor@medisentinel.local', roleId: roles.AUDITOR },
    { fullName: 'Marco Villanueva', username: 'marco.investigator', email: 'marco.investigator@medisentinel.local', roleId: roles.INVESTIGATOR },
    { fullName: 'Liza Ramos', username: 'liza.viewer', email: 'liza.viewer@medisentinel.local', roleId: roles.VIEWER }
  ];
  const accounts = {};
  for (const s of staff) {
    const existing = await User.findOne({ where: { username: s.username }, include: [{ model: Role, as: 'role' }] });
    const user = existing || await createUser({ ...s, password: DEMO_PASSWORD }, adminId, null);
    accounts[s.username] = sessionIdentity(await User.findByPk(user.id, { include: [{ model: Role, as: 'role' }] }));
  }
  const auditor = accounts['rhea.auditor'];
  const investigator = accounts['marco.investigator'];

  // 2. Demo source systems ---------------------------------------------------
  const types = new Map((await AuditEventType.findAll({ raw: true })).map((t) => [t.code, t]));
  const makeSource = async (code, name, description, expected) => {
    const source = await sequelize.transaction((t) => registerSource({ systemCode: code, name, description, environment: 'TEST' }, admin.id, t));
    const { credential, secret } = await sequelize.transaction((t) => issueCredential(source.id, 'Sample data', admin.id, t));
    for (const [eventCode, module] of expected) {
      await AuditEventRegistry.create({ sourceSystemId: source.id, eventTypeId: types.get(eventCode).id, sourceModule: module, isRequired: true, createdByUserId: admin.id });
    }
    return { source: (await SourceSystem.findByPk(source.id)).get({ plain: true }), credential, secret };
  };
  const pos = await makeSource('DEMO_POS', 'Demo POS', 'Sample point-of-sale system.', [
    ['LOGIN_SUCCESS', 'Authentication'], ['LOGIN_FAILED', 'Authentication'], ['TRANSACTION_CREATED', 'Sales'], ['TRANSACTION_UPDATED', 'Sales'],
    ['PAYMENT_STATUS_CHANGED', 'Payments'], ['TRANSACTION_VOIDED', 'Sales'], ['REPORT_EXPORTED', 'Reports'], ['LOGOUT', 'Authentication']
  ]);
  const inv = await makeSource('DEMO_INVENTORY', 'Demo Inventory', 'Sample inventory management system.', [
    ['LOGIN_SUCCESS', 'Authentication'], ['STOCK_IN', 'Stock'], ['STOCK_OUT', 'Stock'], ['INVENTORY_ADJUSTMENT', 'Stock'],
    ['INVENTORY_UPDATED', 'Inventory'], ['REPORT_EXPORTED', 'Reports'], ['LOGOUT', 'Authentication']
  ]);

  // Keys for optional live sample traffic (DEMO_TRAFFIC=true). Stored locally, git-ignored.
  saveDemoCredentials({ DEMO_POS: { keyId: pos.credential.keyId, secret: pos.secret }, DEMO_INVENTORY: { keyId: inv.credential.keyId, secret: inv.secret } });

  // 3. Event generation ------------------------------------------------------
  const queue = [];
  const add = (sys, occurredAt, actor, action, fields = {}) => queue.push({ sys, occurredAt, actor, action, fields });
  const POS = pos;
  const INV = inv;

  for (let day = 13; day >= 0; day -= 1) {
    for (const user of POS_USERS.slice(0, 3)) {
      const startHour = between(7, 9);
      const session = `S-${crypto.randomBytes(3).toString('hex')}`;
      add(POS, at(day, startHour, between(0, 20)), user, 'LOGIN_SUCCESS', { sourceModule: 'Authentication', description: 'Signed in', correlationId: session });
      const sales = between(3, 6);
      for (let i = 0; i < sales; i += 1) {
        const hour = startHour + 1 + i * 2;
        if (hour > 19) break;
        const sale = `SALE-${String(between(10000, 99999))}`;
        const total = between(120, 2400) + 0.5;
        const item = pick(MEDICINES);
        add(POS, at(day, hour, 5), user, 'TRANSACTION_CREATED', { sourceModule: 'Sales', entity: { type: 'SalesTransaction', id: sale }, description: `New sale: ${item}`, changes: { before: null, after: { status: 'Pending', total, item } }, correlationId: session });
        add(POS, at(day, hour, 9), user, 'TRANSACTION_UPDATED', { sourceModule: 'Sales', entity: { type: 'SalesTransaction', id: sale }, description: 'Sale completed', changes: { before: { status: 'Pending', paymentStatus: 'Unpaid' }, after: { status: 'Completed', paymentStatus: 'Paid' } }, correlationId: session });
        add(POS, at(day, hour, 10), user, 'PAYMENT_STATUS_CHANGED', { sourceModule: 'Payments', entity: { type: 'Payment', id: `PAY-${sale.slice(5)}` }, description: `Payment received (${pick(['Cash', 'GCash', 'Card'])})`, changes: { before: { paymentStatus: 'Unpaid' }, after: { paymentStatus: 'Paid', amount: total } }, correlationId: session });
      }
      add(POS, at(day, 20, between(0, 30)), user, 'LOGOUT', { sourceModule: 'Authentication', description: 'Signed out', correlationId: session });
    }
    if (day % 3 === 0) add(POS, at(day, 18, 30), POS_USERS[3], 'REPORT_EXPORTED', { sourceModule: 'Reports', entity: { type: 'Report', id: 'daily-sales' }, description: 'Exported daily sales report' });

    for (const user of INV_USERS) {
      const session = `S-${crypto.randomBytes(3).toString('hex')}`;
      add(INV, at(day, 8, between(0, 30)), user, 'LOGIN_SUCCESS', { sourceModule: 'Authentication', description: 'Signed in', correlationId: session });
      for (let i = 0; i < between(2, 4); i += 1) {
        const item = pick(MEDICINES);
        const sku = `SKU-${1000 + MEDICINES.indexOf(item)}`;
        const qty = between(40, 200);
        const action = i % 2 === 0 ? 'STOCK_IN' : 'STOCK_OUT';
        const moved = action === 'STOCK_IN' ? between(20, 100) : between(5, 30);
        add(INV, at(day, 9 + i * 2, 15), user, action, { sourceModule: 'Stock', entity: { type: 'InventoryItem', id: sku }, description: `${action === 'STOCK_IN' ? 'Received' : 'Released'} ${moved} × ${item}`, changes: { before: { quantity: qty }, after: { quantity: action === 'STOCK_IN' ? qty + moved : qty - moved } }, correlationId: session });
      }
      if (user.username === 'dmendoza' && day % 2 === 0) {
        const item = pick(MEDICINES);
        add(INV, at(day, 15, 40), user, 'INVENTORY_ADJUSTMENT', { sourceModule: 'Stock', entity: { type: 'InventoryItem', id: `SKU-${1000 + MEDICINES.indexOf(item)}` }, description: `Count adjustment: ${item}`, changes: { before: { quantity: 120, reason: null }, after: { quantity: 117, reason: 'Damaged packaging' } } });
        add(INV, at(day, 16, 10), user, 'INVENTORY_UPDATED', { sourceModule: 'Inventory', entity: { type: 'InventoryItem', id: `SKU-${1000 + MEDICINES.indexOf(item)}` }, description: `Updated reorder level: ${item}`, changes: { before: { reorderLevel: 20 }, after: { reorderLevel: 35 } } });
      }
      add(INV, at(day, 17, between(0, 40)), user, 'LOGOUT', { sourceModule: 'Authentication', description: 'Signed out', correlationId: session });
    }
  }

  // Incidents that the detection rules should catch
  for (let i = 0; i < 6; i += 1) add(POS, at(2, 9, 10 + i), POS_USERS[1], 'LOGIN_FAILED', { sourceModule: 'Authentication', outcome: 'FAILURE', description: 'Incorrect password', metadata: { reason: 'BAD_PASSWORD' } });
  for (let i = 0; i < 3; i += 1) add(POS, at(4, 13, 20 + i * 4), POS_USERS[1], 'ACCESS_DENIED', { sourceModule: 'Settings', outcome: 'DENIED', description: 'Tried to open price override settings' });
  for (let i = 0; i < 3; i += 1) add(POS, at(3, 16, 5 + i * 5), POS_USERS[3], 'ROLE_CHANGED', { sourceModule: 'User Management', entity: { type: 'User', id: `POS-10${i + 3}` }, description: 'Changed user role', changes: { before: { role: 'Cashier' }, after: { role: 'Supervisor' } } });
  for (let i = 0; i < 6; i += 1) add(POS, at(1, 14, 2 + i), POS_USERS[3], 'DELETE', { sourceModule: 'Products', entity: { type: 'Product', id: `PRD-${700 + i}` }, description: `Deleted product PRD-${700 + i}`, changes: { before: { name: pick(MEDICINES), price: between(50, 900) }, after: null }, severity: 'HIGH' });
  add(POS, at(5, 23, 20), POS_USERS[3], 'SETTINGS_MODIFIED', { sourceModule: 'Settings', entity: { type: 'Setting', id: 'discount.max' }, description: 'Changed maximum discount', changes: { before: { maxDiscount: 10 }, after: { maxDiscount: 35 } } });
  const voidHour = Math.max(8, Math.min(now.getHours() - 1, 13));
  for (let i = 0; i < 4; i += 1) add(POS, at(0, voidHour, 5 + i * 9), POS_USERS[0], 'TRANSACTION_VOIDED', { sourceModule: 'Sales', entity: { type: 'SalesTransaction', id: `SALE-9${String(i).padStart(4, '0')}` }, description: 'Voided completed sale', changes: { before: { status: 'Completed' }, after: { status: 'Voided', reason: 'Customer request' } }, severity: 'MEDIUM' });

  // Never submit events "from the future"
  const cutoff = now.getTime() - 60000;
  const events = queue.filter((e) => e.occurredAt.getTime() < cutoff).sort((a, b) => a.occurredAt - b.occurredAt);

  process.stdout.write(`Sending ${events.length} events through the ingestion pipeline`);
  const sent = [];
  for (const [i, e] of events.entries()) {
    const payload = {
      eventId: crypto.randomUUID(),
      occurredAt: e.occurredAt.toISOString(),
      sourceSystem: e.sys.source.systemCode,
      actor: { userId: e.actor.userId, username: e.actor.username, role: e.actor.role },
      action: e.action,
      outcome: 'SUCCESS',
      context: { ipAddress: e.actor.ip, userAgent: UA },
      ...e.fields
    };
    await ingestEvent({
      payload, sourceSystem: e.sys.source, credential: e.sys.credential, channel: 'API',
      context: { endpoint: '/api/v1/audit-events', method: 'POST', ipAddress: e.actor.ip, deliveryAttempt: 1 },
      receivedAt: new Date(e.occurredAt.getTime() + between(300, 2500))
    });
    if (i % 3 === 0) sent.push({ payload, sys: e.sys });
    if (i % 100 === 0) process.stdout.write('.');
  }
  console.log(' done');

  // Integration noise: retries (duplicates), invalid payloads, failed authentication
  for (const { payload, sys } of sent.slice(-2)) {
    await ingestEvent({ payload, sourceSystem: sys.source, credential: sys.credential, context: { endpoint: '/api/v1/audit-events', method: 'POST', ipAddress: '10.10.2.14', deliveryAttempt: 2 } });
  }
  const bad = [
    { eventId: crypto.randomUUID(), occurredAt: new Date().toISOString(), sourceSystem: 'DEMO_INVENTORY', sourceModule: 'Stock', actor: { username: 'rlopez' }, action: 'STOCK_TRANSFER', description: 'Transfer to branch', outcome: 'SUCCESS' },
    { eventId: crypto.randomUUID(), occurredAt: new Date().toISOString(), sourceSystem: 'DEMO_INVENTORY', sourceModule: 'Stock', actor: { username: 'rlopez' }, action: 'INVENTORY_ADJUSTMENT', entity: { type: 'InventoryItem', id: 'SKU-1003' }, description: 'Adjustment without values', outcome: 'SUCCESS' }
  ];
  for (const payload of bad) await ingestEvent({ payload, sourceSystem: inv.source, credential: inv.credential, context: { endpoint: '/api/v1/audit-events', method: 'POST', ipAddress: '10.10.2.14' } });
  for (let i = 0; i < 5; i += 1) {
    await logIntegration({ keyId: 'msk_unknown0001', endpoint: '/api/v1/audit-events', method: 'POST', httpStatus: 401, outcome: 'REJECTED_AUTH', errorCode: 'INVALID_CREDENTIALS', errorDetails: [{ message: 'Authentication failed.' }], ipAddress: '203.0.113.45' });
  }
  await evaluateApiAuthFailure({ keyId: null, ipAddress: '203.0.113.45', sourceSystemId: null });

  for (const sys of [pos, inv]) {
    await recordHeartbeat(sys.source, { pendingEvents: 0, failedDeliveries: 0, version: 'demo-client 1.0', status: 'running' });
    await logIntegration({ sourceSystemId: sys.source.id, credentialId: sys.credential.id, keyId: sys.credential.keyId, endpoint: '/api/v1/heartbeat', method: 'POST', httpStatus: 200, outcome: 'HEARTBEAT' });
  }

  // 4. Alert review & investigations ----------------------------------------
  const alertOf = (type) => Alert.findOne({ where: { alertType: type }, order: [['id', 'ASC']] });
  const act = async (alert, action, actor, extra = {}) => sequelize.transaction(async (transaction) => {
    const result = await applyAlertAction(alert.id, action, { userId: actor.id, ...extra }, transaction);
    await recordInternalEvent({ user: actor, action: 'ALERT_UPDATED', module: 'Suspicious Activities', entity: { type: 'Alert', id: formatAlertId(alert.id) }, description: `${action} alert ${formatAlertId(alert.id)}`, before: result.before, after: result.after, transaction });
  });

  const failed = await alertOf('FAILED_LOGIN_BURST');
  if (failed) {
    await act(failed, 'acknowledge', investigator);
    await act(failed, 'note', investigator, { note: 'Called the store. Cashier forgot the new password.' });
    await act(failed, 'resolve', investigator, { note: 'Password reset by store manager. No further action.' });
  }
  const voids = await alertOf('FREQUENT_VOIDS');
  if (voids) await act(voids, 'acknowledge', investigator);

  const deletions = await alertOf('MASS_DELETION');
  if (deletions) {
    const c = await createCase({ title: 'Bulk product deletion in Demo POS', description: 'Six products were deleted within minutes by the store manager account.', severity: 'CRITICAL', alertId: deletions.id, assignedToUserId: investigator.id }, adminId, null);
    await changeStatus(c.id, 'UNDER_INVESTIGATION', 'Started review', investigator, null);
    await addNote(c.id, 'Store manager says the products were discontinued. Waiting for written approval from operations.', 'NOTE', investigator, null);
  }
  const offHours = await alertOf('OFF_HOURS_ADMIN');
  if (offHours) {
    const c = await createCase({ title: 'Late-night discount change', description: 'Maximum discount raised from 10% to 35% at 23:20.', severity: 'MEDIUM', alertId: offHours.id }, adminId, null);
    await assignCase(c.id, investigator.id, adminId, null);
    await changeStatus(c.id, 'UNDER_INVESTIGATION', null, investigator, null);
    await updateFindings(c.id, { findings: 'Change was approved for a weekend promotion. Value restored on Monday.', resolutionNotes: 'Approved promotion. Recommend scheduling changes during business hours.' }, investigator, null);
    await changeStatus(c.id, 'RESOLVED', 'Confirmed with operations manager', investigator, null);
  }

  // 5. QA verification --------------------------------------------------------
  const qa = await executeVerification({ user: auditor, trigger: 'MANUAL' });

  console.log(`\nSample data ready.
  Systems:   Demo POS, Demo Inventory (test systems)
  Events:    ${events.length} sent through the API pipeline
  Alerts:    ${await Alert.count()}
  QA run:    ${qa.overallResult}

  Sample staff accounts (password: ${DEMO_PASSWORD})
    rhea.auditor@medisentinel.local        Auditor
    marco.investigator@medisentinel.local  Investigator
    liza.viewer@medisentinel.local         Read-Only Viewer`);
};

try {
  await run();
} catch (error) {
  console.error('\n✗', error.message);
  process.exitCode = 1;
} finally {
  await sequelize.close();
}
