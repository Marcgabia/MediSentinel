// Sample traffic for the DEMO_POS / DEMO_INVENTORY test systems.
// Enabled with DEMO_TRAFFIC=true. Sends signed heartbeats and occasional events to this
// server's own API over HTTP, so they pass through authentication, validation, the hash
// chain, alert rules and integration monitoring exactly like a real client.
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { fileURLToPath } from 'url';
import { sequelize, SourceSystem } from '../models/index.js';
import { issueCredential } from './integrationService.js';
import { recordInternalEvent } from './auditService.js';
import { MediSentinelClient } from '../clients/medisentinel-client.js';

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
export const DEMO_CREDENTIALS_FILE = process.env.DEMO_CREDENTIALS_FILE || path.join(root, '.demo-credentials.json');
const DEMO_CODES = ['DEMO_POS', 'DEMO_INVENTORY'];

export const saveDemoCredentials = (credentials) => {
  fs.writeFileSync(DEMO_CREDENTIALS_FILE, JSON.stringify(credentials, null, 2), { mode: 0o600 });
};

/** Load stored demo keys; issue new ones (audited) for demo systems that have none on file. */
const ensureCredentials = async () => {
  const stored = fs.existsSync(DEMO_CREDENTIALS_FILE) ? JSON.parse(fs.readFileSync(DEMO_CREDENTIALS_FILE, 'utf8')) : {};
  const sources = await SourceSystem.findAll({ where: { systemCode: DEMO_CODES } });
  let changed = false;
  for (const source of sources) {
    if (stored[source.systemCode] || ['SUSPENDED', 'RETIRED'].includes(source.status)) continue;
    const { credential, secret } = await sequelize.transaction(async (transaction) => {
      const issued = await issueCredential(source.id, 'Sample traffic', null, transaction);
      await recordInternalEvent({ user: null, action: 'CREDENTIAL_ISSUED', module: 'Integrations', entity: { type: 'IntegrationCredential', id: issued.credential.keyId }, description: `Issued API key for ${source.name} sample traffic`, transaction });
      return issued;
    });
    stored[source.systemCode] = { keyId: credential.keyId, secret };
    changed = true;
  }
  if (changed) saveDemoCredentials(stored);
  return stored;
};

const POS_USERS = [
  { userId: 'POS-101', username: 'msantos', role: 'Cashier' },
  { userId: 'POS-102', username: 'jreyes', role: 'Cashier' },
  { userId: 'POS-201', username: 'agarcia', role: 'Pharmacist' }
];
const INV_USERS = [{ userId: 'INV-11', username: 'rlopez', role: 'Stock Clerk' }, { userId: 'INV-20', username: 'dmendoza', role: 'Inventory Manager' }];
const ITEMS = ['Amoxicillin 500mg', 'Paracetamol 500mg', 'Losartan 50mg', 'Metformin 500mg', 'Cetirizine 10mg', 'Omeprazole 20mg'];
const pick = (list) => list[Math.floor(Math.random() * list.length)];
const ctx = (ip) => ({ ipAddress: ip, userAgent: 'PharmaTerminal/3.2 (Windows 10)' });

const posEvents = () => {
  const actor = pick(POS_USERS);
  const sale = `SALE-${Math.floor(10000 + Math.random() * 89999)}`;
  const item = pick(ITEMS);
  const total = Math.round((100 + Math.random() * 2000) * 100) / 100;
  const correlationId = `S-${crypto.randomBytes(3).toString('hex')}`;
  return [
    { sourceModule: 'Sales', actor, action: 'TRANSACTION_CREATED', entity: { type: 'SalesTransaction', id: sale }, description: `New sale: ${item}`, changes: { before: null, after: { status: 'Pending', total, item } }, correlationId, context: ctx('10.10.1.21') },
    { sourceModule: 'Sales', actor, action: 'TRANSACTION_UPDATED', entity: { type: 'SalesTransaction', id: sale }, description: 'Sale completed', changes: { before: { status: 'Pending', paymentStatus: 'Unpaid' }, after: { status: 'Completed', paymentStatus: 'Paid' } }, correlationId, context: ctx('10.10.1.21') }
  ];
};

const invEvents = () => {
  const actor = pick(INV_USERS);
  const item = pick(ITEMS);
  const qty = 40 + Math.floor(Math.random() * 100);
  const moved = 5 + Math.floor(Math.random() * 30);
  const inbound = Math.random() < 0.5;
  return [{
    sourceModule: 'Stock', actor, action: inbound ? 'STOCK_IN' : 'STOCK_OUT',
    entity: { type: 'InventoryItem', id: `SKU-${1000 + ITEMS.indexOf(item)}` },
    description: `${inbound ? 'Received' : 'Released'} ${moved} × ${item}`,
    changes: { before: { quantity: qty }, after: { quantity: inbound ? qty + moved : qty - moved } },
    context: ctx('10.10.2.14')
  }];
};

let timer = null;

export const startDemoTraffic = async ({ port, intervalMs = 60000 }) => {
  if (timer) return;
  const sources = await SourceSystem.count({ where: { systemCode: DEMO_CODES } });
  if (!sources) {
    console.log('ℹ️  DEMO_TRAFFIC is on but no demo systems exist. Run: npm run seed:demo');
    return;
  }
  const creds = await ensureCredentials();
  const baseUrl = `http://127.0.0.1:${port}/api/v1`;
  const clients = Object.entries(creds).map(([code, c]) => ({
    code,
    client: new MediSentinelClient({ baseUrl, keyId: c.keyId, secret: c.secret, sourceSystem: code, maxAttempts: 2, clientVersion: 'demo-traffic/1.0' })
  }));
  let warned = false;
  const tick = async () => {
    for (const { code, client } of clients) {
      try {
        await client.heartbeat({ status: 'running' });
        if (Math.random() < 0.6) {
          for (const event of code === 'DEMO_POS' ? posEvents() : invEvents()) await client.send(event);
        }
      } catch (error) {
        if (!warned) { console.warn('[demo-traffic]', error.message); warned = true; }
      }
    }
  };
  await tick();
  timer = setInterval(() => tick().catch(() => {}), intervalMs);
  timer.unref?.();
  console.log(`🧪 Sample traffic running for ${clients.map((c) => c.code).join(', ')} (every ${Math.round(intervalMs / 1000)}s)`);
};

export const stopDemoTraffic = () => { if (timer) clearInterval(timer); timer = null; };
