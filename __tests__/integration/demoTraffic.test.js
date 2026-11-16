import os from 'os';
import path from 'path';
import fs from 'fs';

// Keep the developer's real demo key file untouched.
process.env.DEMO_CREDENTIALS_FILE = path.join(os.tmpdir(), `ms-demo-creds-${Date.now()}.json`);

const { default: app } = await import('../../index.js');
const { sequelize, SourceSystem, AuditLog, IntegrationLog } = await import('../../models/index.js');
const { registerSource } = await import('../../services/integrationService.js');
const { startDemoTraffic, stopDemoTraffic } = await import('../../services/demoTrafficService.js');
const { listSourcesWithHealth } = await import('../../services/integrationService.js');
const { freshDatabase, closeAll } = await import('../helpers/testApp.js');

let server;
beforeAll(async () => {
  await freshDatabase();
  await sequelize.transaction((t) => registerSource({ systemCode: 'DEMO_POS', name: 'Demo POS', environment: 'TEST' }, null, t));
  server = app.listen(0);
  await new Promise((r) => server.once('listening', r));
});
afterAll(async () => {
  stopDemoTraffic();
  await new Promise((r) => server.close(r));
  fs.rmSync(process.env.DEMO_CREDENTIALS_FILE, { force: true });
  await closeAll();
});

test('sample traffic goes through the signed API and keeps the demo system connected', async () => {
  await startDemoTraffic({ port: server.address().port, intervalMs: 3600000 });
  const source = await SourceSystem.findOne({ where: { systemCode: 'DEMO_POS' } });
  expect(fs.existsSync(process.env.DEMO_CREDENTIALS_FILE)).toBe(true);
  expect(await IntegrationLog.count({ where: { sourceSystemId: source.id, outcome: 'HEARTBEAT' } })).toBe(1);
  const accepted = await IntegrationLog.count({ where: { sourceSystemId: source.id, outcome: 'ACCEPTED' } });
  expect(await AuditLog.count({ where: { sourceSystemId: source.id } })).toBe(accepted);
  const health = (await listSourcesWithHealth()).find((s) => s.systemCode === 'DEMO_POS').health.status;
  expect(health).toBe('HEALTHY');
  // The key was issued through the audited path
  expect(await AuditLog.count({ where: { actionType: 'CREDENTIAL_ISSUED' } })).toBe(1);
});
