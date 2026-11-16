// Development helper: register (if needed) a TEST source system and issue an API credential.
// The action is recorded in the audit trail as a system-initiated governance event.
//
//   node scripts/dev-issue-credential.js --source DEV_SIMULATOR --name "Development Simulator"
//
// Prints MEDISENTINEL_* variables for the simulator. Never use for production systems —
// issue production credentials from the dashboard (System Integrations → source → Issue credential).
import { sequelize, SourceSystem } from '../models/index.js';
import { issueCredential, registerSource } from '../services/integrationService.js';
import { recordInternalEvent } from '../services/auditService.js';

const arg = (name, fallback) => {
  const i = process.argv.indexOf(`--${name}`);
  return i > -1 ? process.argv[i + 1] : fallback;
};

const code = String(arg('source', 'DEV_SIMULATOR')).toUpperCase();
const name = arg('name', 'Development Simulator');

try {
  const { source, credential, secret } = await sequelize.transaction(async (transaction) => {
    let src = await SourceSystem.findOne({ where: { systemCode: code }, transaction });
    if (!src) {
      src = await registerSource({ systemCode: code, name, description: 'Test source used to exercise the ingestion API during development.', environment: 'TEST' }, null, transaction);
      await recordInternalEvent({ user: null, action: 'SOURCE_SYSTEM_REGISTERED', module: 'Integrations', entity: { type: 'SourceSystem', id: code }, description: `Registered test source ${name} (${code}) via developer CLI`, after: { systemCode: code, environment: 'TEST' }, transaction });
    }
    const issued = await issueCredential(src.id, 'developer CLI', null, transaction);
    await recordInternalEvent({ user: null, action: 'CREDENTIAL_ISSUED', module: 'Integrations', entity: { type: 'IntegrationCredential', id: issued.credential.keyId }, description: `Issued API credential ${issued.credential.keyId} for ${src.name} via developer CLI`, transaction });
    return { source: src, ...issued };
  });
  const port = process.env.PORT || 3000;
  console.log(`# ${source.name} (${source.systemCode}) — credential ${credential.keyId}`);
  console.log(`MEDISENTINEL_URL=http://localhost:${port}/api/v1`);
  console.log(`MEDISENTINEL_SOURCE=${source.systemCode}`);
  console.log(`MEDISENTINEL_KEY_ID=${credential.keyId}`);
  console.log(`MEDISENTINEL_SECRET=${secret}`);
} catch (error) {
  console.error('✗', error.message);
  process.exitCode = 1;
} finally {
  await sequelize.close();
}
