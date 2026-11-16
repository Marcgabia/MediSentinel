// POS audit monitoring & cross-system traceability (additive and safe to re-run).
//
// 1. audit_event_types.rules (JSON) — event expectations from utils/posEventCatalog.js.
// 2. Generated, indexed lookup columns on audit_logs derived from the SEALED metadata.trace
//    object. They are computed by MySQL (never written by the application), so they cannot
//    diverge from the integrity-protected data and do not take part in the HMAC chain.
//    Adding VIRTUAL columns is DDL — the append-only UPDATE/DELETE triggers are untouched.
// 3. New QA categories in the qa_* ENUM columns.
// 4. identity_mappings table.
// 5. Grants the new transactions.view permission to the built-in Auditor and Investigator roles.
import { QA_CATEGORIES } from '../utils/auditConstants.js';
import { IdentityMapping } from '../models/index.js';

const GENERATED = [
  { name: 'branchId', type: 'VARCHAR(64)', path: '$.trace.branchId', len: 64, index: 'ix_audit_branch', indexCols: '(branchId, occurredAt)' },
  { name: 'transactionRef', type: 'VARCHAR(128)', path: '$.trace.references.transactionId', len: 128, index: 'ix_audit_transaction', indexCols: '(transactionRef, sourceSystemId)' },
  { name: 'sharedUserId', type: 'VARCHAR(128)', path: '$.trace.identity.sharedUserId', len: 128, index: 'ix_audit_shared_user', indexCols: '(sharedUserId, occurredAt)' }
];

const columnExists = async (sequelize, table, column) => {
  const [rows] = await sequelize.query(
    'SELECT COUNT(*) AS n FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND COLUMN_NAME = ?',
    { replacements: [table, column] }
  );
  return Number(rows[0].n) > 0;
};

const indexExists = async (sequelize, table, index) => {
  const [rows] = await sequelize.query(
    'SELECT COUNT(*) AS n FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND INDEX_NAME = ?',
    { replacements: [table, index] }
  );
  return Number(rows[0].n) > 0;
};

export const up = async ({ sequelize }) => {
  if (!(await columnExists(sequelize, 'audit_event_types', 'rules'))) {
    await sequelize.query('ALTER TABLE audit_event_types ADD COLUMN rules JSON NULL AFTER requiresChanges');
  }

  for (const col of GENERATED) {
    if (!(await columnExists(sequelize, 'audit_logs', col.name))) {
      await sequelize.query(`ALTER TABLE audit_logs ADD COLUMN \`${col.name}\` ${col.type}
        GENERATED ALWAYS AS (LEFT(JSON_UNQUOTE(JSON_EXTRACT(metadata, '${col.path}')), ${col.len})) VIRTUAL`);
    }
    if (!(await indexExists(sequelize, 'audit_logs', col.index))) {
      await sequelize.query(`ALTER TABLE audit_logs ADD INDEX \`${col.index}\` ${col.indexCols}`);
    }
  }

  const enumList = QA_CATEGORIES.map((c) => `'${c}'`).join(',');
  await sequelize.query(`ALTER TABLE qa_findings MODIFY category ENUM(${enumList}) NOT NULL`);
  await sequelize.query(`ALTER TABLE qa_verification_results MODIFY category ENUM(${enumList}) NOT NULL`);

  await IdentityMapping.sync();

  const [roles] = await sequelize.query("SELECT id, code, permissions FROM roles WHERE code IN ('AUDITOR', 'INVESTIGATOR')");
  for (const role of roles) {
    const list = typeof role.permissions === 'string' ? JSON.parse(role.permissions) : (role.permissions || []);
    if (!list.includes('transactions.view')) {
      await sequelize.query('UPDATE roles SET permissions = ? WHERE id = ?', { replacements: [JSON.stringify([...list, 'transactions.view']), role.id] });
    }
  }
};
