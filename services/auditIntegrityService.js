import { Op } from 'sequelize';
import { sequelize, AuditLog, SystemSetting } from '../models/index.js';
import { sealRecord, verifyRecord, GENESIS_HASH } from '../utils/integrityHelper.js';

/**
 * Append a record to the hash chain. The chain lock row is held (SELECT … FOR UPDATE) for the
 * duration of the insert so concurrent writers cannot fork the chain.
 * Must be called inside a transaction.
 */
export const appendAuditRecord = async (attributes, transaction) => {
  if (!transaction) throw new Error('appendAuditRecord requires a transaction');
  await SystemSetting.findOne({ where: { key: 'audit.chainLock' }, transaction, lock: transaction.LOCK.UPDATE });
  const last = await AuditLog.findOne({
    attributes: ['id', 'integrityHash'],
    order: [['id', 'DESC']],
    transaction,
    // Locking read: always sees the latest committed row, even if the surrounding
    // transaction already established an older REPEATABLE READ snapshot.
    lock: transaction.LOCK.UPDATE
  });
  const sealed = sealRecord(attributes, last ? last.integrityHash : GENESIS_HASH);
  return AuditLog.create(sealed, { transaction });
};

/** Verify a single stored record including its link to the preceding record. */
export const verifyStoredRecord = async (record) => {
  const plain = record.get ? record.get({ plain: true }) : record;
  const previous = await AuditLog.findOne({
    attributes: ['id', 'integrityHash'],
    where: { id: { [Op.lt]: plain.id } },
    order: [['id', 'DESC']],
    raw: true
  });
  return verifyRecord(plain, previous ? previous.integrityHash : GENESIS_HASH);
};

/**
 * Walk the whole chain in id order. Returns
 * { checked, failures: [{ auditLogId, eventId, sourceSystemId, issues }], issueCounts }.
 */
export const verifyChain = async ({ batchSize = 1000, maxFailuresReported = 500 } = {}) => {
  let lastId = 0;
  let previousHash = GENESIS_HASH;
  let checked = 0;
  const failures = [];
  const issueCounts = {};

  for (;;) {
    const batch = await AuditLog.findAll({ where: { id: { [Op.gt]: lastId } }, order: [['id', 'ASC']], limit: batchSize, raw: true });
    if (!batch.length) break;
    for (const record of batch) {
      const result = verifyRecord(record, previousHash);
      checked += 1;
      if (!result.valid) {
        result.issues.forEach((issue) => { issueCounts[issue.code] = (issueCounts[issue.code] || 0) + 1; });
        if (failures.length < maxFailuresReported) {
          failures.push({ auditLogId: record.id, eventId: record.eventId, sourceSystemId: record.sourceSystemId, issues: result.issues });
        }
      }
      // Continue the chain from the stored value so a single bad record is reported once.
      previousHash = record.integrityHash || previousHash;
      lastId = record.id;
    }
  }
  return { checked, failures, issueCounts };
};

/** Event identifiers that appear more than once for the same source system. */
export const findDuplicateEventIds = async () => {
  const [rows] = await sequelize.query(
    `SELECT sourceSystemId, eventId, COUNT(*) AS occurrences
       FROM audit_logs GROUP BY sourceSystemId, eventId HAVING COUNT(*) > 1 LIMIT 500`
  );
  return rows;
};

/** True when the append-only triggers are installed. */
export const appendOnlyTriggersPresent = async () => {
  const [rows] = await sequelize.query(
    `SELECT TRIGGER_NAME FROM information_schema.TRIGGERS
      WHERE TRIGGER_SCHEMA = DATABASE() AND EVENT_OBJECT_TABLE = 'audit_logs'`
  );
  const names = rows.map((r) => r.TRIGGER_NAME);
  return { update: names.includes('trg_audit_logs_no_update'), delete: names.includes('trg_audit_logs_no_delete') };
};
