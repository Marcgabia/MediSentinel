import { DataTypes } from 'sequelize';
import { sequelize } from '../config/database.js';
import { INTEGRATION_LOG_OUTCOMES } from '../utils/auditConstants.js';

// One row per API communication attempt (per event for batch submissions).
export const IntegrationLog = sequelize.define('IntegrationLog', {
  id: { type: DataTypes.BIGINT, autoIncrement: true, primaryKey: true },
  sourceSystemId: { type: DataTypes.INTEGER },
  credentialId: { type: DataTypes.INTEGER },
  keyId: { type: DataTypes.STRING(64) },
  endpoint: { type: DataTypes.STRING(200), allowNull: false },
  method: { type: DataTypes.STRING(10), allowNull: false },
  httpStatus: { type: DataTypes.INTEGER, allowNull: false },
  outcome: { type: DataTypes.ENUM(...INTEGRATION_LOG_OUTCOMES), allowNull: false },
  eventId: { type: DataTypes.STRING(128) },
  actionCode: { type: DataTypes.STRING(64) },
  auditLogId: { type: DataTypes.BIGINT },
  batchIndex: { type: DataTypes.INTEGER },
  deliveryAttempt: { type: DataTypes.INTEGER },
  errorCode: { type: DataTypes.STRING(64) },
  errorDetails: { type: DataTypes.JSON },
  ipAddress: { type: DataTypes.STRING(45) },
  processingMs: { type: DataTypes.INTEGER },
  deliveryDelayMs: { type: DataTypes.BIGINT },
  createdAt: { type: DataTypes.DATE(3), allowNull: false, defaultValue: DataTypes.NOW }
}, {
  tableName: 'integration_logs',
  timestamps: false,
  indexes: [
    { name: 'ix_intlog_source_time', fields: ['sourceSystemId', 'createdAt'] },
    { name: 'ix_intlog_outcome_time', fields: ['outcome', 'createdAt'] },
    { name: 'ix_intlog_key_time', fields: ['keyId', 'createdAt'] },
    { name: 'ix_intlog_ip_time', fields: ['ipAddress', 'createdAt'] },
    { name: 'ix_intlog_event', fields: ['eventId'] },
    { name: 'ix_intlog_action', fields: ['sourceSystemId', 'actionCode'] }
  ]
});
