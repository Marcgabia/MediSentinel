import { DataTypes } from 'sequelize';
import { sequelize } from '../config/database.js';
import { EVENT_SEVERITIES, EVENT_OUTCOMES, INGESTION_CHANNELS } from '../utils/auditConstants.js';

// Append-only. Rows are protected by MySQL triggers (no UPDATE / DELETE) and by an HMAC hash chain.
export const AuditLog = sequelize.define('AuditLog', {
  id: { type: DataTypes.BIGINT, autoIncrement: true, primaryKey: true },
  eventId: { type: DataTypes.STRING(128), allowNull: false },
  sourceSystemId: { type: DataTypes.INTEGER, allowNull: false },
  sourceSystemCode: { type: DataTypes.STRING(64), allowNull: false },
  sourceSystemName: { type: DataTypes.STRING(150), allowNull: false },
  sourceModule: { type: DataTypes.STRING(100), allowNull: false },
  actorUserId: { type: DataTypes.STRING(128) },
  actorUsername: { type: DataTypes.STRING(150) },
  actorRole: { type: DataTypes.STRING(100) },
  actionType: { type: DataTypes.STRING(64), allowNull: false },
  actionCategory: { type: DataTypes.STRING(32), allowNull: false },
  entityType: { type: DataTypes.STRING(100) },
  entityId: { type: DataTypes.STRING(128) },
  description: { type: DataTypes.TEXT, allowNull: false },
  previousValues: { type: DataTypes.JSON },
  newValues: { type: DataTypes.JSON },
  outcome: { type: DataTypes.ENUM(...EVENT_OUTCOMES), allowNull: false },
  severity: { type: DataTypes.ENUM(...EVENT_SEVERITIES), allowNull: false, defaultValue: 'INFO' },
  occurredAt: { type: DataTypes.DATE(3), allowNull: false },
  receivedAt: { type: DataTypes.DATE(3), allowNull: false },
  ipAddress: { type: DataTypes.STRING(45) },
  userAgent: { type: DataTypes.STRING(512) },
  correlationId: { type: DataTypes.STRING(128) },
  metadata: { type: DataTypes.JSON },
  ingestionChannel: { type: DataTypes.ENUM(...INGESTION_CHANNELS), allowNull: false, defaultValue: 'API' },
  payloadHash: { type: DataTypes.STRING(64), allowNull: false },
  previousHash: { type: DataTypes.STRING(64), allowNull: false },
  integrityHash: { type: DataTypes.STRING(64), allowNull: false },
  signingKeyId: { type: DataTypes.STRING(32), allowNull: false }
}, {
  tableName: 'audit_logs',
  timestamps: false,
  indexes: [
    { unique: true, name: 'uq_audit_source_event', fields: ['sourceSystemId', 'eventId'] },
    { name: 'ix_audit_occurred', fields: ['occurredAt'] },
    { name: 'ix_audit_received', fields: ['receivedAt'] },
    { name: 'ix_audit_actor', fields: ['sourceSystemId', 'actorUsername', 'occurredAt'] },
    { name: 'ix_audit_actor_id', fields: ['sourceSystemId', 'actorUserId', 'occurredAt'] },
    { name: 'ix_audit_action', fields: ['actionType', 'occurredAt'] },
    { name: 'ix_audit_entity', fields: ['entityType', 'entityId'] },
    { name: 'ix_audit_entity_id', fields: ['entityId'] },
    { name: 'ix_audit_event_id', fields: ['eventId'] },
    { name: 'ix_audit_outcome', fields: ['outcome', 'occurredAt'] },
    { name: 'ix_audit_severity', fields: ['severity', 'occurredAt'] },
    { name: 'ix_audit_module', fields: ['sourceModule'] },
    { name: 'ix_audit_role', fields: ['actorRole'] },
    { name: 'ix_audit_correlation', fields: ['correlationId'] }
  ]
});
