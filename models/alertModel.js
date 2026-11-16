import { DataTypes } from 'sequelize';
import { sequelize } from '../config/database.js';
import { ALERT_SEVERITIES, ALERT_STATUSES } from '../utils/auditConstants.js';

export const Alert = sequelize.define('Alert', {
  id: { type: DataTypes.INTEGER, autoIncrement: true, primaryKey: true },
  ruleId: { type: DataTypes.INTEGER },
  alertType: { type: DataTypes.STRING(64), allowNull: false },
  title: { type: DataTypes.STRING(200), allowNull: false },
  description: { type: DataTypes.TEXT, allowNull: false },
  severity: { type: DataTypes.ENUM(...ALERT_SEVERITIES), allowNull: false },
  status: { type: DataTypes.ENUM(...ALERT_STATUSES), allowNull: false, defaultValue: 'OPEN' },
  sourceSystemId: { type: DataTypes.INTEGER },
  actorUserId: { type: DataTypes.STRING(128) },
  actorUsername: { type: DataTypes.STRING(150) },
  relatedAuditLogId: { type: DataTypes.BIGINT },
  relatedEventIds: { type: DataTypes.JSON, allowNull: false, defaultValue: [] },
  occurrenceCount: { type: DataTypes.INTEGER, allowNull: false, defaultValue: 1 },
  fingerprint: { type: DataTypes.STRING(255), allowNull: false },
  firstDetectedAt: { type: DataTypes.DATE, allowNull: false },
  lastDetectedAt: { type: DataTypes.DATE, allowNull: false },
  assignedToUserId: { type: DataTypes.INTEGER },
  acknowledgedByUserId: { type: DataTypes.INTEGER },
  acknowledgedAt: { type: DataTypes.DATE },
  resolvedByUserId: { type: DataTypes.INTEGER },
  resolvedAt: { type: DataTypes.DATE },
  resolutionNotes: { type: DataTypes.TEXT },
  details: { type: DataTypes.JSON }
}, {
  tableName: 'audit_alerts',
  indexes: [
    { name: 'ix_alert_status', fields: ['status', 'severity'] },
    { name: 'ix_alert_fingerprint', fields: ['fingerprint', 'status'] },
    { name: 'ix_alert_source', fields: ['sourceSystemId'] },
    { name: 'ix_alert_created', fields: ['createdAt'] }
  ]
});

// Alert history and notes (kept separate from the original audit records).
export const AlertActivity = sequelize.define('AlertActivity', {
  id: { type: DataTypes.INTEGER, autoIncrement: true, primaryKey: true },
  alertId: { type: DataTypes.INTEGER, allowNull: false },
  userId: { type: DataTypes.INTEGER },
  activityType: {
    type: DataTypes.ENUM('DETECTED', 'RE_DETECTED', 'ACKNOWLEDGED', 'ASSIGNED', 'NOTE', 'STATUS_CHANGED', 'RESOLVED', 'DISMISSED', 'CASE_LINKED'),
    allowNull: false
  },
  fromStatus: { type: DataTypes.STRING(20) },
  toStatus: { type: DataTypes.STRING(20) },
  note: { type: DataTypes.TEXT }
}, { tableName: 'audit_alert_activities', updatedAt: false, indexes: [{ name: 'ix_alertact_alert', fields: ['alertId'] }] });
