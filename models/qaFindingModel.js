import { DataTypes } from 'sequelize';
import { sequelize } from '../config/database.js';
import { FINDING_SEVERITIES, FINDING_STATUSES, QA_CATEGORIES } from '../utils/auditConstants.js';

export const QaFinding = sequelize.define('QaFinding', {
  id: { type: DataTypes.INTEGER, autoIncrement: true, primaryKey: true },
  runId: { type: DataTypes.INTEGER },
  lastRunId: { type: DataTypes.INTEGER },
  category: { type: DataTypes.ENUM(...QA_CATEGORIES), allowNull: false },
  checkCode: { type: DataTypes.STRING(64), allowNull: false },
  sourceSystemId: { type: DataTypes.INTEGER },
  relatedAuditLogId: { type: DataTypes.BIGINT },
  relatedEventId: { type: DataTypes.STRING(128) },
  title: { type: DataTypes.STRING(200), allowNull: false },
  description: { type: DataTypes.TEXT, allowNull: false },
  severity: { type: DataTypes.ENUM(...FINDING_SEVERITIES), allowNull: false },
  recommendedAction: { type: DataTypes.TEXT, allowNull: false },
  status: { type: DataTypes.ENUM(...FINDING_STATUSES), allowNull: false, defaultValue: 'OPEN' },
  fingerprint: { type: DataTypes.STRING(255), allowNull: false },
  occurrenceCount: { type: DataTypes.INTEGER, allowNull: false, defaultValue: 1 },
  firstDetectedAt: { type: DataTypes.DATE, allowNull: false },
  lastDetectedAt: { type: DataTypes.DATE, allowNull: false },
  details: { type: DataTypes.JSON },
  assignedToUserId: { type: DataTypes.INTEGER },
  resolvedByUserId: { type: DataTypes.INTEGER },
  resolvedAt: { type: DataTypes.DATE },
  resolutionNotes: { type: DataTypes.TEXT },
  verifiedByUserId: { type: DataTypes.INTEGER },
  verifiedAt: { type: DataTypes.DATE },
  verificationNote: { type: DataTypes.STRING(500) }
}, {
  tableName: 'qa_findings',
  indexes: [
    { name: 'ix_finding_status', fields: ['status', 'severity'] },
    { name: 'ix_finding_fingerprint', fields: ['fingerprint'] },
    { name: 'ix_finding_category', fields: ['category'] }
  ]
});
