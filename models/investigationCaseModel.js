import { DataTypes } from 'sequelize';
import { sequelize } from '../config/database.js';
import { ALERT_SEVERITIES, CASE_STATUSES } from '../utils/auditConstants.js';

export const InvestigationCase = sequelize.define('InvestigationCase', {
  id: { type: DataTypes.INTEGER, autoIncrement: true, primaryKey: true },
  caseNumber: { type: DataTypes.STRING(32), allowNull: false, unique: true },
  title: { type: DataTypes.STRING(200), allowNull: false },
  description: { type: DataTypes.TEXT, allowNull: false },
  sourceSystemId: { type: DataTypes.INTEGER },
  severity: { type: DataTypes.ENUM(...ALERT_SEVERITIES), allowNull: false, defaultValue: 'MEDIUM' },
  status: { type: DataTypes.ENUM(...CASE_STATUSES), allowNull: false, defaultValue: 'OPEN' },
  assignedToUserId: { type: DataTypes.INTEGER },
  createdByUserId: { type: DataTypes.INTEGER, allowNull: false },
  originAlertId: { type: DataTypes.INTEGER },
  findings: { type: DataTypes.TEXT },
  resolutionNotes: { type: DataTypes.TEXT },
  resolvedAt: { type: DataTypes.DATE },
  closedAt: { type: DataTypes.DATE }
}, {
  tableName: 'investigation_cases',
  indexes: [
    { name: 'ix_case_status', fields: ['status'] },
    { name: 'ix_case_assignee', fields: ['assignedToUserId', 'status'] }
  ]
});

// Links cases to the ORIGINAL audit records, which are never modified by an investigation.
export const InvestigationCaseEvent = sequelize.define('InvestigationCaseEvent', {
  id: { type: DataTypes.INTEGER, autoIncrement: true, primaryKey: true },
  caseId: { type: DataTypes.INTEGER, allowNull: false },
  auditLogId: { type: DataTypes.BIGINT, allowNull: false },
  addedByUserId: { type: DataTypes.INTEGER },
  note: { type: DataTypes.STRING(500) }
}, {
  tableName: 'investigation_case_events',
  updatedAt: false,
  indexes: [{ unique: true, name: 'uq_case_event', fields: ['caseId', 'auditLogId'] }]
});
