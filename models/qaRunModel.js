import { DataTypes } from 'sequelize';
import { sequelize } from '../config/database.js';
import { QA_STATUSES } from '../utils/auditConstants.js';

export const QaRun = sequelize.define('QaRun', {
  id: { type: DataTypes.INTEGER, autoIncrement: true, primaryKey: true },
  triggerType: { type: DataTypes.ENUM('MANUAL', 'SCHEDULED'), allowNull: false },
  executedByUserId: { type: DataTypes.INTEGER },
  executedByLabel: { type: DataTypes.STRING(150), allowNull: false },
  status: { type: DataTypes.ENUM('RUNNING', 'COMPLETED', 'ERROR'), allowNull: false, defaultValue: 'RUNNING' },
  startedAt: { type: DataTypes.DATE(3), allowNull: false },
  completedAt: { type: DataTypes.DATE(3) },
  totalChecks: { type: DataTypes.INTEGER, allowNull: false, defaultValue: 0 },
  passedChecks: { type: DataTypes.INTEGER, allowNull: false, defaultValue: 0 },
  failedChecks: { type: DataTypes.INTEGER, allowNull: false, defaultValue: 0 },
  warningChecks: { type: DataTypes.INTEGER, allowNull: false, defaultValue: 0 },
  notTestedChecks: { type: DataTypes.INTEGER, allowNull: false, defaultValue: 0 },
  overallResult: { type: DataTypes.ENUM(...QA_STATUSES), allowNull: false, defaultValue: 'NOT_TESTED' },
  recordsVerified: { type: DataTypes.INTEGER, allowNull: false, defaultValue: 0 },
  findingsSummary: { type: DataTypes.JSON },
  errorMessage: { type: DataTypes.TEXT }
}, { tableName: 'qa_verification_runs' });
