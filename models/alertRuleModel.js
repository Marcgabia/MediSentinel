import { DataTypes } from 'sequelize';
import { sequelize } from '../config/database.js';
import { ALERT_SEVERITIES } from '../utils/auditConstants.js';

export const AlertRule = sequelize.define('AlertRule', {
  id: { type: DataTypes.INTEGER, autoIncrement: true, primaryKey: true },
  code: { type: DataTypes.STRING(64), allowNull: false, unique: true },
  name: { type: DataTypes.STRING(150), allowNull: false },
  description: { type: DataTypes.STRING(500) },
  ruleType: { type: DataTypes.ENUM('EVENT_THRESHOLD', 'OFF_HOURS', 'API_AUTH_FAILURE'), allowNull: false },
  threshold: { type: DataTypes.INTEGER, allowNull: false, defaultValue: 1 },
  windowMinutes: { type: DataTypes.INTEGER, allowNull: false, defaultValue: 15 },
  severity: { type: DataTypes.ENUM(...ALERT_SEVERITIES), allowNull: false, defaultValue: 'MEDIUM' },
  params: { type: DataTypes.JSON, allowNull: false, defaultValue: {} },
  isEnabled: { type: DataTypes.BOOLEAN, allowNull: false, defaultValue: true },
  updatedByUserId: { type: DataTypes.INTEGER }
}, { tableName: 'audit_alert_rules' });
