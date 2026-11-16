import { DataTypes } from 'sequelize';
import { sequelize } from '../config/database.js';
import { EVENT_CATEGORIES, EVENT_SEVERITIES } from '../utils/auditConstants.js';

export const AuditEventType = sequelize.define('AuditEventType', {
  id: { type: DataTypes.INTEGER, autoIncrement: true, primaryKey: true },
  code: { type: DataTypes.STRING(64), allowNull: false, unique: true },
  name: { type: DataTypes.STRING(150), allowNull: false },
  category: { type: DataTypes.ENUM(...EVENT_CATEGORIES), allowNull: false },
  description: { type: DataTypes.STRING(500) },
  defaultSeverity: { type: DataTypes.ENUM(...EVENT_SEVERITIES), allowNull: false, defaultValue: 'INFO' },
  isSensitive: { type: DataTypes.BOOLEAN, allowNull: false, defaultValue: false },
  requiresEntity: { type: DataTypes.BOOLEAN, allowNull: false, defaultValue: false },
  requiresChanges: { type: DataTypes.BOOLEAN, allowNull: false, defaultValue: false },
  // Additional expectations (group, reason, authorization, before/after, routine…). See utils/posEventCatalog.js.
  rules: { type: DataTypes.JSON },
  isActive: { type: DataTypes.BOOLEAN, allowNull: false, defaultValue: true },
  isSystem: { type: DataTypes.BOOLEAN, allowNull: false, defaultValue: false }
}, { tableName: 'audit_event_types' });
