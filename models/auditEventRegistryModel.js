import { DataTypes } from 'sequelize';
import { sequelize } from '../config/database.js';

// Monitoring configuration: which events each source system is EXPECTED to submit.
export const AuditEventRegistry = sequelize.define('AuditEventRegistry', {
  id: { type: DataTypes.INTEGER, autoIncrement: true, primaryKey: true },
  sourceSystemId: { type: DataTypes.INTEGER, allowNull: false },
  eventTypeId: { type: DataTypes.INTEGER, allowNull: false },
  sourceModule: { type: DataTypes.STRING(100) },
  isRequired: { type: DataTypes.BOOLEAN, allowNull: false, defaultValue: true },
  notes: { type: DataTypes.STRING(500) },
  isActive: { type: DataTypes.BOOLEAN, allowNull: false, defaultValue: true },
  createdByUserId: { type: DataTypes.INTEGER }
}, {
  tableName: 'audit_event_registry',
  indexes: [{ unique: true, name: 'uq_registry_source_event', fields: ['sourceSystemId', 'eventTypeId'] }]
});
