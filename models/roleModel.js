import { DataTypes } from 'sequelize';
import { sequelize } from '../config/database.js';

export const Role = sequelize.define('Role', {
  id: { type: DataTypes.INTEGER, autoIncrement: true, primaryKey: true },
  code: { type: DataTypes.STRING(40), allowNull: false, unique: true },
  name: { type: DataTypes.STRING(100), allowNull: false },
  description: { type: DataTypes.STRING(500) },
  permissions: { type: DataTypes.JSON, allowNull: false, defaultValue: [] },
  canAccessDashboard: { type: DataTypes.BOOLEAN, allowNull: false, defaultValue: true },
  isSystem: { type: DataTypes.BOOLEAN, allowNull: false, defaultValue: true }
}, { tableName: 'roles' });
