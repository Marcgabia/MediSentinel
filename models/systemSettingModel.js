import { DataTypes } from 'sequelize';
import { sequelize } from '../config/database.js';

export const SystemSetting = sequelize.define('SystemSetting', {
  key: { type: DataTypes.STRING(100), primaryKey: true },
  value: { type: DataTypes.JSON },
  valueType: { type: DataTypes.ENUM('number', 'string', 'boolean', 'json'), allowNull: false, defaultValue: 'string' },
  category: { type: DataTypes.STRING(60), allowNull: false, defaultValue: 'General' },
  label: { type: DataTypes.STRING(200) },
  isInternal: { type: DataTypes.BOOLEAN, allowNull: false, defaultValue: false },
  updatedByUserId: { type: DataTypes.INTEGER }
}, { tableName: 'system_settings' });
