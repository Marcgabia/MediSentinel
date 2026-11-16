import { DataTypes } from 'sequelize';
import { sequelize } from '../config/database.js';

export const Session = sequelize.define('Session', {
  sid: { type: DataTypes.STRING(128), primaryKey: true },
  expiresAt: { type: DataTypes.DATE, allowNull: false },
  data: { type: DataTypes.TEXT('medium'), allowNull: false }
}, {
  tableName: 'sessions',
  timestamps: false,
  indexes: [{ name: 'ix_session_expires', fields: ['expiresAt'] }]
});
