import { DataTypes } from 'sequelize';
import { sequelize } from '../config/database.js';

export const Notification = sequelize.define('Notification', {
  id: { type: DataTypes.INTEGER, autoIncrement: true, primaryKey: true },
  userId: { type: DataTypes.INTEGER, allowNull: false },
  type: { type: DataTypes.STRING(48), allowNull: false },
  severity: { type: DataTypes.ENUM('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'), allowNull: false, defaultValue: 'INFO' },
  title: { type: DataTypes.STRING(200), allowNull: false },
  message: { type: DataTypes.STRING(1000), allowNull: false },
  link: { type: DataTypes.STRING(300) },
  relatedAuditLogId: { type: DataTypes.BIGINT },
  relatedAlertId: { type: DataTypes.INTEGER },
  relatedCaseId: { type: DataTypes.INTEGER },
  relatedFindingId: { type: DataTypes.INTEGER },
  isRead: { type: DataTypes.BOOLEAN, allowNull: false, defaultValue: false },
  readAt: { type: DataTypes.DATE }
}, {
  tableName: 'notifications',
  updatedAt: false,
  indexes: [{ name: 'ix_notif_user', fields: ['userId', 'isRead', 'createdAt'] }]
});
