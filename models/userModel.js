import { DataTypes } from 'sequelize';
import { sequelize } from '../config/database.js';

// Internal MediSentinel accounts only. Users of external systems exist solely as
// identity snapshots inside audit_logs (actorUserId / actorUsername / actorRole).
export const User = sequelize.define('User', {
  id: { type: DataTypes.INTEGER, autoIncrement: true, primaryKey: true },
  fullName: { type: DataTypes.STRING(150), allowNull: false },
  username: { type: DataTypes.STRING(60), allowNull: false, unique: true },
  email: { type: DataTypes.STRING(190), allowNull: false, unique: true, validate: { isEmail: true } },
  passwordHash: { type: DataTypes.STRING(100), allowNull: false },
  roleId: { type: DataTypes.INTEGER, allowNull: false },
  isActive: { type: DataTypes.BOOLEAN, allowNull: false, defaultValue: true },
  failedLoginAttempts: { type: DataTypes.INTEGER, allowNull: false, defaultValue: 0 },
  lockedUntil: { type: DataTypes.DATE },
  lastLoginAt: { type: DataTypes.DATE },
  passwordChangedAt: { type: DataTypes.DATE }
}, {
  tableName: 'users',
  defaultScope: { attributes: { exclude: ['passwordHash'] } },
  scopes: { withPassword: { attributes: { include: ['passwordHash'] } } }
});

export { sequelize };
