import { DataTypes } from 'sequelize';
import { sequelize } from '../config/database.js';
import { SOURCE_SYSTEM_STATUSES, SOURCE_ENVIRONMENTS } from '../utils/auditConstants.js';

export const SourceSystem = sequelize.define('SourceSystem', {
  id: { type: DataTypes.INTEGER, autoIncrement: true, primaryKey: true },
  systemCode: { type: DataTypes.STRING(64), allowNull: false, unique: true },
  name: { type: DataTypes.STRING(150), allowNull: false },
  description: { type: DataTypes.TEXT },
  apiEndpoint: { type: DataTypes.STRING(500), comment: 'Base URL of the source system (informational)' },
  healthCheckUrl: { type: DataTypes.STRING(500), comment: 'URL probed by the connection test' },
  environment: { type: DataTypes.ENUM(...SOURCE_ENVIRONMENTS), allowNull: false, defaultValue: 'PRODUCTION' },
  status: { type: DataTypes.ENUM(...SOURCE_SYSTEM_STATUSES), allowNull: false, defaultValue: 'PENDING' },
  isInternal: { type: DataTypes.BOOLEAN, allowNull: false, defaultValue: false },
  registeredAt: { type: DataTypes.DATE, allowNull: false, defaultValue: DataTypes.NOW },
  registeredByUserId: { type: DataTypes.INTEGER },
  lastSuccessfulConnectionAt: { type: DataTypes.DATE },
  lastEventReceivedAt: { type: DataTypes.DATE },
  lastHeartbeatAt: { type: DataTypes.DATE },
  lastHeartbeatPayload: { type: DataTypes.JSON },
  lastConnectionTestAt: { type: DataTypes.DATE },
  lastConnectionTestResult: { type: DataTypes.JSON }
}, { tableName: 'source_systems' });
