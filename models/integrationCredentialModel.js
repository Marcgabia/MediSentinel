import { DataTypes } from 'sequelize';
import { sequelize } from '../config/database.js';

// Secrets are AES-256-GCM encrypted with CREDENTIAL_ENCRYPTION_KEY (env) and never rendered.
export const IntegrationCredential = sequelize.define('IntegrationCredential', {
  id: { type: DataTypes.INTEGER, autoIncrement: true, primaryKey: true },
  sourceSystemId: { type: DataTypes.INTEGER, allowNull: false },
  keyId: { type: DataTypes.STRING(64), allowNull: false, unique: true },
  secretCiphertext: { type: DataTypes.TEXT, allowNull: false },
  secretFingerprint: { type: DataTypes.STRING(64), allowNull: false },
  label: { type: DataTypes.STRING(120) },
  status: { type: DataTypes.ENUM('ACTIVE', 'REVOKED'), allowNull: false, defaultValue: 'ACTIVE' },
  createdByUserId: { type: DataTypes.INTEGER },
  lastUsedAt: { type: DataTypes.DATE },
  expiresAt: { type: DataTypes.DATE },
  revokedAt: { type: DataTypes.DATE },
  revokedByUserId: { type: DataTypes.INTEGER }
}, {
  tableName: 'integration_credentials',
  defaultScope: { attributes: { exclude: ['secretCiphertext'] } },
  scopes: { withSecret: { attributes: { include: ['secretCiphertext'] } } }
});
