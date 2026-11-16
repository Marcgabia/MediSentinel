import { DataTypes } from 'sequelize';
import { sequelize } from '../config/database.js';

// Explicit, administrator-verified link between a user account on one source system and a
// person. Identical usernames on different systems are NEVER assumed to be the same person;
// only a mapping like this (or a shared identifier sent by the source as actor.sharedUserId)
// connects activity across systems.
export const IdentityMapping = sequelize.define('IdentityMapping', {
  id: { type: DataTypes.INTEGER, autoIncrement: true, primaryKey: true },
  personKey: { type: DataTypes.STRING(64), allowNull: false },
  displayName: { type: DataTypes.STRING(150) },
  sourceSystemId: { type: DataTypes.INTEGER, allowNull: false },
  actorUserId: { type: DataTypes.STRING(128), allowNull: false },
  verificationNote: { type: DataTypes.STRING(500), allowNull: false },
  isActive: { type: DataTypes.BOOLEAN, allowNull: false, defaultValue: true },
  createdByUserId: { type: DataTypes.INTEGER },
  deactivatedByUserId: { type: DataTypes.INTEGER },
  deactivatedAt: { type: DataTypes.DATE }
}, {
  tableName: 'identity_mappings',
  indexes: [
    { name: 'ix_identity_person', fields: ['personKey'] },
    { name: 'ix_identity_source_user', fields: ['sourceSystemId', 'actorUserId', 'isActive'] }
  ]
});
