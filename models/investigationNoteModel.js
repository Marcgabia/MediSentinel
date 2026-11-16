import { DataTypes } from 'sequelize';
import { sequelize } from '../config/database.js';
import { CASE_NOTE_TYPES } from '../utils/auditConstants.js';

export const InvestigationNote = sequelize.define('InvestigationNote', {
  id: { type: DataTypes.INTEGER, autoIncrement: true, primaryKey: true },
  caseId: { type: DataTypes.INTEGER, allowNull: false },
  authorUserId: { type: DataTypes.INTEGER },
  noteType: { type: DataTypes.ENUM(...CASE_NOTE_TYPES), allowNull: false, defaultValue: 'NOTE' },
  content: { type: DataTypes.TEXT, allowNull: false },
  metadata: { type: DataTypes.JSON }
}, {
  tableName: 'investigation_notes',
  updatedAt: false,
  indexes: [{ name: 'ix_note_case', fields: ['caseId', 'createdAt'] }]
});
