import { DataTypes } from 'sequelize';
import { sequelize } from '../config/database.js';
import { QA_STATUSES, QA_CATEGORIES } from '../utils/auditConstants.js';

export const QaResult = sequelize.define('QaResult', {
  id: { type: DataTypes.INTEGER, autoIncrement: true, primaryKey: true },
  runId: { type: DataTypes.INTEGER, allowNull: false },
  category: { type: DataTypes.ENUM(...QA_CATEGORIES), allowNull: false },
  checkCode: { type: DataTypes.STRING(64), allowNull: false },
  checkName: { type: DataTypes.STRING(200), allowNull: false },
  sourceSystemId: { type: DataTypes.INTEGER },
  status: { type: DataTypes.ENUM(...QA_STATUSES), allowNull: false },
  summary: { type: DataTypes.STRING(1000), allowNull: false },
  itemsChecked: { type: DataTypes.INTEGER, allowNull: false, defaultValue: 0 },
  itemsFailed: { type: DataTypes.INTEGER, allowNull: false, defaultValue: 0 },
  details: { type: DataTypes.JSON }
}, {
  tableName: 'qa_verification_results',
  updatedAt: false,
  indexes: [{ name: 'ix_qaresult_run', fields: ['runId', 'category'] }]
});
