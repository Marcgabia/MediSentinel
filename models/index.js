import { sequelize } from '../config/database.js';
import { Role } from './roleModel.js';
import { User } from './userModel.js';
import { SourceSystem } from './sourceSystemModel.js';
import { IntegrationCredential } from './integrationCredentialModel.js';
import { AuditLog } from './auditLogModel.js';
import { AuditEventType } from './auditEventTypeModel.js';
import { AuditEventRegistry } from './auditEventRegistryModel.js';
import { IntegrationLog } from './integrationLogModel.js';
import { AlertRule } from './alertRuleModel.js';
import { Alert, AlertActivity } from './alertModel.js';
import { InvestigationCase, InvestigationCaseEvent } from './investigationCaseModel.js';
import { InvestigationNote } from './investigationNoteModel.js';
import { QaRun } from './qaRunModel.js';
import { QaResult } from './qaResultModel.js';
import { QaFinding } from './qaFindingModel.js';
import { Notification } from './notificationModel.js';
import { SystemSetting } from './systemSettingModel.js';
import { Session } from './sessionModel.js';
import { IdentityMapping } from './identityMappingModel.js';

// Historical records must never disappear because a related row is removed: every
// relationship uses RESTRICT (or SET NULL for optional references), never CASCADE.
const keep = { onDelete: 'RESTRICT', onUpdate: 'RESTRICT' };
const nullable = { onDelete: 'SET NULL', onUpdate: 'RESTRICT' };

Role.hasMany(User, { foreignKey: 'roleId', as: 'users', ...keep });
User.belongsTo(Role, { foreignKey: 'roleId', as: 'role', ...keep });

SourceSystem.belongsTo(User, { foreignKey: 'registeredByUserId', as: 'registeredBy', ...nullable });
SourceSystem.hasMany(IntegrationCredential, { foreignKey: 'sourceSystemId', as: 'credentials', ...keep });
IntegrationCredential.belongsTo(SourceSystem, { foreignKey: 'sourceSystemId', as: 'sourceSystem', ...keep });
IntegrationCredential.belongsTo(User, { foreignKey: 'createdByUserId', as: 'createdBy', ...nullable });
IntegrationCredential.belongsTo(User, { foreignKey: 'revokedByUserId', as: 'revokedBy', ...nullable });

SourceSystem.hasMany(AuditLog, { foreignKey: 'sourceSystemId', as: 'auditLogs', ...keep });
AuditLog.belongsTo(SourceSystem, { foreignKey: 'sourceSystemId', as: 'sourceSystem', ...keep });

SourceSystem.hasMany(AuditEventRegistry, { foreignKey: 'sourceSystemId', as: 'registry', ...keep });
AuditEventRegistry.belongsTo(SourceSystem, { foreignKey: 'sourceSystemId', as: 'sourceSystem', ...keep });
AuditEventRegistry.belongsTo(AuditEventType, { foreignKey: 'eventTypeId', as: 'eventType', ...keep });
AuditEventType.hasMany(AuditEventRegistry, { foreignKey: 'eventTypeId', as: 'registryEntries', ...keep });

IntegrationLog.belongsTo(SourceSystem, { foreignKey: 'sourceSystemId', as: 'sourceSystem', ...nullable });
IntegrationLog.belongsTo(IntegrationCredential, { foreignKey: 'credentialId', as: 'credential', ...nullable });
IntegrationLog.belongsTo(AuditLog, { foreignKey: 'auditLogId', as: 'auditLog', constraints: false });

AlertRule.belongsTo(User, { foreignKey: 'updatedByUserId', as: 'updatedBy', ...nullable });
Alert.belongsTo(AlertRule, { foreignKey: 'ruleId', as: 'rule', ...nullable });
Alert.belongsTo(SourceSystem, { foreignKey: 'sourceSystemId', as: 'sourceSystem', ...keep });
Alert.belongsTo(AuditLog, { foreignKey: 'relatedAuditLogId', as: 'relatedAuditLog', ...keep });
Alert.belongsTo(User, { foreignKey: 'assignedToUserId', as: 'assignedTo', ...nullable });
Alert.belongsTo(User, { foreignKey: 'acknowledgedByUserId', as: 'acknowledgedBy', ...nullable });
Alert.belongsTo(User, { foreignKey: 'resolvedByUserId', as: 'resolvedBy', ...nullable });
Alert.hasMany(AlertActivity, { foreignKey: 'alertId', as: 'activities', ...keep });
AlertActivity.belongsTo(Alert, { foreignKey: 'alertId', as: 'alert', ...keep });
AlertActivity.belongsTo(User, { foreignKey: 'userId', as: 'user', ...nullable });

InvestigationCase.belongsTo(SourceSystem, { foreignKey: 'sourceSystemId', as: 'sourceSystem', ...keep });
InvestigationCase.belongsTo(User, { foreignKey: 'assignedToUserId', as: 'assignedTo', ...nullable });
InvestigationCase.belongsTo(User, { foreignKey: 'createdByUserId', as: 'createdBy', ...keep });
InvestigationCase.belongsTo(Alert, { foreignKey: 'originAlertId', as: 'originAlert', ...nullable });
InvestigationCase.hasMany(InvestigationNote, { foreignKey: 'caseId', as: 'notes', ...keep });
InvestigationNote.belongsTo(InvestigationCase, { foreignKey: 'caseId', as: 'case', ...keep });
InvestigationNote.belongsTo(User, { foreignKey: 'authorUserId', as: 'author', ...nullable });
InvestigationCase.hasMany(InvestigationCaseEvent, { foreignKey: 'caseId', as: 'eventLinks', ...keep });
InvestigationCaseEvent.belongsTo(InvestigationCase, { foreignKey: 'caseId', as: 'case', ...keep });
InvestigationCaseEvent.belongsTo(AuditLog, { foreignKey: 'auditLogId', as: 'auditLog', ...keep });
InvestigationCaseEvent.belongsTo(User, { foreignKey: 'addedByUserId', as: 'addedBy', ...nullable });

QaRun.belongsTo(User, { foreignKey: 'executedByUserId', as: 'executedBy', ...nullable });
QaRun.hasMany(QaResult, { foreignKey: 'runId', as: 'results', ...keep });
QaResult.belongsTo(QaRun, { foreignKey: 'runId', as: 'run', ...keep });
QaResult.belongsTo(SourceSystem, { foreignKey: 'sourceSystemId', as: 'sourceSystem', ...nullable });
QaFinding.belongsTo(QaRun, { foreignKey: 'runId', as: 'run', ...nullable });
QaFinding.belongsTo(SourceSystem, { foreignKey: 'sourceSystemId', as: 'sourceSystem', ...nullable });
QaFinding.belongsTo(AuditLog, { foreignKey: 'relatedAuditLogId', as: 'relatedAuditLog', constraints: false });
QaFinding.belongsTo(User, { foreignKey: 'assignedToUserId', as: 'assignedTo', ...nullable });
QaFinding.belongsTo(User, { foreignKey: 'resolvedByUserId', as: 'resolvedBy', ...nullable });
QaFinding.belongsTo(User, { foreignKey: 'verifiedByUserId', as: 'verifiedBy', ...nullable });

Notification.belongsTo(User, { foreignKey: 'userId', as: 'user', onDelete: 'CASCADE', onUpdate: 'RESTRICT' });
SystemSetting.belongsTo(User, { foreignKey: 'updatedByUserId', as: 'updatedBy', ...nullable });

IdentityMapping.belongsTo(SourceSystem, { foreignKey: 'sourceSystemId', as: 'sourceSystem', ...keep });
IdentityMapping.belongsTo(User, { foreignKey: 'createdByUserId', as: 'createdBy', ...nullable });
IdentityMapping.belongsTo(User, { foreignKey: 'deactivatedByUserId', as: 'deactivatedBy', ...nullable });

export {
  sequelize, Role, User, SourceSystem, IntegrationCredential, AuditLog, AuditEventType, AuditEventRegistry,
  IntegrationLog, AlertRule, Alert, AlertActivity, InvestigationCase, InvestigationCaseEvent, InvestigationNote,
  QaRun, QaResult, QaFinding, Notification, SystemSetting, Session, IdentityMapping
};
