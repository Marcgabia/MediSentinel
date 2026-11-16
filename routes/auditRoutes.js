import express from 'express';
import { requireAuth } from '../middleware/auth.js';
import { requirePermission as can } from '../middleware/permissions.js';
import { noStore } from '../middleware/requestValidation.js';
import { asyncRouter } from '../middleware/errorHandler.js';
import { dashboardPage, dashboardChartData } from '../controllers/dashboardController.js';
import { auditIndex, auditDetail, auditExport } from '../controllers/auditController.js';
import {
  integrationsIndex, integrationsMonitor, integrationLogs, newSourceForm, createSource, sourceDetail, editSourceForm, saveSource,
  createCredential, revokeCredentialAction, runConnectionTest, addRegistry, removeRegistry
} from '../controllers/integrationController.js';
import { activityIndex, activityProfile } from '../controllers/userActivityController.js';
import { alertsIndex, alertDetail, alertAction, rulesPage, saveRule } from '../controllers/alertController.js';
import {
  casesIndex, newCaseForm, createCaseAction, caseDetail, assignAction, statusAction, noteAction, findingsAction, attachAction
} from '../controllers/investigationController.js';
import { reportsIndex, viewReport, exportReport } from '../controllers/reportController.js';
import { qaIndex, runVerification, runsIndex, runDetail, coveragePage, findingsIndex, findingDetail, updateFinding } from '../controllers/qaController.js';
import { notificationsIndex, openNotification, toggleRead, readAll, notificationFeed } from '../controllers/notificationController.js';
import {
  usersIndex, newUserForm, createUserAction, editUserForm, updateUserAction, toggleActiveAction, resetPasswordAction, unlockAction, rolesPage, updateRoleAction
} from '../controllers/userController.js';
import { settingsPage, saveSettings, changeOwnPassword, createEventType, toggleEventType } from '../controllers/settingsController.js';
import {
  transactionsIndex, transactionTimeline, voidsIndex, configurationIndex, crossSystemIndex, identitiesPage, createIdentity, deactivateIdentity, pharmacyDashboard
} from '../controllers/posAuditController.js';
import { applyPosTemplate } from '../controllers/integrationController.js';

// Authenticated dashboard routes. Every route is guarded by an explicit permission.
const router = asyncRouter(express.Router());
router.use(requireAuth, noStore);

// Dashboard
router.get('/dashboard', can('dashboard.view'), dashboardPage);
router.get('/dashboard/charts.json', can('dashboard.view'), dashboardChartData);
router.get('/dashboard/pharmacy', can('dashboard.view'), pharmacyDashboard);

// Audit trail (read-only: there are deliberately no edit / delete routes)
router.get('/audit', can('audit.view'), auditIndex);
router.get('/audit/export', can('audit.export'), auditExport);
// Pharmacy application views (declared before /audit/:id)
router.get('/audit/transactions', can('transactions.view'), transactionsIndex);
router.get('/audit/transactions/:ref', can('transactions.view'), transactionTimeline);
router.get('/audit/voids', can('transactions.view'), voidsIndex);
router.get('/audit/configuration', can('audit.view'), configurationIndex);
router.get('/audit/cross-system', can('audit.view'), crossSystemIndex);
router.get('/audit/identities', can('integrations.manage'), identitiesPage);
router.post('/audit/identities', can('integrations.manage'), createIdentity);
router.post('/audit/identities/:id/deactivate', can('integrations.manage'), deactivateIdentity);
router.get('/audit/:id', can('audit.view'), auditDetail);

// User activity monitoring
router.get('/user-activity', can('activity.view'), activityIndex);
router.get('/user-activity/profile', can('activity.view'), activityProfile);

// Integrations
router.get('/integrations', can('integrations.view'), integrationsIndex);
router.get('/integrations/monitor', can('integrations.view'), integrationsMonitor);
router.get('/integrations/logs', can('integrations.view'), integrationLogs);
router.get('/integrations/new', can('integrations.manage'), newSourceForm);
router.post('/integrations', can('integrations.manage'), createSource);
router.get('/integrations/:id', can('integrations.view'), sourceDetail);
router.get('/integrations/:id/edit', can('integrations.manage'), editSourceForm);
router.post('/integrations/:id', can('integrations.manage'), saveSource);
router.post('/integrations/:id/test', can('integrations.manage'), runConnectionTest);
router.post('/integrations/:id/credentials', can('credentials.manage'), createCredential);
router.post('/integrations/:id/credentials/:credentialId/revoke', can('credentials.manage'), revokeCredentialAction);
router.post('/integrations/:id/registry', can('qa.manage', 'integrations.manage'), addRegistry);
router.post('/integrations/:id/registry/:entryId/delete', can('qa.manage', 'integrations.manage'), removeRegistry);
router.post('/integrations/:id/registry/pos-template', can('qa.manage', 'integrations.manage'), applyPosTemplate);

// Suspicious activity alerts
router.get('/alerts', can('alerts.view'), alertsIndex);
router.get('/alerts/rules', can('alertRules.manage'), rulesPage);
router.post('/alerts/rules/:id', can('alertRules.manage'), saveRule);
router.get('/alerts/:id', can('alerts.view'), alertDetail);
router.post('/alerts/:id/action', can('alerts.manage'), alertAction);

// Investigations
router.get('/investigations', can('investigations.view'), casesIndex);
router.get('/investigations/new', can('investigations.manage'), newCaseForm);
router.post('/investigations', can('investigations.manage'), createCaseAction);
router.get('/investigations/:id', can('investigations.view'), caseDetail);
router.post('/investigations/:id/assign', can('investigations.manage'), assignAction);
router.post('/investigations/:id/status', can('investigations.manage'), statusAction);
router.post('/investigations/:id/notes', can('investigations.manage'), noteAction);
router.post('/investigations/:id/findings', can('investigations.manage'), findingsAction);
router.post('/investigations/:id/events', can('investigations.manage'), attachAction);

// Reports
router.get('/reports', can('reports.view'), reportsIndex);
router.get('/reports/:code', can('reports.view'), viewReport);
router.get('/reports/:code/export', can('reports.export'), exportReport);

// Quality assurance
router.get('/qa', can('qa.view'), qaIndex);
router.post('/qa/run', can('qa.run'), runVerification);
router.get('/qa/runs', can('qa.view'), runsIndex);
router.get('/qa/runs/:id', can('qa.view'), runDetail);
router.get('/qa/coverage', can('qa.view'), coveragePage);
router.get('/qa/findings', can('qa.view'), findingsIndex);
router.get('/qa/findings/:id', can('qa.view'), findingDetail);
router.post('/qa/findings/:id', can('qa.manage'), updateFinding);

// Notifications
router.get('/notifications', can('notifications.view'), notificationsIndex);
router.get('/notifications/feed.json', can('notifications.view'), notificationFeed);
router.post('/notifications/read-all', can('notifications.view'), readAll);
router.get('/notifications/:id/open', can('notifications.view'), openNotification);
router.post('/notifications/:id/read', can('notifications.view'), toggleRead);

// Internal user & permission management
router.get('/users', can('users.manage'), usersIndex);
router.get('/users/new', can('users.manage'), newUserForm);
router.get('/users/roles', can('users.manage'), rolesPage);
router.post('/users/roles/:id', can('users.manage'), updateRoleAction);
router.post('/users', can('users.manage'), createUserAction);
router.get('/users/:id/edit', can('users.manage'), editUserForm);
router.post('/users/:id', can('users.manage'), updateUserAction);
router.post('/users/:id/active', can('users.manage'), toggleActiveAction);
router.post('/users/:id/password', can('users.manage'), resetPasswordAction);
router.post('/users/:id/unlock', can('users.manage'), unlockAction);

// Settings (password change is available to every signed-in user)
router.get('/settings', settingsPage);
router.post('/settings/password', changeOwnPassword);
router.post('/settings/system', can('settings.manage'), saveSettings);
router.post('/settings/event-types', can('settings.manage'), createEventType);
router.post('/settings/event-types/:id/toggle', can('settings.manage'), toggleEventType);

export default router;
