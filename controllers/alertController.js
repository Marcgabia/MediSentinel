import { sequelize, SourceSystem, User, Role } from '../models/index.js';
import {
  listAlerts, getAlert, applyAlertAction, notifyAlertAssignee, listRules, updateRule, formatAlertId, alertCounts
} from '../services/alertService.js';
import { recordInternalEvent } from '../services/auditService.js';
import { parsePagination, buildPagination } from '../utils/pagination.js';
import { hasPermission } from '../middleware/permissions.js';
import { ALERT_STATUSES, ALERT_SEVERITIES, DEFAULT_ALERT_RULES } from '../utils/auditConstants.js';

const alertManagers = async () => {
  const roleIds = (await Role.findAll({ raw: true })).filter((r) => (r.permissions || []).includes('alerts.manage')).map((r) => r.id);
  return User.findAll({ where: { roleId: roleIds, isActive: true }, attributes: ['id', 'fullName', 'username'], order: [['fullName', 'ASC']], raw: true });
};

export const alertsIndex = async (req, res) => {
  const filters = Object.fromEntries(['status', 'severity', 'sourceSystemId', 'alertType', 'search'].filter((k) => req.query[k]).map((k) => [k, String(req.query[k])]));
  if (!req.query.status && !Object.keys(req.query).length) filters.status = 'active';
  const { page, limit, offset } = parsePagination(req.query, { defaultLimit: 25 });
  const [{ rows, count }, sources, counts] = await Promise.all([
    listAlerts({ ...filters, page, limit, offset }),
    SourceSystem.findAll({ attributes: ['id', 'name'], order: [['name', 'ASC']], raw: true }),
    alertCounts()
  ]);
  res.render('alerts/index', {
    title: 'Suspicious Activities', alerts: rows, filters, sources, counts,
    statuses: ALERT_STATUSES, severities: ALERT_SEVERITIES, ruleTypes: DEFAULT_ALERT_RULES.map((r) => ({ code: r.code, name: r.name })),
    canConfigure: hasPermission(req.user, 'alertRules.manage'),
    pagination: buildPagination({ page, limit, total: count, query: filters, basePath: '/alerts' })
  });
};

export const alertDetail = async (req, res) => {
  const alert = await getAlert(req.params.id);
  if (!alert) return res.status(404).render('errors/404', { title: 'Not Found', message: 'Alert not found.' });
  const canManage = hasPermission(req.user, 'alerts.manage');
  return res.render('alerts/detail', {
    title: `Alert ${alert.alertCode}`, alert, canManage,
    canInvestigate: hasPermission(req.user, 'investigations.manage'),
    managers: canManage ? await alertManagers() : [],
    isActive: ['OPEN', 'ACKNOWLEDGED', 'INVESTIGATING'].includes(alert.status)
  });
};

export const alertAction = async (req, res) => {
  const action = String(req.body.action || '');
  const { alert, after, assigneeId } = await sequelize.transaction(async (transaction) => {
    const result = await applyAlertAction(req.params.id, action, { userId: req.user.id, note: req.body.note, assigneeId: req.body.assigneeId }, transaction);
    await recordInternalEvent({
      user: req.user, req, action: 'ALERT_UPDATED', module: 'Suspicious Activities', entity: { type: 'Alert', id: formatAlertId(result.alert.id) },
      description: `${action === 'note' ? 'Added note to' : `${action[0].toUpperCase()}${action.slice(1)}`} alert ${formatAlertId(result.alert.id)}${req.body.note ? `: ${String(req.body.note).slice(0, 300)}` : ''}`,
      before: result.before, after: result.after, transaction
    });
    return result;
  });
  if (assigneeId && assigneeId !== req.user.id) await notifyAlertAssignee(alert, assigneeId);
  req.flash('success_msg', `Alert updated.`);
  res.redirect(`/alerts/${alert.id}`);
};

export const rulesPage = async (req, res) => {
  const rules = await listRules();
  res.render('alerts/rules', { title: 'Alert Detection Rules', rules, severities: ALERT_SEVERITIES });
};

export const saveRule = async (req, res) => {
  const { rule } = await sequelize.transaction(async (transaction) => {
    const result = await updateRule(req.params.id, req.body, req.user.id, transaction);
    await recordInternalEvent({
      user: req.user, req, action: 'ALERT_RULE_CHANGED', module: 'Suspicious Activities', entity: { type: 'AlertRule', id: result.rule.code },
      description: `Updated alert rule ${result.rule.code}`, before: result.before, after: result.after, transaction
    });
    return result;
  });
  req.flash('success_msg', `Rule "${rule.name}" saved.`);
  res.redirect('/alerts/rules');
};
