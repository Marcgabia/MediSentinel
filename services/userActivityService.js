import { Op } from 'sequelize';
import { sequelize, AuditLog, Alert, AuditEventType, SourceSystem } from '../models/index.js';
import { localDateSql, ymd } from '../utils/sqlDates.js';

/**
 * Monitoring of users from integrated systems. Identities are always qualified by source
 * system, because the same username may belong to different people in different applications.
 * The user key is the reported user ID when present, otherwise the username.
 */

const q = (sql, replacements) => sequelize.query(sql, { replacements, type: sequelize.QueryTypes.SELECT });
const ACTOR_KEY = 'COALESCE(actorUserId, actorUsername)';

export const actorWhere = (sourceSystemId, userKey) => ({
  sourceSystemId: Number(sourceSystemId),
  [Op.or]: [{ actorUserId: userKey }, { actorUserId: null, actorUsername: userKey }]
});

export const listActors = async (filters, { limit, offset }) => {
  const conds = [`${ACTOR_KEY} IS NOT NULL`];
  const params = [];
  if (filters.sourceSystemId) { conds.push('sourceSystemId = ?'); params.push(Number(filters.sourceSystemId)); }
  if (filters.search) { conds.push('(actorUsername LIKE ? OR actorUserId LIKE ?)'); params.push(`%${filters.search}%`, `%${filters.search}%`); }
  if (filters.role) { conds.push('actorRole = ?'); params.push(filters.role); }
  if (filters.from) { conds.push('occurredAt >= ?'); params.push(new Date(`${filters.from}T00:00:00`)); }
  if (filters.to) { conds.push('occurredAt <= ?'); params.push(new Date(`${filters.to}T23:59:59.999`)); }
  if (filters.includeInternal !== 'true') conds.push("sourceSystemCode <> 'MEDISENTINEL'");
  const where = conds.join(' AND ');
  const sortMap = { activity: 'lastActivity DESC', total: 'total DESC', failed: 'failed DESC', username: 'username ASC' };
  const order = sortMap[filters.sort] || sortMap.activity;
  const [rows, countRow] = await Promise.all([
    q(`SELECT sourceSystemId, MAX(sourceSystemName) AS sourceSystemName, ${ACTOR_KEY} AS userKey,
              MAX(actorUserId) AS userId, MAX(actorUsername) AS username, MAX(actorRole) AS role,
              COUNT(*) AS total, SUM(outcome = 'SUCCESS') AS success, SUM(outcome <> 'SUCCESS') AS failed,
              SUM(actionType = 'LOGIN_FAILED') AS failedLogins, SUM(outcome = 'DENIED' OR actionType = 'ACCESS_DENIED') AS denied,
              MAX(occurredAt) AS lastActivity
         FROM audit_logs WHERE ${where}
        GROUP BY sourceSystemId, ${ACTOR_KEY} ORDER BY ${order} LIMIT ? OFFSET ?`, [...params, limit, offset]),
    q(`SELECT COUNT(*) AS n FROM (SELECT 1 FROM audit_logs WHERE ${where} GROUP BY sourceSystemId, ${ACTOR_KEY}) t`, params)
  ]);
  return {
    rows: rows.map((r) => ({ ...r, total: Number(r.total), success: Number(r.success), failed: Number(r.failed), failedLogins: Number(r.failedLogins), denied: Number(r.denied) })),
    count: Number(countRow[0]?.n || 0)
  };
};

export const monitoringOverview = async () => {
  const since7 = new Date(Date.now() - 7 * 86400000);
  const since24 = new Date(Date.now() - 86400000);
  const sensitive = (await AuditEventType.findAll({ where: { isSensitive: true }, attributes: ['code'], raw: true })).map((t) => t.code);
  const [failedLogins, denied, roleChanges, repeatedSensitive] = await Promise.all([
    q(`SELECT sourceSystemId, MAX(sourceSystemName) AS sourceSystemName, ${ACTOR_KEY} AS userKey, MAX(actorUsername) AS username,
              COUNT(*) AS n, MAX(occurredAt) AS last
         FROM audit_logs WHERE actionType = 'LOGIN_FAILED' AND occurredAt >= ?
        GROUP BY sourceSystemId, ${ACTOR_KEY} ORDER BY n DESC LIMIT 8`, [since7]),
    AuditLog.findAll({
      where: { occurredAt: { [Op.gte]: since7 }, [Op.or]: [{ actionType: 'ACCESS_DENIED' }, { outcome: 'DENIED' }] },
      attributes: ['id', 'sourceSystemId', 'sourceSystemName', 'actorUsername', 'actorUserId', 'actionType', 'entityType', 'entityId', 'description', 'occurredAt'],
      order: [['occurredAt', 'DESC']], limit: 8, raw: true
    }),
    AuditLog.findAll({
      where: { actionType: { [Op.in]: ['ROLE_CHANGED', 'PERMISSION_CHANGED'] } },
      attributes: ['id', 'sourceSystemId', 'sourceSystemName', 'actorUsername', 'actorUserId', 'actionType', 'entityType', 'entityId', 'description', 'occurredAt'],
      order: [['occurredAt', 'DESC']], limit: 8, raw: true
    }),
    sensitive.length ? q(`SELECT sourceSystemId, MAX(sourceSystemName) AS sourceSystemName, ${ACTOR_KEY} AS userKey, MAX(actorUsername) AS username,
              COUNT(*) AS n, GROUP_CONCAT(DISTINCT actionType ORDER BY actionType SEPARATOR ', ') AS actions
         FROM audit_logs WHERE actionType IN (?) AND occurredAt >= ? AND sourceSystemCode <> 'MEDISENTINEL'
        GROUP BY sourceSystemId, ${ACTOR_KEY} HAVING COUNT(*) >= 3 ORDER BY n DESC LIMIT 8`, [sensitive, since24]) : []
  ]);
  const link = (r) => `/user-activity/profile?sourceSystemId=${r.sourceSystemId}&user=${encodeURIComponent(r.userKey || r.actorUserId || r.actorUsername || '')}`;
  return {
    failedLogins: failedLogins.map((r) => ({ ...r, n: Number(r.n), link: link(r) })),
    denied: denied.map((r) => ({ ...r, link: link(r) })),
    roleChanges: roleChanges.map((r) => ({ ...r, link: link(r) })),
    repeatedSensitive: repeatedSensitive.map((r) => ({ ...r, n: Number(r.n), link: link(r) }))
  };
};

export const userProfile = async (sourceSystemId, userKey) => {
  const source = await SourceSystem.findByPk(sourceSystemId, { raw: true });
  if (!source || !userKey) return null;
  const where = actorWhere(sourceSystemId, userKey);
  const total = await AuditLog.count({ where });
  if (!total) return null;

  const loginActions = ['LOGIN_SUCCESS', 'LOGIN_FAILED', 'LOGOUT', 'PASSWORD_CHANGED'];
  const [outcomes, identity, roles, recentLogins, recentActions, actionBreakdown, daily] = await Promise.all([
    AuditLog.findAll({ where, attributes: ['outcome', [sequelize.fn('COUNT', sequelize.col('id')), 'n']], group: ['outcome'], raw: true }),
    AuditLog.findOne({ where, attributes: ['actorUserId', 'actorUsername', 'actorRole', 'occurredAt'], order: [['occurredAt', 'DESC']], raw: true }),
    AuditLog.findAll({ where: { ...where, actorRole: { [Op.ne]: null } }, attributes: ['actorRole', [sequelize.fn('MIN', sequelize.col('occurredAt')), 'firstSeen'], [sequelize.fn('MAX', sequelize.col('occurredAt')), 'lastSeen'], [sequelize.fn('COUNT', sequelize.col('id')), 'n']], group: ['actorRole'], order: [[sequelize.literal('lastSeen'), 'DESC']], raw: true }),
    AuditLog.findAll({ where: { ...where, actionType: { [Op.in]: loginActions } }, attributes: ['id', 'actionType', 'outcome', 'occurredAt', 'ipAddress', 'userAgent', 'description'], order: [['occurredAt', 'DESC']], limit: 15, raw: true }),
    AuditLog.findAll({ where: { ...where, actionType: { [Op.notIn]: loginActions } }, attributes: ['id', 'actionType', 'sourceModule', 'entityType', 'entityId', 'outcome', 'severity', 'occurredAt', 'description'], order: [['occurredAt', 'DESC']], limit: 25, raw: true }),
    AuditLog.findAll({ where, attributes: ['actionType', [sequelize.fn('COUNT', sequelize.col('id')), 'n']], group: ['actionType'], order: [[sequelize.literal('n'), 'DESC']], limit: 12, raw: true }),
    q(`SELECT ${localDateSql('occurredAt')} AS k, COUNT(*) AS n FROM audit_logs
        WHERE sourceSystemId = ? AND (actorUserId = ? OR (actorUserId IS NULL AND actorUsername = ?)) AND occurredAt >= ? GROUP BY k`,
    [Number(sourceSystemId), userKey, userKey, new Date(Date.now() - 30 * 86400000)])
  ]);
  const outcomeMap = Object.fromEntries(outcomes.map((o) => [o.outcome, Number(o.n)]));
  const username = identity.actorUsername;

  const alertWhere = { sourceSystemId: Number(sourceSystemId), [Op.or]: [{ actorUserId: userKey }, ...(username ? [{ actorUsername: username }] : [])] };
  const [alerts, otherSystems] = await Promise.all([
    Alert.findAll({ where: alertWhere, order: [['lastDetectedAt', 'DESC']], limit: 15, raw: true }),
    username ? q(`SELECT sourceSystemId, MAX(sourceSystemName) AS sourceSystemName, ${ACTOR_KEY} AS userKey, MAX(actorRole) AS role,
                         COUNT(*) AS total, SUM(outcome <> 'SUCCESS') AS failed, MAX(occurredAt) AS lastActivity
                    FROM audit_logs WHERE actorUsername = ? AND sourceSystemId <> ?
                   GROUP BY sourceSystemId, ${ACTOR_KEY}`, [username, Number(sourceSystemId)]) : []
  ]);

  const dailyMap = Object.fromEntries(daily.map((r) => [String(r.k).slice(0, 10), Number(r.n)]));
  const labels = [];
  const values = [];
  for (let i = 29; i >= 0; i -= 1) {
    const d = new Date(); d.setHours(0, 0, 0, 0); d.setDate(d.getDate() - i);
    labels.push(ymd(d).slice(5)); values.push(dailyMap[ymd(d)] || 0);
  }

  return {
    source,
    userKey,
    identity,
    stats: { total, success: outcomeMap.SUCCESS || 0, failed: outcomeMap.FAILURE || 0, denied: outcomeMap.DENIED || 0, failedLogins: recentLogins.filter((l) => l.actionType === 'LOGIN_FAILED').length },
    roles: roles.map((r) => ({ ...r, n: Number(r.n) })),
    recentLogins,
    recentActions,
    actionBreakdown: actionBreakdown.map((a) => ({ ...a, n: Number(a.n) })),
    alerts: alerts.map((a) => ({ ...a, alertCode: `ALR-${String(a.id).padStart(6, '0')}` })),
    otherSystems: otherSystems.map((o) => ({ ...o, total: Number(o.total), failed: Number(o.failed), link: `/user-activity/profile?sourceSystemId=${o.sourceSystemId}&user=${encodeURIComponent(o.userKey)}` })),
    chart: { labels, values }
  };
};
