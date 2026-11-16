import { Op } from 'sequelize';
import { sequelize, AuditLog, Alert } from '../models/index.js';
import { listSourcesWithHealth } from './integrationService.js';
import { alertCounts } from './alertService.js';
import { caseCounts } from './investigationService.js';
import { latestQaStatus } from './qaVerificationService.js';
import { localOffset, localDateSql, ymd } from '../utils/sqlDates.js';
import { actionLabel } from '../utils/viewHelpers.js';

const startOfToday = () => { const d = new Date(); d.setHours(0, 0, 0, 0); return d; };
const daysAgo = (n) => { const d = startOfToday(); d.setDate(d.getDate() - n); return d; };

/** Summary cards — every figure is a live database count. */
export const dashboardSummary = async () => {
  const since24h = new Date(Date.now() - 86400000);
  const [totalEvents, todayEvents, failedToday, activeUsersRow, sources, alerts, cases, qa] = await Promise.all([
    AuditLog.count(),
    AuditLog.count({ where: { occurredAt: { [Op.gte]: startOfToday() } } }),
    AuditLog.count({ where: { occurredAt: { [Op.gte]: startOfToday() }, outcome: { [Op.in]: ['FAILURE', 'DENIED'] } } }),
    sequelize.query(
      "SELECT COUNT(DISTINCT sourceSystemId, COALESCE(actorUserId, actorUsername)) AS n FROM audit_logs WHERE occurredAt >= ? AND (actorUserId IS NOT NULL OR actorUsername IS NOT NULL) AND sourceSystemCode <> 'MEDISENTINEL'",
      { replacements: [since24h], type: sequelize.QueryTypes.SELECT }
    ),
    listSourcesWithHealth({ includeInternal: false }),
    alertCounts(),
    caseCounts(),
    latestQaStatus()
  ]);
  return {
    totalEvents,
    todayEvents,
    failedToday,
    activeUsers: Number(activeUsersRow[0]?.n || 0),
    connectedSystems: sources.filter((s) => s.connected).length,
    registeredSystems: sources.length,
    neverConnected: sources.filter((s) => s.health.status === 'NEVER_CONNECTED').length,
    activeAlerts: alerts.active,
    criticalAlerts: alerts.activeCritical + alerts.activeHigh,
    pendingInvestigations: cases.pending,
    qa
  };
};

const fillDays = (rows, days) => {
  const map = Object.fromEntries(rows.map((r) => [String(r.k).slice(0, 10), Number(r.n)]));
  const labels = [];
  const values = [];
  for (let i = days - 1; i >= 0; i -= 1) {
    const key = ymd(daysAgo(i));
    labels.push(key.slice(5));
    values.push(map[key] || 0);
  }
  return { labels, values };
};

export const dashboardCharts = async () => {
  const tz = localOffset();
  const local = (col) => `CONVERT_TZ(${col}, '+00:00', '${tz}')`;
  const q = (sql, replacements) => sequelize.query(sql, { replacements, type: sequelize.QueryTypes.SELECT });
  const since30 = daysAgo(29);

  const [daily, weekly, monthly, bySource, byAction, byUser, outcomes, alertsDaily] = await Promise.all([
    q(`SELECT ${localDateSql('occurredAt')} AS k, COUNT(*) AS n FROM audit_logs WHERE occurredAt >= ? GROUP BY k`, [daysAgo(13)]),
    q(`SELECT DATE_FORMAT(${local('occurredAt')}, '%x-W%v') AS k, COUNT(*) AS n FROM audit_logs WHERE occurredAt >= ? GROUP BY k ORDER BY k`, [daysAgo(7 * 12)]),
    q(`SELECT DATE_FORMAT(${local('occurredAt')}, '%Y-%m') AS k, COUNT(*) AS n FROM audit_logs WHERE occurredAt >= ? GROUP BY k ORDER BY k`, [new Date(new Date().getFullYear(), new Date().getMonth() - 11, 1)]),
    q('SELECT s.name AS k, COUNT(*) AS n FROM audit_logs a JOIN source_systems s ON s.id = a.sourceSystemId WHERE a.occurredAt >= ? GROUP BY s.id, s.name ORDER BY n DESC LIMIT 10', [since30]),
    q('SELECT actionType AS k, COUNT(*) AS n FROM audit_logs WHERE occurredAt >= ? GROUP BY k ORDER BY n DESC LIMIT 10', [since30]),
    q("SELECT CONCAT(COALESCE(a.actorUsername, a.actorUserId, 'unknown'), ' · ', s.name) AS k, COUNT(*) AS n FROM audit_logs a JOIN source_systems s ON s.id = a.sourceSystemId WHERE a.occurredAt >= ? AND s.isInternal = 0 GROUP BY k ORDER BY n DESC LIMIT 8", [since30]),
    q('SELECT outcome AS k, COUNT(*) AS n FROM audit_logs WHERE occurredAt >= ? GROUP BY k', [since30]),
    q(`SELECT ${localDateSql('firstDetectedAt')} AS k, COUNT(*) AS n FROM audit_alerts WHERE firstDetectedAt >= ? GROUP BY k`, [since30])
  ]);

  const pairs = (rows) => ({ labels: rows.map((r) => r.k), values: rows.map((r) => Number(r.n)) });
  const outcomeMap = Object.fromEntries(outcomes.map((r) => [r.k, Number(r.n)]));
  return {
    daily: fillDays(daily, 14),
    weekly: pairs(weekly),
    monthly: pairs(monthly),
    bySource: pairs(bySource),
    byAction: { labels: byAction.map((r) => actionLabel(r.k)), values: byAction.map((r) => Number(r.n)) },
    byUser: pairs(byUser),
    outcomes: { labels: ['Successful', 'Failed', 'Denied'], values: [outcomeMap.SUCCESS || 0, outcomeMap.FAILURE || 0, outcomeMap.DENIED || 0] },
    suspicious: fillDays(alertsDaily, 30)
  };
};

// External activity only; MediSentinel's own governance events remain in the Audit Trail.
export const recentActivities = (limit = 10) => AuditLog.findAll({
  where: { sourceSystemCode: { [Op.ne]: 'MEDISENTINEL' } },
  attributes: ['id', 'eventId', 'sourceSystemName', 'sourceSystemCode', 'actorUsername', 'actorUserId', 'actionType', 'entityType', 'entityId', 'outcome', 'severity', 'occurredAt', 'description'],
  order: [['occurredAt', 'DESC'], ['id', 'DESC']], limit, raw: true
});

export const recentAlerts = (limit = 5) => Alert.findAll({
  where: { status: { [Op.in]: ['OPEN', 'ACKNOWLEDGED', 'INVESTIGATING'] } },
  order: [['lastDetectedAt', 'DESC']], limit, raw: true
}).then((rows) => rows.map((a) => ({ ...a, alertCode: `ALR-${String(a.id).padStart(6, '0')}` })));
