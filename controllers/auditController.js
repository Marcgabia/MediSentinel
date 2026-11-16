import { AuditLog } from '../models/index.js';
import { searchAuditLogs, getFilterOptions, getAuditDetail, buildAuditWhere, recordInternalEvent } from '../services/auditService.js';
import { parsePagination, buildPagination } from '../utils/pagination.js';
import { toCsv } from '../utils/csv.js';
import { getSetting } from '../services/settingsService.js';
import { hasPermission } from '../middleware/permissions.js';

const FILTER_KEYS = ['q', 'username', 'eventId', 'entityId', 'description', 'sourceSystemId', 'sourceModule', 'actionType', 'actorRole', 'category', 'severity', 'outcome', 'from', 'to', 'sort', 'correlationId', 'actorUserId', 'branchId', 'hideRoutine'];

const pickFilters = (query) => Object.fromEntries(FILTER_KEYS.filter((k) => query[k]).map((k) => [k, String(query[k])]));

export const auditIndex = async (req, res) => {
  const filters = pickFilters(req.query);
  const { page, limit, offset } = parsePagination(req.query, { defaultLimit: 25 });
  const [{ rows, count }, options] = await Promise.all([searchAuditLogs(filters, { limit, offset }), getFilterOptions()]);
  res.render('audit/index', {
    title: 'Audit Trail',
    logs: rows,
    filters,
    options,
    hasFilters: Object.keys(filters).some((k) => k !== 'sort'),
    exportQuery: new URLSearchParams(filters).toString(),
    canExport: hasPermission(req.user, 'audit.export'),
    pagination: buildPagination({ page, limit, total: count, query: { ...filters, limit: req.query.limit }, basePath: '/audit' })
  });
};

export const auditDetail = async (req, res) => {
  const id = Number.parseInt(req.params.id, 10);
  const detail = Number.isFinite(id) ? await getAuditDetail(id) : null;
  if (!detail) return res.status(404).render('errors/404', { title: 'Not Found', message: 'Audit record not found.' });
  return res.render('audit/detail', {
    title: 'Audit Record',
    ...detail,
    canInvestigate: hasPermission(req.user, 'investigations.manage'),
    canViewTransactions: hasPermission(req.user, 'transactions.view')
  });
};

export const auditExport = async (req, res) => {
  const filters = pickFilters(req.query);
  const max = Number(await getSetting('reports.maxExportRows')) || 50000;
  const where = buildAuditWhere(filters);
  const rows = await AuditLog.findAll({
    where,
    attributes: ['id', 'eventId', 'occurredAt', 'receivedAt', 'sourceSystemName', 'sourceModule', 'actorUserId', 'actorUsername', 'actorRole', 'actionType', 'entityType', 'entityId', 'description', 'outcome', 'severity', 'ipAddress', 'correlationId'],
    order: [['occurredAt', filters.sort === 'oldest' ? 'ASC' : 'DESC']],
    limit: max,
    raw: true
  });
  const columns = [
    { key: 'id', label: 'Audit ID' }, { key: 'eventId', label: 'Event ID' }, { key: 'occurredAt', label: 'Occurred At (UTC)' }, { key: 'receivedAt', label: 'Received At (UTC)' },
    { key: 'sourceSystemName', label: 'Source System' }, { key: 'sourceModule', label: 'Module' }, { key: 'actorUserId', label: 'User ID' }, { key: 'actorUsername', label: 'Username' },
    { key: 'actorRole', label: 'Reported Role' }, { key: 'actionType', label: 'Action' }, { key: 'entityType', label: 'Entity Type' }, { key: 'entityId', label: 'Entity ID' },
    { key: 'description', label: 'Description' }, { key: 'outcome', label: 'Outcome' }, { key: 'severity', label: 'Severity' }, { key: 'ipAddress', label: 'IP Address' }, { key: 'correlationId', label: 'Correlation ID' }
  ];
  await recordInternalEvent({
    user: req.user, req, action: 'REPORT_EXPORTED', module: 'Audit Trail', entity: { type: 'Export', id: 'audit-trail' },
    description: `Exported ${rows.length} audit record(s) to CSV`, metadata: { filters, rowCount: rows.length, truncated: rows.length >= max }
  });
  const stamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="medisentinel-audit-trail-${stamp}.csv"`);
  res.send(toCsv(columns, rows));
};
