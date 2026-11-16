import { SourceSystem, AuditEventType } from '../models/index.js';
import { REPORTS, generateReport } from '../services/reportService.js';
import { recordInternalEvent } from '../services/auditService.js';
import { getSetting } from '../services/settingsService.js';
import { toCsv } from '../utils/csv.js';
import { hasPermission } from '../middleware/permissions.js';
import { EVENT_SEVERITIES } from '../utils/auditConstants.js';

const FILTERS = ['from', 'to', 'username', 'sourceSystemId', 'actionType', 'severity'];
const pick = (q) => Object.fromEntries(FILTERS.filter((k) => q[k]).map((k) => [k, String(q[k]).slice(0, 100)]));

export const reportsIndex = (req, res) => {
  res.render('reports/index', { title: 'Audit Reports', reports: Object.entries(REPORTS).map(([code, r]) => ({ code, ...r })) });
};

export const viewReport = async (req, res) => {
  const code = String(req.params.code || '').toUpperCase();
  if (!REPORTS[code]) return res.status(404).render('errors/404', { title: 'Not Found', message: 'Unknown report.' });
  const filters = pick(req.query);
  const [report, sources, eventTypes] = await Promise.all([
    generateReport(code, filters, { limit: 500 }),
    SourceSystem.findAll({ attributes: ['id', 'name'], order: [['name', 'ASC']], raw: true }),
    AuditEventType.findAll({ attributes: ['code', 'name'], order: [['code', 'ASC']], raw: true })
  ]);
  await recordInternalEvent({
    user: req.user, req, action: 'REPORT_GENERATED', module: 'Reports', entity: { type: 'Report', id: code },
    description: `Generated ${report.name} (${report.period.fromStr} to ${report.period.toStr})`, metadata: { filters: report.filters, rows: report.rows.length }
  });
  return res.render('reports/view', {
    title: report.name, report, sources, eventTypes, severities: EVENT_SEVERITIES,
    exportQuery: new URLSearchParams(report.filters).toString(),
    canExport: hasPermission(req.user, 'reports.export'),
    generatedBy: `${req.user.fullName} (${req.user.username})`
  });
};

export const exportReport = async (req, res) => {
  const code = String(req.params.code || '').toUpperCase();
  if (!REPORTS[code]) return res.status(404).render('errors/404', { title: 'Not Found' });
  const max = Number(await getSetting('reports.maxExportRows')) || 50000;
  const report = await generateReport(code, pick(req.query), { limit: max });
  await recordInternalEvent({
    user: req.user, req, action: 'REPORT_EXPORTED', module: 'Reports', entity: { type: 'Report', id: code },
    description: `Exported ${report.name} to CSV (${report.rows.length} rows, ${report.period.fromStr} to ${report.period.toStr})`,
    metadata: { filters: report.filters, rows: report.rows.length, truncated: report.truncated }
  });
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="medisentinel-${code.toLowerCase().replace(/_/g, '-')}-${report.period.fromStr}-to-${report.period.toStr}.csv"`);
  return res.send(toCsv(report.columns, report.rows));
};
