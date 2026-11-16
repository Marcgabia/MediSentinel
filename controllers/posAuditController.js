import {
  getTransactionTimeline, recentTransactions, listVoidInvestigations, listConfigurationChanges, configurationEventTypes,
  searchCrossSystem, listIdentityMappings, createIdentityMapping, deactivateIdentityMapping, posDashboard, posFilterOptions, dateRange
} from '../services/posAuditService.js';
import { recordInternalEvent } from '../services/auditService.js';
import { parsePagination, buildPagination } from '../utils/pagination.js';
import { hasPermission } from '../middleware/permissions.js';
import { ymd } from '../utils/sqlDates.js';
import { SourceSystem } from '../models/index.js';

const pick = (query, keys) => Object.fromEntries(keys.filter((k) => query[k] !== undefined && query[k] !== '').map((k) => [k, String(query[k]).slice(0, 200)]));

// Transaction details are restricted (transactions.view) and every view is itself audited.
const auditView = (req, entity, description, metadata) => recordInternalEvent({
  user: req.user, req, action: 'READ', module: 'Transaction Audit', entity, description, metadata
}).catch(() => {});

// ---------------------------------------------------------------------------
// Transaction Audit Timeline
// ---------------------------------------------------------------------------
export const transactionsIndex = async (req, res) => {
  const ref = String(req.query.ref || '').trim();
  if (ref && req.query.exact !== 'false') {
    const qs = req.query.sourceSystemId ? `?sourceSystemId=${encodeURIComponent(req.query.sourceSystemId)}` : '';
    return res.redirect(`/audit/transactions/${encodeURIComponent(ref)}${qs}`);
  }
  const filters = pick(req.query, ['q', 'sourceSystemId']);
  const [recent, options] = await Promise.all([recentTransactions({ q: filters.q, sourceSystemId: filters.sourceSystemId, limit: 50 }), posFilterOptions()]);
  return res.render('audit/transactions', { title: 'Transaction Audit Timeline', recent, filters, options });
};

export const transactionTimeline = async (req, res) => {
  const ref = String(req.params.ref || '').slice(0, 128);
  const sourceSystemId = req.query.sourceSystemId ? Number(req.query.sourceSystemId) : null;
  const timeline = await getTransactionTimeline(ref, { sourceSystemId });
  if (!timeline) return res.status(404).render('errors/404', { title: 'Not Found', message: 'Transaction reference is required.' });
  await auditView(req, { type: 'Transaction', id: ref }, `Viewed transaction audit timeline for ${ref}`, { sourceSystemId, events: timeline.events.length });
  return res.render('audit/timeline', {
    title: `Transaction ${ref}`,
    ...timeline,
    sourceSystemId,
    canInvestigate: hasPermission(req.user, 'investigations.manage')
  });
};

// ---------------------------------------------------------------------------
// Transaction Void Investigation
// ---------------------------------------------------------------------------
export const voidsIndex = async (req, res) => {
  const filters = pick(req.query, ['from', 'to', 'sourceSystemId', 'branchId', 'requester', 'indicator', 'ref', 'flagged']);
  const [result, options] = await Promise.all([listVoidInvestigations(filters), posFilterOptions()]);
  const { page, limit, offset } = parsePagination(req.query, { defaultLimit: 25 });
  const rows = result.rows.slice(offset, offset + limit);
  await auditView(req, { type: 'VoidInvestigation', id: 'list' }, `Reviewed void investigation list (${result.rows.length} transaction(s))`, { filters });
  return res.render('audit/voids', {
    title: 'Void Investigation',
    ...result,
    rows,
    total: result.rows.length,
    filters: { ...filters, from: filters.from || ymd(result.from), to: filters.to || ymd(result.to) },
    options,
    pagination: buildPagination({ page, limit, total: result.rows.length, query: filters, basePath: '/audit/voids' })
  });
};

// ---------------------------------------------------------------------------
// Configuration Change History
// ---------------------------------------------------------------------------
export const configurationIndex = async (req, res) => {
  const filters = pick(req.query, ['sourceSystemId', 'branchId', 'user', 'actionType', 'entityId', 'field', 'from', 'to']);
  const { page, limit, offset } = parsePagination(req.query, { defaultLimit: 20 });
  const [{ groups, count }, options] = await Promise.all([listConfigurationChanges(filters, { limit, offset }), posFilterOptions()]);
  return res.render('audit/configuration', {
    title: 'Configuration Change History',
    groups,
    filters,
    hasFilters: Object.keys(filters).length > 0,
    options: { ...options, configurationTypes: configurationEventTypes() },
    pagination: buildPagination({ page, limit, total: count, query: filters, basePath: '/audit/configuration' })
  });
};

// ---------------------------------------------------------------------------
// Cross-System Activity View & identity mappings
// ---------------------------------------------------------------------------
export const crossSystemIndex = async (req, res) => {
  const filters = pick(req.query, ['person', 'userId', 'username', 'sourceSystemId', 'transactionRef', 'branchId', 'activity', 'correlationId', 'entityType', 'entityId', 'from', 'to', 'hideRoutine', 'includeInternal']);
  const { page, limit, offset } = parsePagination(req.query, { defaultLimit: 50 });
  const [result, options, people] = await Promise.all([searchCrossSystem(filters, { limit, offset }), posFilterOptions(), listIdentityMappings()]);
  const personKeys = [...new Map(people.map((p) => [p.personKey, { personKey: p.personKey, displayName: p.displayName }])).values()];
  return res.render('audit/cross-system', {
    title: 'Cross-System Activity',
    ...result,
    filters,
    hasFilters: Object.keys(filters).length > 0,
    options,
    personKeys,
    canManageIdentities: hasPermission(req.user, 'integrations.manage'),
    pagination: buildPagination({ page, limit, total: result.count, query: filters, basePath: '/audit/cross-system' })
  });
};

export const identitiesPage = async (req, res) => {
  const [mappings, sources] = await Promise.all([
    listIdentityMappings({ includeInactive: req.query.all === 'true' }),
    SourceSystem.findAll({ where: { isInternal: false }, attributes: ['id', 'name', 'systemCode'], order: [['name', 'ASC']], raw: true })
  ]);
  return res.render('audit/identities', {
    title: 'Cross-System Identities', mappings, sources, showAll: req.query.all === 'true',
    prefill: pick(req.query, ['sourceSystemId', 'actorUserId', 'personKey'])
  });
};

export const createIdentity = async (req, res) => {
  try {
    const mapping = await createIdentityMapping(req.body, req.user, req);
    req.flash('success_msg', `Mapped user ${mapping.actorUserId} to ${mapping.personKey}.`);
  } catch (error) {
    if (!error.status || error.status >= 500) throw error;
    req.flash('error_msg', error.message);
  }
  res.redirect('/audit/identities');
};

export const deactivateIdentity = async (req, res) => {
  await deactivateIdentityMapping(Number(req.params.id), req.user, req);
  req.flash('success_msg', 'Identity mapping deactivated.');
  res.redirect('/audit/identities');
};

// ---------------------------------------------------------------------------
// Pharmacy operations dashboard
// ---------------------------------------------------------------------------
export const pharmacyDashboard = async (req, res) => {
  const filters = pick(req.query, ['sourceSystemId', 'branchId', 'user', 'actionType', 'from', 'to']);
  const [data, options] = await Promise.all([posDashboard(filters), posFilterOptions()]);
  const { from, to } = dateRange(filters, 30, 366);
  res.render('dashboard/pharmacy', {
    title: 'Pharmacy Operations',
    ...data,
    filters: { ...filters, from: filters.from || ymd(from), to: filters.to || ymd(to) },
    filterQuery: new URLSearchParams(filters).toString(),
    options
  });
};
