import { Op } from 'sequelize';
import { SourceSystem, AuditLog, Alert } from '../models/index.js';
import {
  listCases, getCase, createCase, assignCase, changeStatus, addNote, updateFindings, attachEvents, listInvestigators, caseCounts
} from '../services/investigationService.js';
import { parsePagination, buildPagination } from '../utils/pagination.js';
import { hasPermission } from '../middleware/permissions.js';
import { CASE_STATUSES, ALERT_SEVERITIES } from '../utils/auditConstants.js';

export const casesIndex = async (req, res) => {
  const filters = Object.fromEntries(['status', 'severity', 'assignedToUserId', 'sourceSystemId', 'search'].filter((k) => req.query[k]).map((k) => [k, String(req.query[k])]));
  if (!Object.keys(req.query).length) filters.status = 'active';
  const { page, limit, offset } = parsePagination(req.query, { defaultLimit: 25 });
  const [{ rows, count }, sources, investigators, counts] = await Promise.all([
    listCases(req.user, { ...filters, page, limit, offset }),
    SourceSystem.findAll({ attributes: ['id', 'name'], order: [['name', 'ASC']], raw: true }),
    listInvestigators(),
    caseCounts()
  ]);
  res.render('investigations/index', {
    title: 'Investigations', cases: rows, filters, sources, investigators, counts,
    statuses: CASE_STATUSES, severities: ALERT_SEVERITIES,
    canManage: hasPermission(req.user, 'investigations.manage'),
    seesAll: hasPermission(req.user, 'investigations.viewAll'),
    pagination: buildPagination({ page, limit, total: count, query: filters, basePath: '/investigations' })
  });
};

export const newCaseForm = async (req, res) => {
  const auditLogIds = [].concat(req.query.auditLogId || []).map(Number).filter(Boolean);
  const alertId = req.query.alertId ? Number(req.query.alertId) : null;
  const [events, alert, sources, investigators] = await Promise.all([
    auditLogIds.length ? AuditLog.findAll({ where: { id: { [Op.in]: auditLogIds } }, attributes: ['id', 'eventId', 'sourceSystemId', 'sourceSystemName', 'actionType', 'actorUsername', 'entityType', 'entityId', 'description', 'severity', 'occurredAt'], raw: true }) : [],
    alertId ? Alert.findByPk(alertId, { raw: true }) : null,
    SourceSystem.findAll({ attributes: ['id', 'name'], order: [['name', 'ASC']], raw: true }),
    listInvestigators()
  ]);
  const first = events[0];
  const prefill = {
    title: alert ? alert.title : first ? `Review ${first.actionType} on ${first.entityType || 'record'} ${first.entityId || ''}`.trim() : '',
    description: alert ? alert.description : first ? `Opened from audit record #${first.id} (${first.eventId}) reported by ${first.sourceSystemName}: ${first.description}` : '',
    severity: alert ? alert.severity : (first && ['HIGH', 'CRITICAL'].includes(first.severity) ? first.severity : 'MEDIUM'),
    sourceSystemId: alert?.sourceSystemId || first?.sourceSystemId || '',
    assignedToUserId: req.user.permissions.includes('investigations.manage') ? req.user.id : ''
  };
  res.render('investigations/form', {
    title: 'New Investigation', prefill, events, alert: alert ? { ...alert, alertCode: `ALR-${String(alert.id).padStart(6, '0')}` } : null,
    sources, investigators, severities: ALERT_SEVERITIES
  });
};

export const createCaseAction = async (req, res) => {
  const record = await createCase(req.body, req.user, req);
  req.flash('success_msg', `Investigation ${record.caseNumber} opened.`);
  res.redirect(`/investigations/${record.id}`);
};

export const caseDetail = async (req, res) => {
  const record = await getCase(req.params.id, req.user);
  if (!record) return res.status(404).render('errors/404', { title: 'Not Found', message: 'Investigation not found or not assigned to you.' });
  const canManage = hasPermission(req.user, 'investigations.manage');
  return res.render('investigations/detail', {
    title: record.caseNumber, record, canManage,
    investigators: canManage ? await listInvestigators() : [],
    isClosed: record.status === 'CLOSED'
  });
};

const done = (req, res, message) => {
  req.flash('success_msg', message);
  res.redirect(`/investigations/${req.params.id}`);
};

export const assignAction = async (req, res) => { const r = await assignCase(req.params.id, req.body.assignedToUserId, req.user, req); done(req, res, `${r.caseNumber} reassigned.`); };
export const statusAction = async (req, res) => { const r = await changeStatus(req.params.id, req.body.status, req.body.note, req.user, req); done(req, res, `${r.caseNumber} is now ${r.status.replace(/_/g, ' ').toLowerCase()}.`); };
export const noteAction = async (req, res) => { await addNote(req.params.id, req.body.content, req.body.noteType, req.user, req); done(req, res, 'Note added.'); };
export const findingsAction = async (req, res) => { await updateFindings(req.params.id, req.body, req.user, req); done(req, res, 'Findings saved.'); };
export const attachAction = async (req, res) => { const n = await attachEvents(req.params.id, req.body.identifiers, req.user, req); done(req, res, `${n} audit record(s) attached.`); };
