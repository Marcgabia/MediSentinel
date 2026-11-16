import { SourceSystem, User } from '../models/index.js';
import {
  qaDashboard, executeVerification, listRuns, getRun, coverageMatrix, listFindings, getFinding, updateFindingStatus, formatRunId
} from '../services/qaVerificationService.js';
import { parsePagination, buildPagination } from '../utils/pagination.js';
import { hasPermission } from '../middleware/permissions.js';
import { FINDING_SEVERITIES, FINDING_STATUSES, QA_CATEGORY_LABELS } from '../utils/auditConstants.js';
import { usersWithPermission } from '../services/notificationService.js';

export const qaIndex = async (req, res) => {
  const data = await qaDashboard();
  res.render('quality-assurance/index', { title: 'Quality Assurance', ...data, canRun: hasPermission(req.user, 'qa.run') });
};

export const runVerification = async (req, res) => {
  const run = await executeVerification({ user: req.user, trigger: 'MANUAL', req });
  req.flash('success_msg', `${formatRunId(run.id)} completed: ${run.overallResult}.`);
  res.redirect(`/qa/runs/${run.id}`);
};

export const runsIndex = async (req, res) => {
  const { page, limit } = parsePagination(req.query, { defaultLimit: 25 });
  const { rows, count } = await listRuns({ page, limit });
  res.render('quality-assurance/runs', { title: 'QA Verification History', runs: rows, canRun: hasPermission(req.user, 'qa.run'), pagination: buildPagination({ page, limit, total: count, basePath: '/qa/runs' }) });
};

export const runDetail = async (req, res) => {
  const data = await getRun(req.params.id);
  if (!data) return res.status(404).render('errors/404', { title: 'Not Found', message: 'Verification run not found.' });
  return res.render('quality-assurance/run-detail', { title: data.run.runCode, ...data });
};

export const coveragePage = async (req, res) => {
  const matrix = await coverageMatrix();
  res.render('quality-assurance/coverage', { title: 'Event Coverage', matrix, canManage: hasPermission(req.user, 'qa.manage') || hasPermission(req.user, 'integrations.manage') });
};

export const findingsIndex = async (req, res) => {
  const filters = Object.fromEntries(['status', 'severity', 'category', 'sourceSystemId', 'search'].filter((k) => req.query[k]).map((k) => [k, String(req.query[k])]));
  if (!Object.keys(req.query).length) filters.status = 'unresolved';
  const { page, limit } = parsePagination(req.query, { defaultLimit: 25 });
  const [{ rows, count }, sources] = await Promise.all([
    listFindings({ ...filters, page, limit }),
    SourceSystem.findAll({ attributes: ['id', 'name'], order: [['name', 'ASC']], raw: true })
  ]);
  res.render('quality-assurance/findings', {
    title: 'QA Findings', findings: rows, filters, sources,
    severities: FINDING_SEVERITIES, statuses: FINDING_STATUSES, categories: Object.entries(QA_CATEGORY_LABELS).map(([code, label]) => ({ code, label })),
    pagination: buildPagination({ page, limit, total: count, query: filters, basePath: '/qa/findings' })
  });
};

export const findingDetail = async (req, res) => {
  const finding = await getFinding(req.params.id);
  if (!finding) return res.status(404).render('errors/404', { title: 'Not Found', message: 'Finding not found.' });
  const canManage = hasPermission(req.user, 'qa.manage');
  const assignees = canManage ? await User.findAll({ where: { id: (await usersWithPermission('qa.view')).map((u) => u.id) }, attributes: ['id', 'fullName'], raw: true }) : [];
  return res.render('quality-assurance/finding-detail', { title: finding.findingCode, finding, canManage, assignees, statuses: FINDING_STATUSES });
};

export const updateFinding = async (req, res) => {
  const finding = await updateFindingStatus(req.params.id, req.body, req.user, req);
  req.flash('success_msg', `Finding updated.`);
  res.redirect(`/qa/findings/${finding.id}`);
};
