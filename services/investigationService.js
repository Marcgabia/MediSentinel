import { Op } from 'sequelize';
import {
  sequelize, InvestigationCase, InvestigationCaseEvent, InvestigationNote, AuditLog, SourceSystem, User, Alert, AlertActivity, Role
} from '../models/index.js';
import { CASE_STATUSES, CASE_TRANSITIONS, ALERT_SEVERITIES, CASE_ACTIVE_STATUSES } from '../utils/auditConstants.js';
import { recordInternalEvent } from './auditService.js';
import { notifyUsers } from './notificationService.js';

/**
 * Investigation cases reference original audit records but never change them.
 * Every create / assign / status change / significant edit is itself recorded in the
 * central audit trail inside the same database transaction.
 */

const httpError = (status, message) => Object.assign(new Error(message), { status });

export const canSeeAllCases = (user) => (user.permissions || []).includes('investigations.viewAll');

export const caseVisibilityWhere = (user) => (canSeeAllCases(user)
  ? {}
  : { [Op.or]: [{ assignedToUserId: user.id }, { createdByUserId: user.id }] });

const nextCaseNumber = async (transaction) => {
  const year = new Date().getUTCFullYear();
  const prefix = `CASE-${year}-`;
  const last = await InvestigationCase.findOne({
    where: { caseNumber: { [Op.like]: `${prefix}%` } }, order: [['id', 'DESC']], transaction, lock: transaction.LOCK.UPDATE
  });
  const seq = last ? Number(last.caseNumber.slice(prefix.length)) + 1 : 1;
  return `${prefix}${String(seq).padStart(4, '0')}`;
};

export const listInvestigators = async () => {
  const roles = (await Role.findAll({ raw: true })).filter((r) => (r.permissions || []).includes('investigations.manage')).map((r) => r.id);
  return User.findAll({ where: { roleId: { [Op.in]: roles }, isActive: true }, attributes: ['id', 'fullName', 'username'], order: [['fullName', 'ASC']], raw: true });
};

const assertInvestigator = async (userId, transaction) => {
  if (!userId) return null;
  const user = await User.findByPk(userId, { include: [{ model: Role, as: 'role' }], transaction });
  if (!user || !user.isActive || !(user.role?.permissions || []).includes('investigations.manage')) {
    throw httpError(400, 'Cases can only be assigned to active users with investigation permissions.');
  }
  return user;
};

const auditCase = (args) => recordInternalEvent({ module: 'Investigations', ...args });

export const createCase = async (input, actor, req) => {
  const title = String(input.title || '').trim();
  const description = String(input.description || '').trim();
  if (!title || title.length > 200) throw httpError(400, 'Case title is required (max 200 characters).');
  if (!description) throw httpError(400, 'Case description is required.');
  const severity = ALERT_SEVERITIES.includes(input.severity) ? input.severity : 'MEDIUM';
  const auditLogIds = [].concat(input.auditLogIds || []).map(Number).filter(Boolean);
  const alertId = input.alertId ? Number(input.alertId) : null;

  const result = await sequelize.transaction(async (transaction) => {
    const assignee = await assertInvestigator(input.assignedToUserId ? Number(input.assignedToUserId) : null, transaction);
    const events = auditLogIds.length ? await AuditLog.findAll({ where: { id: { [Op.in]: auditLogIds } }, attributes: ['id', 'sourceSystemId'], transaction }) : [];
    let sourceSystemId = input.sourceSystemId ? Number(input.sourceSystemId) : (events[0]?.sourceSystemId || null);
    let alert = null;
    if (alertId) {
      alert = await Alert.findByPk(alertId, { transaction, lock: transaction.LOCK.UPDATE });
      if (!alert) throw httpError(404, 'Alert not found.');
      sourceSystemId ||= alert.sourceSystemId;
      (alert.relatedEventIds || []).slice(-50).forEach((id) => { if (!auditLogIds.includes(Number(id))) auditLogIds.push(Number(id)); });
    }
    const caseRecord = await InvestigationCase.create({
      caseNumber: await nextCaseNumber(transaction),
      title, description, severity, sourceSystemId,
      status: 'OPEN',
      assignedToUserId: assignee?.id || null,
      createdByUserId: actor.id,
      originAlertId: alert?.id || null
    }, { transaction });

    const validIds = auditLogIds.length ? (await AuditLog.findAll({ where: { id: { [Op.in]: auditLogIds } }, attributes: ['id'], transaction })).map((e) => e.id) : [];
    if (validIds.length) {
      await InvestigationCaseEvent.bulkCreate(validIds.map((id) => ({ caseId: caseRecord.id, auditLogId: id, addedByUserId: actor.id })), { transaction });
    }
    await InvestigationNote.create({ caseId: caseRecord.id, authorUserId: actor.id, noteType: 'SYSTEM', content: `Case opened with ${validIds.length} related audit record(s).` }, { transaction });
    if (alert) {
      if (['OPEN', 'ACKNOWLEDGED'].includes(alert.status)) await alert.update({ status: 'INVESTIGATING' }, { transaction });
      await AlertActivity.create({ alertId: alert.id, userId: actor.id, activityType: 'CASE_LINKED', toStatus: alert.status, note: `Linked to ${caseRecord.caseNumber}` }, { transaction });
    }
    await auditCase({
      user: actor, req, action: 'CASE_CREATED', entity: { type: 'InvestigationCase', id: caseRecord.caseNumber },
      description: `Opened investigation ${caseRecord.caseNumber}: ${title}`,
      after: { title, severity, status: 'OPEN', assignedTo: assignee?.username || null, relatedAuditRecords: validIds.length, originAlertId: alert?.id || null },
      transaction
    });
    if (assignee) {
      await auditCase({
        user: actor, req, action: 'CASE_ASSIGNED', entity: { type: 'InvestigationCase', id: caseRecord.caseNumber },
        description: `Assigned ${caseRecord.caseNumber} to ${assignee.username}`, before: { assignedTo: null }, after: { assignedTo: assignee.username }, transaction
      });
    }
    return { caseRecord, assignee };
  });

  if (result.assignee && result.assignee.id !== actor.id) {
    await notifyUsers([result.assignee.id], {
      type: 'INVESTIGATION_ASSIGNMENT', severity: result.caseRecord.severity,
      title: `New investigation assigned: ${result.caseRecord.caseNumber}`,
      message: result.caseRecord.title, link: `/investigations/${result.caseRecord.id}`, relatedCaseId: result.caseRecord.id
    });
  }
  return result.caseRecord;
};

export const listCases = async (user, { status, severity, assignedToUserId, sourceSystemId, search, page = 1, limit = 25 }) => {
  const where = { ...caseVisibilityWhere(user) };
  const and = [];
  if (status === 'active') and.push({ status: { [Op.in]: CASE_ACTIVE_STATUSES } });
  else if (CASE_STATUSES.includes(status)) and.push({ status });
  if (severity) and.push({ severity });
  if (assignedToUserId === 'me') and.push({ assignedToUserId: user.id });
  else if (assignedToUserId) and.push({ assignedToUserId: Number(assignedToUserId) });
  if (sourceSystemId) and.push({ sourceSystemId: Number(sourceSystemId) });
  if (search) and.push({ [Op.or]: [{ title: { [Op.like]: `%${search}%` } }, { caseNumber: { [Op.like]: `%${search}%` } }, { description: { [Op.like]: `%${search}%` } }] });
  if (and.length) where[Op.and] = and;
  const { rows, count } = await InvestigationCase.findAndCountAll({
    where,
    include: [
      { model: User, as: 'assignedTo', attributes: ['id', 'fullName'] },
      { model: SourceSystem, as: 'sourceSystem', attributes: ['id', 'name'] }
    ],
    order: [['updatedAt', 'DESC']], limit, offset: (page - 1) * limit, distinct: true
  });
  const ids = rows.map((r) => r.id);
  const counts = ids.length ? await InvestigationCaseEvent.findAll({ where: { caseId: { [Op.in]: ids } }, attributes: ['caseId', [sequelize.fn('COUNT', sequelize.col('id')), 'n']], group: ['caseId'], raw: true }) : [];
  const countMap = Object.fromEntries(counts.map((c) => [c.caseId, Number(c.n)]));
  return { rows: rows.map((r) => ({ ...r.get({ plain: true }), eventCount: countMap[r.id] || 0 })), count };
};

export const getCase = async (id, user) => {
  const record = await InvestigationCase.findOne({
    where: { id, ...caseVisibilityWhere(user) },
    include: [
      { model: User, as: 'assignedTo', attributes: ['id', 'fullName', 'username'] },
      { model: User, as: 'createdBy', attributes: ['id', 'fullName', 'username'] },
      { model: SourceSystem, as: 'sourceSystem', attributes: ['id', 'name', 'systemCode'] },
      { model: Alert, as: 'originAlert', attributes: ['id', 'title', 'severity', 'status'] },
      { model: InvestigationNote, as: 'notes', include: [{ model: User, as: 'author', attributes: ['fullName', 'username'] }] },
      { model: InvestigationCaseEvent, as: 'eventLinks', include: [{ model: AuditLog, as: 'auditLog', attributes: ['id', 'eventId', 'sourceSystemName', 'actorUsername', 'actionType', 'entityType', 'entityId', 'outcome', 'severity', 'occurredAt', 'description'] }, { model: User, as: 'addedBy', attributes: ['fullName'] }] }
    ],
    order: [[{ model: InvestigationNote, as: 'notes' }, 'createdAt', 'DESC'], [{ model: InvestigationCaseEvent, as: 'eventLinks' }, 'createdAt', 'ASC']]
  });
  if (!record) return null;
  const plain = record.get({ plain: true });
  return { ...plain, allowedTransitions: CASE_TRANSITIONS[plain.status] || [] };
};

const loadCaseForUpdate = async (id, user, transaction) => {
  const record = await InvestigationCase.findOne({ where: { id, ...caseVisibilityWhere(user) }, transaction, lock: transaction.LOCK.UPDATE });
  if (!record) throw httpError(404, 'Case not found or not accessible.');
  return record;
};

export const assignCase = async (id, assigneeId, actor, req) => {
  const result = await sequelize.transaction(async (transaction) => {
    const record = await loadCaseForUpdate(id, actor, transaction);
    const assignee = await assertInvestigator(Number(assigneeId), transaction);
    if (!assignee) throw httpError(400, 'Select an investigator.');
    const previous = record.assignedToUserId ? await User.findByPk(record.assignedToUserId, { attributes: ['username'], transaction }) : null;
    if (record.assignedToUserId === assignee.id) throw httpError(400, 'Case is already assigned to this investigator.');
    await record.update({ assignedToUserId: assignee.id }, { transaction });
    await InvestigationNote.create({ caseId: record.id, authorUserId: actor.id, noteType: 'ASSIGNMENT', content: `Assigned to ${assignee.fullName} (${assignee.username}).` }, { transaction });
    await auditCase({
      user: actor, req, action: 'CASE_ASSIGNED', entity: { type: 'InvestigationCase', id: record.caseNumber },
      description: `Assigned ${record.caseNumber} to ${assignee.username}`,
      before: { assignedTo: previous?.username || null }, after: { assignedTo: assignee.username }, transaction
    });
    return { record, assignee };
  });
  if (result.assignee.id !== actor.id) {
    await notifyUsers([result.assignee.id], {
      type: 'INVESTIGATION_ASSIGNMENT', severity: result.record.severity,
      title: `Investigation assigned: ${result.record.caseNumber}`, message: result.record.title,
      link: `/investigations/${result.record.id}`, relatedCaseId: result.record.id
    });
  }
  return result.record;
};

export const changeStatus = async (id, newStatus, note, actor, req) => sequelize.transaction(async (transaction) => {
  const record = await loadCaseForUpdate(id, actor, transaction);
  if (!CASE_STATUSES.includes(newStatus)) throw httpError(400, 'Invalid status.');
  const allowed = CASE_TRANSITIONS[record.status] || [];
  if (!allowed.includes(newStatus)) throw httpError(400, `Cannot move a case from ${record.status} to ${newStatus}.`);
  const text = String(note || '').trim();
  if (newStatus === 'RESOLVED' && !text && !record.resolutionNotes) throw httpError(400, 'Resolution notes are required to resolve a case.');
  const before = { status: record.status };
  const update = { status: newStatus };
  if (newStatus === 'RESOLVED') { update.resolvedAt = new Date(); if (text) update.resolutionNotes = text; }
  if (newStatus === 'CLOSED') update.closedAt = new Date();
  if (['UNDER_INVESTIGATION', 'OPEN'].includes(newStatus)) { update.closedAt = null; }
  await record.update(update, { transaction });
  await InvestigationNote.create({
    caseId: record.id, authorUserId: actor.id, noteType: newStatus === 'RESOLVED' ? 'RESOLUTION' : 'STATUS_CHANGE',
    content: `Status changed ${before.status} → ${newStatus}${text ? `: ${text}` : ''}`, metadata: { from: before.status, to: newStatus }
  }, { transaction });
  await auditCase({
    user: actor, req, action: 'CASE_STATUS_CHANGED', entity: { type: 'InvestigationCase', id: record.caseNumber },
    description: `${record.caseNumber} status changed from ${before.status} to ${newStatus}`, before, after: { status: newStatus }, transaction
  });
  return record;
});

export const addNote = async (id, content, noteType, actor, req) => sequelize.transaction(async (transaction) => {
  const record = await loadCaseForUpdate(id, actor, transaction);
  const text = String(content || '').trim();
  if (!text) throw httpError(400, 'Note text is required.');
  if (text.length > 10000) throw httpError(400, 'Notes are limited to 10,000 characters.');
  const type = ['NOTE', 'EVIDENCE', 'FINDING'].includes(noteType) ? noteType : 'NOTE';
  const note = await InvestigationNote.create({ caseId: record.id, authorUserId: actor.id, noteType: type, content: text }, { transaction });
  await record.changed('updatedAt', true);
  await record.save({ transaction });
  await auditCase({
    user: actor, req, action: 'CASE_UPDATED', entity: { type: 'InvestigationCase', id: record.caseNumber },
    description: `Added ${type.toLowerCase()} to ${record.caseNumber}`, metadata: { noteId: note.id, noteType: type }, transaction
  });
  return note;
});

export const updateFindings = async (id, { findings, resolutionNotes }, actor, req) => sequelize.transaction(async (transaction) => {
  const record = await loadCaseForUpdate(id, actor, transaction);
  if (record.status === 'CLOSED') throw httpError(400, 'Closed cases cannot be edited. Reopen the case first.');
  const before = { findings: record.findings || null, resolutionNotes: record.resolutionNotes || null };
  const after = {
    findings: String(findings ?? record.findings ?? '').trim() || null,
    resolutionNotes: String(resolutionNotes ?? record.resolutionNotes ?? '').trim() || null
  };
  if (before.findings === after.findings && before.resolutionNotes === after.resolutionNotes) return record;
  await record.update(after, { transaction });
  await InvestigationNote.create({ caseId: record.id, authorUserId: actor.id, noteType: 'FINDING', content: 'Findings / resolution notes updated.' }, { transaction });
  await auditCase({
    user: actor, req, action: 'CASE_UPDATED', entity: { type: 'InvestigationCase', id: record.caseNumber },
    description: `Updated findings for ${record.caseNumber}`, before, after, transaction
  });
  return record;
});

export const attachEvents = async (id, identifiers, actor, req) => sequelize.transaction(async (transaction) => {
  const record = await loadCaseForUpdate(id, actor, transaction);
  const values = String(identifiers || '').split(/[\s,]+/).map((v) => v.trim()).filter(Boolean).slice(0, 100);
  if (!values.length) throw httpError(400, 'Enter one or more audit IDs or event IDs.');
  const numeric = values.filter((v) => /^\d+$/.test(v)).map(Number);
  const events = await AuditLog.findAll({
    where: { [Op.or]: [{ id: { [Op.in]: numeric.length ? numeric : [0] } }, { eventId: { [Op.in]: values } }] },
    attributes: ['id', 'eventId'], transaction
  });
  if (!events.length) throw httpError(404, 'No matching audit records were found.');
  const existing = new Set((await InvestigationCaseEvent.findAll({ where: { caseId: record.id }, attributes: ['auditLogId'], transaction })).map((l) => Number(l.auditLogId)));
  const toAdd = events.filter((e) => !existing.has(Number(e.id)));
  if (!toAdd.length) throw httpError(400, 'Those audit records are already attached.');
  await InvestigationCaseEvent.bulkCreate(toAdd.map((e) => ({ caseId: record.id, auditLogId: e.id, addedByUserId: actor.id })), { transaction });
  await InvestigationNote.create({ caseId: record.id, authorUserId: actor.id, noteType: 'EVIDENCE', content: `Attached audit record(s): ${toAdd.map((e) => `#${e.id}`).join(', ')}` }, { transaction });
  await auditCase({
    user: actor, req, action: 'CASE_UPDATED', entity: { type: 'InvestigationCase', id: record.caseNumber },
    description: `Attached ${toAdd.length} audit record(s) to ${record.caseNumber}`, metadata: { auditLogIds: toAdd.map((e) => Number(e.id)) }, transaction
  });
  return toAdd.length;
});

export const caseCounts = async () => {
  const rows = await InvestigationCase.findAll({ attributes: ['status', [sequelize.fn('COUNT', sequelize.col('id')), 'n']], group: ['status'], raw: true });
  const map = Object.fromEntries(rows.map((r) => [r.status, Number(r.n)]));
  return { ...map, pending: CASE_ACTIVE_STATUSES.reduce((s, k) => s + (map[k] || 0), 0) };
};
