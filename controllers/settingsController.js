import bcrypt from 'bcrypt';
import { User, AuditEventType, sequelize } from '../models/index.js';
import { listSettings, updateSettings } from '../services/settingsService.js';
import { recordInternalEvent } from '../services/auditService.js';
import { validatePassword, BCRYPT_ROUNDS } from '../services/userService.js';
import { invalidateEventTypeCache } from '../services/auditIngestionService.js';
import { hasPermission } from '../middleware/permissions.js';
import { EVENT_CATEGORIES, EVENT_SEVERITIES } from '../utils/auditConstants.js';
import { assertIntegrityKeysConfigured } from '../utils/integrityHelper.js';

export const settingsPage = async (req, res) => {
  const canManage = hasPermission(req.user, 'settings.manage');
  const [groups, eventTypes] = await Promise.all([
    canManage ? listSettings() : [],
    canManage ? AuditEventType.findAll({ order: [['category', 'ASC'], ['code', 'ASC']], raw: true }) : []
  ]);
  let keyStatus = null;
  if (canManage) {
    try { assertIntegrityKeysConfigured(); keyStatus = { ok: true, keyId: process.env.AUDIT_SIGNING_KEY_ID || 'k1' }; } catch (e) { keyStatus = { ok: false, message: e.message }; }
  }
  res.render('settings/index', {
    title: 'Settings', canManage, groups, eventTypes, keyStatus,
    categories: EVENT_CATEGORIES, severities: EVENT_SEVERITIES, tab: req.query.tab || (canManage ? 'system' : 'password')
  });
};

export const saveSettings = async (req, res) => {
  const { before, after } = await updateSettings(req.body, req.user.id);
  if (Object.keys(after).length) {
    await recordInternalEvent({
      user: req.user, req, action: 'SETTINGS_MODIFIED', module: 'Settings', entity: { type: 'SystemSettings', id: 'system' },
      description: `Modified ${Object.keys(after).length} system setting(s): ${Object.keys(after).join(', ')}`, before, after
    });
    req.flash('success_msg', 'Settings saved.');
  } else {
    req.flash('success_msg', 'No changes to save.');
  }
  res.redirect('/settings?tab=system');
};

export const changeOwnPassword = async (req, res) => {
  const { currentPassword, newPassword, confirmPassword } = req.body;
  const back = () => res.redirect('/settings?tab=password');
  if (!currentPassword || !newPassword) { req.flash('error_msg', 'Complete all password fields.'); return back(); }
  if (newPassword !== confirmPassword) { req.flash('error_msg', 'The new password and confirmation do not match.'); return back(); }
  const issue = validatePassword(newPassword);
  if (issue) { req.flash('error_msg', issue); return back(); }
  const user = await User.scope('withPassword').findByPk(req.user.id);
  if (!(await bcrypt.compare(currentPassword, user.passwordHash))) {
    await recordInternalEvent({ user: req.user, req, action: 'PASSWORD_CHANGED', module: 'Settings', outcome: 'FAILURE', description: `${req.user.username} failed to change password (incorrect current password)` });
    req.flash('error_msg', 'Your current password is incorrect.');
    return back();
  }
  if (await bcrypt.compare(newPassword, user.passwordHash)) { req.flash('error_msg', 'Choose a password different from your current one.'); return back(); }
  await sequelize.transaction(async (transaction) => {
    await user.update({ passwordHash: await bcrypt.hash(newPassword, BCRYPT_ROUNDS), passwordChangedAt: new Date() }, { transaction });
    await recordInternalEvent({ user: req.user, req, action: 'PASSWORD_CHANGED', module: 'Settings', entity: { type: 'User', id: req.user.username }, description: `${req.user.username} changed their password`, transaction });
  });
  req.flash('success_msg', 'Password updated.');
  return back();
};

export const createEventType = async (req, res) => {
  const code = String(req.body.code || '').trim().toUpperCase();
  const name = String(req.body.name || '').trim();
  if (!/^[A-Z][A-Z0-9_]{2,63}$/.test(code)) throw Object.assign(new Error('Code must be 3–64 uppercase letters, digits or underscores.'), { status: 400 });
  if (!name) throw Object.assign(new Error('Name is required.'), { status: 400 });
  if (!EVENT_CATEGORIES.includes(req.body.category)) throw Object.assign(new Error('Select a category.'), { status: 400 });
  if (await AuditEventType.findOne({ where: { code } })) throw Object.assign(new Error(`Event type ${code} already exists.`), { status: 409 });
  const data = {
    code, name, category: req.body.category, description: String(req.body.description || '').trim().slice(0, 500) || name,
    defaultSeverity: EVENT_SEVERITIES.includes(req.body.defaultSeverity) ? req.body.defaultSeverity : 'INFO',
    isSensitive: req.body.isSensitive === 'on', requiresEntity: req.body.requiresEntity === 'on', requiresChanges: req.body.requiresChanges === 'on',
    isActive: true, isSystem: false
  };
  await sequelize.transaction(async (transaction) => {
    await AuditEventType.create(data, { transaction });
    await recordInternalEvent({ user: req.user, req, action: 'SETTINGS_MODIFIED', module: 'Settings', entity: { type: 'AuditEventType', id: code }, description: `Registered new audit event type ${code}`, after: data, transaction });
  });
  invalidateEventTypeCache();
  req.flash('success_msg', `Event type ${code} added.`);
  res.redirect('/settings?tab=events');
};

export const toggleEventType = async (req, res) => {
  const type = await AuditEventType.findByPk(req.params.id);
  if (!type) throw Object.assign(new Error('Event type not found.'), { status: 404 });
  await sequelize.transaction(async (transaction) => {
    await type.update({ isActive: !type.isActive }, { transaction });
    await recordInternalEvent({
      user: req.user, req, action: 'SETTINGS_MODIFIED', module: 'Settings', entity: { type: 'AuditEventType', id: type.code },
      description: `${type.isActive ? 'Enabled' : 'Disabled'} audit event type ${type.code}`, before: { isActive: !type.isActive }, after: { isActive: type.isActive }, transaction
    });
  });
  invalidateEventTypeCache();
  req.flash('success_msg', `${type.code} ${type.isActive ? 'enabled' : 'disabled'}.`);
  res.redirect('/settings?tab=events');
};
