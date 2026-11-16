import { Op } from 'sequelize';
import { Notification, User, Role } from '../models/index.js';
import { NOTIFICATION_TYPES } from '../utils/auditConstants.js';

const throttle = new Map();

/** Active internal users whose role grants `permission`. */
export const usersWithPermission = async (permission) => {
  const roles = await Role.findAll({ raw: true });
  const roleIds = roles.filter((r) => (r.permissions || []).includes(permission)).map((r) => r.id);
  if (!roleIds.length) return [];
  return User.findAll({ where: { roleId: { [Op.in]: roleIds }, isActive: true }, attributes: ['id'], raw: true });
};

export const notifyUsers = async (userIds, data, { transaction } = {}) => {
  const unique = [...new Set(userIds.filter(Boolean).map(Number))];
  if (!unique.length) return [];
  if (!NOTIFICATION_TYPES[data.type]) throw new Error(`Unknown notification type ${data.type}`);
  return Notification.bulkCreate(unique.map((userId) => ({
    userId,
    type: data.type,
    severity: data.severity || 'INFO',
    title: String(data.title).slice(0, 200),
    message: String(data.message).slice(0, 1000),
    link: data.link || null,
    relatedAuditLogId: data.relatedAuditLogId || null,
    relatedAlertId: data.relatedAlertId || null,
    relatedCaseId: data.relatedCaseId || null,
    relatedFindingId: data.relatedFindingId || null
  })), { transaction });
};

export const notifyPermission = async (permission, data, options = {}) => {
  const users = await usersWithPermission(permission);
  return notifyUsers(users.map((u) => u.id), data, options);
};

/** Notify at most once per `key` within `ttlMs` (prevents floods, e.g. repeated invalid payloads). */
export const notifyPermissionThrottled = async (key, ttlMs, permission, data) => {
  const last = throttle.get(key);
  if (last && Date.now() - last < ttlMs) return [];
  throttle.set(key, Date.now());
  return notifyPermission(permission, data);
};

export const unreadCount = (userId) => Notification.count({ where: { userId, isRead: false } });

export const unreadCriticalCount = (userId) =>
  Notification.count({ where: { userId, isRead: false, severity: { [Op.in]: ['HIGH', 'CRITICAL'] } } });

export const listNotifications = async (userId, { status, type, page = 1, limit = 25 } = {}) => {
  const where = { userId };
  if (status === 'unread') where.isRead = false;
  if (status === 'read') where.isRead = true;
  if (type && NOTIFICATION_TYPES[type]) where.type = type;
  const { rows, count } = await Notification.findAndCountAll({
    where, order: [['createdAt', 'DESC']], limit, offset: (page - 1) * limit, raw: true
  });
  return { rows: rows.map((n) => ({ ...n, typeLabel: NOTIFICATION_TYPES[n.type] || n.type })), count };
};

export const recentNotifications = async (userId, limit = 6) => {
  const rows = await Notification.findAll({ where: { userId }, order: [['createdAt', 'DESC']], limit, raw: true });
  return rows.map((n) => ({ ...n, typeLabel: NOTIFICATION_TYPES[n.type] || n.type }));
};

export const markRead = async (userId, id) => {
  const [count] = await Notification.update({ isRead: true, readAt: new Date() }, { where: { id, userId, isRead: false } });
  return count;
};

export const markUnread = async (userId, id) => {
  const [count] = await Notification.update({ isRead: false, readAt: null }, { where: { id, userId } });
  return count;
};

export const markAllRead = async (userId) => {
  const [count] = await Notification.update({ isRead: true, readAt: new Date() }, { where: { userId, isRead: false } });
  return count;
};

export const findForUser = (userId, id) => Notification.findOne({ where: { id, userId }, raw: true });
