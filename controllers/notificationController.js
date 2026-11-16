import { listNotifications, markRead, markUnread, markAllRead, findForUser, recentNotifications } from '../services/notificationService.js';
import { parsePagination, buildPagination } from '../utils/pagination.js';
import { NOTIFICATION_TYPES } from '../utils/auditConstants.js';

export const notificationsIndex = async (req, res) => {
  const filters = Object.fromEntries(['status', 'type'].filter((k) => req.query[k]).map((k) => [k, String(req.query[k])]));
  const { page, limit } = parsePagination(req.query, { defaultLimit: 25 });
  const { rows, count } = await listNotifications(req.user.id, { ...filters, page, limit });
  res.render('notifications/index', {
    title: 'Notifications', notifications: rows, filters,
    types: Object.entries(NOTIFICATION_TYPES).map(([code, label]) => ({ code, label })),
    pagination: buildPagination({ page, limit, total: count, query: filters, basePath: '/notifications' })
  });
};

const safeLink = (link) => (link && link.startsWith('/') && !link.startsWith('//') ? link : '/notifications');

export const openNotification = async (req, res) => {
  const n = await findForUser(req.user.id, req.params.id);
  if (!n) return res.redirect('/notifications');
  await markRead(req.user.id, n.id);
  return res.redirect(safeLink(n.link));
};

export const toggleRead = async (req, res) => {
  if (req.body.state === 'unread') await markUnread(req.user.id, req.params.id);
  else await markRead(req.user.id, req.params.id);
  res.redirect(req.get('referer')?.includes('/notifications') ? req.get('referer') : '/notifications');
};

export const readAll = async (req, res) => {
  const n = await markAllRead(req.user.id);
  req.flash('success_msg', `${n} notification(s) marked as read.`);
  res.redirect('/notifications');
};

export const notificationFeed = async (req, res) => {
  res.json({ unread: res.locals.unreadNotifications, critical: res.locals.unreadCritical, items: await recentNotifications(req.user.id, 6) });
};
