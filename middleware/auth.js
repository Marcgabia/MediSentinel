import { User, Role } from '../models/index.js';
import { getSetting } from '../services/settingsService.js';
import { recordInternalEvent } from '../services/auditService.js';
import { unreadCount, unreadCriticalCount } from '../services/notificationService.js';
import { pendingApprovalCount } from '../services/userService.js';

const wantsJson = (req) => req.xhr || (req.get('accept') || '').includes('application/json') || req.path.endsWith('.json');

/** Build the session identity stored after login (never contains the password hash). */
export const sessionIdentity = (user) => ({
  id: user.id,
  username: user.username,
  fullName: user.fullName,
  roleCode: user.role.code,
  roleName: user.role.name,
  permissions: user.role.permissions || []
});

/**
 * Requires a signed-in, active MediSentinel user. The account and its role are re-read on
 * every request so deactivation or permission changes take effect immediately.
 * Also enforces the configurable idle timeout.
 */
export const requireAuth = async (req, res, next) => {
  try {
    if (!req.session?.userId) {
      if (wantsJson(req)) return res.status(401).json({ error: 'Authentication required.' });
      req.session.returnTo = req.method === 'GET' ? req.originalUrl : undefined;
      return res.redirect('/login');
    }
    const idleMinutes = Number(await getSetting('security.sessionIdleMinutes')) || 30;
    const now = Date.now();
    if (req.session.lastActivity && now - req.session.lastActivity > idleMinutes * 60000) {
      const identity = req.session.user;
      await recordInternalEvent({
        user: identity, req, action: 'LOGOUT', module: 'Authentication', description: `Session for ${identity?.username} expired after ${idleMinutes} minutes of inactivity`,
        metadata: { reason: 'IDLE_TIMEOUT' }
      }).catch(() => {});
      return req.session.regenerate(() => {
        if (wantsJson(req)) return res.status(401).json({ error: 'Session expired.' });
        req.flash('error_msg', 'Your session expired due to inactivity. Please sign in again.');
        return res.redirect('/login');
      });
    }
    const user = await User.findByPk(req.session.userId, { include: [{ model: Role, as: 'role' }] });
    if (!user || !user.isActive || !user.role?.canAccessDashboard) {
      return req.session.regenerate(() => {
        req.flash('error_msg', 'Your account is no longer active.');
        return res.redirect('/login');
      });
    }
    req.session.lastActivity = now;
    req.user = sessionIdentity(user);
    req.session.user = req.user;
    res.locals.currentUser = req.user;
    res.locals.permissions = req.user.permissions;
    const [unread, unreadCritical] = await Promise.all([unreadCount(user.id), unreadCriticalCount(user.id)]);
    res.locals.unreadNotifications = unread;
    res.locals.unreadCritical = unreadCritical;
    if (req.user.permissions.includes('users.manage')) res.locals.pendingAccounts = await pendingApprovalCount();
    return next();
  } catch (error) {
    return next(error);
  }
};

export const redirectIfAuthenticated = (req, res, next) => (req.session?.userId ? res.redirect('/dashboard') : next());
