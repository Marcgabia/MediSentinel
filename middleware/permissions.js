import { recordInternalEvent } from '../services/auditService.js';

export const hasPermission = (user, permission) => Boolean(user && (user.permissions || []).includes(permission));

/**
 * Require at least one of the listed permissions. Denials are recorded in the audit trail as
 * ACCESS_DENIED events (which also feed the "repeated unauthorized access" alert rule).
 */
export const requirePermission = (...permissions) => async (req, res, next) => {
  if (permissions.some((p) => hasPermission(req.user, p))) return next();
  await recordInternalEvent({
    user: req.user, req, action: 'ACCESS_DENIED', module: 'Access Control', outcome: 'DENIED',
    description: `Denied ${req.method} ${req.originalUrl.split('?')[0]} (requires ${permissions.join(' or ')})`,
    metadata: { requiredPermissions: permissions }
  }).catch(() => {});
  if (req.xhr || (req.get('accept') || '').includes('application/json')) {
    return res.status(403).json({ error: 'You do not have permission to perform this action.' });
  }
  return res.status(403).render('errors/403', { title: 'Access Denied', message: 'You do not have permission to access this page.' });
};
