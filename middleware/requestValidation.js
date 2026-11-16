import crypto from 'crypto';

/** Synchroniser-token CSRF protection for all state-changing dashboard requests. */
export const csrfProtection = (req, res, next) => {
  if (!req.session.csrfToken) req.session.csrfToken = crypto.randomBytes(24).toString('hex');
  res.locals.csrfToken = req.session.csrfToken;
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
  const supplied = Buffer.from(String(req.body?._csrf || req.get('X-CSRF-Token') || ''));
  const expected = Buffer.from(req.session.csrfToken);
  const ok = supplied.length === expected.length && crypto.timingSafeEqual(supplied, expected);
  if (!ok) {
    const err = new Error('Invalid or missing security token. Reload the page and try again.');
    err.status = 403;
    return next(err);
  }
  return next();
};

/** Conservative security headers. All scripts are served from /js and /vendor (no inline JS). */
export const securityHeaders = (req, res, next) => {
  res.set({
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'same-origin',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
    'Cross-Origin-Opener-Policy': 'same-origin',
    'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'self'"
  });
  next();
};

/** Prevent caching of authenticated pages (audit data should not linger in shared browser caches). */
export const noStore = (req, res, next) => { res.set('Cache-Control', 'no-store'); next(); };

export const toInt = (value, fallback = null) => {
  const n = Number.parseInt(value, 10);
  return Number.isFinite(n) ? n : fallback;
};
