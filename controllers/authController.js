import bcrypt from 'bcrypt';
import { Op } from 'sequelize';
import { User, Role } from '../models/index.js';
import { recordInternalEvent } from '../services/auditService.js';
import { getSetting, getSettingsMap } from '../services/settingsService.js';
import { registerUser } from '../services/userService.js';
import { notifyPermission } from '../services/notificationService.js';
import { sessionIdentity } from '../middleware/auth.js';
import { createRateLimiter } from '../utils/rateLimiter.js';
import { clientIp } from '../middleware/apiAuthentication.js';

const loginLimiter = createRateLimiter({ windowMs: 15 * 60000, max: Number(process.env.LOGIN_RATE_LIMIT || 30) });
// Constant-time-ish rejection for unknown accounts (prevents username enumeration by timing).
const DUMMY_HASH = bcrypt.hashSync('medisentinel-dummy-password', 12);

const registerLimiter = createRateLimiter({ windowMs: 60 * 60000, max: Number(process.env.REGISTER_RATE_LIMIT || 10) });

const registrationAllowed = async () => Number(await getSetting('security.allowSelfRegistration')) !== 0;

export const loginPage = async (req, res) => {
  res.render('auth/login', { title: 'Sign in', layout: false, allowRegistration: await registrationAllowed() });
};

export const registerPage = async (req, res) => {
  if (!await registrationAllowed()) {
    req.flash('error_msg', 'Self-registration is turned off. Ask a MediSentinel administrator to create your account.');
    return res.redirect('/login');
  }
  const registered = req.flash('registered')[0];
  return res.render('auth/register', { title: 'Create account', layout: false, registered, form: {} });
};

export const register = async (req, res) => {
  if (!await registrationAllowed()) {
    req.flash('error_msg', 'Self-registration is turned off. Ask a MediSentinel administrator to create your account.');
    return res.redirect('/login');
  }
  const form = {
    fullName: String(req.body.fullName || '').slice(0, 150),
    username: String(req.body.username || '').slice(0, 60),
    email: String(req.body.email || '').slice(0, 190)
  };
  const rerender = (message, status = 400) => res.status(status).render('auth/register', {
    title: 'Create account', layout: false, form, error_msg: [message]
  });

  const ip = clientIp(req) || 'unknown';
  if (!registerLimiter.hit(ip).allowed) return rerender('Too many sign-up attempts from this network. Please try again later.', 429);

  try {
    const user = await registerUser({ ...form, password: String(req.body.password || ''), confirmPassword: String(req.body.confirmPassword || '') }, req);
    await notifyPermission('users.manage', {
      type: 'ACCOUNT_REQUEST', severity: 'LOW',
      title: `New account request: ${user.fullName}`,
      message: `${user.username} (${user.email}) signed up and is waiting for approval.`,
      link: '/users?status=pending'
    }).catch(() => {});
    req.flash('registered', user.username);
    return res.redirect('/register');
  } catch (error) {
    if (error.status && error.status < 500) return rerender(error.message, error.status);
    throw error;
  }
};

const fail = (req, res, message) => {
  req.flash('error_msg', message);
  return res.redirect('/login');
};

export const login = async (req, res) => {
  const identifier = String(req.body.username || '').trim().toLowerCase().slice(0, 190);
  const password = String(req.body.password || '');
  const ip = clientIp(req) || 'unknown';

  const limit = loginLimiter.hit(ip);
  if (!limit.allowed) {
    await recordInternalEvent({
      user: { username: identifier || '(blank)' }, req, action: 'LOGIN_FAILED', module: 'Authentication', outcome: 'DENIED', severity: 'MEDIUM',
      description: `Sign-in throttled for ${ip}: too many attempts`, metadata: { reason: 'RATE_LIMITED' }
    }).catch(() => {});
    return fail(req, res, 'Too many sign-in attempts. Please wait a few minutes and try again.');
  }
  if (!identifier || !password) return fail(req, res, 'Enter your username and password.');

  const settings = await getSettingsMap(['security.maxFailedLogins', 'security.lockoutMinutes']);
  const user = await User.scope('withPassword').findOne({
    where: { [Op.or]: [{ username: identifier }, { email: identifier }] },
    include: [{ model: Role, as: 'role' }]
  });

  if (!user) {
    await bcrypt.compare(password, DUMMY_HASH);
    await recordInternalEvent({
      user: { username: identifier }, req, action: 'LOGIN_FAILED', module: 'Authentication', outcome: 'FAILURE',
      description: `Failed sign-in for unknown account "${identifier}"`, metadata: { reason: 'UNKNOWN_ACCOUNT' }
    });
    return fail(req, res, 'Invalid username or password.');
  }

  const identity = { id: user.id, username: user.username, roleCode: user.role.code };
  if (user.lockedUntil && user.lockedUntil > new Date()) {
    await recordInternalEvent({
      user: identity, req, action: 'LOGIN_FAILED', module: 'Authentication', outcome: 'DENIED',
      description: `Sign-in rejected for ${user.username}: account temporarily locked`, metadata: { reason: 'ACCOUNT_LOCKED', lockedUntil: user.lockedUntil.toISOString() }
    });
    return fail(req, res, 'This account is temporarily locked after repeated failed sign-ins. Try again later or contact an administrator.');
  }

  const valid = await bcrypt.compare(password, user.passwordHash);
  if (!valid || !user.isActive || !user.role.canAccessDashboard) {
    const reason = !valid ? 'BAD_PASSWORD' : 'ACCOUNT_INACTIVE';
    const update = {};
    let locked = false;
    if (!valid) {
      update.failedLoginAttempts = user.failedLoginAttempts + 1;
      if (update.failedLoginAttempts >= settings['security.maxFailedLogins']) {
        update.lockedUntil = new Date(Date.now() + settings['security.lockoutMinutes'] * 60000);
        update.failedLoginAttempts = 0;
        locked = true;
      }
      await user.update(update);
    }
    await recordInternalEvent({
      user: identity, req, action: 'LOGIN_FAILED', module: 'Authentication', outcome: 'FAILURE', severity: locked ? 'MEDIUM' : undefined,
      description: locked
        ? `Failed sign-in for ${user.username}; account locked for ${settings['security.lockoutMinutes']} minutes`
        : `Failed sign-in for ${user.username}`,
      metadata: { reason, accountLocked: locked }
    });
    // The password was correct: it is safe to say why the account cannot sign in.
    if (valid && !user.isActive && !user.lastLoginAt) return fail(req, res, 'Your account is waiting for administrator approval. You can sign in once it has been approved.');
    if (valid && !user.isActive) return fail(req, res, 'This account has been deactivated. Contact a MediSentinel administrator.');
    return fail(req, res, locked ? 'Too many failed attempts. This account is now temporarily locked.' : 'Invalid username or password.');
  }

  await user.update({ failedLoginAttempts: 0, lockedUntil: null, lastLoginAt: new Date() });
  loginLimiter.reset(ip);
  const returnTo = req.session.returnTo;
  return new Promise((resolve, reject) => {
    // New session id on privilege change (prevents session fixation).
    req.session.regenerate(async (err) => {
      if (err) return reject(err);
      try {
        req.session.userId = user.id;
        req.session.user = sessionIdentity(user);
        req.session.lastActivity = Date.now();
        await recordInternalEvent({
          user: req.session.user, req, action: 'LOGIN_SUCCESS', module: 'Authentication', description: `${user.username} signed in to MediSentinel`
        });
        const target = returnTo && returnTo.startsWith('/') && !returnTo.startsWith('//') ? returnTo : '/dashboard';
        return req.session.save(() => { res.redirect(target); resolve(); });
      } catch (error) {
        return reject(error);
      }
    });
  });
};

export const logout = async (req, res) => {
  const identity = req.session?.user;
  if (identity) {
    await recordInternalEvent({ user: identity, req, action: 'LOGOUT', module: 'Authentication', description: `${identity.username} signed out` }).catch(() => {});
  }
  req.session.destroy(() => {
    res.clearCookie('medisentinel.sid');
    res.redirect('/login');
  });
};
