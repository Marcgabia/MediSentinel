import bcrypt from 'bcrypt';
import { Op } from 'sequelize';
import { sequelize, User, Role } from '../models/index.js';
import { PERMISSIONS } from '../utils/auditConstants.js';
import { recordInternalEvent } from './auditService.js';

const httpError = (status, message) => Object.assign(new Error(message), { status });
export const BCRYPT_ROUNDS = 12;

export const validatePassword = (password) => {
  const issues = [];
  if (typeof password !== 'string' || password.length < 10) issues.push('at least 10 characters');
  if (!/[a-z]/.test(password || '')) issues.push('a lowercase letter');
  if (!/[A-Z]/.test(password || '')) issues.push('an uppercase letter');
  if (!/\d/.test(password || '')) issues.push('a digit');
  if (password && password.length > 128) issues.push('at most 128 characters');
  return issues.length ? `Password must contain ${issues.join(', ')}.` : null;
};

const publicUser = (u) => ({
  id: u.id, fullName: u.fullName, username: u.username, email: u.email, isActive: u.isActive,
  roleId: u.roleId, roleCode: u.role?.code, roleName: u.role?.name, lastLoginAt: u.lastLoginAt,
  failedLoginAttempts: u.failedLoginAttempts, lockedUntil: u.lockedUntil, createdAt: u.createdAt,
  isLocked: Boolean(u.lockedUntil && new Date(u.lockedUntil) > new Date()),
  isPending: !u.isActive && !u.lastLoginAt
});

export const listUsers = async ({ search, roleId, status }) => {
  const where = {};
  if (search) where[Op.or] = [{ fullName: { [Op.like]: `%${search}%` } }, { username: { [Op.like]: `%${search}%` } }, { email: { [Op.like]: `%${search}%` } }];
  if (roleId) where.roleId = Number(roleId);
  if (status === 'active') where.isActive = true;
  if (status === 'inactive') where.isActive = false;
  if (status === 'pending') { where.isActive = false; where.lastLoginAt = null; }
  const users = await User.findAll({ where, include: [{ model: Role, as: 'role' }], order: [['fullName', 'ASC']] });
  return users.map(publicUser);
};

export const getUser = async (id) => {
  const user = await User.findByPk(id, { include: [{ model: Role, as: 'role' }] });
  return user ? publicUser(user) : null;
};

export const listRoles = async () => {
  const roles = await Role.findAll({ order: [['id', 'ASC']], raw: true });
  const counts = await User.findAll({ attributes: ['roleId', [sequelize.fn('COUNT', sequelize.col('id')), 'n']], group: ['roleId'], raw: true });
  const map = Object.fromEntries(counts.map((c) => [c.roleId, Number(c.n)]));
  return roles.map((r) => ({ ...r, userCount: map[r.id] || 0 }));
};

const activeAdminCount = async (transaction) => {
  const admin = await Role.findOne({ where: { code: 'SYSTEM_ADMIN' }, transaction });
  return User.count({ where: { roleId: admin.id, isActive: true }, transaction });
};

const cleanInput = (input) => ({
  fullName: String(input.fullName || '').trim(),
  username: String(input.username || '').trim().toLowerCase(),
  email: String(input.email || '').trim().toLowerCase(),
  roleId: Number(input.roleId)
});

export const createUser = async (input, actor, req) => {
  const data = cleanInput(input);
  if (!data.fullName || data.fullName.length > 150) throw httpError(400, 'Full name is required.');
  if (!/^[a-z0-9._-]{3,60}$/.test(data.username)) throw httpError(400, 'Username must be 3–60 characters: letters, digits, dot, underscore or hyphen.');
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(data.email)) throw httpError(400, 'A valid email address is required.');
  const pwIssue = validatePassword(input.password);
  if (pwIssue) throw httpError(400, pwIssue);
  return sequelize.transaction(async (transaction) => {
    const role = await Role.findByPk(data.roleId, { transaction });
    if (!role) throw httpError(400, 'Select a valid role.');
    if (!role.canAccessDashboard) throw httpError(400, `${role.name} is a machine identity. Issue integration credentials from the source system page instead.`);
    if (await User.findOne({ where: { [Op.or]: [{ username: data.username }, { email: data.email }] }, transaction })) {
      throw httpError(409, 'Username or email is already in use.');
    }
    const user = await User.create({ ...data, passwordHash: await bcrypt.hash(input.password, BCRYPT_ROUNDS), isActive: true, passwordChangedAt: new Date() }, { transaction });
    await recordInternalEvent({
      user: actor, req, action: 'ACCOUNT_CREATED', module: 'User Management', entity: { type: 'User', id: user.username },
      description: `Created MediSentinel account ${user.username} with role ${role.code}`,
      after: { fullName: user.fullName, username: user.username, email: user.email, role: role.code, isActive: true }, transaction
    });
    return user;
  });
};

/**
 * Self-service sign-up from the sign-in page. The account always receives the least-privileged
 * dashboard role (Read-Only Viewer) and is created INACTIVE: an administrator must approve it
 * (User Management → Approve) before it can sign in. The request is recorded in the audit trail.
 */
export const SELF_REGISTRATION_ROLE = 'VIEWER';

export const registerUser = async (input, req) => {
  const data = cleanInput(input);
  if (!data.fullName || data.fullName.length > 150) throw httpError(400, 'Full name is required.');
  if (!/^[a-z0-9._-]{3,60}$/.test(data.username)) throw httpError(400, 'Username must be 3–60 characters: letters, digits, dot, underscore or hyphen.');
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(data.email) || data.email.length > 190) throw httpError(400, 'A valid email address is required.');
  const pwIssue = validatePassword(input.password);
  if (pwIssue) throw httpError(400, pwIssue);
  if (input.password !== input.confirmPassword) throw httpError(400, 'Passwords do not match.');
  const passwordHash = await bcrypt.hash(input.password, BCRYPT_ROUNDS);

  return sequelize.transaction(async (transaction) => {
    const role = await Role.findOne({ where: { code: SELF_REGISTRATION_ROLE }, transaction });
    if (!role) throw httpError(500, 'The Read-Only Viewer role is missing. Run npm run migrate.');
    if (await User.findOne({ where: { [Op.or]: [{ username: data.username }, { email: data.email }] }, transaction })) {
      throw httpError(409, 'That username or email is already registered.');
    }
    const user = await User.create({
      fullName: data.fullName, username: data.username, email: data.email, roleId: role.id,
      passwordHash, isActive: false, passwordChangedAt: new Date()
    }, { transaction });
    await recordInternalEvent({
      user: { id: user.id, username: user.username, roleCode: role.code }, req, action: 'ACCOUNT_CREATED', module: 'Authentication',
      entity: { type: 'User', id: user.username },
      description: `Self-registration request from ${user.username}; awaiting administrator approval`,
      after: { fullName: user.fullName, username: user.username, email: user.email, role: role.code, isActive: false },
      metadata: { selfRegistered: true }, transaction
    });
    return user;
  });
};

/** Accounts that registered themselves (or were created inactive) and have never signed in. */
export const pendingApprovalCount = () => User.count({ where: { isActive: false, lastLoginAt: null } });

export const updateUser = async (id, input, actor, req) => sequelize.transaction(async (transaction) => {
  const user = await User.findByPk(id, { include: [{ model: Role, as: 'role' }], transaction, lock: transaction.LOCK.UPDATE });
  if (!user) throw httpError(404, 'User not found.');
  const data = cleanInput({ ...input, username: user.username });
  if (!data.fullName) throw httpError(400, 'Full name is required.');
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(data.email)) throw httpError(400, 'A valid email address is required.');
  if (data.email !== user.email && await User.findOne({ where: { email: data.email, id: { [Op.ne]: user.id } }, transaction })) throw httpError(409, 'Email is already in use.');
  const newRole = await Role.findByPk(data.roleId, { transaction });
  if (!newRole) throw httpError(400, 'Select a valid role.');
  if (!newRole.canAccessDashboard) throw httpError(400, `${newRole.name} cannot be assigned to a person.`);

  const roleChanged = newRole.id !== user.roleId;
  if (roleChanged && user.role.code === 'SYSTEM_ADMIN') {
    if (user.id === actor.id) throw httpError(400, 'You cannot remove your own administrator role.');
    if (await activeAdminCount(transaction) <= 1) throw httpError(400, 'At least one active System Administrator must remain.');
  }
  const before = { fullName: user.fullName, email: user.email };
  const after = { fullName: data.fullName, email: data.email };
  const previousRole = user.role.code;
  await user.update({ fullName: data.fullName, email: data.email, roleId: newRole.id }, { transaction });

  if (before.fullName !== after.fullName || before.email !== after.email) {
    await recordInternalEvent({
      user: actor, req, action: 'ACCOUNT_MODIFIED', module: 'User Management', entity: { type: 'User', id: user.username },
      description: `Modified account details for ${user.username}`, before, after, transaction
    });
  }
  if (roleChanged) {
    await recordInternalEvent({
      user: actor, req, action: 'ROLE_CHANGED', module: 'User Management', entity: { type: 'User', id: user.username },
      description: `Changed role of ${user.username} from ${previousRole} to ${newRole.code}`,
      before: { role: previousRole }, after: { role: newRole.code }, severity: newRole.code === 'SYSTEM_ADMIN' ? 'HIGH' : 'MEDIUM', transaction
    });
  }
  return user;
});

export const setActive = async (id, active, actor, req) => sequelize.transaction(async (transaction) => {
  const user = await User.findByPk(id, { include: [{ model: Role, as: 'role' }], transaction, lock: transaction.LOCK.UPDATE });
  if (!user) throw httpError(404, 'User not found.');
  if (user.isActive === active) return user;
  if (!active && user.id === actor.id) throw httpError(400, 'You cannot deactivate your own account.');
  if (!active && user.role.code === 'SYSTEM_ADMIN' && await activeAdminCount(transaction) <= 1) throw httpError(400, 'At least one active System Administrator must remain.');
  await user.update({ isActive: active, ...(active ? { failedLoginAttempts: 0, lockedUntil: null } : {}) }, { transaction });
  await recordInternalEvent({
    user: actor, req, action: active ? 'ACCOUNT_ACTIVATED' : 'ACCOUNT_DEACTIVATED', module: 'User Management', entity: { type: 'User', id: user.username },
    description: `${active ? 'Activated' : 'Deactivated'} account ${user.username}`, before: { isActive: !active }, after: { isActive: active }, transaction
  });
  return user;
});

export const adminResetPassword = async (id, password, actor, req) => {
  const issue = validatePassword(password);
  if (issue) throw httpError(400, issue);
  return sequelize.transaction(async (transaction) => {
    const user = await User.findByPk(id, { transaction, lock: transaction.LOCK.UPDATE });
    if (!user) throw httpError(404, 'User not found.');
    await user.update({ passwordHash: await bcrypt.hash(password, BCRYPT_ROUNDS), passwordChangedAt: new Date(), failedLoginAttempts: 0, lockedUntil: null }, { transaction });
    await recordInternalEvent({
      user: actor, req, action: 'PASSWORD_CHANGED', module: 'User Management', entity: { type: 'User', id: user.username },
      description: `Administrator reset the password for ${user.username}`, metadata: { resetBy: actor.username }, transaction
    });
    return user;
  });
};

export const unlockUser = async (id, actor, req) => sequelize.transaction(async (transaction) => {
  const user = await User.findByPk(id, { transaction, lock: transaction.LOCK.UPDATE });
  if (!user) throw httpError(404, 'User not found.');
  await user.update({ failedLoginAttempts: 0, lockedUntil: null }, { transaction });
  await recordInternalEvent({
    user: actor, req, action: 'ACCOUNT_MODIFIED', module: 'User Management', entity: { type: 'User', id: user.username },
    description: `Unlocked account ${user.username}`, before: { locked: true }, after: { locked: false }, transaction
  });
  return user;
});

export const updateRolePermissions = async (roleId, permissions, actor, req) => sequelize.transaction(async (transaction) => {
  const role = await Role.findByPk(roleId, { transaction, lock: transaction.LOCK.UPDATE });
  if (!role) throw httpError(404, 'Role not found.');
  if (role.code === 'SYSTEM_ADMIN') throw httpError(400, 'System Administrator permissions are fixed to prevent lock-out.');
  if (!role.canAccessDashboard) throw httpError(400, 'Integration Service Accounts have no dashboard permissions.');
  const next = [...new Set([].concat(permissions || []).filter((p) => PERMISSIONS[p]))].sort();
  const prev = [...(role.permissions || [])].sort();
  if (JSON.stringify(prev) === JSON.stringify(next)) return role;
  await role.update({ permissions: next }, { transaction });
  await recordInternalEvent({
    user: actor, req, action: 'PERMISSION_CHANGED', module: 'User Management', entity: { type: 'Role', id: role.code },
    description: `Updated permissions of role ${role.code}: +${next.filter((p) => !prev.includes(p)).join(', ') || 'none'} / -${prev.filter((p) => !next.includes(p)).join(', ') || 'none'}`,
    before: { permissions: prev }, after: { permissions: next }, severity: 'MEDIUM', transaction
  });
  return role;
});
