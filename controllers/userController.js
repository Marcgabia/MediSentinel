import { Role } from '../models/index.js';
import {
  listUsers, getUser, listRoles, createUser, updateUser, setActive, adminResetPassword, unlockUser, updateRolePermissions
} from '../services/userService.js';
import { PERMISSIONS } from '../utils/auditConstants.js';

const assignableRoles = () => Role.findAll({ where: { canAccessDashboard: true }, order: [['id', 'ASC']], raw: true });

export const usersIndex = async (req, res) => {
  const filters = Object.fromEntries(['search', 'roleId', 'status'].filter((k) => req.query[k]).map((k) => [k, String(req.query[k])]));
  const [users, roles] = await Promise.all([listUsers(filters), listRoles()]);
  res.render('users/index', { title: 'User Management', users, roles, filters });
};

export const newUserForm = async (req, res) => {
  res.render('users/form', { title: 'New User', account: {}, isNew: true, roles: await assignableRoles() });
};

export const createUserAction = async (req, res) => {
  const user = await createUser(req.body, req.user, req);
  req.flash('success_msg', `Account ${user.username} created.`);
  res.redirect('/users');
};

export const editUserForm = async (req, res) => {
  const account = await getUser(req.params.id);
  if (!account) return res.status(404).render('errors/404', { title: 'Not Found' });
  return res.render('users/form', { title: `Edit ${account.username}`, account, isNew: false, roles: await assignableRoles(), isSelf: account.id === req.user.id });
};

export const updateUserAction = async (req, res) => {
  const user = await updateUser(req.params.id, req.body, req.user, req);
  req.flash('success_msg', `Account ${user.username} updated.`);
  res.redirect('/users');
};

export const toggleActiveAction = async (req, res) => {
  const user = await setActive(req.params.id, req.body.active === 'true', req.user, req);
  req.flash('success_msg', `Account ${user.username} ${user.isActive ? 'activated' : 'deactivated'}.`);
  res.redirect('/users');
};

export const resetPasswordAction = async (req, res) => {
  const user = await adminResetPassword(req.params.id, req.body.password, req.user, req);
  req.flash('success_msg', `Password reset for ${user.username}.`);
  res.redirect(`/users/${user.id}/edit`);
};

export const unlockAction = async (req, res) => {
  const user = await unlockUser(req.params.id, req.user, req);
  req.flash('success_msg', `Account ${user.username} unlocked.`);
  res.redirect('/users');
};

export const rolesPage = async (req, res) => {
  const roles = await listRoles();
  const permissions = Object.entries(PERMISSIONS).map(([code, label]) => ({ code, label }));
  res.render('users/roles', {
    title: 'Roles & Permissions',
    permissions,
    roles: roles.map((r) => ({ ...r, editable: r.canAccessDashboard && r.code !== 'SYSTEM_ADMIN', grants: permissions.map((p) => ({ ...p, granted: (r.permissions || []).includes(p.code) })) }))
  });
};

export const updateRoleAction = async (req, res) => {
  const role = await updateRolePermissions(req.params.id, req.body.permissions, req.user, req);
  req.flash('success_msg', `Permissions for ${role.name} saved.`);
  res.redirect('/users/roles');
};
