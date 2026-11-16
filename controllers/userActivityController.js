import { SourceSystem } from '../models/index.js';
import { listActors, monitoringOverview, userProfile } from '../services/userActivityService.js';
import { parsePagination, buildPagination } from '../utils/pagination.js';
import { sequelize } from '../models/index.js';

export const activityIndex = async (req, res) => {
  const filters = Object.fromEntries(['sourceSystemId', 'search', 'role', 'from', 'to', 'sort', 'includeInternal'].filter((k) => req.query[k]).map((k) => [k, String(req.query[k])]));
  const { page, limit, offset } = parsePagination(req.query, { defaultLimit: 25 });
  const [{ rows, count }, overview, sources, roles] = await Promise.all([
    listActors(filters, { limit, offset }),
    monitoringOverview(),
    SourceSystem.findAll({ attributes: ['id', 'name', 'isInternal'], order: [['isInternal', 'ASC'], ['name', 'ASC']], raw: true }),
    sequelize.query('SELECT DISTINCT actorRole AS v FROM audit_logs WHERE actorRole IS NOT NULL ORDER BY v LIMIT 200', { type: sequelize.QueryTypes.SELECT })
  ]);
  res.render('user-activity/index', {
    title: 'User Activity',
    actors: rows.map((r) => ({ ...r, link: `/user-activity/profile?sourceSystemId=${r.sourceSystemId}&user=${encodeURIComponent(r.userKey)}` })),
    overview, sources, roles: roles.map((r) => r.v), filters,
    pagination: buildPagination({ page, limit, total: count, query: filters, basePath: '/user-activity' })
  });
};

export const activityProfile = async (req, res) => {
  const profile = await userProfile(req.query.sourceSystemId, String(req.query.user || ''));
  if (!profile) return res.status(404).render('errors/404', { title: 'Not Found', message: 'No activity found for this user on the selected source system.' });
  return res.render('user-activity/profile', { title: `User Activity · ${profile.identity.actorUsername || profile.userKey}`, ...profile });
};
