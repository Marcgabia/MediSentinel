import { sequelize, SourceSystem } from '../models/index.js';
import {
  listSourcesWithHealth, integrationOverview, getSourceDetail, registerSource, updateSource, issueCredential,
  revokeCredential, testConnection, addRegistryEntry, removeRegistryEntry, listIntegrationLogs
} from '../services/integrationService.js';
import { recordInternalEvent } from '../services/auditService.js';
import { parsePagination, buildPagination } from '../utils/pagination.js';
import { hasPermission } from '../middleware/permissions.js';
import { SOURCE_ENVIRONMENTS, SOURCE_SYSTEM_STATUSES, INTEGRATION_LOG_OUTCOMES } from '../utils/auditConstants.js';
import { applyPosRegistryTemplate } from '../utils/seedReferenceData.js';
import { invalidateEventTypeCache } from '../services/auditIngestionService.js';

const baseUrl = (req) => process.env.PUBLIC_BASE_URL || `${req.protocol}://${req.get('host')}`;

export const integrationsIndex = async (req, res) => {
  const sources = await listSourcesWithHealth();
  res.render('integrations/index', {
    title: 'System Integrations',
    sources,
    canManage: hasPermission(req.user, 'integrations.manage')
  });
};

export const integrationsMonitor = async (req, res) => {
  const overview = await integrationOverview();
  res.render('integrations/monitor', { title: 'Integration Monitoring', overview, canManage: hasPermission(req.user, 'integrations.manage') });
};

export const integrationLogs = async (req, res) => {
  const filters = Object.fromEntries(['sourceSystemId', 'outcome', 'eventId', 'from', 'to'].filter((k) => req.query[k]).map((k) => [k, String(req.query[k])]));
  const { page, limit, offset } = parsePagination(req.query, { defaultLimit: 50 });
  const [{ rows, count }, sources] = await Promise.all([
    listIntegrationLogs(filters, { limit, offset }),
    SourceSystem.findAll({ where: { isInternal: false }, attributes: ['id', 'name'], order: [['name', 'ASC']], raw: true })
  ]);
  res.render('integrations/logs', {
    title: 'Integration Logs', logs: rows, filters, sources, outcomes: INTEGRATION_LOG_OUTCOMES,
    pagination: buildPagination({ page, limit, total: count, query: filters, basePath: '/integrations/logs' })
  });
};

export const newSourceForm = (req, res) => {
  res.render('integrations/form', { title: 'Register Source System', source: { environment: 'PRODUCTION' }, isNew: true, environments: SOURCE_ENVIRONMENTS, statuses: SOURCE_SYSTEM_STATUSES });
};

export const createSource = async (req, res) => {
  const source = await sequelize.transaction(async (transaction) => {
    const created = await registerSource(req.body, req.user.id, transaction);
    await recordInternalEvent({
      user: req.user, req, action: 'SOURCE_SYSTEM_REGISTERED', module: 'Integrations', entity: { type: 'SourceSystem', id: created.systemCode },
      description: `Registered source system ${created.name} (${created.systemCode})`,
      after: { systemCode: created.systemCode, name: created.name, environment: created.environment, apiEndpoint: created.apiEndpoint, healthCheckUrl: created.healthCheckUrl },
      transaction
    });
    return created;
  });
  req.flash('success_msg', `${source.name} registered. Create an API key to connect it.`);
  res.redirect(`/integrations/${source.id}`);
};

export const sourceDetail = async (req, res) => {
  const detail = await getSourceDetail(req.params.id);
  if (!detail) return res.status(404).render('errors/404', { title: 'Not Found', message: 'Source system not found.' });
  return res.render('integrations/detail', {
    title: detail.source.name,
    ...detail,
    apiBase: `${baseUrl(req)}/api/v1`,
    canManage: hasPermission(req.user, 'integrations.manage'),
    canManageCredentials: hasPermission(req.user, 'credentials.manage'),
    canManageRegistry: hasPermission(req.user, 'qa.manage') || hasPermission(req.user, 'integrations.manage')
  });
};

export const editSourceForm = async (req, res) => {
  const source = await SourceSystem.findByPk(req.params.id, { raw: true });
  if (!source || source.isInternal) return res.status(404).render('errors/404', { title: 'Not Found' });
  return res.render('integrations/form', { title: `Edit ${source.name}`, source, isNew: false, environments: SOURCE_ENVIRONMENTS, statuses: SOURCE_SYSTEM_STATUSES });
};

export const saveSource = async (req, res) => {
  const source = await sequelize.transaction(async (transaction) => {
    const { source: updated, before, after } = await updateSource(req.params.id, req.body, transaction);
    const changed = Object.keys(after).filter((k) => String(before[k] ?? '') !== String(after[k] ?? ''));
    if (changed.length) {
      await recordInternalEvent({
        user: req.user, req, action: 'SOURCE_SYSTEM_UPDATED', module: 'Integrations', entity: { type: 'SourceSystem', id: updated.systemCode },
        description: `Updated source system ${updated.name}: ${changed.join(', ')}`,
        before: Object.fromEntries(changed.map((k) => [k, before[k] ?? null])), after: Object.fromEntries(changed.map((k) => [k, after[k] ?? null])),
        severity: changed.includes('status') ? 'MEDIUM' : undefined, transaction
      });
    }
    return updated;
  });
  req.flash('success_msg', 'Saved.');
  res.redirect(`/integrations/${source.id}`);
};

export const createCredential = async (req, res) => {
  const { credential, secret, source } = await sequelize.transaction(async (transaction) => {
    const issued = await issueCredential(Number(req.params.id), req.body.label, req.user.id, transaction);
    await recordInternalEvent({
      user: req.user, req, action: 'CREDENTIAL_ISSUED', module: 'Integrations', entity: { type: 'IntegrationCredential', id: issued.credential.keyId },
      description: `Issued API credential ${issued.credential.keyId} for ${issued.source.name}`,
      metadata: { sourceSystem: issued.source.systemCode, label: issued.credential.label, secretFingerprint: issued.credential.secretFingerprint.slice(0, 12) },
      transaction
    });
    return issued;
  });
  // Rendered directly (never redirected / flashed / cached) so the secret is shown exactly once.
  res.set('Cache-Control', 'no-store');
  res.render('integrations/credential-issued', {
    title: 'Credential Issued', source: source.get({ plain: true }), keyId: credential.keyId, secret, label: credential.label, apiBase: `${baseUrl(req)}/api/v1`
  });
};

export const revokeCredentialAction = async (req, res) => {
  const credential = await sequelize.transaction(async (transaction) => {
    const revoked = await revokeCredential(Number(req.params.credentialId), req.user.id, transaction);
    await recordInternalEvent({
      user: req.user, req, action: 'CREDENTIAL_REVOKED', module: 'Integrations', entity: { type: 'IntegrationCredential', id: revoked.keyId },
      description: `Revoked API credential ${revoked.keyId}`, metadata: { sourceSystemId: revoked.sourceSystemId }, transaction
    });
    return revoked;
  });
  req.flash('success_msg', `API key ${credential.keyId} revoked.`);
  res.redirect(`/integrations/${credential.sourceSystemId}`);
};

export const runConnectionTest = async (req, res) => {
  const { source, result } = await testConnection(Number(req.params.id));
  await recordInternalEvent({
    user: req.user, req, action: 'SOURCE_SYSTEM_UPDATED', module: 'Integrations', entity: { type: 'SourceSystem', id: source.systemCode },
    description: `Connection test for ${source.name}: ${result.status}`, outcome: result.ok ? 'SUCCESS' : 'FAILURE',
    after: { connectionTest: result.status, httpStatus: result.httpStatus ?? null, latencyMs: result.latencyMs ?? null }
  });
  req.flash(result.ok ? 'success_msg' : 'error_msg', `Connection test: ${result.message}`);
  res.redirect(`/integrations/${source.id}`);
};

export const addRegistry = async (req, res) => {
  const { entry, source, type } = await sequelize.transaction(async (transaction) => {
    const added = await addRegistryEntry(Number(req.params.id), req.body, req.user.id, transaction);
    await recordInternalEvent({
      user: req.user, req, action: 'EVENT_REGISTRY_CHANGED', module: 'Quality Assurance', entity: { type: 'EventRegistry', id: `${added.source.systemCode}:${added.type.code}` },
      description: `Added expected event ${added.type.code} for ${added.source.name}`, metadata: { sourceModule: added.entry.sourceModule, isRequired: added.entry.isRequired }, transaction
    });
    return added;
  });
  req.flash('success_msg', `${type.name} added.`);
  res.redirect(`/integrations/${entry.sourceSystemId}#registry`);
};

/** Register the POS Audit Event Registry as this system's expected events (existing entries kept). */
export const applyPosTemplate = async (req, res) => {
  const source = await SourceSystem.findByPk(Number(req.params.id));
  if (!source || source.isInternal) throw Object.assign(new Error('Source system not found.'), { status: 404 });
  const added = await sequelize.transaction(async (transaction) => {
    const codes = await applyPosRegistryTemplate(source.id, req.user.id, transaction);
    if (codes.length) {
      await recordInternalEvent({
        user: req.user, req, action: 'EVENT_REGISTRY_CHANGED', module: 'Quality Assurance', entity: { type: 'EventRegistry', id: `${source.systemCode}:POS_TEMPLATE` },
        description: `Applied the POS Audit Event Registry to ${source.name} (${codes.length} expected event(s) added)`, metadata: { added: codes }, transaction
      });
    }
    return codes;
  });
  invalidateEventTypeCache();
  req.flash('success_msg', added.length ? `${added.length} POS event type(s) added to the expected events.` : 'All POS event types were already registered.');
  res.redirect(`/integrations/${source.id}#registry`);
};

export const removeRegistry = async (req, res) => {
  const snapshot = await sequelize.transaction(async (transaction) => {
    const removed = await removeRegistryEntry(Number(req.params.entryId), transaction);
    await recordInternalEvent({
      user: req.user, req, action: 'EVENT_REGISTRY_CHANGED', module: 'Quality Assurance', entity: { type: 'EventRegistry', id: `${removed.source}:${removed.eventType}` },
      description: `Removed expected event ${removed.eventType} from ${removed.source}`, metadata: removed, transaction
    });
    return removed;
  });
  req.flash('success_msg', `${snapshot.eventType} removed.`);
  res.redirect(`/integrations/${snapshot.sourceSystemId}#registry`);
};
