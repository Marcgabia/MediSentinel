import { Op } from 'sequelize';
import {
  sequelize, SourceSystem, IntegrationCredential, IntegrationLog, AuditLog, AuditEventRegistry, AuditEventType, User
} from '../models/index.js';
import { encryptSecret, fingerprintSecret, generateKeyId, generateSecret } from '../utils/secretBox.js';
import { computeHealth, isConnected } from '../utils/integrationHealth.js';
import { getSettingsMap } from './settingsService.js';
import { notifyPermissionThrottled } from './notificationService.js';
import { SOURCE_SYSTEM_STATUSES, SOURCE_ENVIRONMENTS } from '../utils/auditConstants.js';

const FAILURE_OUTCOMES = ['REJECTED_AUTH', 'REJECTED_FORBIDDEN', 'REJECTED_VALIDATION', 'CONFLICT', 'RATE_LIMITED', 'ERROR'];
const httpError = (status, message) => Object.assign(new Error(message), { status });

// ---------------------------------------------------------------------------
// Health & statistics
// ---------------------------------------------------------------------------
const outcomeCountsSince = async (since, sourceSystemId) => {
  const where = { createdAt: { [Op.gte]: since } };
  if (sourceSystemId) where.sourceSystemId = sourceSystemId;
  const rows = await IntegrationLog.findAll({
    where,
    attributes: ['sourceSystemId', 'outcome', [sequelize.fn('COUNT', sequelize.col('id')), 'count']],
    group: ['sourceSystemId', 'outcome'],
    raw: true
  });
  const bySource = {};
  rows.forEach((r) => {
    const key = r.sourceSystemId ?? 'unknown';
    bySource[key] ||= {};
    bySource[key][r.outcome] = Number(r.count);
  });
  return bySource;
};

const sumOutcomes = (counts = {}, outcomes) => outcomes.reduce((s, o) => s + (counts[o] || 0), 0);

export const healthConfig = async () => {
  const s = await getSettingsMap(['integration.staleAfterMinutes', 'integration.degradedErrorRate']);
  return { staleAfterMinutes: s['integration.staleAfterMinutes'], degradedErrorRate: s['integration.degradedErrorRate'] };
};

/** All source systems with derived health, counts and credential summary. */
export const listSourcesWithHealth = async ({ includeInternal = true } = {}) => {
  const where = includeInternal ? {} : { isInternal: false };
  const [sources, hourCounts, dayCounts, eventCounts, credentialCounts, cfg] = await Promise.all([
    SourceSystem.findAll({ where, order: [['isInternal', 'ASC'], ['name', 'ASC']], raw: true }),
    outcomeCountsSince(new Date(Date.now() - 3600000)),
    outcomeCountsSince(new Date(Date.now() - 86400000)),
    AuditLog.findAll({ attributes: ['sourceSystemId', [sequelize.fn('COUNT', sequelize.col('id')), 'count']], group: ['sourceSystemId'], raw: true }),
    IntegrationCredential.findAll({ where: { status: 'ACTIVE' }, attributes: ['sourceSystemId', [sequelize.fn('COUNT', sequelize.col('id')), 'count']], group: ['sourceSystemId'], raw: true }),
    healthConfig()
  ]);
  const eventsBySource = Object.fromEntries(eventCounts.map((r) => [r.sourceSystemId, Number(r.count)]));
  const credsBySource = Object.fromEntries(credentialCounts.map((r) => [r.sourceSystemId, Number(r.count)]));
  return sources.map((source) => {
    const hour = hourCounts[source.id] || {};
    const day = dayCounts[source.id] || {};
    const requestsLastHour = Object.values(hour).reduce((a, b) => a + b, 0) - (hour.CONNECTION_TEST_OK || 0) - (hour.CONNECTION_TEST_FAILED || 0);
    const failuresLastHour = sumOutcomes(hour, FAILURE_OUTCOMES);
    const health = computeHealth(source, { requestsLastHour, failuresLastHour }, cfg);
    return {
      ...source,
      health,
      connected: isConnected(health),
      totalEvents: eventsBySource[source.id] || 0,
      activeCredentials: credsBySource[source.id] || 0,
      last24h: {
        accepted: day.ACCEPTED || 0,
        duplicates: day.DUPLICATE || 0,
        invalid: day.REJECTED_VALIDATION || 0,
        authFailures: day.REJECTED_AUTH || 0,
        failed: sumOutcomes(day, FAILURE_OUTCOMES),
        heartbeats: day.HEARTBEAT || 0
      },
      pendingReported: source.lastHeartbeatPayload?.pendingEvents ?? null
    };
  });
};

export const integrationOverview = async () => {
  const sources = await listSourcesWithHealth({ includeInternal: false });
  const since24 = new Date(Date.now() - 86400000);
  const [unknownAuthFailures, delay, recentErrors, failedRetries] = await Promise.all([
    IntegrationLog.count({ where: { sourceSystemId: null, createdAt: { [Op.gte]: since24 } } }),
    IntegrationLog.findOne({
      where: { outcome: 'ACCEPTED', createdAt: { [Op.gte]: since24 }, deliveryDelayMs: { [Op.ne]: null } },
      attributes: [[sequelize.fn('AVG', sequelize.col('deliveryDelayMs')), 'avg'], [sequelize.fn('MAX', sequelize.col('deliveryDelayMs')), 'max']],
      raw: true
    }),
    IntegrationLog.findAll({
      where: { outcome: { [Op.in]: FAILURE_OUTCOMES.concat(['CONNECTION_TEST_FAILED']) } },
      include: [{ model: SourceSystem, as: 'sourceSystem', attributes: ['id', 'name'] }],
      order: [['createdAt', 'DESC']], limit: 15
    }),
    IntegrationLog.count({ where: { deliveryAttempt: { [Op.gt]: 1 }, outcome: { [Op.in]: FAILURE_OUTCOMES }, createdAt: { [Op.gte]: since24 } } })
  ]);
  const totals = sources.reduce((acc, s) => {
    acc.accepted += s.last24h.accepted;
    acc.failed += s.last24h.failed;
    acc.invalid += s.last24h.invalid;
    acc.duplicates += s.last24h.duplicates;
    if (s.pendingReported !== null) { acc.pending += Number(s.pendingReported) || 0; acc.pendingReporters += 1; }
    return acc;
  }, { accepted: 0, failed: 0, invalid: 0, duplicates: 0, pending: 0, pendingReporters: 0 });
  return {
    sources,
    connected: sources.filter((s) => s.connected).length,
    disconnected: sources.filter((s) => s.health.status === 'STALE').length,
    neverConnected: sources.filter((s) => s.health.status === 'NEVER_CONNECTED').length,
    suspended: sources.filter((s) => s.health.status === 'SUSPENDED').length,
    degraded: sources.filter((s) => s.health.status === 'DEGRADED').length,
    totals: { ...totals, failed: totals.failed + unknownAuthFailures, unknownAuthFailures, failedRetries },
    avgDelayMs: delay?.avg !== null && delay?.avg !== undefined ? Math.round(Number(delay.avg)) : null,
    maxDelayMs: delay?.max !== null && delay?.max !== undefined ? Number(delay.max) : null,
    recentErrors: recentErrors.map((e) => e.get({ plain: true }))
  };
};

export const getSourceDetail = async (id) => {
  const source = await SourceSystem.findByPk(id, { include: [{ model: User, as: 'registeredBy', attributes: ['id', 'fullName'] }] });
  if (!source) return null;
  const plain = source.get({ plain: true });
  const [withHealth] = (await listSourcesWithHealth()).filter((s) => s.id === plain.id);
  const [credentials, registry, recentLogs, eventTypes] = await Promise.all([
    IntegrationCredential.findAll({
      where: { sourceSystemId: id },
      include: [{ model: User, as: 'createdBy', attributes: ['fullName'] }, { model: User, as: 'revokedBy', attributes: ['fullName'] }],
      order: [['status', 'ASC'], ['createdAt', 'DESC']]
    }),
    AuditEventRegistry.findAll({ where: { sourceSystemId: id }, include: [{ model: AuditEventType, as: 'eventType' }], order: [['id', 'ASC']] }),
    IntegrationLog.findAll({ where: { sourceSystemId: id }, order: [['createdAt', 'DESC']], limit: 15, raw: true }),
    AuditEventType.findAll({ where: { isActive: true }, order: [['category', 'ASC'], ['name', 'ASC']], raw: true })
  ]);
  const registeredIds = new Set(registry.map((r) => r.eventTypeId));
  return {
    source: { ...plain, ...withHealth },
    credentials: credentials.map((c) => c.get({ plain: true })),
    registry: registry.map((r) => r.get({ plain: true })),
    availableEventTypes: eventTypes.filter((t) => !registeredIds.has(t.id)),
    recentLogs
  };
};

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------
const validUrl = (value) => {
  if (!value) return null;
  try {
    const url = new URL(value);
    if (!['http:', 'https:'].includes(url.protocol)) throw new Error();
    return url.toString();
  } catch {
    throw httpError(400, `"${value}" is not a valid http(s) URL.`);
  }
};

const sanitizeSourceInput = (input, { isNew }) => {
  const out = {
    name: String(input.name || '').trim(),
    description: String(input.description || '').trim() || null,
    apiEndpoint: validUrl(String(input.apiEndpoint || '').trim()),
    healthCheckUrl: validUrl(String(input.healthCheckUrl || '').trim()),
    environment: SOURCE_ENVIRONMENTS.includes(input.environment) ? input.environment : 'PRODUCTION'
  };
  if (!out.name || out.name.length > 150) throw httpError(400, 'System name is required (max 150 characters).');
  if (isNew) {
    out.systemCode = String(input.systemCode || '').trim().toUpperCase();
    if (!/^[A-Z][A-Z0-9_]{2,63}$/.test(out.systemCode)) throw httpError(400, 'System code must be 3–64 characters: uppercase letters, digits and underscores, starting with a letter.');
  }
  return out;
};

export const registerSource = async (input, userId, transaction) => {
  const data = sanitizeSourceInput(input, { isNew: true });
  if (await SourceSystem.findOne({ where: { systemCode: data.systemCode }, transaction })) {
    throw httpError(409, `A source system with code ${data.systemCode} already exists.`);
  }
  return SourceSystem.create({ ...data, status: 'PENDING', registeredByUserId: userId, registeredAt: new Date() }, { transaction });
};

export const updateSource = async (id, input, transaction) => {
  const source = await SourceSystem.findByPk(id, { transaction });
  if (!source) throw httpError(404, 'Source system not found.');
  if (source.isInternal) throw httpError(400, 'The internal MediSentinel source cannot be modified.');
  const data = sanitizeSourceInput(input, { isNew: false });
  if (input.status) {
    if (!SOURCE_SYSTEM_STATUSES.includes(input.status)) throw httpError(400, 'Invalid status.');
    data.status = input.status;
  }
  const fields = Object.keys(data);
  const before = Object.fromEntries(fields.map((f) => [f, source[f]]));
  await source.update(data, { transaction });
  const after = Object.fromEntries(fields.map((f) => [f, source[f]]));
  return { source, before, after };
};

// ---------------------------------------------------------------------------
// Credentials
// ---------------------------------------------------------------------------
export const issueCredential = async (sourceSystemId, label, userId, transaction) => {
  const source = await SourceSystem.findByPk(sourceSystemId, { transaction });
  if (!source) throw httpError(404, 'Source system not found.');
  if (source.isInternal) throw httpError(400, 'The internal source does not use API credentials.');
  if (source.status === 'RETIRED') throw httpError(400, 'Cannot issue credentials for a retired source system.');
  const keyId = generateKeyId();
  const secret = generateSecret();
  const credential = await IntegrationCredential.create({
    sourceSystemId,
    keyId,
    secretCiphertext: encryptSecret(secret),
    secretFingerprint: fingerprintSecret(secret),
    label: String(label || '').trim().slice(0, 120) || null,
    createdByUserId: userId,
    status: 'ACTIVE'
  }, { transaction });
  // The plaintext secret is returned exactly once to the caller and never stored or logged.
  return { credential, secret, source };
};

export const revokeCredential = async (credentialId, userId, transaction) => {
  const credential = await IntegrationCredential.findByPk(credentialId, { transaction });
  if (!credential) throw httpError(404, 'Credential not found.');
  if (credential.status === 'REVOKED') throw httpError(400, 'Credential is already revoked.');
  await credential.update({ status: 'REVOKED', revokedAt: new Date(), revokedByUserId: userId }, { transaction });
  return credential;
};

// ---------------------------------------------------------------------------
// Heartbeat & connection test
// ---------------------------------------------------------------------------
export const recordHeartbeat = async (source, body = {}) => {
  const now = new Date();
  const payload = {
    pendingEvents: Number.isFinite(Number(body.pendingEvents)) ? Math.max(0, Math.floor(Number(body.pendingEvents))) : null,
    failedDeliveries: Number.isFinite(Number(body.failedDeliveries)) ? Math.max(0, Math.floor(Number(body.failedDeliveries))) : null,
    oldestPendingAt: body.oldestPendingAt && !Number.isNaN(new Date(body.oldestPendingAt).getTime()) ? new Date(body.oldestPendingAt).toISOString() : null,
    version: body.version ? String(body.version).slice(0, 40) : null,
    status: body.status ? String(body.status).slice(0, 40) : null,
    reportedAt: now.toISOString()
  };
  const update = { lastHeartbeatAt: now, lastSuccessfulConnectionAt: now, lastHeartbeatPayload: payload };
  if (source.status === 'PENDING') update.status = 'ACTIVE';
  await SourceSystem.update(update, { where: { id: source.id } });
  return payload;
};

export const testConnection = async (sourceSystemId) => {
  const source = await SourceSystem.findByPk(sourceSystemId);
  if (!source) throw httpError(404, 'Source system not found.');
  const { 'integration.connectionTestTimeoutMs': timeoutMs } = await getSettingsMap(['integration.connectionTestTimeoutMs']);
  const testedAt = new Date();
  let result;
  if (!source.healthCheckUrl) {
    result = { ok: false, status: 'NOT_CONFIGURED', message: 'No health-check URL is registered for this system. Add one to enable outbound connection tests.', testedAt };
  } else {
    const started = Date.now();
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs || 5000);
    try {
      const response = await fetch(source.healthCheckUrl, { method: 'GET', signal: controller.signal, redirect: 'manual', headers: { 'User-Agent': 'MediSentinel-ConnectionTest/1.0' } });
      const latencyMs = Date.now() - started;
      result = response.ok
        ? { ok: true, status: 'REACHABLE', httpStatus: response.status, latencyMs, message: `Health endpoint responded HTTP ${response.status} in ${latencyMs} ms.`, testedAt }
        : { ok: false, status: 'HTTP_ERROR', httpStatus: response.status, latencyMs, message: `Health endpoint responded HTTP ${response.status}.`, testedAt };
    } catch (error) {
      result = { ok: false, status: error.name === 'AbortError' ? 'TIMEOUT' : 'UNREACHABLE', latencyMs: Date.now() - started, message: error.name === 'AbortError' ? `No response within ${timeoutMs} ms.` : `Connection failed: ${error.cause?.code || error.message}`, testedAt };
    } finally {
      clearTimeout(timer);
    }
  }
  await source.update({ lastConnectionTestAt: testedAt, lastConnectionTestResult: result });
  await IntegrationLog.create({
    sourceSystemId: source.id,
    endpoint: source.healthCheckUrl || '(not configured)',
    method: 'GET',
    httpStatus: result.httpStatus || 0,
    outcome: result.ok ? 'CONNECTION_TEST_OK' : 'CONNECTION_TEST_FAILED',
    errorCode: result.ok ? null : result.status,
    errorDetails: result.ok ? null : [{ message: result.message }],
    processingMs: result.latencyMs ?? null,
    createdAt: new Date()
  });
  if (!result.ok && result.status !== 'NOT_CONFIGURED') {
    notifyPermissionThrottled(`conntest:${source.id}`, 30 * 60000, 'integrations.view', {
      type: 'FAILED_INTEGRATION',
      severity: 'HIGH',
      title: `Connection test failed: ${source.name}`,
      message: result.message,
      link: `/integrations/${source.id}`
    }).catch(() => {});
  }
  return { source, result };
};

// ---------------------------------------------------------------------------
// Event registry (expected coverage)
// ---------------------------------------------------------------------------
export const addRegistryEntry = async (sourceSystemId, { eventTypeId, sourceModule, isRequired, notes }, userId, transaction) => {
  const [source, type] = await Promise.all([SourceSystem.findByPk(sourceSystemId, { transaction }), AuditEventType.findByPk(eventTypeId, { transaction })]);
  if (!source || !type) throw httpError(404, 'Source system or event type not found.');
  const existing = await AuditEventRegistry.findOne({ where: { sourceSystemId, eventTypeId }, transaction });
  if (existing) throw httpError(409, `${type.name} is already registered for ${source.name}.`);
  const entry = await AuditEventRegistry.create({
    sourceSystemId, eventTypeId,
    sourceModule: String(sourceModule || '').trim().slice(0, 100) || null,
    isRequired: isRequired === undefined ? true : isRequired === 'on' || isRequired === true || isRequired === 'true',
    notes: String(notes || '').trim().slice(0, 500) || null,
    createdByUserId: userId
  }, { transaction });
  return { entry, source, type };
};

export const removeRegistryEntry = async (entryId, transaction) => {
  const entry = await AuditEventRegistry.findByPk(entryId, { include: [{ model: AuditEventType, as: 'eventType' }, { model: SourceSystem, as: 'sourceSystem' }], transaction });
  if (!entry) throw httpError(404, 'Registry entry not found.');
  const snapshot = { sourceSystemId: entry.sourceSystemId, source: entry.sourceSystem.name, eventType: entry.eventType.code, sourceModule: entry.sourceModule };
  await entry.destroy({ transaction });
  return snapshot;
};

// ---------------------------------------------------------------------------
// Integration logs
// ---------------------------------------------------------------------------
export const listIntegrationLogs = async (q, { limit, offset }) => {
  const where = {};
  if (q.sourceSystemId === 'unknown') where.sourceSystemId = null;
  else if (q.sourceSystemId) where.sourceSystemId = Number(q.sourceSystemId);
  if (q.outcome) where.outcome = q.outcome;
  if (q.eventId) where.eventId = q.eventId;
  if (q.from) where.createdAt = { ...(where.createdAt || {}), [Op.gte]: new Date(q.from) };
  if (q.to) where.createdAt = { ...(where.createdAt || {}), [Op.lte]: new Date(`${q.to}T23:59:59.999`) };
  const { rows, count } = await IntegrationLog.findAndCountAll({
    where,
    include: [{ model: SourceSystem, as: 'sourceSystem', attributes: ['id', 'name', 'systemCode'] }],
    order: [['createdAt', 'DESC'], ['id', 'DESC']],
    limit, offset
  });
  return { rows: rows.map((r) => r.get({ plain: true })), count };
};
