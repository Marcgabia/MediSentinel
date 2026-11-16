import { UniqueConstraintError } from 'sequelize';
import { sequelize, AuditLog, AuditEventType, IntegrationLog, SourceSystem } from '../models/index.js';
import { validateEvent } from '../utils/eventValidator.js';
import { normalizeEvent } from '../utils/eventNormalizer.js';
import { computePayloadHash } from '../utils/integrityHelper.js';
import { appendAuditRecord } from './auditIntegrityService.js';
import { evaluateEvent } from './alertService.js';
import { notifyPermission, notifyPermissionThrottled } from './notificationService.js';
import { getSettingsMap } from './settingsService.js';

let eventTypeCache = null;
let eventTypeCacheAt = 0;
export const invalidateEventTypeCache = () => { eventTypeCache = null; };

export const loadEventTypes = async () => {
  if (eventTypeCache && Date.now() - eventTypeCacheAt < 30000) return eventTypeCache;
  const rows = await AuditEventType.findAll({ where: { isActive: true }, raw: true });
  eventTypeCache = new Map(rows.map((r) => [r.code, r]));
  eventTypeCacheAt = Date.now();
  return eventTypeCache;
};

/** Write one row to integration_logs (never throws — logging must not break ingestion). */
export const logIntegration = async (entry) => {
  try {
    return await IntegrationLog.create({ createdAt: new Date(), ...entry });
  } catch (error) {
    console.error('[integration-log] failed to record:', error.message);
    return null;
  }
};

const touchSource = async (sourceSystem, receivedAt) => {
  const update = { lastEventReceivedAt: receivedAt, lastSuccessfulConnectionAt: receivedAt };
  if (sourceSystem.status === 'PENDING') update.status = 'ACTIVE';
  await SourceSystem.update(update, { where: { id: sourceSystem.id } });
};

const afterAccepted = async (auditLog) => {
  await evaluateEvent(auditLog);
  if (auditLog.severity === 'CRITICAL' && auditLog.sourceSystemCode !== 'MEDISENTINEL') {
    await notifyPermission('audit.view', {
      type: 'CRITICAL_AUDIT_ALERT',
      severity: 'CRITICAL',
      title: `Critical event from ${auditLog.sourceSystemName}`,
      message: `${auditLog.actionType} · ${auditLog.description}`.slice(0, 1000),
      link: `/audit/${auditLog.id}`,
      relatedAuditLogId: auditLog.id
    }).catch(() => {});
  }
};

/**
 * Validate, de-duplicate, seal and store one event.
 *
 * @returns {Promise<{ status: 'accepted'|'duplicate'|'conflict'|'rejected', httpStatus: number,
 *                     auditLog?: object, errors?: object[] }>}
 */
export const ingestEvent = async ({
  payload, sourceSystem, credential = null, channel = 'API', context = {}, transaction: outerTransaction = null, skipIntegrationLog = false,
  receivedAt: receivedAtOverride = null // used only by the sample-data seeder to replay history
}) => {
  const startedAt = Date.now();
  const receivedAt = receivedAtOverride || new Date();
  const settings = await getSettingsMap(['integration.timestampToleranceSeconds', 'integration.maxEventAgeDays']);
  const eventTypes = await loadEventTypes();

  const baseLog = {
    sourceSystemId: sourceSystem.id,
    credentialId: credential?.id || null,
    keyId: credential?.keyId || null,
    endpoint: context.endpoint || '/api/v1/audit-events',
    method: context.method || 'POST',
    ipAddress: context.ipAddress || null,
    deliveryAttempt: context.deliveryAttempt || null,
    batchIndex: context.batchIndex ?? null,
    eventId: typeof payload?.eventId === 'string' ? payload.eventId.slice(0, 128) : null,
    actionCode: typeof payload?.action === 'string' ? payload.action.slice(0, 64) : null
  };
  const writeLog = (entry) => (skipIntegrationLog ? null : logIntegration({ ...baseLog, createdAt: receivedAt, processingMs: Date.now() - startedAt, ...entry }));

  // 1. Validation ------------------------------------------------------------
  const validation = validateEvent(payload, {
    eventTypes,
    sourceSystemCode: sourceSystem.systemCode,
    now: receivedAt,
    maxFutureSkewSeconds: settings['integration.timestampToleranceSeconds'],
    maxEventAgeDays: settings['integration.maxEventAgeDays']
  });
  if (!validation.valid) {
    await writeLog({ httpStatus: 422, outcome: 'REJECTED_VALIDATION', errorCode: validation.errors[0].code, errorDetails: validation.errors.slice(0, 25) });
    if (!sourceSystem.isInternal) {
      notifyPermissionThrottled(`invalid:${sourceSystem.id}`, 60 * 60 * 1000, 'integrations.view', {
        type: 'FAILED_EVENT_VALIDATION',
        severity: 'MEDIUM',
        title: `Invalid event submissions from ${sourceSystem.name}`,
        message: `Rejected event ${baseLog.eventId || '(no eventId)'}: ${validation.errors.map((e) => e.message).slice(0, 3).join(' ')}`,
        link: `/integrations/logs?sourceSystemId=${sourceSystem.id}&outcome=REJECTED_VALIDATION`
      }).catch(() => {});
    }
    return { status: 'rejected', httpStatus: 422, errors: validation.errors };
  }

  const payloadHash = computePayloadHash(payload);

  // 2. Idempotency -----------------------------------------------------------
  const checkExisting = async (transaction) => {
    const existing = await AuditLog.findOne({
      where: { sourceSystemId: sourceSystem.id, eventId: payload.eventId },
      attributes: ['id', 'payloadHash', 'receivedAt'],
      transaction
    });
    if (!existing) return null;
    if (existing.payloadHash === payloadHash) {
      return { status: 'duplicate', httpStatus: 200, auditLog: existing.get({ plain: true }) };
    }
    return {
      status: 'conflict', httpStatus: 409, auditLog: existing.get({ plain: true }),
      errors: [{ field: 'eventId', code: 'EVENT_ID_CONFLICT', message: 'eventId was already used for a different event payload.' }]
    };
  };

  const finishExisting = async (result) => {
    await writeLog({
      httpStatus: result.httpStatus,
      outcome: result.status === 'duplicate' ? 'DUPLICATE' : 'CONFLICT',
      auditLogId: result.auditLog.id,
      errorCode: result.status === 'conflict' ? 'EVENT_ID_CONFLICT' : null,
      errorDetails: result.errors || null
    });
    if (result.status === 'duplicate' && !sourceSystem.isInternal) await touchSource(sourceSystem, receivedAt);
    return result;
  };

  // 3. Seal & store ------------------------------------------------------------
  const store = async (transaction) => {
    const existing = await checkExisting(transaction);
    if (existing) return existing;
    const attributes = normalizeEvent(payload, { sourceSystem, eventType: validation.eventType, receivedAt, channel, payloadHash });
    const auditLog = await appendAuditRecord(attributes, transaction);
    return { status: 'accepted', httpStatus: 201, auditLog };
  };

  let result;
  try {
    result = outerTransaction ? await store(outerTransaction) : await sequelize.transaction(store);
  } catch (error) {
    if (error instanceof UniqueConstraintError) {
      const existing = await checkExisting(null);
      if (existing) return finishExisting(existing);
    }
    await writeLog({ httpStatus: 500, outcome: 'ERROR', errorCode: 'STORAGE_ERROR', errorDetails: [{ message: 'Event could not be stored. Retry later.' }] });
    throw error;
  }

  if (result.status !== 'accepted') return finishExisting(result);

  const auditLog = result.auditLog;
  await writeLog({
    httpStatus: 201,
    outcome: 'ACCEPTED',
    auditLogId: auditLog.id,
    deliveryDelayMs: Math.max(0, receivedAt.getTime() - new Date(payload.occurredAt).getTime())
  });
  if (!sourceSystem.isInternal) await touchSource(sourceSystem, receivedAt);

  // Alert evaluation reads committed data, so it runs after the surrounding transaction commits.
  const plain = auditLog.get({ plain: true });
  if (outerTransaction) outerTransaction.afterCommit(() => afterAccepted(plain).catch(() => {}));
  else await afterAccepted(plain);

  return { status: 'accepted', httpStatus: 201, auditLog: plain };
};
