import { ingestEvent, loadEventTypes, logIntegration } from '../services/auditIngestionService.js';
import { recordHeartbeat } from '../services/integrationService.js';
import { getSetting } from '../services/settingsService.js';
import { parseRules } from '../utils/eventNormalizer.js';

const receipt = (result, eventId) => {
  if (result.status === 'accepted' || result.status === 'duplicate') {
    return { status: result.status, eventId, auditId: result.auditLog.id, receivedAt: result.auditLog.receivedAt };
  }
  if (result.status === 'conflict') {
    return { status: 'conflict', eventId, error: { code: 'EVENT_ID_CONFLICT', message: result.errors[0].message, retryable: false } };
  }
  return { status: 'rejected', eventId, error: { code: 'VALIDATION_FAILED', message: 'Event failed validation.', retryable: false, details: result.errors } };
};

/** POST /api/v1/audit-events */
export const submitEvent = async (req, res) => {
  const payload = req.jsonBody;
  try {
    const result = await ingestEvent({
      payload, sourceSystem: req.sourceSystem, credential: req.credential, channel: 'API', context: req.integrationContext
    });
    return res.status(result.httpStatus).json(receipt(result, payload?.eventId ?? null));
  } catch (error) {
    console.error('[api] event storage failed:', error.message);
    return res.status(503).json({ status: 'error', eventId: payload?.eventId ?? null, error: { code: 'STORAGE_UNAVAILABLE', message: 'Event could not be stored. Retry with the same eventId.', retryable: true } });
  }
};

/** POST /api/v1/audit-events/batch   body: { "events": [ … ] } */
export const submitBatch = async (req, res) => {
  const events = req.jsonBody?.events;
  const maxBatch = Number(await getSetting('integration.maxBatchSize')) || 100;
  const fail = async (code, message) => {
    await logIntegration({
      sourceSystemId: req.sourceSystem.id, credentialId: req.credential.id, keyId: req.credential.keyId,
      ...req.integrationContext, httpStatus: 400, outcome: 'REJECTED_VALIDATION', errorCode: code, errorDetails: [{ message }]
    });
    return res.status(400).json({ status: 'error', error: { code, message, retryable: false } });
  };
  if (!Array.isArray(events)) return fail('INVALID_BATCH', 'Body must be {"events": [ ... ]}.');
  if (!events.length) return fail('EMPTY_BATCH', 'Batch contains no events.');
  if (events.length > maxBatch) return fail('BATCH_TOO_LARGE', `A batch may contain at most ${maxBatch} events.`);

  const results = [];
  for (let index = 0; index < events.length; index += 1) {
    const payload = events[index];
    try {
      const result = await ingestEvent({
        payload, sourceSystem: req.sourceSystem, credential: req.credential, channel: 'BATCH',
        context: { ...req.integrationContext, batchIndex: index }
      });
      results.push({ index, ...receipt(result, payload?.eventId ?? null) });
    } catch (error) {
      console.error('[api] batch event storage failed:', error.message);
      results.push({ index, status: 'error', eventId: payload?.eventId ?? null, error: { code: 'STORAGE_UNAVAILABLE', message: 'Event could not be stored. Retry with the same eventId.', retryable: true } });
    }
  }
  const summary = results.reduce((acc, r) => { acc[r.status] = (acc[r.status] || 0) + 1; return acc; }, {});
  return res.status(200).json({ status: 'processed', total: events.length, summary, results });
};

/** POST /api/v1/heartbeat   body: { pendingEvents, failedDeliveries, oldestPendingAt, version, status } */
export const heartbeat = async (req, res) => {
  const payload = await recordHeartbeat(req.sourceSystem, req.jsonBody || {});
  await logIntegration({
    sourceSystemId: req.sourceSystem.id, credentialId: req.credential.id, keyId: req.credential.keyId,
    ...req.integrationContext, httpStatus: 200, outcome: 'HEARTBEAT'
  });
  res.json({ status: 'ok', sourceSystem: req.sourceSystem.systemCode, serverTime: new Date().toISOString(), recorded: payload });
};

/** GET /api/v1/event-types — registered action codes the caller may submit. */
export const eventTypes = async (req, res) => {
  const types = [...(await loadEventTypes()).values()]
    .filter((t) => t.category !== 'SYSTEM')
    .map((t) => {
      const rules = parseRules(t);
      return {
        code: t.code, name: t.name, category: t.category, defaultSeverity: t.defaultSeverity,
        // Enforced at ingestion (422 when missing)
        requiresEntity: Boolean(t.requiresEntity), requiresChanges: Boolean(t.requiresChanges),
        // Checked by QA and investigations (accepted but flagged when missing)
        expectations: rules.group ? {
          group: rules.group, module: rules.module || null, entityTypes: rules.entityTypes || null,
          before: Boolean(rules.expectBefore), after: Boolean(rules.expectAfter), reason: Boolean(rules.requiresReason),
          authorization: Boolean(rules.requiresAuthorization), authorizationOutcomes: rules.expectedAuthorizationOutcomes || null,
          correlationId: Boolean(rules.expectsCorrelation), branch: Boolean(rules.expectsBranch), routine: Boolean(rules.routine)
        } : null
      };
    });
  res.json({ status: 'ok', eventTypes: types });
};

/** GET /api/v1/health — unauthenticated liveness probe (no internal details). */
export const health = (req, res) => res.json({ status: 'ok', service: 'MediSentinel', time: new Date().toISOString() });
