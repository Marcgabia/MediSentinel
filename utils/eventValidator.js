import net from 'net';
import { EVENT_SEVERITIES, OUTCOME_ALIASES, SENSITIVE_FIELD_PATTERN } from './auditConstants.js';
import { AUTHORIZATION_OUTCOMES, LOOKUP_RESULT_STATUSES, EXPORT_FORMATS } from './posEventCatalog.js';

/**
 * Validates a single standardized audit event payload.
 *
 * @param {object} payload        raw event submitted by a source system
 * @param {object} ctx
 * @param {Map}    ctx.eventTypes Map<code, eventType> of registered, active event types
 * @param {string} ctx.sourceSystemCode  code of the authenticated source system
 * @param {Date}   [ctx.now]
 * @param {number} [ctx.maxFutureSkewSeconds=300]
 * @param {number} [ctx.maxEventAgeDays=30]
 * @returns {{ valid: boolean, errors: Array<{field:string, code:string, message:string}> }}
 */

export const LIMITS = {
  eventId: 128, sourceSystem: 64, sourceModule: 100, actorUserId: 128, actorUsername: 150, actorRole: 100,
  action: 64, entityType: 100, entityId: 128, description: 2000, correlationId: 128, userAgent: 512,
  maxEventBytes: 64 * 1024, maxChangesBytes: 32 * 1024, maxMetadataBytes: 16 * 1024,
  // Traceability fields (lengths match the generated lookup columns on audit_logs)
  sharedUserId: 128, branchId: 64, branchName: 150, reason: 500, reference: 128, productCode: 64,
  authMethod: 64, reportType: 64, branchFilter: 64
};

/** Paths of keys that look like secrets anywhere inside a value. */
const findSecretKeys = (value, path, found = []) => {
  if (Array.isArray(value)) value.forEach((item, i) => findSecretKeys(item, `${path}[${i}]`, found));
  else if (value !== null && typeof value === 'object') {
    for (const [key, nested] of Object.entries(value)) {
      const child = `${path}.${key}`;
      if (SENSITIVE_FIELD_PATTERN.test(key)) found.push(child);
      else findSecretKeys(nested, child, found);
    }
  }
  return found;
};

const ID_PATTERN = /^[A-Za-z0-9._:\-]+$/;
// ISO-8601 with an explicit timezone designator (Z or ±hh:mm)
const ISO_WITH_TZ = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d{1,6})?)?(Z|[+-]\d{2}:?\d{2})$/;

const isPlainObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const byteLength = (v) => Buffer.byteLength(JSON.stringify(v ?? null), 'utf8');

export const validateEvent = (payload, ctx = {}) => {
  const errors = [];
  const add = (field, code, message) => errors.push({ field, code, message });
  const now = ctx.now || new Date();
  const maxFutureSkewSeconds = ctx.maxFutureSkewSeconds ?? 300;
  const maxEventAgeDays = ctx.maxEventAgeDays ?? 30;

  if (!isPlainObject(payload)) {
    add('$', 'INVALID_JSON', 'Event must be a JSON object.');
    return { valid: false, errors };
  }
  if (byteLength(payload) > LIMITS.maxEventBytes) {
    add('$', 'PAYLOAD_TOO_LARGE', `Event exceeds ${LIMITS.maxEventBytes} bytes.`);
  }

  const requireString = (field, value, max, { pattern, required = true } = {}) => {
    if (value === undefined || value === null || value === '') {
      if (required) add(field, 'REQUIRED', `${field} is required.`);
      return false;
    }
    if (typeof value !== 'string') { add(field, 'INVALID_TYPE', `${field} must be a string.`); return false; }
    if (!value.trim()) { add(field, 'REQUIRED', `${field} must not be blank.`); return false; }
    if (value.length > max) { add(field, 'TOO_LONG', `${field} must be at most ${max} characters.`); return false; }
    if (pattern && !pattern.test(value)) { add(field, 'INVALID_FORMAT', `${field} contains unsupported characters.`); return false; }
    return true;
  };

  // eventId
  requireString('eventId', payload.eventId, LIMITS.eventId, { pattern: ID_PATTERN });

  // occurredAt
  if (!payload.occurredAt) {
    add('occurredAt', 'REQUIRED', 'occurredAt is required.');
  } else if (typeof payload.occurredAt !== 'string' || !ISO_WITH_TZ.test(payload.occurredAt)) {
    add('occurredAt', 'INVALID_TIMESTAMP', 'occurredAt must be an ISO-8601 timestamp with timezone, e.g. 2026-11-12T10:30:00Z.');
  } else {
    const occurred = new Date(payload.occurredAt);
    if (Number.isNaN(occurred.getTime())) {
      add('occurredAt', 'INVALID_TIMESTAMP', 'occurredAt is not a valid date.');
    } else {
      if (occurred.getTime() - now.getTime() > maxFutureSkewSeconds * 1000) {
        add('occurredAt', 'TIMESTAMP_IN_FUTURE', 'occurredAt is later than the server receipt time beyond the allowed clock skew.');
      }
      if (now.getTime() - occurred.getTime() > maxEventAgeDays * 86400000) {
        add('occurredAt', 'TIMESTAMP_TOO_OLD', `occurredAt is older than ${maxEventAgeDays} days.`);
      }
    }
  }

  // sourceSystem must match the authenticated caller
  if (requireString('sourceSystem', payload.sourceSystem, LIMITS.sourceSystem, { pattern: ID_PATTERN })
      && ctx.sourceSystemCode && payload.sourceSystem !== ctx.sourceSystemCode) {
    add('sourceSystem', 'SOURCE_MISMATCH', `sourceSystem "${payload.sourceSystem}" does not match the authenticated source system.`);
  }

  // sourceModule
  requireString('sourceModule', payload.sourceModule, LIMITS.sourceModule);

  // action
  let eventType = null;
  if (requireString('action', payload.action, LIMITS.action, { pattern: /^[A-Z0-9_]+$/ })) {
    eventType = ctx.eventTypes ? ctx.eventTypes.get(payload.action) : null;
    if (ctx.eventTypes && !eventType) {
      add('action', 'UNKNOWN_ACTION', `action "${payload.action}" is not a registered event type.`);
    }
  }

  // actor
  const actor = payload.actor;
  const isSystemActor = isPlainObject(actor) && String(actor.type || '').toUpperCase() === 'SYSTEM';
  if (actor === undefined || actor === null) {
    add('actor', 'REQUIRED', 'actor is required (use {"type":"SYSTEM","username":"<job>"} for automated activity).');
  } else if (!isPlainObject(actor)) {
    add('actor', 'INVALID_TYPE', 'actor must be an object.');
  } else {
    if (!actor.userId && !actor.username && !isSystemActor) {
      add('actor.username', 'REQUIRED', 'actor.userId or actor.username is required.');
    }
    if (actor.userId !== undefined && actor.userId !== null) {
      const uid = typeof actor.userId === 'number' ? String(actor.userId) : actor.userId;
      requireString('actor.userId', uid, LIMITS.actorUserId, { required: false });
    }
    requireString('actor.username', actor.username, LIMITS.actorUsername, { required: false });
    requireString('actor.role', actor.role, LIMITS.actorRole, { required: false });
    // Verified identifier shared across systems (e.g. HR employee number / SSO subject).
    requireString('actor.sharedUserId', actor.sharedUserId, LIMITS.sharedUserId, { required: false, pattern: ID_PATTERN });
  }

  // entity
  const entity = payload.entity;
  if (entity !== undefined && entity !== null && !isPlainObject(entity)) {
    add('entity', 'INVALID_TYPE', 'entity must be an object with "type" and "id".');
  } else {
    const needsEntity = eventType ? eventType.requiresEntity : false;
    if (needsEntity || entity) {
      requireString('entity.type', entity?.type, LIMITS.entityType, { required: needsEntity || Boolean(entity) });
      const entityId = typeof entity?.id === 'number' ? String(entity.id) : entity?.id;
      requireString('entity.id', entityId, LIMITS.entityId, { required: needsEntity || Boolean(entity) });
    }
  }

  // description
  requireString('description', payload.description, LIMITS.description);

  // changes
  const changes = payload.changes;
  if (changes !== undefined && changes !== null) {
    if (!isPlainObject(changes)) {
      add('changes', 'INVALID_TYPE', 'changes must be an object: {"before": {...}|null, "after": {...}|null}.');
    } else {
      const unknownKeys = Object.keys(changes).filter((k) => !['before', 'after'].includes(k));
      if (unknownKeys.length) add('changes', 'INVALID_FORMAT', `changes only supports "before" and "after" (found: ${unknownKeys.join(', ')}).`);
      ['before', 'after'].forEach((k) => {
        if (changes[k] !== undefined && changes[k] !== null && !isPlainObject(changes[k])) {
          add(`changes.${k}`, 'INVALID_TYPE', `changes.${k} must be an object or null.`);
        }
      });
      if (byteLength(changes) > LIMITS.maxChangesBytes) add('changes', 'PAYLOAD_TOO_LARGE', 'changes exceeds 32 KB.');
    }
  }
  if (eventType?.requiresChanges && !(isPlainObject(changes) && isPlainObject(changes.after))) {
    add('changes.after', 'REQUIRED', `${eventType.code} events must include changes.after (and changes.before when known).`);
  }

  // outcome
  if (!payload.outcome) {
    add('outcome', 'REQUIRED', 'outcome is required (SUCCESS, FAILURE or DENIED).');
  } else if (typeof payload.outcome !== 'string' || !OUTCOME_ALIASES[payload.outcome.toUpperCase()]) {
    add('outcome', 'INVALID_VALUE', 'outcome must be SUCCESS, FAILURE or DENIED.');
  }

  // severity (optional — defaults to the event type's default severity)
  if (payload.severity !== undefined && payload.severity !== null) {
    const sev = typeof payload.severity === 'string' ? payload.severity.toUpperCase() : null;
    if (!sev || !EVENT_SEVERITIES.includes(sev)) add('severity', 'INVALID_VALUE', `severity must be one of ${EVENT_SEVERITIES.join(', ')}.`);
  }

  // correlationId
  requireString('correlationId', payload.correlationId, LIMITS.correlationId, { required: false, pattern: ID_PATTERN });

  // context (ip / user agent)
  const context = payload.context;
  if (context !== undefined && context !== null && !isPlainObject(context)) {
    add('context', 'INVALID_TYPE', 'context must be an object.');
  }
  const ip = context?.ipAddress ?? payload.ipAddress;
  if (ip !== undefined && ip !== null && ip !== '') {
    if (typeof ip !== 'string' || !net.isIP(ip)) add('context.ipAddress', 'INVALID_FORMAT', 'ipAddress must be a valid IPv4 or IPv6 address.');
  }
  const ua = context?.userAgent ?? payload.userAgent;
  requireString('context.userAgent', ua, LIMITS.userAgent, { required: false });

  // metadata (extension point for system-specific fields)
  if (payload.metadata !== undefined && payload.metadata !== null) {
    if (!isPlainObject(payload.metadata)) add('metadata', 'INVALID_TYPE', 'metadata must be an object.');
    else if (byteLength(payload.metadata) > LIMITS.maxMetadataBytes) add('metadata', 'PAYLOAD_TOO_LARGE', 'metadata exceeds 16 KB.');
    else if (Object.prototype.hasOwnProperty.call(payload.metadata, 'trace')) add('metadata.trace', 'RESERVED_FIELD', 'metadata.trace is reserved by MediSentinel; use the top-level branch, reason, authorization, references, report and lookup fields.');
  }

  validateTraceFields(payload, { add, requireString });

  return { valid: errors.length === 0, errors, eventType };
};

// ---------------------------------------------------------------------------
// Traceability fields (all optional; structure only — completeness is a QA concern)
// ---------------------------------------------------------------------------
const objectField = (payload, field, allowedKeys, add) => {
  const value = payload[field];
  if (value === undefined || value === null) return null;
  if (!isPlainObject(value)) { add(field, 'INVALID_TYPE', `${field} must be an object.`); return null; }
  const unknown = Object.keys(value).filter((k) => !allowedKeys.includes(k));
  if (unknown.length) add(field, 'INVALID_FORMAT', `${field} supports only ${allowedKeys.join(', ')} (found: ${unknown.join(', ')}).`);
  return value;
};

const idValue = (v) => (typeof v === 'number' && Number.isFinite(v) ? String(v) : v);
const DATE_ONLY = /^\d{4}-\d{2}-\d{2}$/;

const validatePerson = (path, person, { add, requireString }) => {
  if (person === undefined || person === null) return;
  if (!isPlainObject(person)) { add(path, 'INVALID_TYPE', `${path} must be an object: {"userId", "username", "role"}.`); return; }
  const unknown = Object.keys(person).filter((k) => !['userId', 'username', 'role', 'sharedUserId'].includes(k));
  if (unknown.length) add(path, 'INVALID_FORMAT', `${path} supports only userId, username, role and sharedUserId.`);
  if (!person.userId && !person.username) add(`${path}.userId`, 'REQUIRED', `${path} needs a userId or username.`);
  requireString(`${path}.userId`, idValue(person.userId), LIMITS.actorUserId, { required: false });
  requireString(`${path}.username`, person.username, LIMITS.actorUsername, { required: false });
  requireString(`${path}.role`, person.role, LIMITS.actorRole, { required: false });
  requireString(`${path}.sharedUserId`, person.sharedUserId, LIMITS.sharedUserId, { required: false, pattern: ID_PATTERN });
};

const validateTraceFields = (payload, helpers) => {
  const { add, requireString } = helpers;

  const branch = objectField(payload, 'branch', ['id', 'name'], add);
  if (branch) {
    requireString('branch.id', idValue(branch.id), LIMITS.branchId, { pattern: ID_PATTERN });
    requireString('branch.name', branch.name, LIMITS.branchName, { required: false });
  }

  if (payload.reason !== undefined && payload.reason !== null) {
    requireString('reason', payload.reason, LIMITS.reason);
  }

  if (payload.authorization !== undefined && payload.authorization !== null) {
    // Passwords, PINs or tokens used to authorize an action must never leave the source system.
    const secrets = findSecretKeys(payload.authorization, 'authorization');
    if (secrets.length) {
      add('authorization', 'SECRET_NOT_ALLOWED', `Never send authorization secrets (found: ${secrets.join(', ')}). Send only the outcome and the authorizer's identity or a verification reference.`);
    }
  }
  const auth = objectField(payload, 'authorization', ['requestedBy', 'authorizedBy', 'outcome', 'method', 'reference', 'decidedAt'], add);
  if (auth) {
    validatePerson('authorization.requestedBy', auth.requestedBy, helpers);
    validatePerson('authorization.authorizedBy', auth.authorizedBy, helpers);
    if (auth.outcome === undefined || auth.outcome === null) add('authorization.outcome', 'REQUIRED', `authorization.outcome is required (${AUTHORIZATION_OUTCOMES.join(', ')}).`);
    else if (typeof auth.outcome !== 'string' || !AUTHORIZATION_OUTCOMES.includes(auth.outcome.toUpperCase())) add('authorization.outcome', 'INVALID_VALUE', `authorization.outcome must be one of ${AUTHORIZATION_OUTCOMES.join(', ')}.`);
    requireString('authorization.method', auth.method, LIMITS.authMethod, { required: false });
    requireString('authorization.reference', idValue(auth.reference), LIMITS.reference, { required: false, pattern: ID_PATTERN });
    if (auth.decidedAt !== undefined && auth.decidedAt !== null && (typeof auth.decidedAt !== 'string' || Number.isNaN(new Date(auth.decidedAt).getTime()))) {
      add('authorization.decidedAt', 'INVALID_TIMESTAMP', 'authorization.decidedAt must be an ISO-8601 timestamp.');
    }
  }

  const refs = objectField(payload, 'references', ['transactionId', 'customerId', 'productId', 'productCode', 'branchId'], add);
  if (refs) {
    ['transactionId', 'customerId', 'productId'].forEach((k) => requireString(`references.${k}`, idValue(refs[k]), LIMITS.reference, { required: false, pattern: ID_PATTERN }));
    requireString('references.branchId', idValue(refs.branchId), LIMITS.branchId, { required: false, pattern: ID_PATTERN });
    requireString('references.productCode', idValue(refs.productCode), LIMITS.productCode, { required: false });
  }

  const report = objectField(payload, 'report', ['reportType', 'dateFrom', 'dateTo', 'branchFilter', 'exportFormat', 'resultCount'], add);
  if (report) {
    requireString('report.reportType', report.reportType, LIMITS.reportType, { required: false });
    ['dateFrom', 'dateTo'].forEach((k) => {
      const v = report[k];
      if (v !== undefined && v !== null && (typeof v !== 'string' || (!DATE_ONLY.test(v) && Number.isNaN(new Date(v).getTime())))) {
        add(`report.${k}`, 'INVALID_TIMESTAMP', `report.${k} must be a date (YYYY-MM-DD) or ISO-8601 timestamp.`);
      }
    });
    if (report.dateFrom && report.dateTo && new Date(report.dateFrom) > new Date(report.dateTo)) add('report.dateTo', 'INVALID_VALUE', 'report.dateTo is earlier than report.dateFrom.');
    requireString('report.branchFilter', idValue(report.branchFilter), LIMITS.branchFilter, { required: false });
    if (report.exportFormat !== undefined && report.exportFormat !== null && (typeof report.exportFormat !== 'string' || !EXPORT_FORMATS.includes(report.exportFormat.toUpperCase()))) {
      add('report.exportFormat', 'INVALID_VALUE', `report.exportFormat must be one of ${EXPORT_FORMATS.join(', ')}.`);
    }
    if (report.resultCount !== undefined && report.resultCount !== null && !(Number.isInteger(report.resultCount) && report.resultCount >= 0)) add('report.resultCount', 'INVALID_VALUE', 'report.resultCount must be a non-negative integer.');
  }

  // Lookups record the RESULT only — never the search text (it may contain customer names).
  const lookup = objectField(payload, 'lookup', ['resultStatus', 'resultCount'], add);
  if (lookup) {
    if (typeof lookup.resultStatus !== 'string' || !LOOKUP_RESULT_STATUSES.includes(lookup.resultStatus.toUpperCase())) {
      add('lookup.resultStatus', 'INVALID_VALUE', `lookup.resultStatus must be one of ${LOOKUP_RESULT_STATUSES.join(', ')}.`);
    }
    if (lookup.resultCount !== undefined && lookup.resultCount !== null && !(Number.isInteger(lookup.resultCount) && lookup.resultCount >= 0)) add('lookup.resultCount', 'INVALID_VALUE', 'lookup.resultCount must be a non-negative integer.');
  }
};
