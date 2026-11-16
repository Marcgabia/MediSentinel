import crypto from 'crypto';
import { OUTCOME_ALIASES, SENSITIVE_FIELD_PATTERN } from './auditConstants.js';
import { CUSTOMER_PII_KEYS, GENERIC_PII_KEYS } from './posEventCatalog.js';
import { getCurrentSigningKey } from './integrityHelper.js';

const isPlainObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const str = (v) => (v === undefined || v === null || v === '' ? null : String(v).trim());

export const parseRules = (eventType) => {
  const rules = eventType?.rules;
  if (!rules) return {};
  if (typeof rules === 'string') { try { return JSON.parse(rules) || {}; } catch { return {}; } }
  return rules;
};

// ---------------------------------------------------------------------------
// Customer personal-data masking
// ---------------------------------------------------------------------------
const CUSTOMER_KEYS = new Set(CUSTOMER_PII_KEYS.map((k) => k.toLowerCase()));
const GENERIC_KEYS = new Set(GENERIC_PII_KEYS.map((k) => k.toLowerCase()));

let maskKey = null;
const getMaskKey = () => {
  if (!maskKey) maskKey = crypto.createHmac('sha256', getCurrentSigningKey().key).update('medisentinel:pii-mask:v1').digest();
  return maskKey;
};
export const resetMaskKey = () => { maskKey = null; };

/**
 * Keyed fingerprint of a personal value: equal values give equal fingerprints, so a
 * before/after comparison still shows WHETHER a field changed without storing the value.
 */
export const maskValue = (value) => {
  if (value === null || value === undefined || value === '') return value ?? null;
  const normalized = String(typeof value === 'object' ? JSON.stringify(value) : value).trim().toLowerCase();
  return `[MASKED:${crypto.createHmac('sha256', getMaskKey()).update(normalized).digest('hex').slice(0, 10)}]`;
};

/** Mask customer personal data. `generic` also masks plain keys such as name, phone, email, address. */
export const maskPersonalData = (value, { generic = false, path = '', masked = [] } = {}) => {
  if (Array.isArray(value)) return value.map((item, i) => maskPersonalData(item, { generic, path: `${path}[${i}]`, masked }));
  if (!isPlainObject(value)) return value;
  const out = {};
  for (const [key, nested] of Object.entries(value)) {
    const childPath = path ? `${path}.${key}` : key;
    const lower = key.toLowerCase();
    if (CUSTOMER_KEYS.has(lower) || (generic && GENERIC_KEYS.has(lower))) {
      out[key] = maskValue(nested);
      if (nested !== null && nested !== undefined && nested !== '') masked.push(childPath);
    } else {
      out[key] = maskPersonalData(nested, { generic, path: childPath, masked });
    }
  }
  return out;
};

// ---------------------------------------------------------------------------
// Traceability block (stored as metadata.trace and therefore integrity-protected)
// ---------------------------------------------------------------------------
const compact = (obj) => {
  const out = {};
  for (const [k, v] of Object.entries(obj)) {
    if (v === undefined || v === null || v === '') continue;
    if (isPlainObject(v)) { const inner = compact(v); if (Object.keys(inner).length) out[k] = inner; continue; }
    out[k] = v;
  }
  return out;
};

const person = (p) => (isPlainObject(p) ? compact({ userId: str(p.userId), username: str(p.username), role: str(p.role), sharedUserId: str(p.sharedUserId) }) : null);

export const buildTrace = (payload, rules = {}) => {
  const entity = isPlainObject(payload.entity) ? payload.entity : {};
  const refs = isPlainObject(payload.references) ? payload.references : {};
  const branch = isPlainObject(payload.branch) ? payload.branch : {};
  const auth = isPlainObject(payload.authorization) ? payload.authorization : null;
  const report = isPlainObject(payload.report) ? payload.report : null;
  const lookup = isPlainObject(payload.lookup) ? payload.lookup : null;
  const actor = isPlainObject(payload.actor) ? payload.actor : {};
  const entityId = str(entity.id);

  return compact({
    branchId: str(branch.id) || str(refs.branchId),
    branchName: str(branch.name),
    reason: str(payload.reason),
    authorization: auth ? {
      requestedBy: person(auth.requestedBy),
      authorizedBy: person(auth.authorizedBy),
      outcome: auth.outcome ? String(auth.outcome).toUpperCase() : null,
      method: str(auth.method),
      reference: str(auth.reference),
      decidedAt: str(auth.decidedAt)
    } : null,
    references: {
      transactionId: str(refs.transactionId) || (rules.entityKind === 'TRANSACTION' ? entityId : null),
      customerId: str(refs.customerId) || (rules.entityKind === 'CUSTOMER' ? entityId : null),
      productId: str(refs.productId) || (rules.entityKind === 'PRODUCT' ? entityId : null),
      productCode: str(refs.productCode)
    },
    report: report ? {
      reportType: str(report.reportType),
      dateFrom: str(report.dateFrom),
      dateTo: str(report.dateTo),
      branchFilter: str(report.branchFilter),
      exportFormat: report.exportFormat ? String(report.exportFormat).toUpperCase() : null,
      resultCount: Number.isInteger(report.resultCount) ? report.resultCount : null
    } : null,
    lookup: lookup ? {
      resultStatus: lookup.resultStatus ? String(lookup.resultStatus).toUpperCase() : null,
      resultCount: Number.isInteger(lookup.resultCount) ? lookup.resultCount : null
    } : null,
    identity: { sharedUserId: str(actor.sharedUserId) }
  });
};

/**
 * Replace values of sensitive keys (passwords, tokens, secrets…) with "[REDACTED]".
 * Returns { value, redacted: string[] } where redacted lists the dotted paths removed.
 */
export const redactSensitive = (value, path = '', redacted = []) => {
  if (Array.isArray(value)) {
    return { value: value.map((item, i) => redactSensitive(item, `${path}[${i}]`, redacted).value), redacted };
  }
  if (isPlainObject(value)) {
    const out = {};
    for (const [key, nested] of Object.entries(value)) {
      const childPath = path ? `${path}.${key}` : key;
      if (SENSITIVE_FIELD_PATTERN.test(key)) {
        out[key] = '[REDACTED]';
        redacted.push(childPath);
      } else {
        out[key] = redactSensitive(nested, childPath, redacted).value;
      }
    }
    return { value: out, redacted };
  }
  return { value, redacted };
};

/**
 * Convert a validated API payload into audit_logs attributes (without integrity fields).
 */
export const normalizeEvent = (payload, { sourceSystem, eventType, receivedAt, channel = 'API', payloadHash }) => {
  const actor = isPlainObject(payload.actor) ? payload.actor : {};
  const entity = isPlainObject(payload.entity) ? payload.entity : {};
  const changes = isPlainObject(payload.changes) ? payload.changes : {};
  const context = isPlainObject(payload.context) ? payload.context : {};

  const rules = parseRules(eventType);
  const generic = Boolean(rules.maskPersonalData);
  const maskedPaths = [];

  const redactedPaths = [];
  let before = isPlainObject(changes.before) ? redactSensitive(changes.before, 'before', redactedPaths).value : null;
  let after = isPlainObject(changes.after) ? redactSensitive(changes.after, 'after', redactedPaths).value : null;
  let metadata = isPlainObject(payload.metadata) ? redactSensitive(payload.metadata, 'metadata', redactedPaths).value : null;

  // Customer personal data is never stored in clear text (identifiers are kept).
  if (before) before = maskPersonalData(before, { generic, path: 'before', masked: maskedPaths });
  if (after) after = maskPersonalData(after, { generic, path: 'after', masked: maskedPaths });
  if (metadata) metadata = maskPersonalData(metadata, { generic, path: 'metadata', masked: maskedPaths });

  if (String(actor.type || '').toUpperCase() === 'SYSTEM') {
    metadata = { ...(metadata || {}), actorType: 'SYSTEM' };
  }
  if (redactedPaths.length) {
    metadata = { ...(metadata || {}), redactedFields: redactedPaths };
  }
  if (maskedPaths.length) {
    metadata = { ...(metadata || {}), maskedFields: maskedPaths };
  }
  const trace = buildTrace(payload, rules);
  if (Object.keys(trace).length) {
    metadata = { ...(metadata || {}), trace };
  }

  const severity = (payload.severity ? String(payload.severity).toUpperCase() : null) || eventType?.defaultSeverity || 'INFO';

  return {
    eventId: str(payload.eventId),
    sourceSystemId: sourceSystem.id,
    sourceSystemCode: sourceSystem.systemCode,
    sourceSystemName: sourceSystem.name,
    sourceModule: str(payload.sourceModule),
    actorUserId: str(actor.userId),
    actorUsername: str(actor.username) || (String(actor.type || '').toUpperCase() === 'SYSTEM' ? 'system' : null),
    actorRole: str(actor.role),
    actionType: payload.action,
    actionCategory: eventType?.category || 'OPERATIONAL',
    entityType: str(entity.type),
    entityId: str(entity.id),
    description: String(payload.description).trim(),
    previousValues: before,
    newValues: after,
    outcome: OUTCOME_ALIASES[String(payload.outcome).toUpperCase()],
    severity,
    occurredAt: new Date(payload.occurredAt),
    receivedAt,
    ipAddress: str(context.ipAddress ?? payload.ipAddress),
    userAgent: str(context.userAgent ?? payload.userAgent),
    correlationId: str(payload.correlationId),
    metadata,
    payloadHash,
    ingestionChannel: channel
  };
};
