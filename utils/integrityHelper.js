import crypto from 'crypto';

/**
 * Tamper-evidence helpers.
 *
 * Every accepted audit record receives an HMAC-SHA256 value computed over a canonical
 * representation of its immutable fields plus the integrity value of the previous record
 * (a hash chain). Editing a stored field breaks that record's HMAC; deleting or reordering
 * records breaks the chain link of the following record.
 *
 * The signing key lives in the environment (AUDIT_SIGNING_KEY), never in the database or
 * source code. This provides tamper EVIDENCE and DETECTION — not tamper-proof storage:
 * anyone holding both database write access and the signing key could forge records.
 */

export const GENESIS_HASH = '0'.repeat(64);

export const INTEGRITY_FIELDS = [
  'eventId', 'sourceSystemId', 'sourceSystemCode', 'sourceSystemName', 'sourceModule',
  'actorUserId', 'actorUsername', 'actorRole', 'actionType', 'actionCategory',
  'entityType', 'entityId', 'description', 'previousValues', 'newValues',
  'outcome', 'severity', 'occurredAt', 'receivedAt', 'ipAddress', 'userAgent',
  'correlationId', 'metadata', 'payloadHash', 'ingestionChannel', 'previousHash', 'signingKeyId'
];

const HEX_64 = /^[a-f0-9]{64}$/;

/** Deterministic JSON: sorted object keys, ISO dates, undefined → null. */
export const canonicalize = (value) => {
  if (value === undefined || value === null) return 'null';
  if (value instanceof Date) return JSON.stringify(value.toISOString());
  if (Array.isArray(value)) return `[${value.map((item) => canonicalize(item)).join(',')}]`;
  if (typeof value === 'object') {
    const keys = Object.keys(value).filter((key) => value[key] !== undefined).sort();
    return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(',')}}`;
  }
  if (typeof value === 'number' && !Number.isFinite(value)) return 'null';
  if (typeof value === 'bigint') return JSON.stringify(value.toString());
  return JSON.stringify(value);
};

export const sha256 = (input) => crypto.createHash('sha256').update(input).digest('hex');

export const computePayloadHash = (payload) => sha256(canonicalize(payload));

const normalizeField = (name, value) => {
  if (value === undefined) return null;
  if ((name === 'occurredAt' || name === 'receivedAt') && value) {
    const date = value instanceof Date ? value : new Date(value);
    return Number.isNaN(date.getTime()) ? String(value) : date.toISOString();
  }
  if (name === 'sourceSystemId' && value !== null) return Number(value);
  return value;
};

export const buildIntegrityMaterial = (record) => {
  const material = {};
  for (const field of INTEGRITY_FIELDS) {
    material[field] = normalizeField(field, record[field]);
  }
  return canonicalize(material);
};

// ---------------------------------------------------------------------------
// Key management (environment only)
// ---------------------------------------------------------------------------
const loadKeyring = () => {
  const keyring = new Map();
  const currentId = process.env.AUDIT_SIGNING_KEY_ID || 'k1';
  if (process.env.AUDIT_SIGNING_KEY) keyring.set(currentId, process.env.AUDIT_SIGNING_KEY);
  // Retired keys remain available for verification only: "k0:hexkey,k-old:hexkey"
  (process.env.AUDIT_SIGNING_KEYS_RETIRED || '').split(',').map((s) => s.trim()).filter(Boolean).forEach((entry) => {
    const idx = entry.indexOf(':');
    if (idx > 0) keyring.set(entry.slice(0, idx), entry.slice(idx + 1));
  });
  return { currentId, keyring };
};

export const getCurrentSigningKey = () => {
  const { currentId, keyring } = loadKeyring();
  const key = keyring.get(currentId);
  if (!key || key.length < 32) {
    throw new Error('AUDIT_SIGNING_KEY is missing or too short (min 32 chars). Run `npm run setup` to generate one.');
  }
  return { keyId: currentId, key };
};

export const getSigningKeyById = (keyId) => loadKeyring().keyring.get(keyId) || null;

export const assertIntegrityKeysConfigured = () => { getCurrentSigningKey(); return true; };

export const computeIntegrityHash = (record, key) =>
  crypto.createHmac('sha256', key).update(buildIntegrityMaterial(record)).digest('hex');

/** Attach previousHash, signingKeyId and integrityHash to a record that is about to be stored. */
export const sealRecord = (record, previousHash = GENESIS_HASH) => {
  const { keyId, key } = getCurrentSigningKey();
  const sealed = { ...record, previousHash: previousHash || GENESIS_HASH, signingKeyId: keyId };
  sealed.integrityHash = computeIntegrityHash(sealed, key);
  return sealed;
};

const safeEqualHex = (a, b) => {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  return crypto.timingSafeEqual(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8'));
};

/**
 * Verify one stored record. `expectedPreviousHash` is the integrityHash of the record that
 * precedes it (by id); pass undefined to skip chain verification.
 * Returns { valid, issues: [{ code, message }] }.
 */
export const verifyRecord = (record, expectedPreviousHash) => {
  const issues = [];
  if (!record.integrityHash) {
    issues.push({ code: 'MISSING_INTEGRITY', message: 'Record has no integrity value.' });
    return { valid: false, issues };
  }
  if (!HEX_64.test(record.integrityHash)) {
    issues.push({ code: 'INVALID_HASH_FORMAT', message: 'Integrity value is not a 64-character hex HMAC.' });
  }
  if (record.previousHash && !HEX_64.test(record.previousHash)) {
    issues.push({ code: 'INVALID_HASH_FORMAT', message: 'Chain link (previousHash) is malformed.' });
  }
  const key = getSigningKeyById(record.signingKeyId);
  if (!key) {
    issues.push({ code: 'UNKNOWN_SIGNING_KEY', message: `Signing key "${record.signingKeyId}" is not available for verification.` });
  } else if (!safeEqualHex(computeIntegrityHash(record, key), record.integrityHash)) {
    issues.push({ code: 'SIGNATURE_MISMATCH', message: 'Stored content does not match its integrity value (record modified or corrupted).' });
  }
  if (expectedPreviousHash !== undefined && record.previousHash !== expectedPreviousHash) {
    issues.push({ code: 'CHAIN_BROKEN', message: 'Chain link does not match the preceding record (a record may have been removed, inserted or reordered).' });
  }
  return { valid: issues.length === 0, issues };
};
