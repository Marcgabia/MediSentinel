import crypto from 'crypto';

/**
 * AES-256-GCM encryption for integration secrets.
 *
 * HMAC request signing requires the server to know the shared secret, so secrets cannot be
 * stored as one-way hashes. They are encrypted at rest with CREDENTIAL_ENCRYPTION_KEY (env),
 * and a SHA-256 fingerprint is stored alongside for identification. Plaintext secrets are only
 * ever returned once, at issuance.
 */

const getKey = () => {
  const raw = process.env.CREDENTIAL_ENCRYPTION_KEY || '';
  const key = /^[a-f0-9]{64}$/i.test(raw) ? Buffer.from(raw, 'hex') : crypto.createHash('sha256').update(raw).digest();
  if (raw.length < 32) {
    throw new Error('CREDENTIAL_ENCRYPTION_KEY is missing or too short. Run `npm run setup` to generate one.');
  }
  return key;
};

export const assertCredentialKeyConfigured = () => { getKey(); return true; };

export const encryptSecret = (plaintext) => {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', getKey(), iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `v1:${iv.toString('base64')}:${tag.toString('base64')}:${ciphertext.toString('base64')}`;
};

export const decryptSecret = (payload) => {
  const [version, ivB64, tagB64, dataB64] = String(payload).split(':');
  if (version !== 'v1') throw new Error('Unsupported secret format');
  const decipher = crypto.createDecipheriv('aes-256-gcm', getKey(), Buffer.from(ivB64, 'base64'));
  decipher.setAuthTag(Buffer.from(tagB64, 'base64'));
  return Buffer.concat([decipher.update(Buffer.from(dataB64, 'base64')), decipher.final()]).toString('utf8');
};

export const fingerprintSecret = (secret) => crypto.createHash('sha256').update(secret).digest('hex');

export const generateKeyId = () => `msk_${crypto.randomBytes(9).toString('hex')}`;
export const generateSecret = () => `mss_${crypto.randomBytes(32).toString('base64url')}`;

// ---------------------------------------------------------------------------
// Request signing (shared by the API middleware, tests, simulator and client SDK)
// ---------------------------------------------------------------------------
export const buildStringToSign = ({ timestamp, method, path, body }) => {
  const bodyHash = crypto.createHash('sha256').update(body || '').digest('hex');
  return `${timestamp}\n${String(method).toUpperCase()}\n${path}\n${bodyHash}`;
};

export const signRequest = ({ secret, timestamp, method, path, body }) =>
  `v1=${crypto.createHmac('sha256', secret).update(buildStringToSign({ timestamp, method, path, body })).digest('hex')}`;

export const verifyRequestSignature = ({ secret, timestamp, method, path, body, signature }) => {
  const expected = signRequest({ secret, timestamp, method, path, body });
  const a = Buffer.from(String(signature || ''));
  const b = Buffer.from(expected);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
};
