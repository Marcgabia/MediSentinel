import { IntegrationCredential, SourceSystem } from '../models/index.js';
import { decryptSecret, verifyRequestSignature } from '../utils/secretBox.js';
import { createRateLimiter } from '../utils/rateLimiter.js';
import { logIntegration } from '../services/auditIngestionService.js';
import { evaluateApiAuthFailure } from '../services/alertService.js';
import { getSetting } from '../services/settingsService.js';

/**
 * Authenticates source systems using HMAC-SHA256 signed requests.
 *
 *   X-MediSentinel-Key:        <keyId>
 *   X-MediSentinel-Timestamp:  <unix seconds>
 *   X-MediSentinel-Signature:  v1=<hex HMAC-SHA256(secret, timestamp \n METHOD \n path \n sha256(body))>
 *
 * Every rejected attempt is written to integration_logs and evaluated by the
 * API_AUTH_FAILURE alert rule.
 */

const apiLimiter = createRateLimiter({ windowMs: 60000, max: Number(process.env.API_RATE_LIMIT_PER_MINUTE || 1200) });

export const clientIp = (req) => {
  const raw = req.ip || req.socket?.remoteAddress || null;
  return raw && raw.startsWith('::ffff:') ? raw.slice(7) : raw;
};

const sendError = (res, status, code, message, extra = {}) =>
  res.status(status).json({ status: 'error', error: { code, message, ...extra } });

export const authenticateSource = async (req, res, next) => {
  const keyId = req.get('X-MediSentinel-Key');
  const timestamp = req.get('X-MediSentinel-Timestamp');
  const signature = req.get('X-MediSentinel-Signature');
  const ipAddress = clientIp(req);
  const deliveryAttempt = Number.parseInt(req.get('X-MediSentinel-Delivery-Attempt'), 10) || null;
  const endpoint = req.originalUrl.split('?')[0].slice(0, 200);

  const reject = async ({ status, outcome = 'REJECTED_AUTH', code, message, credential = null, sourceSystemId = null }) => {
    await logIntegration({
      sourceSystemId, credentialId: credential?.id || null, keyId: keyId ? String(keyId).slice(0, 64) : null,
      endpoint, method: req.method, httpStatus: status, outcome, errorCode: code,
      errorDetails: [{ message }], ipAddress, deliveryAttempt
    });
    if (outcome === 'REJECTED_AUTH') {
      evaluateApiAuthFailure({ keyId: credential ? credential.keyId : null, ipAddress, sourceSystemId }).catch(() => {});
    }
    return sendError(res, status, code, message);
  };

  try {
    if (!keyId || !timestamp || !signature) {
      return reject({ status: 401, code: 'MISSING_AUTHENTICATION', message: 'X-MediSentinel-Key, X-MediSentinel-Timestamp and X-MediSentinel-Signature headers are required.' });
    }
    const tolerance = Number(await getSetting('integration.timestampToleranceSeconds')) || 300;
    const ts = Number(timestamp);
    if (!/^\d{9,11}$/.test(String(timestamp)) || Math.abs(Date.now() / 1000 - ts) > tolerance) {
      return reject({ status: 401, code: 'TIMESTAMP_OUT_OF_RANGE', message: `Request timestamp must be unix seconds within ±${tolerance}s of server time (server time: ${Math.floor(Date.now() / 1000)}).` });
    }

    const credential = await IntegrationCredential.scope('withSecret').findOne({
      where: { keyId: String(keyId).slice(0, 64) },
      include: [{ model: SourceSystem, as: 'sourceSystem' }]
    });
    if (!credential) {
      return reject({ status: 401, code: 'INVALID_CREDENTIALS', message: 'Authentication failed.' });
    }
    const sourceSystemId = credential.sourceSystemId;
    if (credential.status !== 'ACTIVE' || (credential.expiresAt && credential.expiresAt < new Date())) {
      return reject({ status: 401, code: 'CREDENTIAL_REVOKED', message: 'This credential has been revoked or has expired.', credential, sourceSystemId });
    }

    let secret;
    try {
      secret = decryptSecret(credential.secretCiphertext);
    } catch {
      return reject({ status: 500, outcome: 'ERROR', code: 'CREDENTIAL_UNREADABLE', message: 'Credential could not be loaded. Contact the MediSentinel administrator.', credential, sourceSystemId });
    }

    const body = Buffer.isBuffer(req.body) ? req.body.toString('utf8') : '';
    const valid = verifyRequestSignature({ secret, timestamp: String(timestamp), method: req.method, path: req.originalUrl, body, signature });
    if (!valid) {
      return reject({ status: 401, code: 'INVALID_SIGNATURE', message: 'Request signature does not match.', credential, sourceSystemId });
    }

    const source = credential.sourceSystem;
    if (!source || ['SUSPENDED', 'RETIRED'].includes(source.status)) {
      return reject({ status: 403, outcome: 'REJECTED_FORBIDDEN', code: 'SOURCE_SUSPENDED', message: 'This source system is suspended or retired and may not submit events.', credential, sourceSystemId });
    }

    const limit = apiLimiter.hit(credential.keyId);
    if (!limit.allowed) {
      res.set('Retry-After', String(Math.ceil((limit.retryAfterMs || 1000) / 1000)));
      return reject({ status: 429, outcome: 'RATE_LIMITED', code: 'RATE_LIMITED', message: 'Too many requests. Retry after the indicated delay.', credential, sourceSystemId });
    }

    credential.update({ lastUsedAt: new Date() }).catch(() => {});
    req.sourceSystem = source.get({ plain: true });
    req.credential = { id: credential.id, keyId: credential.keyId };
    req.integrationContext = { endpoint, method: req.method, ipAddress, deliveryAttempt };
    return next();
  } catch (error) {
    return next(error);
  }
};

/** Parse the (already authenticated) raw body as JSON. Invalid JSON is logged against the source. */
export const parseSignedJson = async (req, res, next) => {
  const text = Buffer.isBuffer(req.body) ? req.body.toString('utf8') : '';
  if (!text.trim()) { req.jsonBody = {}; return next(); }
  try {
    req.jsonBody = JSON.parse(text);
    return next();
  } catch {
    await logIntegration({
      sourceSystemId: req.sourceSystem.id, credentialId: req.credential.id, keyId: req.credential.keyId,
      ...req.integrationContext, httpStatus: 400, outcome: 'REJECTED_VALIDATION', errorCode: 'INVALID_JSON',
      errorDetails: [{ message: 'Request body is not valid JSON.' }]
    });
    return sendError(res, 400, 'INVALID_JSON', 'Request body is not valid JSON.');
  }
};
