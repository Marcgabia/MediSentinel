import express from 'express';
import { authenticateSource, parseSignedJson } from '../middleware/apiAuthentication.js';
import { submitEvent, submitBatch, heartbeat, eventTypes, health } from '../controllers/apiController.js';

// Machine-to-machine API for registered source systems (Integration Service Accounts).
// Bodies are read raw so the HMAC signature can be verified over the exact bytes sent.
const router = express.Router();
const rawBody = express.raw({ type: () => true, limit: '2mb' });
const signed = [rawBody, authenticateSource, parseSignedJson];

router.get('/health', health);
router.post('/audit-events', ...signed, submitEvent);
router.post('/audit-events/batch', ...signed, submitBatch);
router.post('/heartbeat', ...signed, heartbeat);
router.get('/event-types', ...signed, eventTypes);

router.use((req, res) => res.status(404).json({ status: 'error', error: { code: 'NOT_FOUND', message: 'Unknown API endpoint.' } }));

// JSON error handler for the API (never leaks stack traces).
// eslint-disable-next-line no-unused-vars
router.use((err, req, res, next) => {
  if (err.type === 'entity.too.large') {
    return res.status(413).json({ status: 'error', error: { code: 'PAYLOAD_TOO_LARGE', message: 'Request body exceeds 2 MB.' } });
  }
  console.error('[api] unhandled error:', err.message);
  return res.status(500).json({ status: 'error', error: { code: 'INTERNAL_ERROR', message: 'Unexpected error. Retry later.', retryable: true } });
});

export default router;
