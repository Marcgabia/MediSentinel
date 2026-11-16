/**
 * MediSentinel reference client (Node.js ≥ 18, zero dependencies, ES module).
 *
 * Copy this file into a source system (e.g. PharmaCore POS) to submit audit events with:
 *   - HMAC-SHA256 request signing
 *   - automatic retries with exponential back-off for transient failures (network, 429, 5xx)
 *   - idempotent re-delivery (the same eventId is safe to resend)
 *   - an optional durable on-disk outbox so events survive restarts / outages
 *   - heartbeats that report the outbox backlog to MediSentinel
 *
 *   import { MediSentinelClient } from './medisentinel-client.js';
 *   const audit = new MediSentinelClient({
 *     baseUrl: process.env.MEDISENTINEL_URL,          // e.g. http://localhost:3000/api/v1
 *     keyId: process.env.MEDISENTINEL_KEY_ID,
 *     secret: process.env.MEDISENTINEL_SECRET,
 *     sourceSystem: process.env.MEDISENTINEL_SOURCE,  // e.g. PHARMACORE_POS
 *     outboxFile: './data/medisentinel-outbox.jsonl'
 *   });
 *   await audit.record({ sourceModule: 'Sales', actor: {...}, action: 'TRANSACTION_CREATED', ... });
 */
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');

export const signRequest = ({ secret, timestamp, method, path: urlPath, body }) =>
  `v1=${crypto.createHmac('sha256', secret).update(`${timestamp}\n${method.toUpperCase()}\n${urlPath}\n${sha256(body || '')}`).digest('hex')}`;

export class MediSentinelClient {
  constructor({ baseUrl, keyId, secret, sourceSystem, outboxFile = null, maxAttempts = 5, timeoutMs = 10000, clientVersion = 'medisentinel-client/1.0' }) {
    if (!baseUrl || !keyId || !secret || !sourceSystem) throw new Error('baseUrl, keyId, secret and sourceSystem are required');
    this.baseUrl = baseUrl.replace(/\/+$/, '');
    this.keyId = keyId;
    this.secret = secret;
    this.sourceSystem = sourceSystem;
    this.outboxFile = outboxFile;
    this.maxAttempts = maxAttempts;
    this.timeoutMs = timeoutMs;
    this.clientVersion = clientVersion;
    this.failedDeliveries = 0;
  }

  /** Build a standardized event (fills eventId, occurredAt and sourceSystem). */
  buildEvent(fields) {
    return {
      eventId: fields.eventId || crypto.randomUUID(),
      occurredAt: fields.occurredAt || new Date().toISOString(),
      sourceSystem: this.sourceSystem,
      outcome: 'SUCCESS',
      ...fields
    };
  }

  /** Low-level signed request. Returns { status, body }. */
  async request(method, endpoint, payload, attempt = 1) {
    const url = new URL(this.baseUrl + endpoint);
    const body = payload === undefined ? '' : JSON.stringify(payload);
    const timestamp = String(Math.floor(Date.now() / 1000));
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const res = await fetch(url, {
        method,
        body: body || undefined,
        signal: controller.signal,
        headers: {
          'Content-Type': 'application/json',
          'X-MediSentinel-Key': this.keyId,
          'X-MediSentinel-Timestamp': timestamp,
          'X-MediSentinel-Signature': signRequest({ secret: this.secret, timestamp, method, path: url.pathname + url.search, body }),
          'X-MediSentinel-Delivery-Attempt': String(attempt),
          'User-Agent': this.clientVersion
        }
      });
      const text = await res.text();
      let parsed = null;
      try { parsed = text ? JSON.parse(text) : null; } catch { parsed = { raw: text }; }
      return { status: res.status, body: parsed, retryAfter: Number(res.headers.get('retry-after')) || null };
    } finally {
      clearTimeout(timer);
    }
  }

  static isRetryable(result) {
    if (!result) return true; // network error / timeout
    if (result.status === 429 || result.status >= 500) return true;
    if (result.status === 401 && result.body?.error?.code === 'TIMESTAMP_OUT_OF_RANGE') return true;
    return false;
  }

  /** Send with retries. Resolves with the final result; never throws for HTTP errors. */
  async deliver(method, endpoint, payload) {
    let last = null;
    for (let attempt = 1; attempt <= this.maxAttempts; attempt += 1) {
      try {
        last = await this.request(method, endpoint, payload, attempt);
      } catch (error) {
        last = { status: 0, body: { error: { code: 'NETWORK_ERROR', message: error.message } } };
      }
      if (!MediSentinelClient.isRetryable(last.status === 0 ? null : last)) return { ...last, attempts: attempt };
      if (attempt < this.maxAttempts) {
        const backoff = last.retryAfter ? last.retryAfter * 1000 : Math.min(30000, 500 * 2 ** (attempt - 1)) + Math.floor(Math.random() * 250);
        await sleep(backoff);
      }
    }
    this.failedDeliveries += 1;
    return { ...last, attempts: this.maxAttempts, exhausted: true };
  }

  /** Submit one event immediately (with retries). */
  async send(fields) {
    const event = fields.eventId && fields.occurredAt && fields.sourceSystem ? fields : this.buildEvent(fields);
    return { event, ...(await this.deliver('POST', '/audit-events', event)) };
  }

  /** Submit up to the server's batch limit (default 100) in one request. */
  async sendBatch(events) {
    return this.deliver('POST', '/audit-events/batch', { events: events.map((e) => (e.eventId ? e : this.buildEvent(e))) });
  }

  async heartbeat(extra = {}) {
    const pending = this.readOutbox();
    return this.deliver('POST', '/heartbeat', {
      pendingEvents: pending.length,
      failedDeliveries: this.failedDeliveries,
      oldestPendingAt: pending[0]?.occurredAt || null,
      version: this.clientVersion,
      ...extra
    });
  }

  // ---------------------------------------------------------------- outbox
  readOutbox() {
    if (!this.outboxFile || !fs.existsSync(this.outboxFile)) return [];
    return fs.readFileSync(this.outboxFile, 'utf8').split('\n').filter(Boolean).map((line) => JSON.parse(line));
  }

  writeOutbox(events) {
    fs.mkdirSync(path.dirname(path.resolve(this.outboxFile)), { recursive: true });
    const tmp = `${this.outboxFile}.tmp`;
    fs.writeFileSync(tmp, events.map((e) => JSON.stringify(e)).join('\n') + (events.length ? '\n' : ''));
    fs.renameSync(tmp, this.outboxFile);
  }

  /**
   * Durable recording: append to the outbox first, then try to flush.
   * If MediSentinel is unreachable the event stays queued and is retried on the next flush.
   */
  async record(fields) {
    const event = this.buildEvent(fields);
    if (!this.outboxFile) return this.send(event);
    fs.mkdirSync(path.dirname(path.resolve(this.outboxFile)), { recursive: true });
    fs.appendFileSync(this.outboxFile, `${JSON.stringify(event)}\n`);
    await this.flush();
    return { event, queued: true };
  }

  /** Deliver queued events in order. Permanently rejected events are moved to <outbox>.rejected. */
  async flush() {
    const queue = this.readOutbox();
    const remaining = [];
    for (let i = 0; i < queue.length; i += 1) {
      const result = await this.deliver('POST', '/audit-events', queue[i]);
      if ([200, 201].includes(result.status)) continue;
      if (MediSentinelClient.isRetryable(result.status === 0 ? null : result)) { remaining.push(...queue.slice(i)); break; }
      fs.appendFileSync(`${this.outboxFile}.rejected`, `${JSON.stringify({ event: queue[i], response: result.body })}\n`);
    }
    this.writeOutbox(remaining);
    return { delivered: queue.length - remaining.length, pending: remaining.length };
  }
}
