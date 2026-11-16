// Small in-memory fixed-window rate limiter (per process). Suitable for a single-node deployment.
export const createRateLimiter = ({ windowMs, max }) => {
  const hits = new Map();
  const sweep = setInterval(() => {
    const now = Date.now();
    for (const [key, entry] of hits) if (now - entry.start > windowMs) hits.delete(key);
  }, Math.max(windowMs, 60000));
  sweep.unref?.();

  return {
    hit(key) {
      const now = Date.now();
      const entry = hits.get(key);
      if (!entry || now - entry.start > windowMs) {
        hits.set(key, { start: now, count: 1 });
        return { allowed: true, remaining: max - 1 };
      }
      entry.count += 1;
      return { allowed: entry.count <= max, remaining: Math.max(0, max - entry.count), retryAfterMs: windowMs - (now - entry.start) };
    },
    reset(key) { hits.delete(key); }
  };
};
