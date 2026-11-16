/**
 * Derive integration health strictly from observed communication.
 * A manually assigned status never makes a system "healthy".
 *
 * @param {object} source  { status, isInternal, lastSuccessfulConnectionAt, lastHeartbeatAt }
 * @param {object} stats   { requestsLastHour, failuresLastHour }
 * @param {object} cfg     { staleAfterMinutes, degradedErrorRate, now }
 */
export const computeHealth = (source, stats = {}, cfg = {}) => {
  const now = cfg.now || new Date();
  const staleAfterMs = (cfg.staleAfterMinutes ?? 30) * 60000;
  const degradedRate = cfg.degradedErrorRate ?? 25;

  if (source.isInternal) return { status: 'INTERNAL', label: 'Internal', reason: 'MediSentinel governance events.' };
  if (['SUSPENDED', 'RETIRED'].includes(source.status)) {
    return { status: 'SUSPENDED', label: source.status === 'RETIRED' ? 'Retired' : 'Suspended', reason: `Source is ${source.status.toLowerCase()} by an administrator; events are rejected.` };
  }
  const times = [source.lastSuccessfulConnectionAt, source.lastHeartbeatAt].filter(Boolean).map((d) => new Date(d).getTime());
  if (!times.length) {
    return { status: 'NEVER_CONNECTED', label: 'Never connected', reason: 'No authenticated event or heartbeat has ever been received from this system.' };
  }
  const lastContact = Math.max(...times);
  const minutesAgo = Math.round((now.getTime() - lastContact) / 60000);
  if (now.getTime() - lastContact > staleAfterMs) {
    return { status: 'STALE', label: 'Disconnected', reason: `No communication for ${minutesAgo} minute(s) (threshold ${cfg.staleAfterMinutes ?? 30}).`, lastContact: new Date(lastContact) };
  }
  const requests = Number(stats.requestsLastHour || 0);
  const failures = Number(stats.failuresLastHour || 0);
  const errorRate = requests ? Math.round((failures / requests) * 100) : 0;
  if (requests >= 5 && errorRate > degradedRate) {
    return { status: 'DEGRADED', label: 'Degraded', reason: `${errorRate}% of the last hour's requests failed (threshold ${degradedRate}%).`, lastContact: new Date(lastContact), errorRate };
  }
  return { status: 'HEALTHY', label: 'Connected', reason: `Last communication ${minutesAgo} minute(s) ago.`, lastContact: new Date(lastContact), errorRate };
};

export const isConnected = (health) => ['HEALTHY', 'DEGRADED'].includes(health.status);
