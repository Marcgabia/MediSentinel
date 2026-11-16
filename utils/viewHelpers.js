// Handlebars helpers for .xian templates. Class names are listed literally so Tailwind keeps them.
import { DEFAULT_EVENT_TYPES } from './auditConstants.js';

const TONES = {
  green: { pill: 'bg-emerald-50 text-emerald-700', dot: 'bg-emerald-500' },
  red: { pill: 'bg-red-50 text-red-700', dot: 'bg-red-500' },
  orange: { pill: 'bg-orange-50 text-orange-700', dot: 'bg-orange-500' },
  amber: { pill: 'bg-amber-50 text-amber-700', dot: 'bg-amber-500' },
  blue: { pill: 'bg-sky-50 text-sky-700', dot: 'bg-sky-500' },
  violet: { pill: 'bg-violet-50 text-violet-700', dot: 'bg-violet-500' },
  slate: { pill: 'bg-slate-100 text-slate-600', dot: 'bg-slate-400' }
};

const TONE_OF = {
  CRITICAL: 'red', HIGH: 'orange', MEDIUM: 'amber', LOW: 'blue', INFO: 'slate', INFORMATIONAL: 'slate',
  SUCCESS: 'green', FAILURE: 'red', DENIED: 'violet',
  PASS: 'green', FAIL: 'red', WARNING: 'amber', NOT_TESTED: 'slate',
  HEALTHY: 'green', DEGRADED: 'amber', STALE: 'red', NEVER_CONNECTED: 'slate', SUSPENDED: 'slate', INTERNAL: 'violet',
  OPEN: 'red', ACKNOWLEDGED: 'amber', INVESTIGATING: 'blue', UNDER_INVESTIGATION: 'blue', PENDING_REVIEW: 'violet',
  RESOLVED: 'green', VERIFIED: 'green', CLOSED: 'slate', DISMISSED: 'slate',
  ACTIVE: 'green', INACTIVE: 'slate', PENDING_APPROVAL: 'amber', LOCKED: 'amber', PENDING: 'slate', RETIRED: 'slate', REVOKED: 'slate',
  RUNNING: 'blue', COMPLETED: 'green', ERROR: 'red',
  ACCEPTED: 'green', DUPLICATE: 'slate', CONFLICT: 'orange', REJECTED_VALIDATION: 'amber', REJECTED_AUTH: 'red',
  REJECTED_FORBIDDEN: 'red', RATE_LIMITED: 'orange', HEARTBEAT: 'blue', CONNECTION_TEST_OK: 'green', CONNECTION_TEST_FAILED: 'red',
  REACHABLE: 'green', NOT_CONFIGURED: 'slate', TIMEOUT: 'red', UNREACHABLE: 'red', HTTP_ERROR: 'red',
  NOT_OBSERVED: 'slate', INVALID_ONLY: 'red',
  ADDED: 'green', REMOVED: 'red', CHANGED: 'amber', UNCHANGED: 'slate',
  APPROVED: 'green', REJECTED: 'red', FAILED: 'red', NOT_REQUIRED: 'slate', FOUND: 'green', NOT_FOUND: 'amber', MULTIPLE: 'blue',
  completed: 'green', voided: 'red', cancelled: 'slate', pending: 'amber', refunded: 'violet', open: 'blue'
};

const LABEL_OF = {
  SUCCESS: 'Success', FAILURE: 'Failed', DENIED: 'Denied', NOT_TESTED: 'Not tested',
  HEALTHY: 'Connected', STALE: 'Disconnected', NEVER_CONNECTED: 'Never connected', INTERNAL: 'Internal',
  REJECTED_VALIDATION: 'Invalid', REJECTED_AUTH: 'Auth failed', REJECTED_FORBIDDEN: 'Forbidden', RATE_LIMITED: 'Rate limited',
  CONNECTION_TEST_OK: 'Test passed', CONNECTION_TEST_FAILED: 'Test failed', NOT_OBSERVED: 'Not yet seen', INVALID_ONLY: 'Invalid only',
  INFO: 'Info', INFORMATIONAL: 'Info', PASS: 'Pass', FAIL: 'Fail', VERIFIED: 'Verified'
};

const ACTION_NAMES = Object.fromEntries(DEFAULT_EVENT_TYPES.map((t) => [t.code, t.name]));

export const humanize = (v) => String(v ?? '').replace(/_/g, ' ').toLowerCase().replace(/^\w/, (c) => c.toUpperCase());
export const statusLabel = (v) => LABEL_OF[v] || humanize(v);
export const actionLabel = (code) => ACTION_NAMES[code] || humanize(code);

const pad = (n) => String(n).padStart(2, '0');
const toDate = (v) => (v instanceof Date ? v : new Date(v));
const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

export const registerHelpers = (hbs) => {
  const { SafeString, escapeExpression } = hbs.handlebars;

  hbs.registerHelper('eq', (a, b) => String(a) === String(b));
  hbs.registerHelper('startsWith', (value, prefix) => String(value ?? '').startsWith(String(prefix ?? '')));
  // Person snapshot { userId, username, role } → "username (userId)"; never merges identities.
  hbs.registerHelper('who', (p) => {
    if (!p || typeof p !== 'object') return '—';
    const name = p.username || p.userId;
    if (!name) return '—';
    return p.username && p.userId ? `${p.username} (${p.userId})` : name;
  });
  hbs.registerHelper('ne', (a, b) => String(a) !== String(b));
  hbs.registerHelper('gt', (a, b) => Number(a) > Number(b));
  hbs.registerHelper('lt', (a, b) => Number(a) < Number(b));
  hbs.registerHelper('and', (...args) => args.slice(0, -1).every(Boolean));
  hbs.registerHelper('or', (...args) => args.slice(0, -1).some(Boolean));
  hbs.registerHelper('not', (v) => !v);
  hbs.registerHelper('isSet', (v) => v !== null && v !== undefined && v !== '');
  hbs.registerHelper('includes', (list, value) => Array.isArray(list) && list.map(String).includes(String(value)));
  hbs.registerHelper('add', (a, b) => Number(a) + Number(b));
  hbs.registerHelper('percent', (a, b) => (Number(b) ? Math.round((Number(a) / Number(b)) * 100) : 0));
  hbs.registerHelper('default', (v, fallback) => (v === null || v === undefined || v === '' ? fallback : v));
  hbs.registerHelper('json', (v) => JSON.stringify(v ?? null, null, 2));
  // Safe for embedding in <script type="application/json">: "<" can never close the tag.
  hbs.registerHelper('jsonInline', (v) => JSON.stringify(v ?? null).replace(/</g, '\\u003c').replace(/>/g, '\\u003e').replace(/&/g, '\\u0026'));
  hbs.registerHelper('upper', (v) => String(v ?? '').toUpperCase());
  hbs.registerHelper('humanize', (v) => humanize(v));
  hbs.registerHelper('isStatus', (v) => typeof v === 'string' && Object.prototype.hasOwnProperty.call(TONE_OF, v));
  hbs.registerHelper('statusText', (v) => statusLabel(v));
  hbs.registerHelper('action', (v) => actionLabel(v));
  hbs.registerHelper('truncate', (v, n) => { const s = String(v ?? ''); return s.length > n ? `${s.slice(0, n - 1)}…` : s; });
  hbs.registerHelper('padId', (prefix, id, width) => `${prefix}${String(id).padStart(Number(width) || 6, '0')}`);
  hbs.registerHelper('initials', (v) => String(v ?? '?').split(/\s+/).filter(Boolean).slice(0, 2).map((w) => w[0]).join('').toUpperCase());
  hbs.registerHelper('can', (permission, options) => (options.data.root.permissions || []).includes(permission));
  hbs.registerHelper('active', (path, prefix) => {
    const p = String(path || '');
    const on = prefix === '/qa' ? p === '/qa' || p.startsWith('/qa/runs') || p.startsWith('/qa/coverage') : p.startsWith(prefix);
    return on ? 'nav-on' : '';
  });
  hbs.registerHelper('selected', (a, b) => (String(a ?? '') === String(b ?? '') ? 'selected' : ''));
  hbs.registerHelper('checked', (v) => (v ? 'checked' : ''));
  hbs.registerHelper('encode', (v) => encodeURIComponent(String(v ?? '')));

  hbs.registerHelper('badge', (value, label) => {
    if (value === null || value === undefined || value === '') return '';
    const tone = TONES[TONE_OF[String(value)] || 'slate'];
    const text = typeof label === 'string' ? label : statusLabel(value);
    return new SafeString(`<span class="inline-flex items-center gap-1.5 whitespace-nowrap rounded-full px-2 py-0.5 text-xs font-medium ${tone.pill}"><span class="h-1.5 w-1.5 rounded-full ${tone.dot}"></span>${escapeExpression(text)}</span>`);
  });

  hbs.registerHelper('date', (v) => {
    if (!v) return '—';
    const d = toDate(v);
    if (Number.isNaN(d.getTime())) return '—';
    return `${MONTHS[d.getMonth()]} ${d.getDate()}, ${d.getFullYear()} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
  });
  hbs.registerHelper('dateTime', (v) => {
    if (!v) return '—';
    const d = toDate(v);
    return Number.isNaN(d.getTime()) ? '—' : `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
  });
  hbs.registerHelper('dateOnly', (v) => {
    if (!v) return '—';
    const d = toDate(v);
    return Number.isNaN(d.getTime()) ? '—' : `${MONTHS[d.getMonth()]} ${d.getDate()}, ${d.getFullYear()}`;
  });
  hbs.registerHelper('time', (v) => {
    if (!v) return '—';
    const d = toDate(v);
    return Number.isNaN(d.getTime()) ? '—' : `${pad(d.getHours())}:${pad(d.getMinutes())}`;
  });
  hbs.registerHelper('today', () => { const d = new Date(); return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`; });
  hbs.registerHelper('isoDate', (v) => (v ? toDate(v).toISOString() : ''));
  hbs.registerHelper('ago', (v) => {
    if (!v) return 'never';
    const diff = Date.now() - toDate(v).getTime();
    const abs = Math.abs(diff);
    if (abs < 60000) return 'just now';
    const [n, u] = abs < 3600000 ? [Math.round(abs / 60000), 'min'] : abs < 86400000 ? [Math.round(abs / 3600000), 'h'] : [Math.round(abs / 86400000), 'd'];
    return diff >= 0 ? `${n} ${u} ago` : `in ${n} ${u}`;
  });
  hbs.registerHelper('duration', (ms) => {
    if (ms === null || ms === undefined || ms === '') return '—';
    const n = Number(ms);
    if (n < 1000) return `${n} ms`;
    if (n < 60000) return `${(n / 1000).toFixed(1)} s`;
    if (n < 3600000) return `${(n / 60000).toFixed(1)} min`;
    return `${(n / 3600000).toFixed(1)} h`;
  });
  hbs.registerHelper('number', (v) => (v === null || v === undefined ? '—' : Number(v).toLocaleString('en-US')));
  hbs.registerHelper('cell', (row, key) => {
    const v = row?.[key];
    if (v instanceof Date) return hbs.handlebars.helpers.date(v);
    if (v && typeof v === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/.test(v)) return hbs.handlebars.helpers.date(v);
    if (v === null || v === undefined || v === '') return '—';
    if (key === 'actionType') return actionLabel(v);
    return v;
  });
};
