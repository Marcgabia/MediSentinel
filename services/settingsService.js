import { SystemSetting } from '../models/index.js';
import { DEFAULT_SETTINGS } from '../utils/auditConstants.js';

const DEFAULTS = new Map(DEFAULT_SETTINGS.map((s) => [s.key, s]));
const CACHE_TTL_MS = 10000;
let cache = null;
let cacheLoadedAt = 0;

const load = async () => {
  if (cache && Date.now() - cacheLoadedAt < CACHE_TTL_MS) return cache;
  const rows = await SystemSetting.findAll({ where: { isInternal: false }, raw: true });
  cache = new Map(rows.map((r) => [r.key, r]));
  cacheLoadedAt = Date.now();
  return cache;
};

export const invalidateSettingsCache = () => { cache = null; };

export const getSetting = async (key) => {
  const settings = await load();
  if (settings.has(key)) return settings.get(key).value;
  return DEFAULTS.get(key)?.value;
};

export const getSettingsMap = async (keys) => {
  const out = {};
  for (const key of keys) out[key] = await getSetting(key);
  return out;
};

export const listSettings = async () => {
  const settings = await load();
  const grouped = {};
  for (const def of DEFAULT_SETTINGS) {
    const row = settings.get(def.key) || def;
    (grouped[def.category] ||= []).push({ ...def, value: row.value });
  }
  return Object.entries(grouped).map(([category, items]) => ({ category, items }));
};

/** Validate and persist submitted settings; returns { before, after } of changed keys. */
export const updateSettings = async (input, userId) => {
  const before = {};
  const after = {};
  const errors = [];
  for (const def of DEFAULT_SETTINGS) {
    if (!(def.key in input)) continue;
    let value = input[def.key];
    if (def.valueType === 'number') {
      value = Number(value);
      if (!Number.isFinite(value) || value < 0) { errors.push(`${def.label}: must be a non-negative number.`); continue; }
    }
    const current = await getSetting(def.key);
    if (current !== value) {
      before[def.key] = current;
      after[def.key] = value;
    }
  }
  if (errors.length) {
    const err = new Error(errors.join(' '));
    err.status = 400;
    throw err;
  }
  for (const [key, value] of Object.entries(after)) {
    const def = DEFAULTS.get(key);
    await SystemSetting.upsert({ ...def, key, value, updatedByUserId: userId || null });
  }
  invalidateSettingsCache();
  return { before, after };
};
