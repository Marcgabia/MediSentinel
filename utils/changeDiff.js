const isPlainObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

/** Flatten nested objects to dotted paths: { a: { b: 1 } } → { 'a.b': 1 }. Arrays are kept as values. */
export const flatten = (obj, prefix = '', out = {}) => {
  if (!isPlainObject(obj)) return out;
  for (const [key, value] of Object.entries(obj)) {
    const path = prefix ? `${prefix}.${key}` : key;
    if (isPlainObject(value) && Object.keys(value).length) flatten(value, path, out);
    else out[path] = value;
  }
  return out;
};

const display = (v) => {
  if (v === undefined) return '';
  if (v === null) return 'null';
  if (typeof v === 'object') return JSON.stringify(v);
  return String(v);
};

const humanize = (path) => path.split('.').map((part) => part
  .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
  .replace(/[_-]+/g, ' ')
  .replace(/^./, (c) => c.toUpperCase())).join(' › ');

/**
 * Compare before/after snapshots field by field.
 * Returns rows: { field, label, before, after, change: 'ADDED'|'REMOVED'|'CHANGED'|'UNCHANGED' }
 */
export const diffChanges = (before, after) => {
  const a = flatten(before || {});
  const b = flatten(after || {});
  const keys = [...new Set([...Object.keys(a), ...Object.keys(b)])].sort();
  return keys.map((key) => {
    const inBefore = Object.prototype.hasOwnProperty.call(a, key);
    const inAfter = Object.prototype.hasOwnProperty.call(b, key);
    let change = 'UNCHANGED';
    if (!inBefore && inAfter) change = 'ADDED';
    else if (inBefore && !inAfter) change = 'REMOVED';
    else if (JSON.stringify(a[key]) !== JSON.stringify(b[key])) change = 'CHANGED';
    return {
      field: key,
      label: humanize(key),
      before: inBefore ? display(a[key]) : '',
      after: inAfter ? display(b[key]) : '',
      change,
      isChanged: change !== 'UNCHANGED'
    };
  });
};

export const summarizeDiff = (rows) => ({
  changed: rows.filter((r) => r.change === 'CHANGED').length,
  added: rows.filter((r) => r.change === 'ADDED').length,
  removed: rows.filter((r) => r.change === 'REMOVED').length,
  unchanged: rows.filter((r) => r.change === 'UNCHANGED').length
});
