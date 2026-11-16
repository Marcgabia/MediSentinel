// CSV serialisation with formula-injection protection (cells beginning with = + - @ tab or CR are prefixed).
const FORMULA_START = /^[=+\-@\t\r]/;

export const escapeCsvCell = (value) => {
  if (value === null || value === undefined) return '""';
  let text = value instanceof Date ? value.toISOString() : typeof value === 'object' ? JSON.stringify(value) : String(value);
  if (FORMULA_START.test(text)) text = `'${text}`;
  return `"${text.replace(/"/g, '""').replace(/\r?\n/g, ' ')}"`;
};

export const toCsv = (columns, rows) => {
  const header = columns.map((c) => escapeCsvCell(c.label)).join(',');
  const body = rows.map((row) => columns.map((c) => escapeCsvCell(row[c.key])).join(','));
  // BOM helps spreadsheet apps detect UTF-8
  return `﻿${[header, ...body].join('\r\n')}`;
};
