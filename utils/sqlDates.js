import { sequelize } from '../config/database.js';

// Timestamps are stored in UTC. Group by the server's local calendar day so that
// reports and charts line up with the dates users select.
export const localOffset = (date = new Date()) => {
  const minutes = -date.getTimezoneOffset();
  const sign = minutes >= 0 ? '+' : '-';
  const abs = Math.abs(minutes);
  return `${sign}${String(Math.floor(abs / 60)).padStart(2, '0')}:${String(abs % 60).padStart(2, '0')}`;
};

export const localDateSql = (column) => `DATE(CONVERT_TZ(${column}, '+00:00', '${localOffset()}'))`;

export const localDate = (column) => sequelize.literal(localDateSql(column));

export const ymd = (d) => {
  const x = new Date(d);
  return `${x.getFullYear()}-${String(x.getMonth() + 1).padStart(2, '0')}-${String(x.getDate()).padStart(2, '0')}`;
};
