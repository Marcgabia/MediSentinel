// Creates every table defined by the Sequelize models (CREATE TABLE IF NOT EXISTS semantics).
// `sync()` without `alter`/`force` never modifies or drops existing tables or data.
import '../models/index.js';

export const up = async ({ sequelize }) => {
  await sequelize.sync();
};
