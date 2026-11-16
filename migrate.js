// Safe, versioned schema migration + idempotent reference data.
// Never drops or truncates existing data. Usage: npm run migrate
import { runMigrations } from './utils/migrator.js';
import { seedReferenceData } from './utils/seedReferenceData.js';
import { sequelize, databaseName } from './config/database.js';

try {
  console.log(`MediSentinel migrations → database "${databaseName}"`);
  await runMigrations();
  await seedReferenceData();
  console.log('✓ reference data ensured');
} catch (error) {
  console.error('✗ migration failed:', error.message);
  process.exitCode = 1;
} finally {
  await sequelize.close();
}
