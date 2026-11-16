// Runs before every test file. Forces the dedicated test database and fixed test keys.
process.env.NODE_ENV = 'test';
process.env.DB_TEST_NAME = process.env.DB_TEST_NAME || 'medisentinel_test';
process.env.AUDIT_SIGNING_KEY_ID = 'ktest';
process.env.AUDIT_SIGNING_KEY = 'a'.repeat(64);
process.env.AUDIT_SIGNING_KEYS_RETIRED = 'kold:' + 'b'.repeat(64);
process.env.CREDENTIAL_ENCRYPTION_KEY = 'c'.repeat(64);
process.env.SESSION_SECRET = 'test-session-secret-'.padEnd(48, 'x');
process.env.ADMIN_INITIAL_USERNAME = 'admin';
process.env.ADMIN_INITIAL_EMAIL = 'admin@test.local';
process.env.ADMIN_INITIAL_PASSWORD = 'AdminPass123';
process.env.LOGIN_RATE_LIMIT = '1000';
