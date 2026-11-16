import dotenv from 'dotenv';
import { Sequelize } from 'sequelize';

dotenv.config({ quiet: true });

const isTest = process.env.NODE_ENV === 'test';

export const databaseName = isTest
  ? (process.env.DB_TEST_NAME || 'medisentinel_test')
  : (process.env.DB_NAME || 'medisentinel_audit');

export const connectionOptions = {
  host: process.env.DB_HOST || 'localhost',
  port: Number(process.env.DB_PORT || 3306),
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || ''
};

export const sequelize = new Sequelize(databaseName, connectionOptions.user, connectionOptions.password, {
  host: connectionOptions.host,
  port: connectionOptions.port,
  dialect: 'mysql',
  logging: process.env.DB_LOGGING === 'true' ? console.log : false,
  timezone: '+00:00',
  dialectOptions: {
    dateStrings: false,
    supportBigNumbers: true,
    bigNumberStrings: false
  },
  pool: { max: 10, min: 0, idle: 10000 },
  define: {
    timestamps: true,
    underscored: false,
    charset: 'utf8mb4',
    collate: 'utf8mb4_unicode_ci'
  }
});

export const isSqlite = false;
