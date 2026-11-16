import express from 'express';
import path from 'path';
import fs from 'fs';
import hbs from 'hbs';
import { fileURLToPath, pathToFileURL } from 'url';
import { dirname } from 'path';
import router from './routes/index.js';
import { sequelize } from './models/index.js';
import { runMigrations } from './utils/migrator.js';
import { seedReferenceData } from './utils/seedReferenceData.js';
import { registerHelpers } from './utils/viewHelpers.js';
import { securityHeaders } from './middleware/requestValidation.js';
import { notFound, errorHandler } from './middleware/errorHandler.js';
import { assertIntegrityKeysConfigured } from './utils/integrityHelper.js';
import { assertCredentialKeyConfigured } from './utils/secretBox.js';
import { startQaScheduler } from './services/qaVerificationService.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

app.disable('x-powered-by');
if (process.env.TRUST_PROXY) app.set('trust proxy', process.env.TRUST_PROXY);

app.use(securityHeaders);
app.use(express.static(path.join(__dirname, 'public'), { maxAge: '1h' }));
app.use('/vendor', express.static(path.join(__dirname, 'node_modules', 'chart.js', 'dist'), { maxAge: '7d' }));

// XianFire `.xian` view engine (Handlebars) -----------------------------------
app.engine('xian', (filePath, options, callback) => {
  hbs.__express(filePath, options, callback);
});
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'xian');
registerHelpers(hbs);

const partialsDir = path.join(__dirname, 'views/partials');
fs.readdirSync(partialsDir).filter((file) => file.endsWith('.xian')).forEach((file) => {
  hbs.registerPartial(file.replace('.xian', ''), fs.readFileSync(path.join(partialsDir, file), 'utf8'));
});

app.use('/', router);
app.use(notFound);
app.use(errorHandler);

export default app;

export const startServer = async (port = PORT) => {
  // Fail closed: never accept audit events without integrity and credential keys.
  assertIntegrityKeysConfigured();
  assertCredentialKeyConfigured();

  if (process.env.AUTO_MIGRATE !== 'false') {
    await runMigrations({ log: () => {} });
    await seedReferenceData();
  } else {
    await sequelize.authenticate();
  }
  startQaScheduler();

  return new Promise((resolve, reject) => {
    const server = app.listen(port, () => {
      console.log(`🔥 MediSentinel running at http://localhost:${port}`);
      if (process.env.DEMO_TRAFFIC === 'true') {
        import('./services/demoTrafficService.js')
          .then(({ startDemoTraffic }) => startDemoTraffic({ port: server.address().port }))
          .catch((error) => console.warn('[demo-traffic] not started:', error.message));
      }
      resolve(server);
    });
    server.on('error', reject);
  });
};

const isDirectRun = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isDirectRun && !process.env.XIAN_ELECTRON) {
  startServer().catch((error) => {
    console.error('✗ MediSentinel failed to start:', error.message);
    process.exit(1);
  });
}
