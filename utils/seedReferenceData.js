import crypto from 'crypto';
import bcrypt from 'bcrypt';
import {
  Role, User, SourceSystem, AuditEventType, AuditEventRegistry, AlertRule, SystemSetting
} from '../models/index.js';
import {
  ROLE_DEFINITIONS, DEFAULT_EVENT_TYPES, DEFAULT_ALERT_RULES, DEFAULT_SETTINGS,
  DEFAULT_SOURCE_SYSTEMS, INTERNAL_SOURCE_CODE, PERMISSIONS
} from './auditConstants.js';
import { POS_REGISTRY_TEMPLATE } from './posEventCatalog.js';

/**
 * Register the POS Audit Event Registry as the expected events of a source system.
 * Existing entries are left unchanged. Returns the event codes that were added.
 */
export const applyPosRegistryTemplate = async (sourceSystemId, userId = null, transaction = undefined) => {
  const types = new Map((await AuditEventType.findAll({ where: { isActive: true }, raw: true, transaction })).map((t) => [t.code, t]));
  const added = [];
  for (const [code, module, isRequired] of POS_REGISTRY_TEMPLATE) {
    const type = types.get(code);
    if (!type) continue;
    const [, created] = await AuditEventRegistry.findOrCreate({
      where: { sourceSystemId, eventTypeId: type.id },
      defaults: { sourceSystemId, eventTypeId: type.id, sourceModule: module, isRequired, createdByUserId: userId, notes: 'POS Audit Event Registry template' },
      transaction
    });
    if (created) added.push(code);
  }
  return added;
};

/**
 * Idempotent reference data: roles, event types, alert rules, settings, the internal
 * MediSentinel source, the two expected pharmacy integrations (registered as PENDING —
 * never shown as connected until they actually communicate) and the first administrator.
 * No audit events, alerts or statistics are fabricated.
 */
export const seedReferenceData = async ({ log = console.log } = {}) => {
  for (const def of ROLE_DEFINITIONS) {
    const [role, created] = await Role.findOrCreate({
      where: { code: def.code },
      defaults: { ...def, isSystem: true }
    });
    // The administrator role always receives every permission (including newly added ones).
    if (!created && def.code === 'SYSTEM_ADMIN') {
      await role.update({ permissions: Object.keys(PERMISSIONS) });
    }
  }

  for (const type of DEFAULT_EVENT_TYPES) {
    const [row, created] = await AuditEventType.findOrCreate({ where: { code: type.code }, defaults: type });
    // Built-in types receive catalogue rule updates; administrator-controlled fields
    // (active flag, severity, sensitivity) are left as configured.
    if (!created && row.isSystem && JSON.stringify(row.rules ?? null) !== JSON.stringify(type.rules ?? null)) {
      await row.update({ rules: type.rules ?? null });
    }
  }

  for (const rule of DEFAULT_ALERT_RULES) {
    await AlertRule.findOrCreate({ where: { code: rule.code }, defaults: { ...rule, isEnabled: true } });
  }

  for (const setting of DEFAULT_SETTINGS) {
    await SystemSetting.findOrCreate({ where: { key: setting.key }, defaults: setting });
  }
  // Row locked (SELECT … FOR UPDATE) to serialise hash-chain appends.
  await SystemSetting.findOrCreate({
    where: { key: 'audit.chainLock' },
    defaults: { key: 'audit.chainLock', value: { purpose: 'hash chain append lock' }, valueType: 'json', category: 'Internal', isInternal: true }
  });

  await SourceSystem.findOrCreate({
    where: { systemCode: INTERNAL_SOURCE_CODE },
    defaults: {
      systemCode: INTERNAL_SOURCE_CODE,
      name: 'MediSentinel',
      description: 'Governance events produced by MediSentinel itself: sign-ins, configuration changes, investigations, QA runs and report exports.',
      environment: 'PRODUCTION',
      status: 'ACTIVE',
      isInternal: true
    }
  });

  const [seededFlag, firstSeed] = await SystemSetting.findOrCreate({
    where: { key: 'setup.defaultSourcesSeeded' },
    defaults: { key: 'setup.defaultSourcesSeeded', value: true, valueType: 'boolean', category: 'Internal', isInternal: true }
  });
  if (firstSeed && seededFlag) {
    const types = new Map((await AuditEventType.findAll({ raw: true })).map((t) => [t.code, t]));
    for (const def of DEFAULT_SOURCE_SYSTEMS) {
      const [source] = await SourceSystem.findOrCreate({
        where: { systemCode: def.systemCode },
        defaults: { systemCode: def.systemCode, name: def.name, description: def.description, environment: def.environment, status: 'PENDING' }
      });
      for (const [code, module, isRequired = true] of def.expectedEvents) {
        const type = types.get(code);
        if (type) {
          await AuditEventRegistry.findOrCreate({
            where: { sourceSystemId: source.id, eventTypeId: type.id },
            defaults: { sourceSystemId: source.id, eventTypeId: type.id, sourceModule: module, isRequired }
          });
        }
      }
    }
  }

  // Existing installations: add the POS Audit Event Registry to PharmaCore POS once.
  // (Runs a single time so that entries an administrator later removes stay removed.)
  const [, posFirst] = await SystemSetting.findOrCreate({
    where: { key: 'setup.posCatalogRegistrySeeded' },
    defaults: { key: 'setup.posCatalogRegistrySeeded', value: true, valueType: 'boolean', category: 'Internal', isInternal: true }
  });
  if (posFirst) {
    const pos = await SourceSystem.findOne({ where: { systemCode: 'PHARMACORE_POS' } });
    if (pos) await applyPosRegistryTemplate(pos.id, null);
  }

  if ((await User.count()) === 0) {
    const adminRole = await Role.findOne({ where: { code: 'SYSTEM_ADMIN' } });
    const generated = !process.env.ADMIN_INITIAL_PASSWORD;
    const password = process.env.ADMIN_INITIAL_PASSWORD || `Ms-${crypto.randomBytes(9).toString('base64url')}`;
    await User.create({
      fullName: 'System Administrator',
      username: process.env.ADMIN_INITIAL_USERNAME || 'admin',
      email: process.env.ADMIN_INITIAL_EMAIL || 'admin@medisentinel.local',
      passwordHash: await bcrypt.hash(password, 12),
      roleId: adminRole.id,
      isActive: true
    });
    log(`✓ created initial administrator "${process.env.ADMIN_INITIAL_USERNAME || 'admin'}"`);
    if (generated) log(`  generated password: ${password}  (change it after first sign-in)`);
  }
};
