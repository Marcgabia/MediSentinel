// Central catalogue of enumerations, permissions, and reference data used across MediSentinel.
import { POS_EVENT_DEFINITIONS, GENERIC_RULE_OVERRIDES, POS_REGISTRY_TEMPLATE } from './posEventCatalog.js';

export const INTERNAL_SOURCE_CODE = 'MEDISENTINEL';

export const EVENT_SEVERITIES = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
export const SEVERITY_RANK = { INFO: 0, INFORMATIONAL: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };

export const EVENT_OUTCOMES = ['SUCCESS', 'FAILURE', 'DENIED'];
export const OUTCOME_ALIASES = {
  SUCCESS: 'SUCCESS', SUCCEEDED: 'SUCCESS', OK: 'SUCCESS',
  FAILURE: 'FAILURE', FAILED: 'FAILURE', FAIL: 'FAILURE', ERROR: 'FAILURE',
  DENIED: 'DENIED', UNAUTHORIZED: 'DENIED', FORBIDDEN: 'DENIED'
};

export const EVENT_CATEGORIES = ['AUTHENTICATION', 'RECORD', 'OPERATIONAL', 'ADMINISTRATIVE', 'SECURITY', 'SYSTEM'];

export const INGESTION_CHANNELS = ['API', 'BATCH', 'INTERNAL'];

export const SOURCE_SYSTEM_STATUSES = ['PENDING', 'ACTIVE', 'SUSPENDED', 'RETIRED'];
export const SOURCE_ENVIRONMENTS = ['PRODUCTION', 'STAGING', 'TEST', 'DEVELOPMENT'];

// Health is always derived from real communication, never assigned manually.
export const HEALTH_STATUSES = ['HEALTHY', 'DEGRADED', 'STALE', 'NEVER_CONNECTED', 'SUSPENDED'];

export const INTEGRATION_LOG_OUTCOMES = [
  'ACCEPTED', 'DUPLICATE', 'CONFLICT', 'REJECTED_VALIDATION', 'REJECTED_AUTH',
  'REJECTED_FORBIDDEN', 'RATE_LIMITED', 'ERROR', 'HEARTBEAT', 'CONNECTION_TEST_OK', 'CONNECTION_TEST_FAILED'
];

export const ALERT_SEVERITIES = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
export const ALERT_STATUSES = ['OPEN', 'ACKNOWLEDGED', 'INVESTIGATING', 'RESOLVED', 'DISMISSED'];
export const ALERT_ACTIVE_STATUSES = ['OPEN', 'ACKNOWLEDGED', 'INVESTIGATING'];

export const CASE_STATUSES = ['OPEN', 'UNDER_INVESTIGATION', 'PENDING_REVIEW', 'RESOLVED', 'CLOSED'];
export const CASE_ACTIVE_STATUSES = ['OPEN', 'UNDER_INVESTIGATION', 'PENDING_REVIEW'];
export const CASE_TRANSITIONS = {
  OPEN: ['UNDER_INVESTIGATION', 'PENDING_REVIEW', 'CLOSED'],
  UNDER_INVESTIGATION: ['PENDING_REVIEW', 'OPEN', 'RESOLVED'],
  PENDING_REVIEW: ['UNDER_INVESTIGATION', 'RESOLVED'],
  RESOLVED: ['CLOSED', 'UNDER_INVESTIGATION'],
  CLOSED: ['UNDER_INVESTIGATION']
};
export const CASE_NOTE_TYPES = ['NOTE', 'STATUS_CHANGE', 'ASSIGNMENT', 'FINDING', 'EVIDENCE', 'RESOLUTION', 'SYSTEM'];

export const QA_STATUSES = ['PASS', 'FAIL', 'WARNING', 'NOT_TESTED'];
export const QA_CATEGORIES = [
  'EVENT_VALIDATION', 'AUDIT_INTEGRITY', 'EVENT_COVERAGE', 'INTEGRATION_QUALITY',
  'POS_EVENT_VALIDATION', 'TRANSACTION_CONSISTENCY', 'CONFIGURATION_AUDIT', 'CROSS_SYSTEM_CONSISTENCY'
];
export const QA_CATEGORY_LABELS = {
  EVENT_VALIDATION: 'Audit Event Validation',
  AUDIT_INTEGRITY: 'Audit Integrity Verification',
  EVENT_COVERAGE: 'Event Coverage Monitoring',
  INTEGRATION_QUALITY: 'API & Integration Quality',
  POS_EVENT_VALIDATION: 'POS Event Validation',
  TRANSACTION_CONSISTENCY: 'Transaction Audit Consistency',
  CONFIGURATION_AUDIT: 'Configuration Audit Verification',
  CROSS_SYSTEM_CONSISTENCY: 'Cross-System Consistency'
};
export const POS_QA_CATEGORIES = ['POS_EVENT_VALIDATION', 'TRANSACTION_CONSISTENCY', 'CONFIGURATION_AUDIT', 'CROSS_SYSTEM_CONSISTENCY'];
export const FINDING_SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL'];
export const FINDING_STATUSES = ['OPEN', 'UNDER_INVESTIGATION', 'RESOLVED', 'VERIFIED'];

export const NOTIFICATION_TYPES = {
  CRITICAL_AUDIT_ALERT: 'Critical Audit Alert',
  SUSPICIOUS_ACTIVITY: 'Suspicious Activity',
  FAILED_INTEGRATION: 'Failed Integration',
  FAILED_EVENT_VALIDATION: 'Failed Event Validation',
  INTEGRITY_FAILURE: 'Integrity Verification Failure',
  UNRESOLVED_QA_FINDING: 'Unresolved QA Finding',
  REPEATED_AUTH_FAILURE: 'Repeated Authentication Failure',
  INVESTIGATION_ASSIGNMENT: 'New Investigation Assignment',
  ACCOUNT_REQUEST: 'Account Awaiting Approval'
};

// ---------------------------------------------------------------------------
// Internal permissions (MediSentinel users only — never the roles reported by source systems)
// ---------------------------------------------------------------------------
export const PERMISSIONS = {
  'dashboard.view': 'View dashboard',
  'audit.view': 'View audit records',
  'audit.export': 'Export audit records',
  'transactions.view': 'View transaction audit timelines and void investigations',
  'activity.view': 'View user activity monitoring',
  'integrations.view': 'View integrations & monitoring',
  'integrations.manage': 'Register and manage source systems',
  'credentials.manage': 'Issue and revoke integration credentials',
  'alerts.view': 'View suspicious activity alerts',
  'alerts.manage': 'Acknowledge, assign, annotate and resolve alerts',
  'alertRules.manage': 'Configure alert detection rules',
  'investigations.view': 'View assigned investigations',
  'investigations.viewAll': 'View all investigations',
  'investigations.manage': 'Create and update investigation cases',
  'reports.view': 'Generate audit reports',
  'reports.export': 'Export reports to CSV',
  'qa.view': 'View QA dashboard, runs and findings',
  'qa.run': 'Execute QA verification runs',
  'qa.manage': 'Manage QA findings and event registry',
  'notifications.view': 'View notifications',
  'users.manage': 'Manage internal users and roles',
  'settings.manage': 'Modify system settings and event types'
};

export const ROLE_DEFINITIONS = [
  {
    code: 'SYSTEM_ADMIN',
    name: 'System Administrator',
    description: 'Manages MediSentinel, integrations, credentials, rules, users and QA settings.',
    canAccessDashboard: true,
    permissions: Object.keys(PERMISSIONS)
  },
  {
    code: 'AUDITOR',
    name: 'Auditor',
    description: 'Read-only access to audit records, comparisons, reports and QA results.',
    canAccessDashboard: true,
    permissions: ['dashboard.view', 'audit.view', 'audit.export', 'transactions.view', 'activity.view', 'integrations.view',
      'alerts.view', 'investigations.view', 'investigations.viewAll', 'reports.view', 'reports.export',
      'qa.view', 'notifications.view']
  },
  {
    code: 'INVESTIGATOR',
    name: 'Investigator',
    description: 'Reviews suspicious activity and manages assigned investigation cases.',
    canAccessDashboard: true,
    permissions: ['dashboard.view', 'audit.view', 'transactions.view', 'activity.view', 'alerts.view', 'alerts.manage',
      'investigations.view', 'investigations.manage', 'notifications.view']
  },
  {
    code: 'VIEWER',
    name: 'Read-Only Viewer',
    description: 'Views authorised dashboards and audit records. Cannot modify anything.',
    canAccessDashboard: true,
    permissions: ['dashboard.view', 'audit.view', 'notifications.view']
  },
  {
    code: 'INTEGRATION_SERVICE',
    name: 'Integration Service Account',
    description: 'Machine identity for source systems. Submits events through the signed API only; cannot sign in to the dashboard.',
    canAccessDashboard: false,
    permissions: []
  }
];

// ---------------------------------------------------------------------------
// Registered audit event types (action codes accepted by the ingestion API)
// ---------------------------------------------------------------------------
const t = (code, name, category, opts = {}) => ({
  code, name, category,
  description: opts.description || name,
  defaultSeverity: opts.severity || 'INFO',
  isSensitive: Boolean(opts.sensitive),
  requiresEntity: Boolean(opts.entity),
  requiresChanges: Boolean(opts.changes),
  rules: opts.rules || GENERIC_RULE_OVERRIDES[code] || null,
  isSystem: true
});

export const DEFAULT_EVENT_TYPES = [
  // Authentication
  t('LOGIN_SUCCESS', 'Successful Login', 'AUTHENTICATION'),
  t('LOGIN_FAILED', 'Failed Login', 'AUTHENTICATION', { severity: 'LOW' }),
  t('LOGOUT', 'Logout', 'AUTHENTICATION'),
  t('PASSWORD_CHANGED', 'Password Change', 'AUTHENTICATION', { severity: 'LOW', sensitive: true }),
  t('ACCOUNT_ACTIVATED', 'Account Activation', 'AUTHENTICATION', { entity: true, sensitive: true }),
  t('ACCOUNT_DEACTIVATED', 'Account Deactivation', 'AUTHENTICATION', { entity: true, sensitive: true, severity: 'LOW' }),
  // Record activities
  t('CREATE', 'Record Created', 'RECORD', { entity: true }),
  t('READ', 'Sensitive Record Accessed', 'RECORD', { entity: true, sensitive: true }),
  t('UPDATE', 'Record Updated', 'RECORD', { entity: true, changes: true }),
  t('DELETE', 'Record Deleted', 'RECORD', { entity: true, sensitive: true, severity: 'MEDIUM' }),
  t('ARCHIVE', 'Record Archived', 'RECORD', { entity: true }),
  t('RESTORE', 'Record Restored', 'RECORD', { entity: true }),
  // Operational activities (reported by POS / inventory systems; MediSentinel never performs them)
  t('PAYMENT_STATUS_CHANGED', 'Payment Status Changed', 'OPERATIONAL', { entity: true, changes: true, sensitive: true }),
  t('INVENTORY_UPDATED', 'Inventory Record Updated', 'OPERATIONAL', { entity: true, changes: true }),
  t('STOCK_IN', 'Stock-In Recorded', 'OPERATIONAL', { entity: true }),
  t('STOCK_OUT', 'Stock-Out Recorded', 'OPERATIONAL', { entity: true }),
  t('STOCK_MOVEMENT', 'Stock Movement Recorded', 'OPERATIONAL', { entity: true }),
  t('INVENTORY_ADJUSTMENT', 'Inventory Adjustment', 'OPERATIONAL', { entity: true, changes: true, sensitive: true, severity: 'LOW' }),
  // Administrative activities
  t('ROLE_CHANGED', 'User Role Changed', 'ADMINISTRATIVE', { entity: true, changes: true, sensitive: true, severity: 'MEDIUM' }),
  t('PERMISSION_CHANGED', 'User Permission Changed', 'ADMINISTRATIVE', { entity: true, changes: true, sensitive: true, severity: 'MEDIUM' }),
  t('ACCOUNT_CREATED', 'Account Created', 'ADMINISTRATIVE', { entity: true }),
  t('ACCOUNT_MODIFIED', 'Account Modified', 'ADMINISTRATIVE', { entity: true, changes: true }),
  t('ACCOUNT_DISABLED', 'Account Disabled', 'ADMINISTRATIVE', { entity: true, sensitive: true, severity: 'LOW' }),
  t('SETTINGS_MODIFIED', 'Settings Modified', 'ADMINISTRATIVE', { changes: true, sensitive: true, severity: 'LOW' }),
  t('REPORT_GENERATED', 'Report Generated', 'ADMINISTRATIVE'),
  t('REPORT_EXPORTED', 'Report Exported', 'ADMINISTRATIVE', { sensitive: true }),
  // Security
  t('ACCESS_DENIED', 'Restricted Access Attempt', 'SECURITY', { severity: 'MEDIUM' }),
  // MediSentinel internal governance events
  t('SOURCE_SYSTEM_REGISTERED', 'Source System Registered', 'SYSTEM', { entity: true }),
  t('SOURCE_SYSTEM_UPDATED', 'Source System Updated', 'SYSTEM', { entity: true, changes: true }),
  t('CREDENTIAL_ISSUED', 'Integration Credential Issued', 'SYSTEM', { entity: true, sensitive: true, severity: 'LOW' }),
  t('CREDENTIAL_REVOKED', 'Integration Credential Revoked', 'SYSTEM', { entity: true, sensitive: true, severity: 'LOW' }),
  t('ALERT_UPDATED', 'Alert Updated', 'SYSTEM', { entity: true }),
  t('ALERT_RULE_CHANGED', 'Alert Rule Changed', 'SYSTEM', { entity: true, changes: true, sensitive: true }),
  t('CASE_CREATED', 'Investigation Case Created', 'SYSTEM', { entity: true }),
  t('CASE_UPDATED', 'Investigation Case Updated', 'SYSTEM', { entity: true }),
  t('CASE_ASSIGNED', 'Investigation Case Assigned', 'SYSTEM', { entity: true, changes: true }),
  t('CASE_STATUS_CHANGED', 'Investigation Status Changed', 'SYSTEM', { entity: true, changes: true }),
  t('QA_VERIFICATION_RUN', 'QA Verification Executed', 'SYSTEM', { entity: true }),
  t('QA_FINDING_UPDATED', 'QA Finding Updated', 'SYSTEM', { entity: true, changes: true }),
  t('EVENT_REGISTRY_CHANGED', 'Event Registry Changed', 'SYSTEM', { entity: true }),
  t('IDENTITY_MAPPING_CHANGED', 'Cross-System Identity Mapping Changed', 'SYSTEM', { entity: true, sensitive: true }),
  // Pharmacy application activities (POS Audit Event Registry — see utils/posEventCatalog.js).
  // TRANSACTION_CREATED / _UPDATED / _VOIDED keep their original codes and requirements.
  ...POS_EVENT_DEFINITIONS.map((def) => t(def.code, def.name, def.category, def))
];

// ---------------------------------------------------------------------------
// Expected event coverage for the two primary integrations (monitoring config only)
// ---------------------------------------------------------------------------
export const DEFAULT_SOURCE_SYSTEMS = [
  {
    systemCode: 'PHARMACORE_POS',
    name: 'PharmaCore POS',
    description: 'Pharmacy point-of-sale system. Submits customer, store configuration, branch, product, transaction, void authorization, report and price-check events.',
    environment: 'PRODUCTION',
    expectedEvents: POS_REGISTRY_TEMPLATE
  },
  {
    systemCode: 'PHARMA_INVENTORY',
    name: 'Pharmacy Inventory Management System',
    description: 'Inventory and stock management system. Submits stock movements, adjustments and authentication events.',
    environment: 'PRODUCTION',
    expectedEvents: [
      ['LOGIN_SUCCESS', 'Authentication'], ['STOCK_IN', 'Stock'], ['STOCK_OUT', 'Stock'],
      ['INVENTORY_ADJUSTMENT', 'Stock'], ['INVENTORY_UPDATED', 'Inventory'], ['REPORT_EXPORTED', 'Reports'],
      ['LOGOUT', 'Authentication']
    ]
  }
];

// ---------------------------------------------------------------------------
// Alert rule presets. Every rule uses the same generic engine (see utils/alertRuleEngine.js).
// ---------------------------------------------------------------------------
export const ALERT_RULE_TYPES = {
  EVENT_THRESHOLD: 'Event count threshold',
  OFF_HOURS: 'Activity outside business hours',
  API_AUTH_FAILURE: 'Repeated failed API authentication'
};

export const DEFAULT_ALERT_RULES = [
  {
    code: 'FAILED_LOGIN_BURST', name: 'Multiple failed login attempts', ruleType: 'EVENT_THRESHOLD',
    description: 'Several failed logins for the same user on the same source system within the window.',
    threshold: 5, windowMinutes: 15, severity: 'HIGH', params: { actions: ['LOGIN_FAILED'], groupBy: 'actor' }
  },
  {
    code: 'UNAUTHORIZED_ACCESS_REPEAT', name: 'Repeated unauthorized access attempts', ruleType: 'EVENT_THRESHOLD',
    description: 'A user repeatedly attempted to reach restricted functions (ACCESS_DENIED events or DENIED outcomes).',
    threshold: 3, windowMinutes: 30, severity: 'HIGH', params: { actions: ['ACCESS_DENIED'], outcomes: ['DENIED'], matchMode: 'any', groupBy: 'actor' }
  },
  {
    code: 'PRIVILEGE_CHANGE_BURST', name: 'Unusual permission changes', ruleType: 'EVENT_THRESHOLD',
    description: 'Multiple role or permission modifications performed by the same user within the window.',
    threshold: 3, windowMinutes: 60, severity: 'HIGH', params: { actions: ['ROLE_CHANGED', 'PERMISSION_CHANGED'], groupBy: 'actor' }
  },
  {
    code: 'SENSITIVE_MODIFICATION_BURST', name: 'Rapid sensitive record modifications', ruleType: 'EVENT_THRESHOLD',
    description: 'Many sensitive modifications by the same user in a short period.',
    threshold: 10, windowMinutes: 15, severity: 'MEDIUM',
    params: { actions: ['UPDATE', 'PAYMENT_STATUS_CHANGED', 'INVENTORY_ADJUSTMENT', 'ACCOUNT_MODIFIED'], groupBy: 'actor' }
  },
  {
    code: 'MASS_DELETION', name: 'High-volume record deletion', ruleType: 'EVENT_THRESHOLD',
    description: 'Large number of DELETE events by the same user.',
    threshold: 5, windowMinutes: 10, severity: 'CRITICAL', params: { actions: ['DELETE'], groupBy: 'actor' }
  },
  {
    code: 'FREQUENT_VOIDS', name: 'Frequent transaction voiding', ruleType: 'EVENT_THRESHOLD',
    description: 'A user voided several transactions within the window.',
    threshold: 3, windowMinutes: 60, severity: 'HIGH', params: { actions: ['TRANSACTION_VOIDED'], groupBy: 'actor' }
  },
  {
    code: 'VOID_AUTHORIZATION_FAILURES', name: 'Repeated rejected void authorizations', ruleType: 'EVENT_THRESHOLD',
    description: 'Several void requests by the same user were rejected within the window. An indicator for review, not proof of wrongdoing.',
    threshold: 3, windowMinutes: 60, severity: 'MEDIUM', params: { actions: ['TRANSACTION_VOID_REJECTED'], groupBy: 'actor' }
  },
  {
    code: 'OFF_HOURS_ADMIN', name: 'Administrative activity outside business hours', ruleType: 'OFF_HOURS',
    description: 'Administrative actions recorded outside configured business hours.',
    threshold: 1, windowMinutes: 60, severity: 'MEDIUM',
    params: { categories: ['ADMINISTRATIVE'], startHour: 7, endHour: 21, timezone: 'Asia/Manila', groupBy: 'actor' }
  },
  {
    code: 'EVENT_VOLUME_SPIKE', name: 'Unexpected audit event volume', ruleType: 'EVENT_THRESHOLD',
    description: 'A source system submitted an unusually high number of events in a short window.',
    threshold: 500, windowMinutes: 5, severity: 'MEDIUM', params: { groupBy: 'source' }
  },
  {
    code: 'CRITICAL_EVENT', name: 'Critical severity event reported', ruleType: 'EVENT_THRESHOLD',
    description: 'A source system reported an event with CRITICAL severity.',
    threshold: 1, windowMinutes: 1, severity: 'CRITICAL', params: { minSeverity: 'CRITICAL', groupBy: 'event' }
  },
  {
    code: 'API_AUTH_FAILURE', name: 'Repeated failed API authentication', ruleType: 'API_AUTH_FAILURE',
    description: 'Repeated signature or credential failures against the ingestion API from the same key or address.',
    threshold: 5, windowMinutes: 10, severity: 'HIGH', params: {}
  }
];

// ---------------------------------------------------------------------------
// Configurable system settings
// ---------------------------------------------------------------------------
export const DEFAULT_SETTINGS = [
  { key: 'integration.staleAfterMinutes', value: 30, valueType: 'number', category: 'Integration', label: 'Mark disconnected after (minutes)' },
  { key: 'integration.degradedErrorRate', value: 25, valueType: 'number', category: 'Integration', label: 'Mark degraded above error rate (%)' },
  { key: 'integration.timestampToleranceSeconds', value: 300, valueType: 'number', category: 'Integration', label: 'Allowed clock difference (seconds)' },
  { key: 'integration.maxBatchSize', value: 100, valueType: 'number', category: 'Integration', label: 'Max events per batch' },
  { key: 'integration.maxEventAgeDays', value: 30, valueType: 'number', category: 'Integration', label: 'Reject events older than (days)' },
  { key: 'integration.connectionTestTimeoutMs', value: 5000, valueType: 'number', category: 'Integration', label: 'Connection test timeout (ms)' },
  { key: 'qa.scheduleIntervalMinutes', value: 60, valueType: 'number', category: 'Quality Assurance', label: 'Run QA every (minutes, 0 = off)' },
  { key: 'qa.maxDeliveryDelaySeconds', value: 300, valueType: 'number', category: 'Quality Assurance', label: 'Max delivery delay (seconds)' },
  { key: 'qa.lookbackDays', value: 7, valueType: 'number', category: 'Quality Assurance', label: 'Look back (days)' },
  { key: 'qa.invalidRateWarningPercent', value: 5, valueType: 'number', category: 'Quality Assurance', label: 'Warn above invalid rate (%)' },
  { key: 'security.sessionIdleMinutes', value: 30, valueType: 'number', category: 'Security', label: 'Sign out after inactivity (minutes)' },
  { key: 'security.maxFailedLogins', value: 5, valueType: 'number', category: 'Security', label: 'Lock after failed logins' },
  { key: 'security.lockoutMinutes', value: 15, valueType: 'number', category: 'Security', label: 'Lock duration (minutes)' },
  { key: 'security.allowSelfRegistration', value: 1, valueType: 'number', category: 'Security', label: 'Allow "Create account" on the sign-in page (1 = yes, 0 = no). New accounts are read-only and need approval' },
  { key: 'reports.maxExportRows', value: 50000, valueType: 'number', category: 'Reports', label: 'Max rows per CSV export' },
  { key: 'pos.observationWindowMinutes', value: 30, valueType: 'number', category: 'Pharmacy Operations', label: 'Wait before treating an expected event as missing (minutes)' },
  { key: 'pos.voidAuthorizationRequired', value: 1, valueType: 'number', category: 'Pharmacy Operations', label: 'Voids need an authorizer or verified reference (1 = yes, 0 = no)' },
  { key: 'pos.repeatedVoidThreshold', value: 3, valueType: 'number', category: 'Pharmacy Operations', label: 'Flag repeated voids by one user at' },
  { key: 'pos.repeatedVoidWindowHours', value: 24, valueType: 'number', category: 'Pharmacy Operations', label: 'Repeated void window (hours)' }
];

export const SENSITIVE_FIELD_PATTERN = /(pass(word|wd)?|secret|token|api[_-]?key|authorization|cookie|session|pin|cvv|card[_-]?number)/i;
