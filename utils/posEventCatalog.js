// Standardized audit event registry for integrated pharmacy applications (POS and its
// associated modules). MediSentinel only RECORDS these activities — it never performs them.
//
// Each definition becomes a row in audit_event_types. `rules` drives:
//   - normalization (transaction reference, customer-data masking),
//   - QA expectations (reason, authorization, before/after values, correlation),
//   - the transaction timeline, void investigation, configuration history and dashboard groups.
//
// Ingestion REJECTS only structurally invalid events. Business-completeness expectations
// (e.g. a void without a reason) are ACCEPTED and FLAGGED, because rejecting them would
// erase the evidence that the activity happened.

export const POS_GROUPS = {
  CUSTOMER: 'Customer management',
  CONFIGURATION: 'Store configuration',
  BRANCH: 'Branch management',
  PRODUCT: 'Product management',
  TRANSACTION: 'Transactions',
  VOID: 'Void authorization',
  REPORT: 'Sales history & reports',
  PRICE_CHECK: 'Price checks'
};

// Normalized (lower-case) transaction statuses and the transitions a POS may report.
// PharmaCore uses "completed" and "voided"; other systems add pending/cancelled/refunded.
export const TRANSACTION_STATUS_TRANSITIONS = {
  draft: ['pending', 'open', 'completed', 'cancelled'],
  open: ['pending', 'completed', 'cancelled', 'voided'],
  pending: ['completed', 'cancelled', 'voided'],
  completed: ['voided', 'refunded'],
  cancelled: [],
  voided: [],
  refunded: []
};
export const TERMINAL_STATUSES = ['cancelled', 'voided', 'refunded'];

export const AUTHORIZATION_OUTCOMES = ['APPROVED', 'REJECTED', 'PENDING', 'NOT_REQUIRED', 'FAILED'];
export const LOOKUP_RESULT_STATUSES = ['FOUND', 'NOT_FOUND', 'MULTIPLE', 'ERROR'];
export const EXPORT_FORMATS = ['CSV', 'PDF', 'XLSX', 'PRINT', 'JSON'];

// Customer personal data keys that are always masked (any event), and the generic keys that
// are additionally masked on events whose rules set `maskPersonalData`.
export const CUSTOMER_PII_KEYS = [
  'customerName', 'customerFullName', 'customerPhone', 'customerMobile', 'customerEmail', 'customerAddress',
  'customerBirthDate', 'customerContact'
];
export const GENERIC_PII_KEYS = [
  'name', 'fullName', 'firstName', 'middleName', 'lastName', 'phone', 'phoneNumber', 'mobile', 'mobileNumber',
  'contactNumber', 'contact', 'email', 'emailAddress', 'address', 'street', 'barangay', 'city', 'birthDate',
  'dateOfBirth', 'dob', 'birthday', 'seniorCitizenId', 'pwdId', 'idNumber', 'governmentId', 'philhealthNumber'
];

const d = (code, name, category, group, opts = {}) => ({
  code,
  name,
  category,
  description: opts.description || name,
  severity: opts.severity || 'INFO',
  sensitive: Boolean(opts.sensitive),
  entity: Boolean(opts.entity),
  changes: Boolean(opts.changes),
  rules: {
    group,
    module: opts.module,
    entityTypes: opts.entityTypes || null,
    entityKind: opts.entityKind || null,
    expectBefore: Boolean(opts.expectBefore),
    expectAfter: Boolean(opts.expectAfter || opts.changes),
    requiresReason: Boolean(opts.reason),
    requiresAuthorization: Boolean(opts.authorization),
    expectedAuthorizationOutcomes: opts.authOutcomes || null,
    expectsCorrelation: Boolean(opts.correlation),
    expectsBranch: Boolean(opts.branch),
    maskPersonalData: Boolean(opts.mask),
    routine: Boolean(opts.routine),
    configuration: Boolean(opts.configuration),
    report: Boolean(opts.report),
    lookup: Boolean(opts.lookup),
    oneTime: Boolean(opts.oneTime),
    setsStatus: opts.setsStatus || null
  }
});

const CUSTOMER = { module: 'Customers', entityTypes: ['Customer'], entityKind: 'CUSTOMER', mask: true };
const STORE = { module: 'Store Settings', entityTypes: ['StoreSettings', 'Store'], configuration: true };
const BRANCH = { module: 'Branches', entityTypes: ['Branch'], entityKind: 'BRANCH' };
const PRODUCT = { module: 'Products', entityTypes: ['Product'], entityKind: 'PRODUCT' };
const TXN = { module: 'Sales', entityTypes: ['Transaction', 'SalesTransaction', 'Sale'], entityKind: 'TRANSACTION', entity: true, correlation: true, branch: true };
const VOID = { ...TXN, module: 'Sales' };
const REPORT = { module: 'Reports', report: true };

export const POS_EVENT_DEFINITIONS = [
  // A. Customer management
  d('CUSTOMER_LOOKUP', 'Customer Lookup', 'RECORD', 'CUSTOMER', { ...CUSTOMER, routine: true, lookup: true }),
  d('CUSTOMER_CREATED', 'Customer Created', 'RECORD', 'CUSTOMER', { ...CUSTOMER, entity: true, expectAfter: true }),
  d('CUSTOMER_INFORMATION_UPDATED', 'Customer Information Updated', 'RECORD', 'CUSTOMER', { ...CUSTOMER, entity: true, changes: true, expectBefore: true, sensitive: true }),

  // B. Store configuration
  d('STORE_SETTINGS_VIEWED', 'Store Settings Viewed', 'ADMINISTRATIVE', 'CONFIGURATION', { ...STORE, configuration: false, routine: true }),
  d('STORE_SETTINGS_UPDATED', 'Store Settings Updated', 'ADMINISTRATIVE', 'CONFIGURATION', { ...STORE, changes: true, expectBefore: true, sensitive: true, severity: 'LOW' }),
  d('STORE_LOGO_UPDATED', 'Store Logo Updated', 'ADMINISTRATIVE', 'CONFIGURATION', { ...STORE, changes: true, expectBefore: true }),
  d('DEFAULT_BRANCH_CHANGED', 'Default Branch Changed', 'ADMINISTRATIVE', 'CONFIGURATION', { ...STORE, changes: true, expectBefore: true, sensitive: true, severity: 'LOW' }),
  d('RECEIPT_SETTING_CHANGED', 'Receipt Setting Changed', 'ADMINISTRATIVE', 'CONFIGURATION', { ...STORE, changes: true, expectBefore: true }),
  d('PRODUCT_DISPLAY_SETTING_CHANGED', 'Product Display Setting Changed', 'ADMINISTRATIVE', 'CONFIGURATION', { ...STORE, changes: true, expectBefore: true }),

  // C. Branch management
  d('BRANCH_CREATED', 'Branch Created', 'ADMINISTRATIVE', 'BRANCH', { ...BRANCH, entity: true, expectAfter: true, configuration: true }),
  d('BRANCH_UPDATED', 'Branch Updated', 'ADMINISTRATIVE', 'BRANCH', { ...BRANCH, entity: true, changes: true, expectBefore: true, configuration: true }),
  d('BRANCH_DEACTIVATED', 'Branch Deactivated', 'ADMINISTRATIVE', 'BRANCH', { ...BRANCH, entity: true, expectBefore: true, expectAfter: true, sensitive: true, severity: 'LOW', configuration: true }),
  d('BRANCH_SETTINGS_UPDATED', 'Branch Settings Updated', 'ADMINISTRATIVE', 'BRANCH', { ...BRANCH, entity: true, changes: true, expectBefore: true, configuration: true }),

  // D. Product management (MediSentinel never stores the catalogue — only the changed fields)
  d('PRODUCT_CREATED', 'Product Created', 'RECORD', 'PRODUCT', { ...PRODUCT, entity: true, expectAfter: true }),
  d('PRODUCT_UPDATED', 'Product Updated', 'RECORD', 'PRODUCT', { ...PRODUCT, entity: true, changes: true, expectBefore: true }),
  d('PRODUCT_ARCHIVED', 'Product Archived', 'RECORD', 'PRODUCT', { ...PRODUCT, entity: true }),
  d('PRODUCT_DELETED', 'Product Deleted', 'RECORD', 'PRODUCT', { ...PRODUCT, entity: true, sensitive: true, severity: 'MEDIUM' }),
  d('PRODUCT_PRICE_UPDATED', 'Product Price Updated', 'RECORD', 'PRODUCT', { ...PRODUCT, entity: true, changes: true, expectBefore: true, sensitive: true, severity: 'LOW' }),

  // E. Transactions
  d('TRANSACTION_CREATED', 'Transaction Created', 'OPERATIONAL', 'TRANSACTION', { ...TXN, oneTime: true }),
  d('TRANSACTION_UPDATED', 'Transaction Updated', 'OPERATIONAL', 'TRANSACTION', { ...TXN, changes: true }),
  d('CHECKOUT_COMPLETED', 'Checkout Completed', 'OPERATIONAL', 'TRANSACTION', { ...TXN, oneTime: true, setsStatus: 'completed' }),
  d('PAYMENT_RECORDED', 'Payment Recorded', 'OPERATIONAL', 'TRANSACTION', { ...TXN, expectAfter: true }),
  d('TRANSACTION_CANCELLED', 'Transaction Cancelled', 'OPERATIONAL', 'TRANSACTION', { ...TXN, reason: true, sensitive: true, severity: 'LOW', setsStatus: 'cancelled' }),
  d('TRANSACTION_STATUS_CHANGED', 'Transaction Status Changed', 'OPERATIONAL', 'TRANSACTION', { ...TXN, changes: true, expectBefore: true }),

  // F. Void authorization (MediSentinel never approves or voids — it records the outcome)
  d('TRANSACTION_VOID_REQUESTED', 'Void Requested', 'OPERATIONAL', 'VOID', { ...VOID, reason: true, sensitive: true, severity: 'LOW' }),
  d('TRANSACTION_VOID_APPROVED', 'Void Approved', 'OPERATIONAL', 'VOID', { ...VOID, authorization: true, authOutcomes: ['APPROVED'], sensitive: true, severity: 'LOW' }),
  d('TRANSACTION_VOID_REJECTED', 'Void Rejected', 'OPERATIONAL', 'VOID', { ...VOID, authorization: true, authOutcomes: ['REJECTED', 'FAILED'], sensitive: true, severity: 'MEDIUM' }),
  d('TRANSACTION_VOIDED', 'Transaction Voided', 'OPERATIONAL', 'VOID', { ...VOID, reason: true, authorization: true, authOutcomes: ['APPROVED', 'NOT_REQUIRED'], sensitive: true, severity: 'MEDIUM', oneTime: true, setsStatus: 'voided' }),

  // G. Sales history & reports (routine access is optional — see the integration guide)
  d('TRANSACTION_HISTORY_ACCESSED', 'Transaction History Accessed', 'RECORD', 'REPORT', { ...REPORT, module: 'Transaction History', routine: true }),
  d('TRANSACTION_DETAILS_VIEWED', 'Transaction Details Viewed', 'RECORD', 'REPORT', { ...REPORT, module: 'Transaction History', entityTypes: TXN.entityTypes, entityKind: 'TRANSACTION', routine: true, report: false }),
  d('SALES_REPORT_ACCESSED', 'Sales Report Accessed', 'RECORD', 'REPORT', { ...REPORT, routine: true }),
  d('DAILY_REPORT_GENERATED', 'Daily Report Generated', 'ADMINISTRATIVE', 'REPORT', REPORT),
  d('MONTHLY_REPORT_GENERATED', 'Monthly Report Generated', 'ADMINISTRATIVE', 'REPORT', REPORT),
  d('YEARLY_REPORT_GENERATED', 'Yearly Report Generated', 'ADMINISTRATIVE', 'REPORT', REPORT),
  d('SALES_REPORT_EXPORTED', 'Sales Report Exported', 'ADMINISTRATIVE', 'REPORT', { ...REPORT, sensitive: true }),

  // H. Price checks
  d('PRICE_CHECK_PERFORMED', 'Price Check Performed', 'OPERATIONAL', 'PRICE_CHECK', { module: 'Price Check', entityTypes: ['Product'], entityKind: 'PRODUCT', routine: true, lookup: true })
];

// Rules attached to pre-existing generic event types so they appear in the new views.
export const GENERIC_RULE_OVERRIDES = {
  SETTINGS_MODIFIED: { group: 'CONFIGURATION', configuration: true, expectBefore: true, expectAfter: true },
  REPORT_GENERATED: { group: 'REPORT', report: true },
  REPORT_EXPORTED: { group: 'REPORT', report: true },
  PAYMENT_STATUS_CHANGED: { group: 'TRANSACTION', expectAfter: true }
};

// ---------------------------------------------------------------------------
// Derived lookups
// ---------------------------------------------------------------------------
const byCode = new Map(POS_EVENT_DEFINITIONS.map((def) => [def.code, def]));
export const posDefinition = (code) => byCode.get(code) || null;
export const POS_EVENT_CODES = POS_EVENT_DEFINITIONS.map((def) => def.code);

export const rulesFor = (code) => byCode.get(code)?.rules || (GENERIC_RULE_OVERRIDES[code] ? { ...GENERIC_RULE_OVERRIDES[code] } : null);

const codesWhere = (predicate) => POS_EVENT_DEFINITIONS.filter((def) => predicate(def.rules)).map((def) => def.code);
export const codesInGroup = (...groups) => codesWhere((r) => groups.includes(r.group));

export const TRANSACTION_CODES = codesWhere((r) => r.entityKind === 'TRANSACTION' && ['TRANSACTION', 'VOID'].includes(r.group));
export const VOID_CODES = codesInGroup('VOID');
export const CUSTOMER_CODES = codesInGroup('CUSTOMER');
export const ROUTINE_CODES = codesWhere((r) => r.routine);
// Configuration history covers store, branch and other registered administrative settings.
export const CONFIGURATION_CODES = [...codesWhere((r) => r.configuration), 'SETTINGS_MODIFIED'];

// Events a POS is expected to submit (routine access events are optional: isRequired=false).
export const POS_REGISTRY_TEMPLATE = [
  ['LOGIN_SUCCESS', 'Authentication', true], ['LOGIN_FAILED', 'Authentication', true], ['LOGOUT', 'Authentication', true],
  ...POS_EVENT_DEFINITIONS.map((def) => [def.code, def.rules.module, !def.rules.routine && def.code !== 'PRODUCT_DELETED'])
];

/** Lower-case, trimmed status ("Completed " → "completed"); null when absent. */
export const normalizeStatus = (value) => {
  if (value === undefined || value === null || value === '') return null;
  return String(value).trim().toLowerCase();
};

export const isAllowedTransition = (from, to, transitions = TRANSACTION_STATUS_TRANSITIONS) => {
  const a = normalizeStatus(from);
  const b = normalizeStatus(to);
  if (!a || !b || a === b) return true;
  if (!Object.prototype.hasOwnProperty.call(transitions, a)) return true; // unknown vocabulary: not judged
  return transitions[a].includes(b);
};
