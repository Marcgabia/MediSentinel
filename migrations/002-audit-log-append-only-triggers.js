// Database-level append-only protection for audit_logs.
// Any UPDATE or DELETE on audit_logs is rejected by MySQL, independently of the application.
// (Someone with DDL privileges could drop these triggers — the HMAC hash chain exists to
// make such tampering detectable during QA verification.)

export const up = async ({ sequelize }) => {
  await sequelize.query('DROP TRIGGER IF EXISTS trg_audit_logs_no_update');
  await sequelize.query('DROP TRIGGER IF EXISTS trg_audit_logs_no_delete');
  await sequelize.query(`CREATE TRIGGER trg_audit_logs_no_update BEFORE UPDATE ON audit_logs
    FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'audit_logs is append-only: UPDATE is not permitted'`);
  await sequelize.query(`CREATE TRIGGER trg_audit_logs_no_delete BEFORE DELETE ON audit_logs
    FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'audit_logs is append-only: DELETE is not permitted'`);
};
