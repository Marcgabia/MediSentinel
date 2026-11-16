import session from 'express-session';
import { Op } from 'sequelize';
import { Session } from '../models/index.js';

/** Minimal MySQL-backed express-session store (sessions survive restarts; no MemoryStore leaks). */
export class SequelizeSessionStore extends session.Store {
  constructor({ ttlMs = 8 * 3600000, cleanupIntervalMs = 15 * 60000 } = {}) {
    super();
    this.ttlMs = ttlMs;
    this.timer = setInterval(() => this.cleanup().catch(() => {}), cleanupIntervalMs);
    this.timer.unref?.();
  }

  expiry(sess) {
    const cookieExpiry = sess?.cookie?.expires ? new Date(sess.cookie.expires) : null;
    return cookieExpiry && !Number.isNaN(cookieExpiry.getTime()) ? cookieExpiry : new Date(Date.now() + this.ttlMs);
  }

  get(sid, cb) {
    Session.findByPk(sid, { raw: true })
      .then((row) => {
        if (!row || new Date(row.expiresAt) < new Date()) return cb(null, null);
        return cb(null, JSON.parse(row.data));
      })
      .catch((err) => cb(err));
  }

  set(sid, sess, cb) {
    Session.upsert({ sid, data: JSON.stringify(sess), expiresAt: this.expiry(sess) })
      .then(() => cb && cb(null))
      .catch((err) => cb && cb(err));
  }

  touch(sid, sess, cb) {
    Session.update({ expiresAt: this.expiry(sess) }, { where: { sid } })
      .then(() => cb && cb(null))
      .catch((err) => cb && cb(err));
  }

  destroy(sid, cb) {
    Session.destroy({ where: { sid } }).then(() => cb && cb(null)).catch((err) => cb && cb(err));
  }

  cleanup() {
    return Session.destroy({ where: { expiresAt: { [Op.lt]: new Date() } } });
  }

  close() { clearInterval(this.timer); }
}
