import session from 'express-session';
import { SequelizeSessionStore } from '../utils/sessionStore.js';

let store = null;
export const getSessionStore = () => {
  if (!store) store = new SequelizeSessionStore({ ttlMs: 8 * 3600000 });
  return store;
};

const secret = () => {
  const value = process.env.SESSION_SECRET;
  if (!value || value.length < 32) {
    if (process.env.NODE_ENV === 'production') throw new Error('SESSION_SECRET must be set (min 32 chars) in production.');
    return 'medisentinel-development-session-secret-change-me';
  }
  return value;
};

export const sessionMiddleware = session({
  name: 'medisentinel.sid',
  secret: secret(),
  store: getSessionStore(),
  resave: false,
  saveUninitialized: false,
  rolling: true,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.COOKIE_SECURE === 'true',
    maxAge: 8 * 3600000
  }
});
