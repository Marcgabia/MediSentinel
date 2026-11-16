import express from 'express';
import flash from 'connect-flash';
import apiRoutes from './apiRoutes.js';
import auditRoutes from './auditRoutes.js';
import { sessionMiddleware } from '../middleware/session.js';
import { csrfProtection } from '../middleware/requestValidation.js';
import { asyncRouter } from '../middleware/errorHandler.js';
import { redirectIfAuthenticated } from '../middleware/auth.js';
import { loginPage, login, logout, registerPage, register } from '../controllers/authController.js';

const router = asyncRouter(express.Router());

// 1. Machine-to-machine API (signed requests; raw bodies; no cookies, sessions or CSRF).
router.use('/api/v1', apiRoutes);

// 2. Dashboard (session-based).
router.use(express.urlencoded({ extended: false, limit: '200kb' }));
router.use(express.json({ limit: '200kb' }));
router.use(sessionMiddleware);
router.use(flash());
router.use(csrfProtection);
router.use((req, res, next) => {
  res.locals.success_msg = req.flash('success_msg');
  res.locals.error_msg = req.flash('error_msg');
  res.locals.currentPath = req.path;
  res.locals.currentUser = null;
  next();
});

router.get('/', (req, res) => res.redirect(req.session.userId ? '/dashboard' : '/login'));
router.get('/login', redirectIfAuthenticated, loginPage);
router.post('/login', login);
router.post('/logout', logout);
router.get('/register', redirectIfAuthenticated, registerPage);
router.post('/register', redirectIfAuthenticated, register);

router.use(auditRoutes);

export default router;
