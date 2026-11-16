/** Wrap async route handlers so rejected promises reach the error handler (Express 4). */
export const wrap = (fn) => {
  const wrapped = (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
  // Keep the original name so `npm run route:list` shows real handler names.
  Object.defineProperty(wrapped, 'name', { value: fn.name || 'handler' });
  return wrapped;
};

/** Wrap every handler registered on a router. */
export const asyncRouter = (router) => {
  ['get', 'post', 'put', 'patch', 'delete'].forEach((method) => {
    const original = router[method].bind(router);
    router[method] = (path, ...handlers) => original(path, ...handlers.map((h) => (typeof h === 'function' && h.length < 4 ? wrap(h) : h)));
  });
  return router;
};

export const notFound = (req, res) => {
  res.status(404).render('errors/404', { title: 'Page Not Found' });
};

// eslint-disable-next-line no-unused-vars
export const errorHandler = (err, req, res, next) => {
  const status = err.status && err.status >= 400 && err.status < 600 ? err.status : 500;
  if (status >= 500) console.error('[error]', err);
  const message = status >= 500 ? 'An unexpected error occurred. The issue has been logged.' : err.message;

  if (req.xhr || (req.get('accept') || '').includes('application/json')) {
    return res.status(status).json({ error: message });
  }
  // Validation errors on form posts: flash and go back where the user came from.
  if (status === 400 || status === 409 || (status === 403 && req.method === 'POST')) {
    if (req.flash) req.flash('error_msg', message);
    const back = req.get('referer');
    if (back && new URL(back, `http://${req.get('host')}`).host === req.get('host')) return res.redirect(back);
  }
  return res.status(status).render(status === 404 ? 'errors/404' : 'errors/error', { title: status === 404 ? 'Not Found' : 'Error', status, message });
};
