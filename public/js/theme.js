// Theme selection (Light / Dark / System). Loaded synchronously in <head> so the correct theme is
// applied before first paint (no white flash). External file: compatible with the strict CSP.
(function () {
  'use strict';

  var KEY = 'medisentinel.theme';
  var root = document.documentElement;
  var media = window.matchMedia ? window.matchMedia('(prefers-color-scheme: dark)') : null;

  var stored = function () {
    try { var v = localStorage.getItem(KEY); return v === 'light' || v === 'dark' ? v : 'system'; } catch (e) { return 'system'; }
  };
  var resolve = function (pref) { return pref === 'system' ? (media && media.matches ? 'dark' : 'light') : pref; };

  var apply = function (pref, animate) {
    var mode = resolve(pref);
    if (!animate) root.classList.add('theme-switching');
    root.classList.toggle('dark', mode === 'dark');
    root.setAttribute('data-theme-pref', pref);
    if (!animate) setTimeout(function () { root.classList.remove('theme-switching'); }, 0);
    var buttons = document.querySelectorAll('[data-theme-set]');
    for (var i = 0; i < buttons.length; i += 1) {
      buttons[i].setAttribute('aria-pressed', String(buttons[i].getAttribute('data-theme-set') === pref));
    }
    var toggles = document.querySelectorAll('[data-theme-toggle]');
    for (var j = 0; j < toggles.length; j += 1) {
      var label = mode === 'dark' ? 'Switch to light mode' : 'Switch to dark mode';
      toggles[j].setAttribute('aria-label', label);
      toggles[j].setAttribute('title', label);
    }
    try { window.dispatchEvent(new CustomEvent('themechange', { detail: { mode: mode, preference: pref } })); } catch (e) { /* old browsers */ }
  };

  var set = function (pref) {
    try { if (pref === 'system') localStorage.removeItem(KEY); else localStorage.setItem(KEY, pref); } catch (e) { /* private mode */ }
    apply(pref, true);
  };

  apply(stored(), false);

  if (media) {
    var onSystemChange = function () { if (stored() === 'system') apply('system', true); };
    if (media.addEventListener) media.addEventListener('change', onSystemChange); else if (media.addListener) media.addListener(onSystemChange);
  }

  // Printouts are always light.
  window.addEventListener('beforeprint', function () { root.classList.remove('dark'); });
  window.addEventListener('afterprint', function () { apply(stored(), false); });

  document.addEventListener('DOMContentLoaded', function () {
    apply(stored(), false);
    document.addEventListener('click', function (e) {
      var target = e.target.closest ? e.target.closest('[data-theme-toggle],[data-theme-set]') : null;
      if (!target) return;
      if (target.hasAttribute('data-theme-set')) {
        e.stopPropagation();
        set(target.getAttribute('data-theme-set'));
      } else {
        set(root.classList.contains('dark') ? 'light' : 'dark');
      }
    });
  });

  window.MediSentinelTheme = { set: set, current: function () { return resolve(stored()); } };
}());
