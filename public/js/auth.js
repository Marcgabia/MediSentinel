// Sign-in / sign-up page behaviours (external file: compatible with the strict CSP).
(function () {
  'use strict';

  // Show / hide password
  document.querySelectorAll('[data-reveal]').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var input = document.getElementById(btn.getAttribute('data-reveal'));
      if (!input) return;
      var show = input.type === 'password';
      input.type = show ? 'text' : 'password';
      var label = show ? 'Hide password' : 'Show password';
      btn.setAttribute('aria-label', label);
      btn.setAttribute('title', label);
      var open = btn.querySelector('[data-eye-open]');
      var closed = btn.querySelector('[data-eye-closed]');
      if (open) open.classList.toggle('hidden', show);
      if (closed) closed.classList.toggle('hidden', !show);
      input.focus();
    });
  });

  // Password rules + strength meter (mirrors the server-side policy in services/userService.js)
  var checks = {
    len: function (v) { return v.length >= 10; },
    upper: function (v) { return /[A-Z]/.test(v); },
    lower: function (v) { return /[a-z]/.test(v); },
    digit: function (v) { return /\d/.test(v); }
  };
  var tones = ['bg-red-500', 'bg-orange-500', 'bg-amber-500', 'bg-emerald-500'];
  document.querySelectorAll('[data-strength]').forEach(function (input) {
    var meter = document.getElementById(input.getAttribute('data-strength'));
    var rules = document.querySelector('[data-rules-for="' + input.id + '"]');
    var update = function () {
      var v = input.value;
      var passed = 0;
      Object.keys(checks).forEach(function (key) {
        var ok = checks[key](v);
        if (ok) passed += 1;
        var li = rules && rules.querySelector('[data-rule="' + key + '"]');
        if (li) {
          li.classList.toggle('text-emerald-600', ok);
          li.classList.toggle('text-slate-400', !ok);
          li.textContent = (ok ? '✓ ' : '') + li.textContent.replace(/^✓ /, '');
        }
      });
      if (meter) {
        var bars = meter.querySelectorAll('span');
        bars.forEach(function (bar, i) {
          tones.concat('bg-slate-200').forEach(function (t) { bar.classList.remove(t); });
          bar.classList.add(v && i < passed ? tones[passed - 1] : 'bg-slate-200');
        });
      }
    };
    input.addEventListener('input', update);
    update();
  });

  // Confirm-password match
  document.querySelectorAll('[data-match]').forEach(function (confirm) {
    var original = document.getElementById(confirm.getAttribute('data-match'));
    var error = confirm.parentElement.querySelector('[data-match-error]');
    var check = function () {
      var mismatch = confirm.value && original && confirm.value !== original.value;
      confirm.setCustomValidity(mismatch ? 'Passwords do not match.' : '');
      if (error) error.classList.toggle('hidden', !mismatch);
    };
    confirm.addEventListener('input', check);
    if (original) original.addEventListener('input', check);
  });
}());
