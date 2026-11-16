// Chart rendering (Chart.js served from /vendor). Data comes from an inline JSON block or a JSON endpoint.
(function () {
  'use strict';
  if (typeof Chart === 'undefined') return;

  // Colours come from the active theme's CSS variables (see src/styles/input.css) and are
  // re-read whenever the theme changes, so charts stay legible and low-glare in dark mode.
  const cssColor = (name, alpha = 1) => {
    const rgb = getComputedStyle(document.documentElement).getPropertyValue(`--${name}`).trim().split(/\s+/).join(',');
    return rgb ? `rgba(${rgb},${alpha})` : undefined;
  };
  let NAVY; let GREEN; let BLUE; let RED; let VIOLET; let PALETTE; let GRID; let SURFACE;
  const readTheme = () => {
    NAVY = cssColor('brand-600');
    GREEN = cssColor('emerald-500');
    BLUE = cssColor('sky-500');
    RED = cssColor('red-500');
    VIOLET = cssColor('violet-500');
    PALETTE = [cssColor('brand-600'), cssColor('sky-500'), cssColor('emerald-400'), cssColor('amber-500'), cssColor('violet-500'),
      cssColor('brand-300'), cssColor('orange-500'), cssColor('red-500'), cssColor('sky-300'), cssColor('slate-400')];
    GRID = cssColor('slate-200', 0.7);
    SURFACE = cssColor('surface');
    Chart.defaults.color = cssColor('slate-500');
    Chart.defaults.borderColor = GRID;
    Chart.defaults.plugins.tooltip.backgroundColor = document.documentElement.classList.contains('dark') ? cssColor('slate-100') : 'rgba(15,23,42,0.95)';
    Chart.defaults.plugins.tooltip.titleColor = document.documentElement.classList.contains('dark') ? cssColor('slate-900') : '#fff';
    Chart.defaults.plugins.tooltip.bodyColor = document.documentElement.classList.contains('dark') ? cssColor('slate-700') : '#e2e8f0';
  };

  Chart.defaults.font.family = "Inter, 'Segoe UI', system-ui, sans-serif";
  Chart.defaults.font.size = 11;
  Chart.defaults.plugins.legend.labels.boxWidth = 8;
  Chart.defaults.plugins.legend.labels.usePointStyle = true;
  Chart.defaults.plugins.tooltip.padding = 10;
  Chart.defaults.plugins.tooltip.cornerRadius = 8;
  Chart.defaults.maintainAspectRatio = false;
  readTheme();

  const instances = new Map();

  const showEmpty = (canvas) => {
    canvas.classList.add('hidden');
    let note = canvas.parentElement.querySelector('.chart-empty');
    if (!note) {
      note = document.createElement('div');
      note.className = 'chart-empty flex h-full items-center justify-center text-sm text-slate-400';
      note.textContent = 'No data yet';
      canvas.parentElement.appendChild(note);
    }
    note.classList.remove('hidden');
  };

  const color = (opts) => (typeof opts.color === 'function' ? opts.color() : opts.color);
  const withAlpha = (rgba, a) => rgba.replace(/rgba\(([^)]+),[\d.]+\)/,`rgba($1,${a})`);

  const render = (canvas, type, series, opts = {}) => {
    if (instances.has(canvas)) { instances.get(canvas).destroy(); instances.delete(canvas); }
    const note = canvas.parentElement.querySelector('.chart-empty');
    if (!series || !series.values || !series.values.some((v) => Number(v) > 0)) { showEmpty(canvas); return; }
    canvas.classList.remove('hidden');
    if (note) note.classList.add('hidden');
    const isPie = type === 'doughnut';
    const chart = new Chart(canvas, {
      type,
      data: {
        labels: series.labels,
        datasets: [{
          label: opts.label || 'Events',
          data: series.values,
          backgroundColor: isPie ? (opts.colors ? opts.colors() : PALETTE) : (type === 'line' ? withAlpha(color(opts) || GREEN, 0.12) : (color(opts) || NAVY)),
          borderColor: type === 'line' ? (color(opts) || GREEN) : (isPie ? SURFACE : (color(opts) || NAVY)),
          borderWidth: type === 'line' ? 2 : (isPie ? 2 : 0),
          borderRadius: type === 'bar' ? 6 : 0,
          maxBarThickness: 28,
          fill: type === 'line',
          tension: 0.35,
          pointRadius: 0,
          pointHoverRadius: 4
        }]
      },
      options: {
        indexAxis: opts.horizontal ? 'y' : 'x',
        cutout: isPie ? '68%' : undefined,
        plugins: { legend: { display: isPie, position: 'right' } },
        scales: isPie ? {} : {
          x: { grid: { display: false }, border: { display: false }, ticks: { autoSkip: true, maxRotation: 0 } },
          y: { beginAtZero: true, grid: { color: GRID }, border: { display: false }, ticks: { precision: 0 } }
        }
      }
    });
    instances.set(canvas, chart);
  };

  const CHARTS = {
    daily: { type: 'bar', opts: { color: () => NAVY } },
    weekly: { type: 'line', opts: { color: () => GREEN } },
    monthly: { type: 'bar', opts: { color: () => BLUE } },
    bySource: { type: 'doughnut', opts: {} },
    byAction: { type: 'bar', opts: { horizontal: true, color: () => NAVY } },
    byUser: { type: 'bar', opts: { horizontal: true, color: () => GREEN } },
    outcomes: { type: 'doughnut', opts: { colors: () => [GREEN, RED, VIOLET] } },
    suspicious: { type: 'line', opts: { color: () => RED, label: 'Alerts' } },
    profile: { type: 'bar', opts: { color: () => NAVY } },
    // Pharmacy operations dashboard
    posTrend: { type: 'bar', opts: { color: () => NAVY } },
    posVoids: { type: 'line', opts: { color: () => RED, label: 'Voids' } },
    posStatus: { type: 'bar', opts: { horizontal: true, color: () => BLUE, label: 'Changes' } },
    posCashier: { type: 'bar', opts: { horizontal: true, color: () => GREEN } },
    posBranch: { type: 'bar', opts: { horizontal: true, color: () => NAVY } },
    posSource: { type: 'doughnut', opts: {} }
  };

  let lastData = null;
  const draw = (data) => {
    lastData = data;
    document.querySelectorAll('canvas[data-chart]').forEach((canvas) => {
      const key = canvas.getAttribute('data-chart');
      const cfg = CHARTS[key];
      if (cfg && data[key]) render(canvas, cfg.type, data[key], cfg.opts);
    });
    // Tabbed charts: <canvas data-chart-tabs="daily"> + <button data-chart-tab="weekly">
    document.querySelectorAll('canvas[data-chart-tabs]').forEach((canvas) => {
      const show = (key) => {
        render(canvas, CHARTS[key].type, data[key], CHARTS[key].opts);
        canvas.closest('.card').querySelectorAll('[data-chart-tab]').forEach((b) => b.classList.toggle('tab-active', b.getAttribute('data-chart-tab') === key));
      };
      const tabs = canvas.closest('.card').querySelectorAll('[data-chart-tab]');
      if (!canvas.dataset.tabsBound) {
        canvas.dataset.tabsBound = '1';
        tabs.forEach((b) => b.addEventListener('click', () => { canvas.dataset.currentTab = b.getAttribute('data-chart-tab'); show(canvas.dataset.currentTab); }));
      }
      show(canvas.dataset.currentTab || canvas.getAttribute('data-chart-tabs'));
    });
  };

  window.addEventListener('themechange', () => { readTheme(); if (lastData) draw(lastData); });

  const inline = document.getElementById('chart-data');
  if (inline) {
    try { draw(JSON.parse(inline.textContent)); } catch { /* ignore */ }
  }
  const remote = document.querySelector('[data-chart-source]');
  if (remote) {
    fetch(remote.getAttribute('data-chart-source'), { headers: { Accept: 'application/json' }, credentials: 'same-origin' })
      .then((r) => (r.ok ? r.json() : Promise.reject()))
      .then(draw)
      .catch(() => document.querySelectorAll('canvas[data-chart], canvas[data-chart-tabs]').forEach(showEmpty));
  }
}());
