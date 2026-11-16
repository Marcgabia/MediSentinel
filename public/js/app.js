// MediSentinel UI behaviours (no inline scripts — compatible with the strict Content-Security-Policy).
(function () {
  'use strict';

  const $ = (sel, root) => (root || document).querySelector(sel);
  const $$ = (sel, root) => Array.from((root || document).querySelectorAll(sel));
  const escapeHtml = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

  // Sidebar (mobile)
  const sidebar = $('#sidebar');
  const backdrop = $('#sidebar-backdrop');
  const toggleSidebar = (open) => {
    if (!sidebar) return;
    sidebar.classList.toggle('-translate-x-full', !open);
    if (backdrop) backdrop.classList.toggle('hidden', !open);
  };
  $('#sidebar-toggle')?.addEventListener('click', () => toggleSidebar(true));
  backdrop?.addEventListener('click', () => toggleSidebar(false));

  // Confirmation prompts: <form data-confirm="..."> or <button data-confirm="...">
  document.addEventListener('submit', (e) => {
    const form = e.target;
    const message = form.getAttribute('data-confirm') || (e.submitter && e.submitter.getAttribute('data-confirm'));
    if (message && !window.confirm(message)) e.preventDefault();
  });

  // Auto-submit filters
  $$('[data-autosubmit]').forEach((el) => el.addEventListener('change', () => el.form && el.form.submit()));

  // Print buttons
  $$('[data-print]').forEach((el) => el.addEventListener('click', () => window.print()));

  // Copy to clipboard
  $$('[data-copy]').forEach((el) => el.addEventListener('click', async () => {
    const target = document.getElementById(el.getAttribute('data-copy'));
    if (!target) return;
    const text = target.value !== undefined ? target.value : target.textContent;
    try {
      await navigator.clipboard.writeText(text.trim());
      const original = el.textContent;
      el.textContent = 'Copied ✓';
      setTimeout(() => { el.textContent = original; }, 1500);
    } catch {
      if (target.select) target.select();
    }
  }));

  // Show / hide panels: <button data-toggle="panel-id">
  $$('[data-toggle]').forEach((el) => el.addEventListener('click', (e) => {
    e.stopPropagation();
    const panel = document.getElementById(el.getAttribute('data-toggle'));
    if (panel) panel.classList.toggle('hidden');
  }));
  const userMenu = $('#user-menu');
  document.addEventListener('click', (e) => {
    if (userMenu && !userMenu.classList.contains('hidden') && !userMenu.contains(e.target)) userMenu.classList.add('hidden');
  });

  // Diff viewer: show only changed rows
  $$('[data-diff-filter]').forEach((el) => el.addEventListener('change', () => {
    $$('[data-diff-row]').forEach((row) => {
      row.classList.toggle('hidden', el.checked && row.getAttribute('data-diff-row') === 'UNCHANGED');
    });
  }));

  // Select-all checkboxes
  $$('[data-check-all]').forEach((el) => el.addEventListener('change', () => {
    $$(`input[type=checkbox][name="${el.getAttribute('data-check-all')}"]`).forEach((cb) => { cb.checked = el.checked; });
  }));

  // Notification dropdown
  const notifToggle = $('#notif-toggle');
  const notifPanel = $('#notif-panel');
  let notifLoaded = false;
  const severityDot = { CRITICAL: 'bg-red-600', HIGH: 'bg-orange-500', MEDIUM: 'bg-amber-500', LOW: 'bg-sky-500', INFO: 'bg-slate-400' };
  const loadNotifications = async () => {
    const container = $('#notif-items');
    try {
      const res = await fetch('/notifications/feed.json', { headers: { Accept: 'application/json' }, credentials: 'same-origin' });
      if (!res.ok) throw new Error();
      const data = await res.json();
      if (!data.items.length) { container.innerHTML = '<div class="empty">No notifications yet.</div>'; return; }
      container.innerHTML = data.items.map((n) => `
        <a href="/notifications/${n.id}/open" class="flex gap-3 px-4 py-3 hover:bg-slate-50 ${n.isRead ? 'opacity-70' : ''}">
          <span class="mt-1.5 h-2 w-2 flex-none rounded-full ${severityDot[n.severity] || 'bg-slate-400'}"></span>
          <span class="min-w-0">
            <span class="block text-[11px] font-semibold uppercase tracking-wide text-slate-500">${escapeHtml(n.typeLabel)}</span>
            <span class="block truncate font-semibold text-slate-900">${escapeHtml(n.title)}</span>
            <span class="block truncate text-xs text-slate-500">${escapeHtml(n.message)}</span>
            <span class="block text-[11px] text-slate-400">${escapeHtml(new Date(n.createdAt).toLocaleString())}</span>
          </span>
        </a>`).join('');
    } catch {
      container.innerHTML = '<div class="empty">Notifications could not be loaded.</div>';
    }
  };
  notifToggle?.addEventListener('click', (e) => {
    e.stopPropagation();
    notifPanel.classList.toggle('hidden');
    if (!notifLoaded) { notifLoaded = true; loadNotifications(); }
  });
  document.addEventListener('click', (e) => {
    if (notifPanel && !notifPanel.classList.contains('hidden') && !notifPanel.contains(e.target)) notifPanel.classList.add('hidden');
  });

  // Local-time rendering for <time data-local datetime="ISO">
  $$('time[data-local]').forEach((el) => {
    const d = new Date(el.getAttribute('datetime'));
    if (!Number.isNaN(d.getTime())) el.title = d.toISOString();
  });
}());
