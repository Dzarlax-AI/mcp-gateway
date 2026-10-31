(() => {
  'use strict';
  const base = document.body.dataset.base || '';
  const serverID = document.body.dataset.server;
  const status = document.querySelector('[data-status]');
  const refresh = document.querySelector('[data-refresh]');
  function checkedLabel(value) {
    if (!value) return 'No fresh check';
    const date = new Date(value), age = Date.now() - date.getTime();
    if (!Number.isFinite(age)) return 'Checked';
    if (age >= 0 && age < 60000) return 'Checked just now';
    if (age >= 0 && age < 3600000) return 'Checked ' + Math.floor(age / 60000) + ' min ago';
    return 'Checked ' + date.toLocaleString(undefined, {month:'short',day:'numeric',hour:'2-digit',minute:'2-digit'});
  }
  const initialCheck=document.querySelector('[data-checked]');
  if(initialCheck) initialCheck.textContent=checkedLabel(initialCheck.dataset.time);
  let busy = false, uncertain = document.body.dataset.uncertain === 'true';
  const q = (s, root = document) => root.querySelector(s);
  const all = (s, root = document) => Array.from(root.querySelectorAll(s));
  function lock() {
    all('form button, [data-select], [data-group-select]').forEach(b => { b.disabled = busy || uncertain; });
    refresh.disabled = busy;
    if (!busy && !uncertain) count();
  }
  function selected() { return all('[data-select]:checked'); }
  function count() {
    if (q('[data-selection-label]')) q('[data-selection-label]').textContent = selected().length + ' selected';
    all('[data-group]').forEach(group => {
      const boxes = all('[data-select]', group).filter(b => !b.closest('[data-tool]').hidden);
      const check = q('[data-group-select]', group);
      check.checked = boxes.length > 0 && boxes.every(b => b.checked);
      check.indeterminate = boxes.some(b => b.checked) && !check.checked;
      check.disabled = busy || uncertain || boxes.length === 0;
      q('[data-group-count]', group).textContent = String(boxes.length);
    });
  }
  function filterTools(clear = false) {
    const hadSelection = clear && selected().length > 0;
    if (clear) all('[data-select]').forEach(b => { b.checked = false; });
    if (hadSelection) status.textContent = 'Selection cleared because the tool filter changed.';
    const term = (q('#tool-search')?.value || '').toLocaleLowerCase().trim();
    const filter = q('#tool-filter')?.value || 'all';
    all('[data-tool]').forEach(row => {
      row.hidden = !row.dataset.search.toLocaleLowerCase().includes(term) || (filter === 'enabled' && row.dataset.enabled !== 'true') || (filter === 'disabled' && row.dataset.enabled === 'true');
      if (row.hidden) q('[data-select]', row).checked = false;
    });
    count();
  }
  function filterServers() {
    const term = (q('#server-search')?.value || '').toLocaleLowerCase().trim();
    const filter = q('#server-filter')?.value || 'all';
    all('[data-server-item]').forEach(row => { row.hidden = !row.dataset.name.toLocaleLowerCase().includes(term) || (filter === 'enabled' && row.dataset.enabled !== 'true') || (filter === 'disabled' && row.dataset.enabled === 'true') || (filter === 'failed' && row.dataset.failed !== 'true'); });
  }
  const search = q('#server-search'), filter = q('#server-filter'), toolSearch = q('#tool-search'), toolFilter = q('#tool-filter');
  const params = new URL(location.href).searchParams;
  if (search) search.value = params.get('servers') || '';
  if (filter) filter.value = params.get('server_status') || 'all';
  if (toolSearch) toolSearch.value = params.get('q') || '';
  if (toolFilter) toolFilter.value = params.get('tool_status') || 'all';
  function setURL(key, value, defaultValue = '') {
    const url = new URL(location.href);
    if (value && value !== defaultValue) url.searchParams.set(key, value); else url.searchParams.delete(key);
    history.replaceState(null, '', url);
    all('[data-server-item]').forEach(link => {
      const target = new URL(link.href);
      for (const name of ['servers', 'server_status']) {
        if (url.searchParams.has(name)) target.searchParams.set(name, url.searchParams.get(name)); else target.searchParams.delete(name);
      }
      link.href = target.href;
    });
  }
  setURL('servers', search?.value || '');
  setURL('server_status', filter?.value || 'all', 'all');
  lock(); filterServers(); filterTools();
  search?.addEventListener('input', () => { setURL('servers', search.value); filterServers(); });
  filter?.addEventListener('change', () => { setURL('server_status', filter.value, 'all'); filterServers(); });
  toolSearch?.addEventListener('input', () => { setURL('q', toolSearch.value); filterTools(true); });
  toolFilter?.addEventListener('change', () => { setURL('tool_status', toolFilter.value, 'all'); filterTools(true); });
  document.addEventListener('change', e => {
    if (e.target.matches('[data-select]')) count();
    if (e.target.matches('[data-group-select]')) { all('[data-select]', e.target.closest('[data-group]')).filter(b => !b.closest('[data-tool]').hidden).forEach(b => { b.checked = e.target.checked; }); count(); }
  });
  q('[data-clear]')?.addEventListener('click', () => { all('[data-select]').forEach(b => { b.checked = false; }); count(); });
  document.addEventListener('input', e => { const form = e.target.closest('form'); if (form && !form.matches('[data-quick]')) form.dataset.dirty = 'true'; });
  async function replaceGroups(focusHint) {
    const names = new Set(selected().map(b => b.value));
    const focused = document.activeElement;
    const focusRow = focused?.closest('[data-tool]');
    const focusName = focusHint?.name || focusRow?.dataset.tool;
    let focusTarget = focusHint?.selector || '';
    if (focused?.matches('[data-select]')) focusTarget = '[data-select]';
    else if (focused?.closest('[data-toggle]')) focusTarget = '[data-toggle] button';
    else if (focused?.matches('select[name=operation_kind]')) focusTarget = 'select[name=operation_kind]';
    else if (focused?.matches('summary')) focusTarget = 'summary';
    const opened = new Map(all('[data-tool]').map(row => [row.dataset.tool, all('details', row).map(d => d.open)]));
    const response = await fetch(base + '/admin/servers/' + encodeURIComponent(serverID), {credentials:'same-origin', redirect:'error'});
    if (!response.ok) throw Error('Could not refresh tools');
    const parsed = new DOMParser().parseFromString(await response.text(), 'text/html');
    const incoming = all('[data-group]', parsed);
    const groupStates = new Map(all('[data-group]').map(g => [g.dataset.group, g.open]));
    const current = all('[data-group]');
    if (incoming.length !== 3 || current.length !== 3) throw Error('Invalid tool view');
    for (const group of current) {
      const next = incoming.find(item => item.dataset.group === group.dataset.group);
      if (!next) throw Error('Missing tool group');
      next.open = groupStates.get(group.dataset.group);
      group.replaceWith(next);
    }
    all('[data-tool]').forEach(row => {
      const box = q('[data-select]', row);
      box.checked = names.has(box.value);
      const states = opened.get(row.dataset.tool) || [];
      all('details', row).forEach((d, i) => { d.open = Boolean(states[i]); });
    });
    filterTools();
    if (focusName && focusTarget) {
      const row = all('[data-tool]').find(item => item.dataset.tool === focusName);
      if (row) row.closest('[data-group]').open = true;
      q(focusTarget, row || document)?.focus({preventScroll:true});
    }
  }
  async function apply(state, isRefresh, focusHint, forceGroups = false) {
    if (!Number.isSafeInteger(state.revision) || !Array.isArray(state.servers)) throw Error('Invalid response');
    const server = state.servers.find(s => s.id === serverID);
    if (serverID && (!server || !Array.isArray(server.tools))) throw Error('Server missing');
    if (server) {
      const current = all('[data-tool]');
      if (forceGroups || server.tools.some(t => !current.some(r => r.dataset.tool === t.Name)) || current.some(r => !server.tools.some(t => t.Name === r.dataset.tool))) {
        await replaceGroups(focusHint);
        current.splice(0, current.length, ...all('[data-tool]'));
      }
      const sf = q('[data-server-toggle]');
      sf.action = base + '/admin/servers/' + encodeURIComponent(serverID) + (server.enabled ? '/disable' : '/enable');
      q('button', sf).setAttribute('aria-checked', String(server.enabled));
      q('[data-server-status]').textContent = server.enabled ? 'Enabled' : 'Disabled';
      q('[data-checked]').textContent = checkedLabel(server.checked);
      q('[data-catalog]').textContent = (server.catalog_fresh ? 'Catalog current' : 'No fresh catalog') + (server.catalog_at ? ' · ' + server.catalog_at : '');
      const sidebar = all('[data-server-item]').find(s => new URL(s.href).pathname.endsWith('/' + encodeURIComponent(serverID)));
      if (sidebar) { sidebar.dataset.enabled = String(server.enabled); q('.dot', sidebar).classList.toggle('on', server.enabled); q('[data-server-count]', sidebar).textContent = server.tools.filter(t => t.Enabled).length + '/' + server.tools.length + ' enabled ›'; }
      for (const tool of server.tools) {
        const row = current.find(r => r.dataset.tool === tool.Name);
        const group = all('[data-group]').find(g => g.dataset.group === tool.OperationKind);
        if (!group) throw Error('Unknown classification');
        if (row.dataset.kind !== tool.OperationKind) { row.dataset.kind = tool.OperationKind; q('.rows', group).append(row); }
        row.dataset.search = tool.Name + ' ' + (tool.Description || '');
        q('.classification > span', row).textContent = tool.OperationLabel;
        const reason = q('[data-operation-help]', row);
        const help = tool.OperationReason === 'manual_read_stale' ? 'Check the connection and review this classification again.' : tool.OperationKind === 'unknown' ? 'Review and classify this tool.' : '';
        if (reason) reason.textContent = help;
        row.dataset.enabled = String(tool.Enabled);
        const op = q('select[name=operation_kind]', row); op.value = tool.ManualKind || '';
        q('input[name=contract_hash]', row).value = tool.DefinitionHash || '';
        const form = q('[data-toggle]', row);
        form.action = base + '/admin/servers/' + encodeURIComponent(serverID) + (tool.Enabled ? '/tool-disable' : '/tool-enable');
        q('button', form).setAttribute('aria-checked', String(tool.Enabled));
        q('.sr', form).textContent = tool.Enabled ? 'Enabled' : 'Disabled';
      }
    }
    all('input[name=revision]').forEach(input => { if (!isRefresh || !input.form?.dataset.dirty) input.value = String(state.revision); });
    filterTools(); filterServers();
  }
  document.addEventListener('submit', async event => {
    const form = event.target;
    if (busy || uncertain) { event.preventDefault(); return; }
    if (!form.matches('[data-quick]')) return;
    event.preventDefault();
    if (form.id === 'bulk' && !selected().length) { status.textContent = 'Select at least one visible tool.'; return; }
    const submitter = event.submitter;
    const focusRow = submitter?.closest('[data-tool]');
    const focusHint = focusRow ? {name: focusRow.dataset.tool, selector: submitter.closest('[data-toggle]') ? '[data-toggle] button' : '.tool-name summary'} : null;
    const action = submitter?.getAttribute('formaction') || form.action;
    const body = new URLSearchParams(new FormData(form));
    if (form.id === 'bulk') {
      const kinds = new Set(selected().map(box => box.closest('[data-tool]').dataset.kind));
      if (kinds.size === 1) body.set('selection_kind', kinds.values().next().value);
    }
    let saved = false;
    busy = true; lock(); status.textContent = 'Saving…';
    try {
      const response = await fetch(action, {method:'POST', credentials:'same-origin', headers:{Accept:'application/json'}, body, redirect:'error'});
      if (!response.ok) {
        if (response.status === 409 || response.status >= 500 || response.status === 401 || response.status === 403) uncertain = true;
        status.textContent = response.status === 409 ? 'Registry changed. Refresh before making another change.' : 'Action failed. ' + (uncertain ? 'Refresh before making another change.' : 'Review your request.');
        refresh.hidden = !uncertain; return;
      }
      saved = true;
      await apply(await response.json(), false, focusHint, /\/(check|tool-operation)$/.test(new URL(action, location.href).pathname)); status.textContent = 'Saved.';
    } catch (_) { uncertain = true; refresh.hidden = false; status.textContent = saved ? 'Saved; refresh failed. Refresh state before making another change.' : 'Save result unknown. Refresh state before making another change.'; }
    finally { busy = false; lock(); if (submitter?.isConnected) submitter.focus({preventScroll:true}); }
  });
  refresh.addEventListener('click', async () => {
    busy = true; lock();
    try {
      const response = await fetch(base + '/admin/servers', {credentials:'same-origin', headers:{Accept:'application/json'}, redirect:'error'});
      if (!response.ok) throw Error('Refresh failed');
      await apply(await response.json(), true); uncertain = false; refresh.hidden = true; status.textContent = 'State refreshed. Review any unsaved settings before saving.';
    } catch (_) { status.textContent = 'Could not refresh the catalog in place. Save a copy of any draft and reload this page.'; }
    finally { busy = false; lock(); }
  });
})();
