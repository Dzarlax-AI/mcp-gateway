(() => {
  'use strict';
  const script = document.currentScript;
  const base = new URL(script.src).pathname.replace(/\/admin\/actions\.js$/, '');
  let busy = false;
  let uncertain = false;
  function lock(value) {
    busy = value;
    document.querySelectorAll('form button, [data-refresh]').forEach(b => { b.disabled = b.hasAttribute("data-fixed-disabled") || value || (uncertain && !b.matches('[data-refresh]')); });
  }
  function status(card, message, refresh = false) {
    card.querySelector('[data-action-status]').textContent = message;
    card.querySelector('[data-refresh]').hidden = !refresh;
  }
  function input(name, value) {
    const node = document.createElement('input'); node.type = 'hidden'; node.name = name; node.value = value; return node;
  }
  function setSwitch(button, enabled, label) {
    button.setAttribute('aria-checked', String(enabled));
    button.setAttribute('aria-label', label);
    button.querySelector('[data-switch-label]').textContent = enabled ? 'Enabled' : 'Disabled';
  }
  function apply(state, refresh = false) {
    if (!Number.isSafeInteger(state.revision) || !Array.isArray(state.servers)) throw new Error('Invalid server response');
    const active = document.activeElement;
    const toolName = active?.closest('[data-tool]')?.dataset.tool;
    const serverID = active?.closest('[data-server]')?.dataset.server;
    for (const server of state.servers) {
      const card = Array.from(document.querySelectorAll('[data-server]')).find(c => c.dataset.server === server.id);
      if (!card) continue;
      const serverForm = Array.from(card.querySelectorAll('form[data-quick]')).find(f => /\/(enable|disable)$/.test(f.action));
      if (!serverForm) continue;
      serverForm.action = base + '/admin/servers/' + encodeURIComponent(server.id) + (server.enabled ? '/disable' : '/enable');
      setSwitch(serverForm.querySelector('button'), server.enabled, 'Enable server ' + server.id);
      const batchForm=card.querySelector('[data-batch-switch]');
      if (batchForm) {
        batchForm.action=base+'/admin/servers/'+encodeURIComponent(server.id)+(server.batch_enabled?'/batch-disable':'/batch-enable');
        setSwitch(batchForm.querySelector('button'),Boolean(server.batch_enabled),'Enable batch reads on '+server.id);
        card.querySelector('[data-batch-count]').textContent=server.batch_count+' verified enabled reads';
      }
      const profile=card.querySelector('[data-batch-profile]');
      if (profile && !profile.dataset.dirty) profile.querySelector('select').value=server.batch_profile;
      const enabledCount = server.tools.filter(t => t.Enabled).length;
      card.querySelector('[data-tool-count]').textContent = enabledCount + '/' + server.tools.length + ' tools enabled';
      card.querySelector('[data-tools-count]').textContent = enabledCount + '/' + server.tools.length + ' enabled';
      card.querySelector('[data-server-unavailable]').hidden = server.enabled;
      const badge = card.querySelector('[data-connection-badge]');
      badge.textContent = server.checked ? 'Connection checked' : 'Not checked';
      badge.dataset.checked = String(Boolean(server.checked));
      card.querySelector('[data-probe-status]').textContent = server.checked ? 'Connection checked at ' + server.checked + ' (checked recently).' : 'Enable automatically checks the connection when needed.';
      const tools = card.querySelector('[data-tools]');
      tools.querySelector('[data-empty-tools]')?.toggleAttribute('hidden', server.tools.length > 0);
      for (const tool of server.tools) {
        let row = Array.from(tools.querySelectorAll('[data-tool]')).find(r => r.dataset.tool === tool.Name);
        if (!row) {
          row = document.createElement('div'); row.className = 'tool-row'; row.dataset.tool = tool.Name;
          const details = document.createElement('details'); details.className = 'tool-details'; row.append(details);
          const summary = document.createElement('summary'); summary.dataset.toolName = ''; details.append(summary);
          const description = document.createElement('p'); description.dataset.description = ''; details.append(description);
          const reason=document.createElement('p');reason.dataset.batchReason='';details.append(reason);
          const schema = document.createElement('details'); schema.dataset.schema = ''; schema.append(document.createElement('summary'), document.createElement('pre')); schema.firstChild.textContent = 'Input schema'; details.append(schema);
          const form = document.createElement('form'); form.method = 'post'; form.dataset.quick = '';
          const csrf = document.querySelector('input[name=csrf]').value;
          const button = document.createElement('button'); button.type = 'submit'; button.className = 'switch'; button.setAttribute('role', 'switch');
          const label = document.createElement('span'); label.dataset.switchLabel = ''; button.append(label);
          const track = document.createElement('span'); track.className = 'switch-track'; track.setAttribute('aria-hidden', 'true'); button.append(track);
          form.append(input('csrf', csrf), input('revision', String(state.revision)), input('tool', tool.Name), button); row.append(form); tools.querySelector('[data-tool-list]').append(row);
        }
        row.querySelector('[data-tool-name]').textContent = tool.Name;
        row.querySelector('[data-description]').textContent = tool.Description;
        row.querySelector('[data-batch-reason]').textContent=tool.BatchReason;
        const schema = row.querySelector('[data-schema]'); schema.hidden = !tool.Schema; schema.querySelector('pre').textContent = tool.Schema;
        const form = row.querySelector('form'); form.action = base + '/admin/servers/' + encodeURIComponent(server.id) + (tool.Enabled ? '/tool-disable' : '/tool-enable');
        setSwitch(form.querySelector('button'), tool.Enabled, 'Enable tool ' + tool.Name + ' on server ' + server.id);
      }
      for (const row of tools.querySelectorAll('[data-tool]')) if (!server.tools.some(t => t.Name === row.dataset.tool)) row.remove();
    }
    document.querySelectorAll('input[name=revision]').forEach(i => { if (!refresh || !i.form?.dataset.dirty) i.value = String(state.revision); });
    document.querySelector('[data-revision]').textContent = String(state.revision);
    if (active?.isConnected) active.focus({preventScroll: true});
    else if (toolName && serverID) {
      const card = Array.from(document.querySelectorAll('[data-server]')).find(c => c.dataset.server === serverID);
      const row = Array.from(card?.querySelectorAll('[data-tool]') || []).find(r => r.dataset.tool === toolName);
      row?.querySelector('button')?.focus({preventScroll: true});
    }
  }
  document.addEventListener('input', event => { const form = event.target.closest('form'); if (form && !form.matches('[data-quick]')) form.dataset.dirty = 'true'; });
  document.addEventListener('submit', async event => {
    const form = event.target;
    if (busy || uncertain) { event.preventDefault(); return; }
    if (!form.matches('form[data-quick]')) return;
    event.preventDefault();
    const card = form.closest('[data-server]'); const button = form.querySelector('button');
    const body = new URLSearchParams(new FormData(form));
    const checking = /\/(check|enable|tool-enable|batch-enable)$/.test(form.action);
    lock(true); button.setAttribute('aria-busy', 'true'); status(card, checking ? 'Checking and saving…' : 'Saving…');
    try {
      const response = await fetch(form.action, {method: 'POST', credentials: 'same-origin', headers: {'Accept': 'application/json'}, body, redirect: 'error'});
      if (!response.ok) {
        const messages = {400: form.matches('[data-batch-switch]') ? 'Batch requires a reviewed profile, an enabled connector and an enabled verified read. Check connection and settings.' : 'Invalid settings. Review the form before retrying.', 401: 'Session expired. Sign in again.', 403: 'Access or CSRF check failed. Reload and sign in again.', 409: 'Registry changed. Refresh state before trying again.', 502: 'Connection check failed. Verify the endpoint and authentication.'};
        status(card, messages[response.status] || 'Action failed. Refresh state to verify whether it was saved.', response.status !== 401 && response.status !== 403);
        if ([401,403,409].includes(response.status) || (response.status >= 500 && response.status !== 502)) uncertain = true;
        return;
      }
      const saved = await response.json(); apply(saved); status(card, saved.audit_status === 'degraded' ? 'Saved; audit unavailable.' : 'Saved.');
    } catch (_) {
      uncertain = true; status(card, 'Result unknown: the connection was interrupted. Refresh state before making another change.', true);
    } finally { button.removeAttribute('aria-busy'); lock(false); if (document.activeElement === document.body) button.focus({preventScroll: true}); }
  });
  document.addEventListener('click', async event => {
    const button = event.target.closest('[data-refresh]'); if (!button || busy) return;
    const card = button.closest('[data-server]'); lock(true); status(card, 'Refreshing state…', true);
    try {
      const response = await fetch(base + '/admin/servers', {headers: {'Accept': 'application/json'}, credentials: 'same-origin', redirect: 'error'});
      if (!response.ok) throw new Error('Refresh failed');
      apply(await response.json(), true); uncertain = false; status(card, 'State refreshed. Review it before your next action; unsaved settings may require a reload.');
    } catch (_) { status(card, 'Could not refresh state. Reload or sign in again before changing anything.', true); }
    finally { lock(false); }
  });
})();
