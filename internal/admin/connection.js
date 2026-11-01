(() => {
  'use strict';
  const page = document.querySelector('[data-connection]');
  if (!page) return;
  const base = page.dataset.base;
  const csrf = page.querySelector('input[name="csrf"]').value;
  const status = page.querySelector('[data-key-status]');
  const refresh = page.querySelector('[data-keys-refresh]');
  const issued = page.querySelector('[data-issued]');
  const secret = page.querySelector('#issued-key');
  const workspace = page.dataset.clientWorkspace === 'true';
  let permissionBusy = false, permissionDirty = false, permissionUncertain = false;
  let busy = false;
  let uncertain = false;
  let revision = Number(page.querySelector('[data-key-revision]').textContent);
  let generation = 0;
  let hideTimer;
  const clear = () => { const wasVisible = !issued.hidden; generation++; clearTimeout(hideTimer); secret.value = ''; secret.removeAttribute('value'); issued.hidden = true; if (wasVisible) status.textContent = 'Key hidden.'; };
  if (!issued.hidden) hideTimer = setTimeout(clear, 60000);
  page.querySelector('[data-dismiss]').addEventListener('click', clear);
  window.addEventListener('pagehide', clear);
  window.addEventListener('pageshow', event => { if (event.persisted) clear(); });
  const lock = () => {
    page.querySelectorAll('[data-key-create] button,[data-key-delete] button,[data-key-reveal] button').forEach(button => { button.disabled = busy || uncertain || permissionBusy || permissionDirty || permissionUncertain; });
    refresh.disabled = busy || permissionBusy || permissionDirty;
    if (workspace) window.dispatchEvent(new CustomEvent('gateway-key-state',{detail:{busy, uncertain}}));
  };
  if (workspace) {
    window.addEventListener('gateway-permission-state', event => {
      permissionBusy = event.detail.busy; permissionDirty = event.detail.dirty; permissionUncertain = event.detail.uncertain;
      const savedRevision = Number(page.querySelector('[data-key-revision]').textContent);
      if (Number.isSafeInteger(savedRevision) && savedRevision > 0) revision = savedRevision;
      const note = page.querySelector('[data-key-lock-note]'); if (note) note.hidden = !permissionDirty && !permissionUncertain;
      page.querySelectorAll('[data-key-create] button,[data-key-delete] button,[data-key-reveal] button').forEach(button => {button.disabled = busy || uncertain || permissionBusy || permissionDirty || permissionUncertain;});
    });
    const search = page.querySelector('#client-search');
    search.addEventListener('input', () => {const term=search.value.toLocaleLowerCase().trim();page.querySelectorAll('[data-client-link]').forEach(link=>{link.hidden=!link.dataset.clientSearch.toLocaleLowerCase().includes(term);});});
  }
  const element = (tag, text, className) => {
    const node = document.createElement(tag);
    if (text !== undefined) node.textContent = text;
    if (className) node.className = className;
    return node;
  };
  const hidden = (name, value) => { const input = element('input'); input.type = 'hidden'; input.name = name; input.value = value; return input; };
  function validState(data) {
    return data && Number.isSafeInteger(data.revision) && data.revision > 0 && Array.isArray(data.keys) && data.keys.every(key =>
      key && typeof key.id === 'string' && /^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,127}$/.test(key.id) && typeof key.name === 'string' && typeof key.managed === 'boolean' && typeof key.recoverable === 'boolean' &&
      (!key.managed || (typeof key.prefix === 'string' && typeof key.created_at === 'string')));
  }
  function apply(data) {
    clear();
    revision = data.revision;
    page.querySelector('[data-key-revision]').textContent = revision;
    page.querySelector('[data-key-count]').textContent = String(data.keys.length);
    page.querySelector('[data-key-create] input[name="revision"]').value = revision;
    const list = page.querySelector('[data-key-list]');
    const fragment = document.createDocumentFragment();
    data.keys.forEach(key => {
      const card = element('article', undefined, 'key-card'); card.dataset.keyId = key.id;
      const heading = element('header', undefined, 'key-heading');
      heading.append(element('h3', key.name), element('span', key.legacy ? 'Shared access' : 'Restricted', 'policy-tag')); card.append(heading);
      const access = element('div', undefined, 'key-access');
      access.append(element('span', (key.configured || 0) + ' configured', 'access-stat'), element('span', (key.effective || 0) + ' available', 'access-stat')); card.append(access);
      if (key.legacy) card.append(element('p', 'Legacy shared access: enabled shared tools are available.'));
      const permissions = element('a', 'Edit permissions', 'permission-link'); permissions.href = base + '/admin/connection/permissions/' + encodeURIComponent(key.id); card.append(permissions);
      const metadata = element('details', undefined, 'key-meta'); metadata.append(element('summary', 'Key details'));
      const principal = element('p', 'Principal '); principal.append(element('code', key.id), document.createTextNode(' · Policy ' + (key.policy || 'unknown'))); metadata.append(principal);
      if (key.managed) { const info = element('p'); info.append(element('code', key.prefix + '…'), document.createTextNode(' · Created ' + key.created_at)); metadata.append(info); }
      else metadata.append(element('p', 'Managed by environment.'));
      card.append(metadata);
      if (key.managed) {
        if (key.recoverable) {
          const reveal = element('form'); reveal.dataset.keyReveal = ''; reveal.method = 'post'; reveal.action = base + '/admin/connection/keys/' + encodeURIComponent(key.id) + '/reveal';
          reveal.append(hidden('csrf', csrf), hidden('revision', revision));
          const show = element('button', 'Show key', 'secondary'); show.type = 'submit'; show.dataset.revealId = key.id;
          const copy = element('button', 'Copy key', 'secondary'); copy.type = 'button'; copy.dataset.copyKey = key.id;
          const buttons = element('div', undefined, 'key-buttons'); buttons.append(show, copy); reveal.append(buttons); card.append(reveal);
        } else card.append(element('p', 'Repeat display is unavailable. Create a new key if you need to show it again.'));
        const details = element('details'); details.append(element('summary', 'Delete key'));
        const form = element('form'); form.dataset.keyDelete = ''; form.method = 'post'; form.action = base + '/admin/connection/keys/' + encodeURIComponent(key.id) + '/delete';
        form.append(hidden('csrf', csrf), hidden('revision', revision));
        const label = element('label', 'Type ' + key.name + ' to confirm deletion');
        const confirm = element('input'); confirm.name = 'confirm'; confirm.required = true; confirm.autocomplete = 'off'; confirm.maxLength = 128; label.append(confirm);
        const button = element('button', 'Delete key', 'danger'); button.type = 'submit';
        form.append(label, element('p', 'Clients using this key will lose access. This cannot be undone.'), button); details.append(form); card.append(details);
      } else card.append(element('p', 'Managed by environment. Preserved for existing clients; the value is not displayed here.'));
      fragment.append(card);
    });
    list.replaceChildren(fragment);
  }
  page.addEventListener('click', async event => {
    const keyCopy = event.target.closest('[data-copy-key]');
    if (keyCopy) { await revealKey(keyCopy.dataset.copyKey, true); return; }
    const button = event.target.closest('[data-copy]'); if (!button) return;
    const target = document.getElementById(button.dataset.copy);
    const text = target.value !== undefined ? target.value : target.textContent;
    if (!text) return;
    try {
      if (!navigator.clipboard) throw new Error('Clipboard unavailable');
      await navigator.clipboard.writeText(text);
      status.textContent = 'Copied.';
    } catch {
      if (typeof target.select === 'function') target.select();
      else { const range = document.createRange(); range.selectNodeContents(target); const selection = window.getSelection(); selection.removeAllRanges(); selection.addRange(range); }
      status.textContent = 'Copy was not completed. Select and copy the text manually.';
    }
  });
  function showKey(token) {
    secret.value = token; issued.hidden = false; secret.focus();
    hideTimer = setTimeout(clear, 60000);
  }
  async function revealKey(id, copy) {
    if (busy || uncertain || permissionBusy || permissionDirty || permissionUncertain) return;
    clear(); const requestGeneration = generation;
    busy = true; lock(); status.textContent = copy ? 'Copying…' : 'Showing…';
    try {
      const response = await fetch(base + '/admin/connection/keys/' + encodeURIComponent(id) + '/reveal', {method:'POST',headers:{'Accept':'application/json','Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({csrf,revision}),credentials:'same-origin',redirect:'error',cache:'no-store'});
      if (requestGeneration !== generation) return;
      if (!response.ok) { if (response.status === 409) { uncertain = true; refresh.hidden = false; } throw new Error('Unavailable'); }
      const data = await response.json();
      if (requestGeneration !== generation) return;
      if (data.id !== id || typeof data.token !== 'string' || !/^mgw_[A-Za-z0-9_-]{43}$/.test(data.token)) throw new Error('Invalid');
      if (copy) {
        try {
          if (!navigator.clipboard) throw new Error('Clipboard unavailable');
          await navigator.clipboard.writeText(data.token);
          if (requestGeneration === generation) status.textContent = 'Copied.';
        } catch {
          if (requestGeneration !== generation) return;
          showKey(data.token); secret.select(); status.textContent = 'Copy was not completed. Select and copy the text manually.';
        }
      } else { showKey(data.token); status.textContent = 'Key shown temporarily.'; }
    } catch { if (requestGeneration === generation) status.textContent = 'Key could not be shown or copied. Refresh keys if the list changed.'; }
    finally { busy = false; lock(); }
  }
  page.addEventListener('submit', async event => {
    const form = event.target;
    if (form.matches('[data-key-reveal]')) { event.preventDefault(); const id = form.querySelector('[data-reveal-id]').dataset.revealId; await revealKey(id, false); return; }
    if (!form.matches('[data-key-create],[data-key-delete]')) return;
    event.preventDefault();
    if (busy || uncertain || permissionBusy || permissionDirty || permissionUncertain) return;
    clear();
    busy = true; lock(); status.textContent = 'Saving…';
    try {
      const response = await fetch(form.action, {method:'POST', headers:{'Accept':'application/json','Content-Type':'application/x-www-form-urlencoded'}, body:new URLSearchParams(new FormData(form)), credentials:'same-origin', redirect:'error', cache:'no-store'});
      if (!response.ok) {
        if (response.status === 400) { status.textContent = await response.text(); return; }
        throw new Error('Unconfirmed');
      }
      const data = await response.json();
      const creation = form.matches('[data-key-create]');
      if (!validState(data) || data.token !== undefined) throw new Error('Unconfirmed');
      if (workspace) {
        const existing = new Set(Array.from(page.querySelectorAll('[data-client-link]')).map(link => link.dataset.keyId));
        const created = creation ? data.keys.find(key => !existing.has(key.id)) : null;
        location.assign(created ? base + '/admin/connection/permissions/' + encodeURIComponent(created.id) : base + '/admin/connection');
        return;
      }
      apply(data);
      if (creation) {
        form.reset(); form.querySelector('[name="revision"]').value = revision;
        status.textContent = 'Key created with no tool access. Edit permissions, then use Show key or Copy key when needed.';
      } else status.textContent = 'Key deleted. Subsequent requests using it are rejected.';
      if (data.audit_status === 'degraded') status.textContent += ' Change saved; audit unavailable.';
    } catch {
      uncertain = true; refresh.hidden = false;
      status.textContent = 'Change could not be confirmed. Refresh keys before retrying. Check whether the key appeared before creating another. Its value can be shown from its card.';
    } finally { busy = false; lock(); }
  });
  refresh.addEventListener('click', async () => {
    if (busy || permissionBusy || permissionDirty) return;
    busy = true; lock();
    try {
      const response = await fetch(base + '/admin/connection', {headers:{'Accept':'application/json'}, credentials:'same-origin', redirect:'error', cache:'no-store'});
      if (!response.ok) throw new Error('Refresh failed');
      const data = await response.json(); if (!validState(data)) throw new Error('Invalid state');
      if (workspace) { location.reload(); return; }
      apply(data); uncertain = false; refresh.hidden = true;
      status.textContent = 'Keys refreshed. Check the list before making another change.';
    } catch { status.textContent = 'Refresh failed. Your pending key name is preserved. Try refresh again.'; }
    finally { busy = false; lock(); }
  });
})();
