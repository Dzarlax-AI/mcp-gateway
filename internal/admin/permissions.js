(() => {
  'use strict';
  const form = document.querySelector('[data-permissions]');
  if (!form) return;
  const status = document.querySelector('[data-permission-status]');
  const button = form.querySelector('button[type="submit"]');
  let busy = false, uncertain = form.dataset?.uncertain === 'true', keyBusy = false;
  const workspace = document.querySelector('[data-client-workspace]');
  const policy = form.querySelector('[name="policy"]');
  const boxes = () => Array.from(form.querySelectorAll('input[name^="grant:"]'));
  let saved = new Map(boxes().map(input => [input.name, input.checked])), savedPolicy = policy.value;
  let serverDraft = form.dataset?.draft === 'true', dirty = serverDraft;
  const publish = () => { if (workspace) window.dispatchEvent(new CustomEvent('gateway-permission-state', {detail:{busy, uncertain, dirty}})); };
  function update() {
    if (!workspace) return;
    dirty = serverDraft || policy.value !== savedPolicy || boxes().some(input => input.checked !== saved.get(input.name));
    const locked = busy || uncertain || keyBusy, shared = policy.value === 'legacy_shared';
    policy.disabled = locked;
    boxes().forEach(input => { input.disabled = locked || shared; });
    form.querySelectorAll('[data-permission-group]').forEach(group => {
      const rows = Array.from(group.querySelectorAll('[data-permission-row]'));
      const visible = rows.filter(row => !row.hidden).map(row => row.querySelector('input[type="checkbox"]'));
      const all = rows.map(row => row.querySelector('input[type="checkbox"]'));
      const check = group.querySelector('[data-permission-group-select]');
      check.checked = visible.length > 0 && visible.every(input => input.checked);
      check.indeterminate = visible.some(input => input.checked) && !check.checked;
      check.disabled = locked || shared || !visible.length;
      group.querySelector('[data-group-grant-count]').textContent = all.filter(input => input.checked).length + '/' + all.length + ' configured';
    });
    form.querySelectorAll('[data-allow-visible],[data-deny-visible]').forEach(el => {el.disabled = locked || shared;});
    form.querySelector('[data-draft-count]').textContent = dirty ? 'Unsaved permission changes' : 'Saved permissions';
    button.disabled = locked;
    publish();
  }
  function filter() {
    const term = form.querySelector('#permission-search').value.toLocaleLowerCase().trim();
    form.querySelectorAll('[data-permission-group]').forEach(group => {
      const rows = Array.from(group.querySelectorAll('[data-permission-row]'));
      rows.forEach(row => {row.hidden = !row.dataset.search.toLocaleLowerCase().includes(term);});
      group.hidden = rows.every(row => row.hidden);
      if (term && !group.hidden) group.open = true;
    });
    update();
  }
  if (workspace) {
    const search = form.querySelector('#permission-search');
    search.addEventListener('input', filter);
    search.addEventListener('keydown', e => {if(e.key === 'Enter') e.preventDefault();});
    form.addEventListener('change', event => {
      if (busy || uncertain || keyBusy) return;
      if (event.target.matches('[data-permission-group-select]') && policy.value === 'restricted') {
        event.target.closest('[data-permission-group]').querySelectorAll('[data-permission-row]').forEach(row => {if(!row.hidden) row.querySelector('input[type="checkbox"]').checked = event.target.checked;});
      }
      update();
    });
    for (const [selector, checked] of [['[data-allow-visible]',true],['[data-deny-visible]',false]]) {
      form.querySelector(selector).addEventListener('click', () => {
        if (busy || uncertain || keyBusy || policy.value !== 'restricted') return;
        form.querySelectorAll('[data-permission-row]').forEach(row => {if(!row.hidden) row.querySelector('input[type="checkbox"]').checked = checked;}); update();
      });
    }
    window.addEventListener('gateway-key-state', event => {keyBusy = event.detail.busy; uncertain ||= event.detail.uncertain; update();});
    window.addEventListener('beforeunload', event => {if(dirty){event.preventDefault();event.returnValue='';}});
    update();
  }
  form.addEventListener('submit', async event => {
    event.preventDefault();
    if (busy || uncertain || keyBusy) return;
    const body = new URLSearchParams(new FormData(form));
    busy = true; button.disabled = true; update(); status.textContent = 'Saving draft…';
    try {
      const response = await fetch(form.action, {method:'POST',headers:{Accept:'application/json','Content-Type':'application/x-www-form-urlencoded'},body,credentials:'same-origin',redirect:'error',cache:'no-store'});
      if (!response.ok) {
        if (response.status === 400) { status.textContent = 'Invalid permission selection. Your draft is preserved.'; return; }
        throw new Error('Unconfirmed');
      }
      const data = await response.json();
      if (!Number.isSafeInteger(data.revision) || data.revision <= 0 || !['disabled','ok','degraded'].includes(data.audit_status)) throw new Error('Unconfirmed');
      if (!data.rights || typeof data.rights !== 'object' || Array.isArray(data.rights)) throw new Error('Unconfirmed');
      boxes().forEach(input => {
        const allowed = data.rights[input.name];
        if (typeof allowed !== 'boolean') throw new Error('Unconfirmed');
        input.closest('tr').querySelector('[data-policy-cell]').textContent = allowed ? 'Allowed' : 'Denied';
      });
      form.querySelector('[name="revision"]').value = data.revision;
      document.querySelector('[data-permission-revision]').textContent = data.revision;
      document.querySelector('[data-audit-status]').textContent = data.audit_status;
      status.textContent = data.audit_status === 'degraded' ? 'Permissions saved; audit unavailable. Reload saved state if needed.' : 'Permissions saved. Effective access updated.';
      // A legacy principal converted to restricted cannot be broadened back here.
      saved = new Map(boxes().map(input => [input.name, input.checked])); savedPolicy = policy.value; serverDraft = false;
      if (workspace) {
        workspace.querySelectorAll('input[name=revision]').forEach(input => {input.value = data.revision;});
        workspace.querySelector('[data-key-revision]').textContent = data.revision;
        const configured = policy.value === 'restricted' ? boxes().filter(input => input.checked).length : 0;
        const effective = Object.values(data.rights).filter(Boolean).length;
        workspace.querySelector('[data-selected-access]').textContent = configured + ' configured · ' + effective + ' available';
        workspace.querySelector('[data-selected-policy]').textContent = policy.value === 'restricted' ? 'Restricted' : 'Shared access';
        const rail = workspace.querySelector('.client-link.active [data-client-access]');
        if (rail) rail.textContent = (policy.value === 'restricted' ? configured + ' configured' : 'Shared access') + ' · ' + effective + ' available';
      }
      if (policy.value === 'restricted') {
        policy.querySelectorAll('option[value="legacy_shared"]').forEach(option => option.remove());
        document.querySelector('[data-legacy-warning]')?.remove();
      }
    } catch {
      uncertain = true;
      status.textContent = 'Save could not be confirmed. Your draft is preserved. Reload saved permissions before retrying.';
    } finally { busy = false; button.disabled = uncertain; update(); }
  });
})();
