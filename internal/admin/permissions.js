(() => {
  'use strict';
  const form = document.querySelector('[data-permissions]');
  if (!form) return;
  const status = document.querySelector('[data-permission-status]');
  const button = form.querySelector('button[type="submit"]');
  let busy = false, uncertain = false;
  form.addEventListener('submit', async event => {
    event.preventDefault();
    if (busy || uncertain) return;
    busy = true; button.disabled = true; status.textContent = 'Saving draft…';
    try {
      const response = await fetch(form.action, {method:'POST',headers:{Accept:'application/json','Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams(new FormData(form)),credentials:'same-origin',redirect:'error',cache:'no-store'});
      if (!response.ok) {
        if (response.status === 400) { status.textContent = 'Invalid permission selection. Your draft is preserved.'; return; }
        throw new Error('Unconfirmed');
      }
      const data = await response.json();
      if (!Number.isSafeInteger(data.revision) || data.revision <= 0 || !['disabled','ok','degraded'].includes(data.audit_status)) throw new Error('Unconfirmed');
      if (!data.rights || typeof data.rights !== 'object' || Array.isArray(data.rights)) throw new Error('Unconfirmed');
      form.querySelectorAll('input[type="checkbox"]').forEach(input => {
        const allowed = data.rights[input.name];
        if (typeof allowed !== 'boolean') throw new Error('Unconfirmed');
        input.closest('tr').querySelector('[data-policy-cell]').textContent = allowed ? 'Allowed' : 'Denied';
      });
      form.querySelector('[name="revision"]').value = data.revision;
      document.querySelector('[data-permission-revision]').textContent = data.revision;
      document.querySelector('[data-audit-status]').textContent = data.audit_status;
      status.textContent = data.audit_status === 'degraded' ? 'Permissions saved; audit unavailable. Reload saved state if needed.' : 'Permissions saved. Effective access updated.';
      // A legacy principal converted to restricted cannot be broadened back here.
      const policy = form.querySelector('[name="policy"]');
      if (policy.value === 'restricted') {
        policy.querySelectorAll('option[value="legacy_shared"]').forEach(option => option.remove());
        document.querySelector('[data-legacy-warning]')?.remove();
      }
    } catch {
      uncertain = true;
      status.textContent = 'Save could not be confirmed. Your draft is preserved. Reload saved permissions before retrying.';
    } finally { busy = false; button.disabled = uncertain; }
  });
})();
