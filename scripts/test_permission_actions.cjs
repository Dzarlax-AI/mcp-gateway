// Run the real progressive enhancement script with bounded synthetic responses.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
function fixture() {
 const status={textContent:''}, revision={value:'1'}, revText={}, audit={}, button={disabled:false};
 const cell={}, checkbox={name:'grant:synthetic',checked:true,closest:()=>({querySelector:()=>cell})};
 const legacy={removed:false,remove(){this.removed=true;}};
 const policy={value:'restricted',querySelectorAll:()=>[legacy]};
 let submit;
 const form={action:'/admin/connection/permissions/synthetic',addEventListener:(name,cb)=>{submit=cb;},querySelector:s=>s.includes('revision')?revision:s.includes('policy')?policy:button,querySelectorAll:()=>[checkbox]};
 const nodes={'[data-permissions]':form,'[data-permission-status]':status,'[data-permission-revision]':revText,'[data-audit-status]':audit};
 const responses=[],calls=[];
 vm.runInNewContext(fs.readFileSync('internal/admin/permissions.js','utf8'),{document:{querySelector:s=>nodes[s]},URLSearchParams,FormData:class{*[Symbol.iterator](){yield['policy',policy.value];yield['revision',revision.value];yield[checkbox.name,'1'];}},fetch:async(url,options)=>{calls.push({url,options});const r=responses.shift();assert.ok(r,'Unexpected POST retry');if(r instanceof Error)throw r;return typeof r==='function'?r():r;}});
 return {status,revision,button,cell,checkbox,legacy,audit,responses,calls,submit:()=>submit({preventDefault(){}})};
}

async function testWorkspaceGroups() {
 const node=()=>({textContent:'',value:'',disabled:false,hidden:false,listeners:{},addEventListener(n,f){this.listeners[n]=f;}});
 const status=node(),revision=node(),revText=node(),keyRev=node(),audit=node(),button=node(),search=node(),allow=node(),deny=node(),draft=node(),selected=node(),badge=node(),rail=node();revision.value='1';
 const policy={...node(),value:'restricted',querySelectorAll:()=>[]};
 function group(server,states) {
  const check={...node(),checked:false,indeterminate:false,matches:s=>s==='[data-permission-group-select]'},count=node();
  const g={hidden:false,open:true,rows:[],querySelector:s=>s==='[data-permission-group-select]'?check:count,querySelectorAll:()=>g.rows};
  check.closest=()=>g;
  g.rows=states.map((checked,i)=>{const cell=node(),box={name:'grant:'+server+i,checked,disabled:false,matches:()=>false};const row={hidden:false,dataset:{search:server+' tool'+i},querySelector:s=>s==='input[type="checkbox"]'?box:cell};box.closest=()=>row;return row;});return {g,check,count};
 }
 const calendar=group('calendar',[true,false]),memory=group('memory',[true]);const groups=[calendar.g,memory.g],rows=groups.flatMap(g=>g.rows),boxes=rows.map(r=>r.querySelector('input[type="checkbox"]'));
 const form={...node(),dataset:{},action:'/admin/connection/permissions/client',querySelector:s=>({'button[type="submit"]':button,'[name="policy"]':policy,'[name="revision"]':revision,'#permission-search':search,'[data-allow-visible]':allow,'[data-deny-visible]':deny,'[data-draft-count]':draft}[s]),querySelectorAll:s=>s==='[data-permission-group]'?groups:s==='[data-permission-row]'?rows:s==='[data-allow-visible],[data-deny-visible]'?[allow,deny]:boxes};
 const workspace={querySelector:s=>({'[data-key-revision]':keyRev,'[data-selected-access]':selected,'[data-selected-policy]':badge,'.client-link.active [data-client-access]':rail}[s]),querySelectorAll:()=>[revision]};
 const nodes={'[data-permissions]':form,'[data-client-workspace]':workspace,'[data-permission-status]':status,'[data-permission-revision]':revText,'[data-audit-status]':audit};
 const window={listeners:{},addEventListener(n,f){this.listeners[n]=f;},dispatchEvent(){}};const responses=[],calls=[];
 const rights=()=>Object.fromEntries(boxes.map(b=>[b.name,b.checked]));
 vm.runInNewContext(fs.readFileSync('internal/admin/permissions.js','utf8'),{document:{querySelector:s=>nodes[s]},window,CustomEvent:class {constructor(type,o){this.type=type;this.detail=o.detail;}},URLSearchParams,
 FormData:class {*[Symbol.iterator](){if(!policy.disabled)yield['policy',policy.value];yield['revision',revision.value];for(const b of boxes)if(b.checked&&!b.disabled)yield[b.name,'1'];}},
 fetch:async(url,o)=>{calls.push(o);return responses.shift();}});
 assert.equal(calendar.check.indeterminate,true);
 search.value='calendar';search.listeners.input();assert.equal(memory.g.hidden,true);
 allow.listeners.click();assert.deepEqual(boxes.map(b=>b.checked),[true,true,true]);assert.equal(calendar.check.checked,true);assert.match(draft.textContent,/Unsaved/);
 deny.listeners.click();assert.deepEqual(boxes.map(b=>b.checked),[false,false,true]);
 let prevented=false;window.listeners.beforeunload({preventDefault(){prevented=true;}});assert.equal(prevented,true);
 const savedRights=rights();responses.push({ok:true,json:async()=>({revision:2,audit_status:'ok',rights:savedRights})});
 await form.listeners.submit({preventDefault(){}});
 assert.equal(calls.length,1);assert.equal(calls[0].body.get('grant:memory0'),'1');assert.equal(calls[0].body.get('grant:calendar0'),null);assert.equal(calls[0].body.get('policy'),'restricted');assert.equal(revision.value,2);assert.equal(button.disabled,false);assert.equal(draft.textContent,'Saved permissions');
 calendar.check.checked=true;form.listeners.change({target:calendar.check});assert.deepEqual(boxes.map(b=>b.checked),[true,true,true]);
 window.listeners['gateway-key-state']({detail:{busy:true,uncertain:false}});assert.equal(button.disabled,true);assert.ok(boxes.every(b=>b.disabled));
 window.listeners['gateway-key-state']({detail:{busy:false,uncertain:false}});assert.equal(button.disabled,false);
 policy.value='legacy_shared';form.listeners.change({target:{matches:()=>false}});assert.ok(boxes.every(b=>b.disabled));assert.equal(allow.disabled,true);assert.equal(calendar.check.disabled,true);
 policy.value='restricted';form.listeners.change({target:{matches:()=>false}});
 responses.push({ok:false,status:409});await form.listeners.submit({preventDefault(){}});assert.equal(button.disabled,true);assert.ok(boxes.every(b=>b.disabled));await form.listeners.submit({preventDefault(){}});assert.equal(calls.length,2);
 console.log('client workspace: partial groups, filtered bulk, hidden grants, serialize before locking, legacy mode, cross-form locks and stale-save guards passed');
}
const good=(revision,audit_status='ok')=>({ok:true,json:async()=>({revision,audit_status,rights:{'grant:synthetic':true}})});
(async()=>{
 let f=fixture();f.responses.push(good(2));await f.submit();assert.equal(f.revision.value,2);assert.equal(f.cell.textContent,'Allowed');assert.equal(f.legacy.removed,true);assert.equal(f.checkbox.checked,true);assert.equal(f.button.disabled,false);
 f.responses.push(good(3,'degraded'));await f.submit();assert.match(f.status.textContent,/saved; audit unavailable/);assert.equal(f.calls.length,2);
 f.responses.push({ok:false,status:400});await f.submit();assert.equal(f.checkbox.checked,true);assert.equal(f.button.disabled,false);assert.match(f.status.textContent,/draft is preserved/);
 for(const failure of [new Error('Lost acknowledgement'),{ok:false,status:409},{ok:false,status:403},{ok:true,json:async()=>({revision:4,audit_status:'ok'})}]) {
  f=fixture();f.responses.push(failure);await f.submit();assert.equal(f.checkbox.checked,true);assert.equal(f.revision.value,'1');assert.equal(f.button.disabled,true);await f.submit();assert.equal(f.calls.length,1);assert.match(f.status.textContent,/Reload saved/);
 }
 f=fixture();let resolve;f.responses.push(()=>new Promise(r=>{resolve=r;}));const pending=f.submit();await f.submit();assert.equal(f.calls.length,1);resolve(good(2));await pending;
 await testWorkspaceGroups();
 console.log('permission actions: confirmed rights, degraded audit, preserved drafts, rejected/stale/lost responses, one pending POST and no retries passed');
})().catch(e=>{console.error(e);process.exitCode=1;});
