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
const good=(revision,audit_status='ok')=>({ok:true,json:async()=>({revision,audit_status,rights:{'grant:synthetic':true}})});
(async()=>{
 let f=fixture();f.responses.push(good(2));await f.submit();assert.equal(f.revision.value,2);assert.equal(f.cell.textContent,'Allowed');assert.equal(f.legacy.removed,true);assert.equal(f.checkbox.checked,true);assert.equal(f.button.disabled,false);
 f.responses.push(good(3,'degraded'));await f.submit();assert.match(f.status.textContent,/saved; audit unavailable/);assert.equal(f.calls.length,2);
 f.responses.push({ok:false,status:400});await f.submit();assert.equal(f.checkbox.checked,true);assert.equal(f.button.disabled,false);assert.match(f.status.textContent,/draft is preserved/);
 for(const failure of [new Error('Lost acknowledgement'),{ok:false,status:409},{ok:false,status:403},{ok:true,json:async()=>({revision:4,audit_status:'ok'})}]) {
  f=fixture();f.responses.push(failure);await f.submit();assert.equal(f.checkbox.checked,true);assert.equal(f.revision.value,'1');assert.equal(f.button.disabled,true);await f.submit();assert.equal(f.calls.length,1);assert.match(f.status.textContent,/Reload saved/);
 }
 f=fixture();let resolve;f.responses.push(()=>new Promise(r=>{resolve=r;}));const pending=f.submit();await f.submit();assert.equal(f.calls.length,1);resolve(good(2));await pending;
 console.log('permission actions: confirmed rights, degraded audit, preserved drafts, rejected/stale/lost responses, one pending POST and no retries passed');
})().catch(e=>{console.error(e);process.exitCode=1;});
