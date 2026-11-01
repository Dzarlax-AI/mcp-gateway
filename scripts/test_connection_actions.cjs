// Exercise the real script's failure boundaries using isolated synthetic keys.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
class Node {
 constructor(tag=''){this.tag=tag;this.value='';this.textContent='';this.dataset={};this.hidden=false;this.disabled=false;this.children=[];this.listeners={};}
 append(...nodes){this.children.push(...nodes);} replaceChildren(...nodes){this.children=nodes;}
 addEventListener(name,cb){this.listeners[name]=cb;} removeAttribute(name){this.removedAttribute=name;}
 focus(){this.focused=true;} select(){this.selected=true;}
}
async function run(){
 const page=new Node();page.dataset.base='/gateway';
 const keyCount=new Node();
 const status=new Node(),refresh=new Node(),issued=new Node(),secret=new Node(),dismiss=new Node(),list=new Node(),revText=new Node();
 issued.hidden=true;refresh.hidden=true;revText.textContent='1';
 const csrf=new Node();csrf.value='synthetic-csrf';const revision=new Node();revision.value='1';const name=new Node();name.value='Pending draft';
 const submit=new Node('button'),form=new Node('form');form.action='/gateway/admin/connection/keys/create';
 form.matches=selector=>selector.includes('[data-key-create]');form.querySelector=selector=>selector.includes('revision')?revision:name;form.reset=()=>{name.value='';};
 const copyTarget=new Node();copyTarget.value='synthetic-copy-text';
 const nodes={'input[name="csrf"]':csrf,'[data-key-status]':status,'[data-keys-refresh]':refresh,'[data-issued]':issued,'#issued-key':secret,'[data-dismiss]':dismiss,'[data-key-revision]':revText,'[data-key-create]':form,'[data-key-create] input[name="revision"]':revision,'[data-key-count]':keyCount,'[data-key-list]':list};
 page.querySelector=selector=>{assert.ok(nodes[selector],selector);return nodes[selector];};page.querySelectorAll=()=>[submit];
 const window=new Node(),responses=[],calls=[],timers=new Map();let timerID=0,copyDenied=true,clipboard='';
 const document={querySelector:()=>page,getElementById:()=>copyTarget,createElement:tag=>new Node(tag),createTextNode:text=>({textContent:text}),createDocumentFragment:()=>new Node()};
 const sandbox={document,window,navigator:{clipboard:{writeText:async text=>{if(copyDenied)throw Error('Denied');clipboard=text;}}},URLSearchParams,encodeURIComponent,
 setTimeout:(cb,ms)=>{assert.equal(ms,60000);timers.set(++timerID,cb);return timerID;},clearTimeout:id=>timers.delete(id),
 FormData:class{*[Symbol.iterator](){yield ['csrf',csrf.value];yield ['revision',revision.value];yield ['name',name.value];}},
 fetch:async(url,options)=>{calls.push({url,method:options.method||'GET'});const r=responses.shift();if(r instanceof Error)throw r;if(typeof r==='function')return r();assert.ok(r,'Unexpected retry');return r;}};
 vm.runInNewContext(fs.readFileSync('internal/admin/connection.js','utf8'),sandbox);
 const response=data=>({ok:true,status:200,json:async()=>data});const submitForm=()=>page.listeners.submit({target:form,preventDefault(){}});
 responses.push(new Error('Lost POST response'));await submitForm();assert.equal(calls.length,1);assert.equal(submit.disabled,true);assert.equal(name.value,'Pending draft');
 await submitForm();assert.equal(calls.length,1);responses.push(new Error('Offline'));await refresh.listeners.click();assert.equal(submit.disabled,true);
 responses.push(response({revision:2,keys:[]}));await refresh.listeners.click();assert.equal(submit.disabled,false);assert.equal(name.value,'Pending draft');assert.equal(keyCount.textContent,'0');
 const token='mgw_'+'a'.repeat(43);const key={id:'key_test',name:'Laptop',managed:true,recoverable:true,prefix:'mgw_aaaaaaaa',created_at:'2026-10-12T12:00:00Z'};
 responses.push(response({revision:3,keys:[key]}));await submitForm();assert.equal(issued.hidden,true);assert.equal(secret.value,'');assert.equal(name.value,'');assert.equal(keyCount.textContent,'1');
 const revealForm=new Node();revealForm.matches=selector=>selector.includes('[data-key-reveal]');revealForm.querySelector=()=>({dataset:{revealId:'key_test'}});
 const reveal=()=>page.listeners.submit({target:revealForm,preventDefault(){}});
 for(let i=0;i<2;i++){responses.push(response({id:'key_test',token}));await reveal();assert.equal(secret.value,token);assert.equal(issued.hidden,false);dismiss.listeners.click();assert.equal(secret.value,'');}
 responses.push(response({id:'key_test',token}));await reveal();assert.equal(timers.size,1);[...timers.values()][0]();assert.equal(secret.value,'');assert.equal(issued.hidden,true);
 const copy=()=>page.listeners.click({target:{closest:selector=>selector==='[data-copy-key]'?{dataset:{copyKey:'key_test'}}:null}});
 responses.push(response({id:'key_test',token}));await copy();assert.equal(secret.value,token);assert.equal(secret.selected,true);assert.match(status.textContent,/not completed/);dismiss.listeners.click();
 copyDenied=false;responses.push(response({id:'key_test',token}));await copy();assert.equal(clipboard,token);assert.equal(issued.hidden,true);assert.equal(secret.value,'');assert.equal(status.textContent,'Copied.');
 // Navigation while a reveal is pending must prevent a late response restoring it.
 let finish;responses.push(()=>new Promise(resolve=>{finish=resolve;}));const pending=reveal();window.listeners.pagehide();finish(response({id:'key_test',token}));await pending;assert.equal(secret.value,'');assert.equal(issued.hidden,true);
 responses.push(response({id:'wrong_id',token}));await reveal();assert.equal(secret.value,'');
 responses.push({ok:false,status:409});await reveal();assert.equal(submit.disabled,true);const before=calls.length;await reveal();assert.equal(calls.length,before);
 responses.push(response({revision:4,keys:[]}));await refresh.listeners.click();assert.equal(submit.disabled,false);
 // A malformed creation response cannot unexpectedly populate the secret field.
 responses.push(response({revision:5,keys:[],token}));await submitForm();assert.equal(submit.disabled,true);assert.equal(secret.value,'');
 window.listeners.pageshow({persisted:true});assert.equal(secret.value,'');
 console.log('connection actions: hidden creation, repeat reveal, timer/hide/navigation, copy success/fallback, stale/lost response and refresh passed');
}
run().then(verifyWorkspaceRevision).catch(error=>{console.error(error);process.exitCode=1;});

async function verifyWorkspaceRevision() {
 const page=new Node();page.dataset={base:'/gateway',clientWorkspace:'true'};
 const status=new Node(),refresh=new Node(),issued=new Node(),secret=new Node(),dismiss=new Node(),revText=new Node(),csrf=new Node(),search=new Node(),note=new Node();
 issued.hidden=true;revText.textContent='7';csrf.value='synthetic-csrf';
 const buttons=[new Node('button')];
 const nodes={'input[name="csrf"]':csrf,'[data-key-status]':status,'[data-keys-refresh]':refresh,'[data-issued]':issued,'#issued-key':secret,'[data-dismiss]':dismiss,'[data-key-revision]':revText,'#client-search':search,'[data-key-lock-note]':note};
 page.querySelector=s=>{assert.ok(nodes[s],s);return nodes[s];};page.querySelectorAll=()=>buttons;
 const window=new Node();window.dispatchEvent=()=>{};const calls=[];let timer=0;
 const token='mgw_'+'w'.repeat(43);
 vm.runInNewContext(fs.readFileSync('internal/admin/connection.js','utf8'),{document:{querySelector:()=>page},window,CustomEvent:class{constructor(type,options){this.type=type;this.detail=options.detail;}},URLSearchParams,encodeURIComponent,
 setTimeout:()=>++timer,clearTimeout:()=>{},fetch:async(url,options)=>{calls.push(options);return{ok:true,json:async()=>({id:'key_workspace',token})};}});
 const revealForm=new Node();revealForm.matches=s=>s.includes('[data-key-reveal]');revealForm.querySelector=()=>({dataset:{revealId:'key_workspace'}});
 const reveal=()=>page.listeners.submit({target:revealForm,preventDefault(){}});
 revText.textContent='8';window.listeners['gateway-permission-state']({detail:{busy:false,dirty:false,uncertain:false}});
 await reveal();assert.equal(calls.length,1);assert.equal(calls[0].body.get('revision'),'8');assert.equal(secret.value,token);dismiss.listeners.click();
 window.listeners['gateway-permission-state']({detail:{busy:false,dirty:true,uncertain:false}});await reveal();assert.equal(calls.length,1);assert.ok(buttons.every(b=>b.disabled));
 window.listeners['gateway-permission-state']({detail:{busy:false,dirty:false,uncertain:true}});await reveal();assert.equal(calls.length,1);
 console.log('client keys workspace: post-permission revision, dirty draft and uncertain state guards passed');
}
