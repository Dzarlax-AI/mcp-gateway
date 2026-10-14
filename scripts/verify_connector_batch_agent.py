import pathlib,json,os,subprocess,tempfile,shutil,tomllib,urllib.request,http.cookiejar,re
import sys
root=pathlib.Path(__file__).resolve().parents[1];origin=sys.argv[1];endpoint=sys.argv[2]
assert origin.startswith('http://127.0.0.1:') and endpoint.startswith('http://127.0.0.1:')
jar=http.cookiejar.CookieJar();client=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
def get(p):return client.open(origin+p).read().decode()
def post(p,data):
 import urllib.parse
 req=urllib.request.Request(origin+p,data=urllib.parse.urlencode(data).encode(),headers={'Origin':origin});return client.open(req).read().decode()
html=get('/admin/login');csrf=re.search(r'name="csrf" value="([^"]+)"',html)[1];html=post('/admin/login',{'csrf':csrf,'token':'synthetic-connector-admin-token'})
def batch(enable):
 html=get('/admin/servers');csrf=re.search(r'name="csrf" value="([^"]+)"',html)[1];rev=re.search(r'name="revision" value="([^"]+)"',html)[1];post('/admin/servers/homeassistant/'+('batch-enable' if enable else 'batch-disable'),{'csrf':csrf,'revision':rev})
rows=[]
with tempfile.TemporaryDirectory(prefix='connector-codex-') as tmp:
 home=pathlib.Path(tmp);shutil.copyfile(pathlib.Path.home()/'.codex/auth.json',home/'auth.json');(home/'auth.json').chmod(0o600)
 model=tomllib.loads((pathlib.Path.home()/'.codex/config.toml').read_text()).get('model')
 s=('model = '+json.dumps(model)+'\n') if model else ''
 s+='[features]\napps = false\n[mcp_servers.fixture]\nurl = '+json.dumps(endpoint)+'\nbearer_token_env_var = "CONNECTOR_AGENT_TOKEN"\n'
 for tool in ['discover_server','discover_tools','search_tools','invoke_tool','invoke_read_batch']:
  s+='[mcp_servers.fixture.tools.'+tool+']\napproval_mode = "approve"\n'
 (home/'config.toml').write_text(s);env=os.environ.copy();env['CODEX_HOME']=tmp;env['CONNECTOR_AGENT_TOKEN']='synthetic-connector-fixture-client-token'
 cases=[('known_single',True,'Read homeassistant tool llm__GetDateTime with arguments {}. It is already known to be permitted by the connector batch read profile. Only this one read is needed.',['invoke_read_batch']),('known_multi',True,'Read homeassistant tools llm__GetDateTime and homeassistant__GetLiveContext, both with arguments {}. They are already known to be independent reads permitted by the connector batch read profile.',['invoke_read_batch']),('unknown_read',True,'Find the synthetic homeassistant tool that gives the current date and time; its exact name and schema are unknown. Read it using the gateway route specified by its returned batch_read_allowed field.',['search_tools','invoke_read_batch']),('ordinary_read',False,'Read homeassistant tool llm__GetDateTime with arguments {}. Connector batch reads are disabled; this read is known to be permitted through ordinary invocation.',['invoke_tool'])]
 for name,enabled,prompt,expected in cases:
  batch(enabled);r=subprocess.run(['codex','exec','--skip-git-repo-check','--sandbox','read-only','--json','Use only fixture MCP gateway. Do not use shell, files, web, apps or any other integrations. '+prompt],env=env,cwd=tmp,capture_output=True,text=True,timeout=120)
  calls=[]
  for l in r.stdout.splitlines():
   try:e=json.loads(l)
   except ValueError:continue
   i=e.get('item',{})
   if e.get('type')=='item.completed' and i.get('type')=='mcp_tool_call':calls.append({k:i.get(k) for k in ['tool','status','error','arguments','result']})
  passed=r.returncode==0 and [x['tool'] for x in calls]==expected and all(x['status']=='completed' and not x['error'] and not (x.get('result') or {}).get('isError',False) for x in calls)
  for c in calls:
   if c['tool']=='invoke_read_batch':
    v=(c.get('result') or {}).get('structured_content',{});passed=passed and v.get('complete') is True and len(v.get('results',[]))==(2 if name=='known_multi' else 1) and all(i.get('status')=='ok' and i.get('dispatched') for i in v.get('results',[]))
  rows.append({'case':name,'passed':bool(passed),'expected':expected,'calls':calls,'exit_code':r.returncode});print(name,passed,flush=True)
(root/'docs/verification/connector-batch-agent-local.json').write_text(json.dumps({'scope':'isolated Codex home; synthetic loopback only; live config unchanged','model':model,'cases':rows,'all_passed':all(x['passed'] for x in rows)},indent=2))
assert all(x['passed'] for x in rows),'see local agent evidence'
