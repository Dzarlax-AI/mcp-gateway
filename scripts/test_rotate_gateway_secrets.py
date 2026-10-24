import base64
from contextlib import redirect_stderr, redirect_stdout
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import tarfile
import tempfile
import threading
import unittest
from unittest import mock
from urllib.parse import urlsplit, urlunsplit
from urllib.request import Request, urlopen

spec=importlib.util.spec_from_file_location('rotation_operator',Path(__file__).with_name('rotate_gateway_secrets.py'))
op=importlib.util.module_from_spec(spec);spec.loader.exec_module(op)

class OperatorUnitTests(unittest.TestCase):
    def test_env_exact_preservation_and_strict_inputs(self):
        raw=b'# retained\nGATEWAY_SECRET_KEY=old\nGATEWAY_DATABASE_URL=oldurl\nOTHER="retained-value"\n'
        changed=op.patch_env(raw,{'GATEWAY_SECRET_KEY':'new','GATEWAY_DATABASE_URL':'newurl'})
        self.assertEqual(changed.replace(b'=new\n',b'=old\n').replace(b'=newurl\n',b'=oldurl\n'),raw)
        for raw in (b'A=1\nA=2',b'A=${SECRET}',b'A="unterminated'):
            with self.assertRaises(op.RotationFailure):op.env_values(raw)
    def test_no_exception_or_child_output_leak(self):
        sentinel='synthetic-sensitive-command-argument'
        with self.assertRaises(op.RotationFailure) as e:
            op.run_cli('/does-not-exist/'+sentinel,[],{})
        self.assertNotIn(sentinel,str(e.exception))
        stdout,stderr=io.StringIO(),io.StringIO()
        with redirect_stdout(stdout),redirect_stderr(stderr):
            code=op.main(['apply','--unknown',sentinel])
        self.assertEqual(code,1);self.assertNotIn(sentinel,stdout.getvalue()+stderr.getvalue())
        from unittest.mock import patch
        failed=subprocess.CompletedProcess(['private-command'],1,sentinel.encode(),sentinel.encode())
        with patch.object(op.subprocess,'run',return_value=failed):
            with self.assertRaises(op.RotationFailure) as e:op.run_cli('/private-command',[],{})
        self.assertNotIn(sentinel,str(e.exception))
    def test_private_files_and_symlinks(self):
        with tempfile.TemporaryDirectory() as root:
            p=Path(root)/'input';op.write_private(p,b'synthetic-sensitive')
            self.assertEqual(op.private_read(p),b'synthetic-sensitive')
            p.chmod(0o644)
            with self.assertRaises(op.RotationFailure):op.private_read(p)
            p.chmod(0o600);alias=Path(root)/'alias';alias.symlink_to(p)
            with self.assertRaises((op.RotationFailure,OSError)):op.private_read(alias)
            with self.assertRaises(op.RotationFailure):op.write_private(p,b'overwrite')
    def test_atomic_replace_failure_preserves_original(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as root:
            p=Path(root)/'env';op.write_private(p,b'old')
            with patch.object(op.os,'replace',side_effect=OSError('synthetic-secret')):
                with self.assertRaises(OSError):op.write_private(p,b'new',replace=True)
            self.assertEqual(op.private_read(p),b'old')
            with patch.object(op.os,'fsync',side_effect=OSError('synthetic-secret')):
                with self.assertRaises(OSError):op.write_private(p,b'new',replace=True)
            self.assertEqual(op.private_read(p),b'old')


@unittest.skipUnless(os.getenv('TEST_ROTATION_REHEARSAL_ADMIN_URL'),'requires isolated synthetic PostgreSQL')
class PostgreSQLRehearsal(unittest.TestCase):
    def safe(self,args,env=None):
        r=subprocess.run(args,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=45)
        self.outputs.append(r.stdout+r.stderr)
        self.assertEqual(r.returncode,0,'synthetic helper failed; output suppressed')
        return r.stdout
    def sql(self,query,database=None):
        return self.safe(['docker','exec',self.container,'psql','-U','postgres','-d',database or self.database,'-Atc',query]).decode().strip()
    def setUp(self):
        self.outputs=[]
        target=urlsplit(os.environ['TEST_ROTATION_REHEARSAL_ADMIN_URL'])
        if target.hostname not in ('127.0.0.1','localhost','::1') or not target.path.startswith('/rotation_'):
            self.fail('rehearsal requires isolated loopback rotation_ database')
        self.container=os.environ.get('TEST_ROTATION_REHEARSAL_CONTAINER','gateway-rotation-rehearsal-pg')
        self.binary=os.environ.get('TEST_ROTATION_REGISTRY','/tmp/gateway-rotation-registry')
        self.fixture=os.environ.get('TEST_ROTATION_FIXTURE','/tmp/gateway-rotation-fixture')
        self.server_binary=os.environ.get('TEST_ROTATION_SERVER','/tmp/gateway-rotation-server')
        self.temp=tempfile.TemporaryDirectory(prefix='gateway-rotation-synthetic-');self.root=Path(self.temp.name)
        self.database='rotation_rehearsal_'+os.urandom(5).hex()
        self.sql('CREATE DATABASE '+self.database,'postgres')
        self.old_password='o'*64
        self.sql("DO $$ BEGIN IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='mcp_gateway_runtime') THEN CREATE ROLE mcp_gateway_runtime LOGIN; END IF; END $$",'postgres')
        self.sql("ALTER ROLE mcp_gateway_runtime PASSWORD '"+self.old_password+"'",'postgres')
        admin=urlsplit(os.environ['TEST_ROTATION_REHEARSAL_ADMIN_URL'])
        self.admin_url=urlunsplit(admin._replace(path='/'+self.database))
        self.runtime_url=urlunsplit(admin._replace(netloc='mcp_gateway_runtime:'+self.old_password+'@'+admin.netloc.rsplit('@',1)[1],path='/'+self.database))
        self.old_key=base64.b64encode(bytes([71])*32).decode()
        self.env=os.environ.copy();self.env.update({'ROTATION_CLIENT_TOKEN':'synthetic-client-token-preserved','ROTATION_UPSTREAM_A':'synthetic-upstream-secret-A-preserved','ROTATION_UPSTREAM_B':'synthetic-upstream-secret-B-preserved'})
        self.upstream_calls=0
        case=self
        class Upstream(BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_POST(self):
                try:
                    expected=case.env['ROTATION_UPSTREAM_A'] if self.path=='/a' else case.env['ROTATION_UPSTREAM_B']
                    header='Authorization' if self.path=='/a' else 'X-API-Key'
                    actual=self.headers.get(header);want='Bearer '+expected if header=='Authorization' else expected
                    if actual!=want:self.send_response(401);self.end_headers();return
                    data=json.loads(self.rfile.read(int(self.headers.get('Content-Length','0'))))
                    method=data['method']
                    if 'id' not in data:self.send_response(202);self.end_headers();return
                    if method=='initialize':result={'protocolVersion':'2025-11-25','capabilities':{'tools':{}},'serverInfo':{'name':'rotation-synthetic','version':'1'}}
                    elif method=='tools/list':result={'tools':[{'name':'hello','description':'Synthetic read','inputSchema':{'type':'object','properties':{},'additionalProperties':False}}]}
                    elif method=='tools/call':
                        case.upstream_calls+=1;result={'content':[{'type':'text','text':'synthetic-read-ok'}]}
                    else:result={}
                    raw=json.dumps({'jsonrpc':'2.0','id':data['id'],'result':result}).encode()
                    self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
                except BaseException:self.send_response(500);self.end_headers()
            def do_GET(self):self.send_response(405);self.end_headers()
            def do_DELETE(self):self.send_response(200);self.end_headers()
        self.upstream=ThreadingHTTPServer(('127.0.0.1',0),Upstream);self.thread=threading.Thread(target=self.upstream.serve_forever,daemon=True);self.thread.start()
        url='http://127.0.0.1:'+str(self.upstream.server_port)
        cfg={'registry_version':2,'servers':{s:{'url':url+path,'enabled':True,'token_ref':s,'tools':{'hello':{'enabled':True,'access_mode':'shared'}},**extra} for s,path,extra in [('demo','/a',{}),('second','/b',{'auth_header':'X-API-Key'})]},'principals':{'codex':{'token_env':'ROTATION_CLIENT_TOKEN','access_policy':'legacy_shared','tool_allowlist':{}}}}
        self.config=self.root/'fixture.json';op.write_private(self.config,json.dumps(cfg).encode())
        self.loc=self.root/'operator.url';op.write_private(self.loc,self.admin_url.encode())
        self.key=self.root/'old.key';op.write_private(self.key,self.old_key.encode())
        self.safe([self.fixture,'-mode','seed','-location-file',str(self.loc),'-key-file',str(self.key),'-fixture-file',str(self.config)],self.env)
        self.sql('GRANT USAGE ON SCHEMA mcp_gateway TO mcp_gateway_runtime; GRANT SELECT ON mcp_gateway.schema_version TO mcp_gateway_runtime; GRANT SELECT,INSERT,UPDATE,DELETE ON mcp_gateway.registry_state,mcp_gateway.upstream_secrets,mcp_gateway.client_key_secrets TO mcp_gateway_runtime')
        self.document=self.sql('SELECT document FROM mcp_gateway.registry_state')
        self.acls=self.sql("SELECT relname,relacl::text FROM pg_class WHERE relnamespace='mcp_gateway'::regnamespace ORDER BY relname")
        self.role_attrs=self.sql("SELECT row_to_json(r)::text FROM (SELECT rolname,rolsuper,rolcreatedb,rolcreaterole,rolinherit,rolcanlogin,rolreplication,rolconnlimit,rolvaliduntil,rolbypassrls,rolconfig FROM pg_roles WHERE rolname='mcp_gateway_runtime') r")
        self.env_file=self.root/'gateway.env'
        env={'GATEWAY_STORAGE':'postgres','GATEWAY_DATABASE_URL':self.runtime_url,'GATEWAY_SECRET_KEY':self.old_key,'GATEWAY_LISTEN_ADDR':'127.0.0.1:0',**{k:v for k,v in self.env.items() if k.startswith('ROTATION_')}}
        op.write_private(self.env_file,''.join(k+'='+v+'\n' for k,v in env.items()).encode())
        self.backup=self.root/'backup.dump'
        op.write_private(self.backup,self.safe(['docker','exec',self.container,'pg_dump','-U','postgres','-d',self.database,'-Fc','-n','mcp_gateway']))
        self.state=self.root/'state';self.state.mkdir(mode=0o700)
        self.recovery_dir=self.root/'recovery';self.recovery_dir.mkdir(mode=0o700);self.recovery_key=self.recovery_dir/'key'
        # Scan only rotation-period logs; synthetic setup intentionally used ordinary password DDL.
        log_baseline=subprocess.run(['docker','logs',self.container],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15)
        self.assertEqual(log_baseline.returncode,0,'log baseline failed')
        self.log_start=(len(log_baseline.stdout),len(log_baseline.stderr))
        self.started=[]
        # Capture all operator child output independently of its sanitizing wrapper.
        real_run=subprocess.run
        def observed_run(*args,**kwargs):
            r=real_run(*args,**kwargs)
            argv=args[0] if args else kwargs.get('args',[])
            if argv and argv[0]==self.binary:
                self.outputs.append((r.stdout or b'')+(r.stderr or b''))
            return r
        self.run_patch=mock.patch.object(subprocess,'run',side_effect=observed_run);self.run_patch.start()
    def tearDown(self):
        self.run_patch.stop()
        for p in getattr(self,'started',[]):
            p.terminate()
            try:p.communicate(timeout=10)
            except subprocess.TimeoutExpired:p.kill();p.communicate()
        self.upstream.shutdown();self.upstream.server_close();self.thread.join(timeout=5)
        self.sql('DROP DATABASE '+self.database+' WITH (FORCE)','postgres')
        self.temp.cleanup()
    def prepare(self):
        with unittest.mock.patch.dict(os.environ,self.env,clear=True):
            return op.prepare(self.binary,self.env_file,self.loc,self.backup,self.state,self.recovery_key,2)
    def verify(self):
        self.safe([self.fixture,'-mode','verify','-location-file',str(self.state/'runtime.url'),'-key-file',str(self.state/'new.key')],self.env)
        self.assertEqual(self.sql('SELECT document FROM mcp_gateway.registry_state'),self.document)
        self.assertEqual(self.sql("SELECT relname,relacl::text FROM pg_class WHERE relnamespace='mcp_gateway'::regnamespace ORDER BY relname"),self.acls)
        self.assertEqual(self.sql("SELECT row_to_json(r)::text FROM (SELECT rolname,rolsuper,rolcreatedb,rolcreaterole,rolinherit,rolcanlogin,rolreplication,rolconnlimit,rolvaliduntil,rolbypassrls,rolconfig FROM pg_roles WHERE rolname='mcp_gateway_runtime') r"),self.role_attrs)
        self.assertEqual(self.sql('SELECT revision FROM mcp_gateway.registry_state'),'3')
        self.assertEqual(op.env_values(op.private_read(self.env_file))['ROTATION_CLIENT_TOKEN'],self.env['ROTATION_CLIENT_TOKEN'])
    def check_leaks(self):
        r=subprocess.run(['docker','logs',self.container],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15)
        self.assertEqual(r.returncode,0,'log inspection failed')
        logs=r.stdout[self.log_start[0]:]+r.stderr[self.log_start[1]:]
        # Actual process stdout/stderr plus aggressive PostgreSQL statement/duration logs.
        combined=b''.join(self.outputs)+logs
        for value in [self.old_password.encode(),self.old_key.encode(),op.private_read(self.state/'new.password'),op.private_read(self.state/'new.key'),op.private_read(self.recovery_key),('mgw_'+'r'*43).encode(),('mgw_'+'h'*43).encode(),*map(str.encode,(self.env[k] for k in self.env if k.startswith('ROTATION_')))]:
            self.assertNotIn(value,combined,'secret leaked; value/output suppressed')
        self.assertNotIn(b'PASSWORD \'SCRAM-SHA-256$',logs,'SCRAM verifier leaked')
    def call_gateway(self):
        # Real gateway process, synthetic upstream credentials, and all three unchanged clients.
        with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
        env=self.env.copy();env.update(op.env_values(op.private_read(self.env_file)));env['GATEWAY_LISTEN_ADDR']='127.0.0.1:'+str(port)
        p=subprocess.Popen([self.server_binary],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE);self.started.append(p)
        import time
        deadline=time.monotonic()+8
        while time.monotonic()<deadline:
            try:
                with socket.create_connection(('127.0.0.1',port),timeout=0.1):break
            except OSError:time.sleep(0.05)
        for token in [self.env['ROTATION_CLIENT_TOKEN'],'mgw_'+'r'*43,'mgw_'+'h'*43]:
            for server in ['demo','second']:
                msg={'jsonrpc':'2.0','id':1,'method':'tools/call','params':{'name':'invoke_tool','arguments':{'server_id':server,'tool_name':'hello','arguments':{}}}}
                req=Request('http://127.0.0.1:'+str(port)+'/mcp',data=json.dumps(msg).encode(),headers={'Content-Type':'application/json','Accept':'application/json, text/event-stream','Authorization':'Bearer '+token,'MCP-Protocol-Version':'2025-11-25'})
                with urlopen(req,timeout=10) as response:payload=json.load(response)
                self.assertNotIn('error',payload,'MCP read failed')
                self.assertFalse(payload['result'].get('isError',False),'gateway read failed')
                self.assertIn('synthetic-read-ok',json.dumps(payload))
        p.terminate();out,err=p.communicate(timeout=10);self.outputs.append(out+err);self.started.remove(p)
    def test_complete_rotation_and_recovery_archive(self):
        self.call_gateway();self.assertEqual(self.upstream_calls,6)
        self.assertTrue(self.prepare()['recovery_verified'])
        with self.assertRaises(op.RotationFailure):op.apply(self.binary,self.state,False)
        import time
        started=time.monotonic()
        out=op.apply(self.binary,self.state,True);self.assertEqual(out['revision'],3)
        print('synthetic_rotation_apply_ms='+str(round((time.monotonic()-started)*1000,2)))
        self.verify();self.call_gateway();self.call_gateway();self.assertEqual(self.upstream_calls,18)
        # Restore the sealed pre-rotation snapshot to an isolated second DB, then rotate it forward.
        restored=self.root/'restored.tar'
        self.safe([self.binary,'seal-recovery','--open','--key-file',str(self.recovery_key),'--input-file',str(self.state/'recovery.sealed'),'--output-file',str(restored)],self.env)
        with tarfile.open(restored) as tar:
            dump=tar.extractfile('registry.dump').read();oldkey=tar.extractfile('old.key').read()
        restore_db=self.database+'_restore';self.sql('CREATE DATABASE '+restore_db,'postgres')
        try:
            r=subprocess.run(['docker','exec','-i',self.container,'pg_restore','-U','postgres','-d',restore_db],input=dump,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            self.outputs.append(r.stdout+r.stderr);self.assertEqual(r.returncode,0,'restore failed')
            restore_url=urlunsplit(urlsplit(self.admin_url)._replace(path='/'+restore_db))
            restored_loc=self.root/'restore.url';op.write_private(restored_loc,restore_url.encode())
            restored_key=self.root/'restore.key';op.write_private(restored_key,oldkey)
            self.safe([self.fixture,'-mode','verify','-location-file',str(restored_loc),'-key-file',str(restored_key)],self.env)
            self.safe([self.binary,'rotate-secret-key','--storage','postgres','--database-url-file',str(restored_loc),'--old-key-file',str(restored_key),'--new-key-file',str(self.state/'new.key'),'--expected-revision','2'],self.env)
            self.safe([self.fixture,'-mode','verify','-location-file',str(restored_loc),'-key-file',str(self.state/'new.key')],self.env)
        finally:self.sql('DROP DATABASE '+restore_db+' WITH (FORCE)','postgres')
        self.check_leaks()
    def test_crash_boundaries_resume_without_reapplying(self):
        self.prepare()
        # Abrupt process exit after actual SQL commit, before the journal update.
        import sys
        code="import sys,os;from pathlib import Path;sys.path.insert(0,sys.argv[1]);import rotate_gateway_secrets as o;o.apply(sys.argv[2],Path(sys.argv[3]),True,lambda stage:os._exit(73) if stage=='after_db' else None)"
        child=subprocess.run([sys.executable,'-c',code,str(Path(__file__).parent.resolve()),self.binary,str(self.state)],env=self.env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=45)
        self.outputs.append(child.stdout+child.stderr);self.assertEqual(child.returncode,73,'crash stage not reached')
        self.assertEqual(json.loads(op.private_read(self.state/'journal.json'))['phase'],'prepared')
        self.assertEqual(self.sql('SELECT revision FROM mcp_gateway.registry_state'),'3')
        def crash_env(stage):
            if stage=='after_env':raise op.RotationFailure('simulated_crash')
        with self.assertRaises(op.RotationFailure):op.apply(self.binary,self.state,True,crash_env)
        self.assertEqual(json.loads(op.private_read(self.state/'journal.json'))['phase'],'db_committed')
        self.assertEqual(op.apply(self.binary,self.state,True)['revision'],3)
        self.assertEqual(op.apply(self.binary,self.state,True)['revision'],3)
        self.verify();self.check_leaks()
    def test_precommit_and_rename_failure_recovery(self):
        from unittest.mock import patch
        self.prepare()
        def crash(stage):
            if stage=='before_db':raise op.RotationFailure('simulated_crash')
        with self.assertRaises(op.RotationFailure):op.apply(self.binary,self.state,True,crash)
        self.assertEqual(self.sql('SELECT revision FROM mcp_gateway.registry_state'),'2')
        before=op.private_read(self.env_file)
        original_replace=op.os.replace
        def fail_env(src,dst):
            if Path(dst)==self.env_file:raise OSError('synthetic-sensitive-failure')
            original_replace(src,dst)
        with patch.object(op.os,'replace',side_effect=fail_env):
            with self.assertRaises(OSError):op.apply(self.binary,self.state,True)
        self.assertEqual(op.private_read(self.env_file),before)
        self.assertEqual(self.sql('SELECT revision FROM mcp_gateway.registry_state'),'3')
        op.apply(self.binary,self.state,True);self.verify();self.check_leaks()
    def test_staged_secret_drift_stops_before_database_write(self):
        self.prepare()
        op.write_private(self.state/'new.key',base64.b64encode(b'z'*32),replace=True)
        with self.assertRaises(op.RotationFailure):op.apply(self.binary,self.state,True)
        self.assertEqual(self.sql('SELECT revision FROM mcp_gateway.registry_state'),'2')
    def test_runtime_connection_cannot_change_password(self):
        op.write_private(self.loc,self.runtime_url.encode(),replace=True)
        self.prepare()
        with self.assertRaises(op.RotationFailure):op.apply(self.binary,self.state,True)
        self.assertEqual(self.sql('SELECT revision FROM mcp_gateway.registry_state'),'2')
        self.assertEqual(op.env_values(op.private_read(self.env_file))['GATEWAY_DATABASE_URL'],self.runtime_url)


if __name__=='__main__':unittest.main()
