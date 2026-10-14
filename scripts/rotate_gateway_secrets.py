#!/usr/bin/env python3
"""Offline operator rotation. No Docker/SSH actions; service quiescence is explicit."""
import argparse
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import secrets
import stat
import subprocess
import tarfile
import tempfile
from urllib.parse import urlsplit, urlunsplit, quote


class RotationFailure(Exception):
    pass


def private_read(path, limit=256 * 1024 * 1024):
    path = Path(path)
    parent = path.parent.lstat()
    if not path.is_absolute() or not stat.S_ISDIR(parent.st_mode) or parent.st_mode & 0o077:
        raise RotationFailure('private_input_invalid')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as f:
        st = os.fstat(f.fileno())
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o077 or st.st_size > limit:
            raise RotationFailure('private_input_invalid')
        return f.read(limit + 1)


def write_private(path, data, replace=False):
    path = Path(path)
    parent = path.parent.lstat()
    if not path.is_absolute() or not stat.S_ISDIR(parent.st_mode) or parent.st_mode & 0o077:
        raise RotationFailure('private_output_invalid')
    if replace:
        private_read(path)
    elif path.exists() or path.is_symlink():
        raise RotationFailure('private_output_exists')
    fd, tmp = tempfile.mkstemp(prefix='.rotation-', dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'wb') as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        if replace:
            os.replace(tmp, path)
        else:
            # Atomic publication without overwriting an existing path.
            os.link(tmp, path)
            os.unlink(tmp)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def env_values(data):
    """Strict supported dotenv subset; preserve original bytes when patching two lines."""
    values = {}
    for line in data.decode('utf-8').splitlines():
        s = line.strip()
        if not s or s.startswith('#'):
            continue
        if '=' not in s:
            raise RotationFailure('env_format_unsupported')
        k, v = s.split('=', 1)
        if not k.isidentifier() or k in values:
            raise RotationFailure('env_format_unsupported')
        if v.startswith(('"', "'")):
            if len(v) < 2 or v[-1] != v[0]:
                raise RotationFailure('env_format_unsupported')
            v = v[1:-1]
        if any(c in v for c in ('$','\\','\r','\n')):
            raise RotationFailure('env_format_unsupported')
        values[k] = v
    return values


def patch_env(data, changes):
    env_values(data)
    lines = data.decode().splitlines(keepends=True)
    found = set()
    for i, line in enumerate(lines):
        if '=' not in line or line.lstrip().startswith('#'):
            continue
        k = line.split('=', 1)[0].strip()
        if k in changes:
            ending = '\r\n' if line.endswith('\r\n') else '\n' if line.endswith('\n') else ''
            lines[i] = k + '=' + changes[k] + ending
            found.add(k)
    if found != set(changes):
        raise RotationFailure('env_missing_rotation_fields')
    return ''.join(lines).encode()


def run_cli(binary, args, env):
    # Never raise CalledProcessError, echo stderr, or print env/command structures.
    try:
        r = subprocess.run([binary] + args, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           timeout=45, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise RotationFailure('operator_command_unknown') from None
    if r.returncode:
        raise RotationFailure('operator_command_failed')
    return r.stdout


def digest(data):
    return hashlib.sha256(data).hexdigest()


def save_journal(state, journal):
    p = state / 'journal.json'
    write_private(p, json.dumps(journal, sort_keys=True).encode(), replace=p.exists())


def load_state(state):
    j = json.loads(private_read(state / 'journal.json'))
    old_env = private_read(state / 'original.env')
    env = os.environ.copy()
    env.update(env_values(old_env))
    return j, env


def rotation_args(state, revision, old='old.key', verify=False, runtime=False):
    args = ['rotate-secret-key', '--storage', 'postgres', '--expected-revision', str(revision),
            '--old-key-file', str(state / old), '--new-key-file', str(state / ('probe.key' if old == 'new.key' else 'new.key')),
            '--database-url-file', str(state / ('runtime.url' if runtime else 'operator.url'))]
    if verify:
        args += ['--verify-only']
    else:
        args += ['--role', 'mcp_gateway_runtime', '--new-password-file', str(state / 'new.password')]
    return args


def validate_report(raw, expected, committed):
    r = json.loads(raw)
    if r.get('revision') != expected or r.get('committed') is not committed:
        raise RotationFailure('operator_report_invalid')
    return r


def prepare(binary, env_file, operator_url, backup_file, state, recovery_key, revision):
    if revision < 1:
        raise RotationFailure('revision_invalid')
    data = private_read(env_file)
    values = env_values(data)
    u = urlsplit(values['GATEWAY_DATABASE_URL'])
    if u.scheme not in ('postgres', 'postgresql') or u.username != 'mcp_gateway_runtime' or not u.password:
        raise RotationFailure('runtime_dsn_invalid')
    old = base64.b64decode(values['GATEWAY_SECRET_KEY'], validate=True)
    if len(old) != 32:
        raise RotationFailure('key_invalid')
    operator_data = private_read(operator_url,8192)
    operator = urlsplit(operator_data.decode())
    if operator.scheme not in ('postgres','postgresql') or (operator.hostname,operator.port,operator.path)!=(u.hostname,u.port,u.path):
        raise RotationFailure('operator_database_mismatch')
    # Caller supplies an existing mode0700 state directory; prepare is deliberately non-repeatable.
    if any(state.iterdir()):
        raise RotationFailure('state_not_empty')
    key = base64.b64encode(secrets.token_bytes(32))
    password = secrets.token_hex(32).encode()
    netloc = u.username + ':' + quote(password.decode(), safe='') + '@' + u.netloc.rsplit('@',1)[1]
    runtime_url = urlunsplit(u._replace(netloc=netloc))
    staged = patch_env(data, {'GATEWAY_SECRET_KEY':key.decode(), 'GATEWAY_DATABASE_URL':runtime_url})
    for name, content in {'original.env':data, 'staged.env':staged, 'old.key':base64.b64encode(old),
                          'new.key':key, 'probe.key':base64.b64encode(secrets.token_bytes(32)),
                          'new.password':password, 'operator.url':operator_data,
                          'runtime.url':runtime_url.encode()}.items():
        write_private(state / name, content)
    env = os.environ.copy();env.update(values)
    baseline = validate_report(run_cli(binary, rotation_args(state,revision,verify=True),env),revision,False)
    # Seal the full backup, old key and env under an independent key. No secrets in tar filenames.
    bundle = io.BytesIO()
    with tarfile.open(fileobj=bundle, mode='w') as tar:
        for name, content in [('registry.dump',private_read(backup_file)),('original.env',data),('old.key',base64.b64encode(old))]:
            ti=tarfile.TarInfo(name);ti.size=len(content);ti.mode=0o600;tar.addfile(ti,io.BytesIO(content))
    write_private(recovery_key,base64.b64encode(secrets.token_bytes(32)))
    write_private(state/'recovery.tar',bundle.getvalue())
    run_cli(binary,['seal-recovery','--key-file',str(recovery_key),'--input-file',str(state/'recovery.tar'),
                    '--output-file',str(state/'recovery.sealed')],env)
    run_cli(binary,['seal-recovery','--open','--key-file',str(recovery_key),'--input-file',str(state/'recovery.sealed'),
                    '--output-file',str(state/'recovery.verified.tar')],env)
    if private_read(state/'recovery.verified.tar')!=bundle.getvalue():
        raise RotationFailure('recovery_verify_failed')
    # Remove only generated scratch plaintext after verified envelope round-trip.
    (state/'recovery.tar').unlink();(state/'recovery.verified.tar').unlink()
    journal={'version':1,'phase':'prepared','revision':revision,'env_file':str(env_file),
             'original_hash':digest(data),'staged_hash':digest(staged),'baseline':baseline}
    save_journal(state,journal)
    return {'phase':'prepared','upstreams':baseline['upstreams'],'clients':baseline['clients'],'recovery_verified':True}


def apply(binary,state,quiesced,fault=None):
    if not quiesced:
        raise RotationFailure('service_quiescence_required')
    j,env=load_state(state)
    if j['version']!=1 or j['phase'] not in ('prepared','db_committed','env_installed'):
        raise RotationFailure('journal_invalid')
    target=Path(j['env_file']);current=private_read(target)
    staged=private_read(state/'staged.env')
    if digest(staged)!=j['staged_hash'] or digest(current) not in (j['original_hash'],j['staged_hash']):
        raise RotationFailure('env_drift')
    staged_values=env_values(staged)
    if staged_values['GATEWAY_SECRET_KEY'].encode()!=private_read(state/'new.key') or staged_values['GATEWAY_DATABASE_URL'].encode()!=private_read(state/'runtime.url') or urlsplit(staged_values['GATEWAY_DATABASE_URL']).password.encode()!=private_read(state/'new.password'):
        raise RotationFailure('staged_secret_drift')
    hit=lambda stage: fault(stage) if fault else None
    if j['phase']=='prepared':
        # Inspect both generations first. Never replay a commit that may already have happened.
        try:
            observed=validate_report(run_cli(binary,rotation_args(state,j['revision']+1,old='new.key',verify=True),env),j['revision']+1,False)
            committed=True
        except RotationFailure:
            committed=False
        if not committed:
            validate_report(run_cli(binary,rotation_args(state,j['revision'],verify=True),env),j['revision'],False)
            hit('before_db')
            validate_report(run_cli(binary,rotation_args(state,j['revision']),env),j['revision']+1,True)
            hit('after_db')
        j['phase']='db_committed';save_journal(state,j)
    # Verify the new physical runtime login and new key before installing any env file.
    observed=validate_report(run_cli(binary,rotation_args(state,j['revision']+1,old='new.key',verify=True,runtime=True),env),j['revision']+1,False)
    if (observed['upstreams'],observed['clients'])!=(j['baseline']['upstreams'],j['baseline']['clients']):
        raise RotationFailure('row_count_drift')
    hit('before_env')
    if digest(current)==j['original_hash']:
        write_private(target,staged,replace=True)
    hit('after_env')
    j['phase']='env_installed';save_journal(state,j)
    return {'phase':'env_installed','revision':j['revision']+1,'runtime_login_verified':True,
            'upstreams':observed['upstreams'],'clients':observed['clients']}


def main(argv=None):
    class SafeParser(argparse.ArgumentParser):
        def error(self, message):
            raise RotationFailure('arguments_invalid')
    parser=SafeParser(description=__doc__)
    parser.add_argument('mode',choices=['prepare','apply'])
    parser.add_argument('--registry',required=True)
    parser.add_argument('--state-dir',required=True)
    parser.add_argument('--env-file');parser.add_argument('--operator-url-file')
    parser.add_argument('--backup-file');parser.add_argument('--recovery-key-file')
    parser.add_argument('--expected-revision',type=int);parser.add_argument('--service-quiesced',action='store_true')
    os.umask(0o077)
    try:
        a=parser.parse_args(argv)
        state=Path(a.state_dir)
        if a.mode=='prepare':
            out=prepare(a.registry,Path(a.env_file),Path(a.operator_url_file),Path(a.backup_file),state,
                        Path(a.recovery_key_file),a.expected_revision)
        else:
            out=apply(a.registry,state,a.service_quiesced)
        print(json.dumps(out,sort_keys=True));return 0
    except BaseException:
        # Suppress argv, secret env, child output and Python tracebacks even for unexpected failures.
        print('rotation_operator_failed; inspect private journal before recovery',file=__import__('sys').stderr)
        return 1


if __name__=='__main__':
    raise SystemExit(main())
