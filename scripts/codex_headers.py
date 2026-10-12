#!/usr/bin/env python3
"""Codex HTTP headers helper; stdout is reserved for credential JSON."""
import fcntl
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import time
import urllib.request

ROOT = Path(__file__).resolve().parent.parent
RUNTIME = Path.home() / '.local/share/mcp-gateway'
PORT = 18080


def main():
    RUNTIME.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(RUNTIME, 0o700)
    with open(RUNTIME / 'startup.lock', 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        token_path = RUNTIME / 'codex.token'
        if not token_path.exists():
            fd = os.open(token_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'w') as stream:
                stream.write(secrets.token_urlsafe(32))
        os.chmod(token_path, 0o600)
        token = token_path.read_text().strip()
        if len(token) < 16 or any(c.isspace() for c in token):
            raise RuntimeError('invalid gateway credential')
        pid_path = RUNTIME / 'gateway.pid'
        running = False
        if pid_path.exists():
            try:
                pid = int(pid_path.read_text())
                if pid > 0:
                    os.kill(pid, 0)
                    running = True
            except (ValueError, ProcessLookupError):
                pass
        if not running:
            with socket.socket() as probe:
                if probe.connect_ex(('127.0.0.1', PORT)) == 0:
                    raise RuntimeError('gateway port occupied by another process')
            binary = RUNTIME / 'bin/mcp-gateway'
            if not binary.is_file():
                raise RuntimeError('gateway binary not installed')
            env = os.environ.copy()
            env['GATEWAY_CODEX_TOKEN'] = token
            env['GATEWAY_CONFIG'] = str(ROOT / 'config/codex-local.json')
            env['GATEWAY_LISTEN_ADDR'] = f'127.0.0.1:{PORT}'
            # No payload logs are captured or printed by the helper.
            process = subprocess.Popen([str(binary)], env=env, stdin=subprocess.DEVNULL,
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                       start_new_session=True)
            pid_path.write_text(str(process.pid))
            os.chmod(pid_path, 0o600)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        for _ in range(100):
            try:
                with opener.open(f'http://127.0.0.1:{PORT}/healthz', timeout=.2) as response:
                    if response.status == 200 and response.read() == b'ok\n':
                        print(json.dumps({'Authorization': 'Bearer ' + token}))
                        return
            except OSError:
                time.sleep(.05)
        raise RuntimeError('gateway did not become healthy')


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('Gateway credential/startup helper failed; check local installation and config.', file=sys.stderr)
        sys.exit(1)
