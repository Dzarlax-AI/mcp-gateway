#!/usr/bin/env python3
"""Remote Codex headers helper; stdout is reserved exclusively for credentials."""
import json
import os
from pathlib import Path
import stat
import sys


def main():
    path = Path(os.environ.get('GATEWAY_PUBLIC_TOKEN_FILE',
                               str(Path.home() / '.local/share/mcp-gateway/public.token')))
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'r') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
            raise ValueError('unsafe credential file')
        token = stream.read(4097)
    if not 43 <= len(token) <= 4096 or any(c.isspace() for c in token):
        raise ValueError('invalid credential')
    print(json.dumps({'Authorization': 'Bearer ' + token}))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('Public gateway credential helper failed; check private token file and permissions.', file=sys.stderr)
        sys.exit(1)
