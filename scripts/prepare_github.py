#!/usr/bin/env python3
"""Export reviewed publication inputs without local deployment state or Git actions."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil

ROOT = Path(__file__).resolve().parent.parent
# Root instructions are authoritative. Historical docs/repository templates are
# not inputs: mapping them onto root files would discard newer instructions.
FILES = [
    'AGENTS.md', '.gitignore', 'README.md', 'Dockerfile', '.dockerignore',
    'go.mod', 'go.sum', 'CONTRIBUTING.md', 'SECURITY.md', 'CLAUDE.md',
    '.github/workflows/ci.yml',
    'config/example.json', 'config/bootstrap.json', 'config/codex-local.json',
    'config/read-batch.example.json', 'config/claude-mcp.json.example',
    'docs/self-hosting.md', 'docs/development.md', 'docs/security-model.md',
    'docs/claude.md', 'docs/deployment/connector-batch-reading.md',
    'docs/deployment/secret-rotation.md', 'docs/deployment/chatgpt-oauth.md',
    'examples/deployment/docker-compose.mcp-oauth.yml',
    'internal/readpolicy/contracts/README.md',
    'internal/readpolicy/contracts/calendar-mcp-v1.json',
    'internal/readpolicy/contracts/home-assistant-review.json',
    'internal/readpolicy/contracts/home-assistant-v1.json',
    'scripts/codex_headers.py', 'scripts/codex_public_headers.py',
    'scripts/test_codex_public_headers.py', 'scripts/test_connection_actions.cjs',
    'scripts/measure_read_batch.go', 'scripts/connector_batch_fixture.go',
    'scripts/rotation_fixture.go', 'scripts/rotate_gateway_secrets.py',
    'scripts/test_rotate_gateway_secrets.py',
    'scripts/test_connector_batch_admin.cjs',
    'scripts/verify_connector_batch_agent.py',
    'scripts/prepare_github.py', 'scripts/test_prepare_github.py',
]
PRIVATE = re.compile(
    r'/Users/[^/]+/(?:Projects|Documents)/|'
    r'-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----'
)


class ExportError(ValueError):
    pass


def export(root, output):
    root = Path(root).resolve()
    requested = Path(output).expanduser()
    if os.path.lexists(requested):
        raise ExportError('output already exists; choose a new directory')
    output = requested.resolve()
    if output == root or root in output.parents or output in root.parents:
        raise ExportError('output must be outside the working tree and its ancestors')
    files = list(FILES)
    files += [p.relative_to(root).as_posix() for directory in ('cmd', 'internal')
              for p in (root / directory).rglob('*')
              if (p.is_file() or p.is_symlink()) and p.suffix in ('.go', '.js')]
    if os.path.lexists(root / 'LICENSE'):
        files.append('LICENSE')
    contents = {}
    for name in sorted(set(files)):
        source = root / name
        # Refuse symlinked directories as well as symlinked leaf files.
        parts = [root.joinpath(*Path(name).parts[:i])
                 for i in range(1, len(Path(name).parts) + 1)]
        if any(p.is_symlink() for p in parts) or not source.is_file():
            raise ExportError('invalid publication input: ' + name)
        data = source.read_bytes()
        try:
            text = data.decode('utf-8')
        except UnicodeDecodeError:
            raise ExportError('non-UTF-8 publication input: ' + name) from None
        if PRIVATE.search(text):
            raise ExportError('private deployment detail found in: ' + name)
        contents[name] = data
    # Validate the entire input set before creating output. Unknown local files
    # and operational directories are never copied by a broad tree sync.
    output.mkdir(mode=0o755)
    for name, data in contents.items():
        target = output / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        shutil.copymode(root / name, target)
    manifest = {name: hashlib.sha256(data).hexdigest()
                for name, data in contents.items()}
    (output / 'PUBLICATION.json').write_text(json.dumps({
        'files_sha256': manifest,
        'license_included': 'LICENSE' in manifest,
        'git_initialized': False,
        'published': False,
    }, indent=2) + '\n')
    return len(manifest)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        count = export(ROOT, args.output)
    except (ExportError, OSError) as exc:
        parser.error(str(exc))
    print(f'Exported {count} files; no Git or publication actions performed')


if __name__ == '__main__':
    main()
