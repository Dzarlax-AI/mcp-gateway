#!/usr/bin/env python3
"""Export an explicit publication allowlist; never copy local deployment state."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil

ROOT = Path(__file__).resolve().parent.parent
FILES = [
    'README.md', 'Dockerfile', '.dockerignore', 'go.mod', 'go.sum',
    'CONTRIBUTING.md', 'SECURITY.md', 'CLAUDE.md', '.github/workflows/ci.yml',
    'config/example.json', 'config/bootstrap.json', 'config/codex-local.json',
    'config/read-batch.example.json', 'scripts/measure_read_batch.go',
    'docs/self-hosting.md', 'docs/development.md', 'docs/security-model.md',
    'docs/claude.md', 'config/claude-mcp.json.example',
    'docs/repository/AGENTS.public.md', 'docs/repository/gitignore.public',
    'scripts/codex_headers.py', 'scripts/codex_public_headers.py',
    'scripts/test_codex_public_headers.py', 'scripts/test_connection_actions.cjs',
    'scripts/prepare_github.py',
]
MAPPINGS = {'docs/repository/AGENTS.public.md': 'AGENTS.md',
            'docs/repository/gitignore.public': '.gitignore'}
PRIVATE = re.compile(r'/Users/[^/]+/(?:Projects|Documents)/|BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.expanduser().resolve()
    if output == ROOT or ROOT in output.parents or output in ROOT.parents:
        parser.error('output must be outside the working tree and its ancestors')
    if output.exists():
        parser.error('output already exists; choose a new directory to avoid overwriting work')
    files = list(FILES)
    files += [p.relative_to(ROOT).as_posix() for directory in ('cmd', 'internal')
              for p in (ROOT / directory).rglob('*')
              if p.is_file() and p.suffix in ('.go', '.js')]
    if (ROOT / 'LICENSE').is_file():
        files.append('LICENSE')
    contents = {}
    for name in sorted(set(files)):
        source = ROOT / name
        if source.is_symlink() or not source.is_file():
            parser.error('invalid publication input: ' + name)
        data = source.read_bytes()
        if PRIVATE.search(data.decode('utf-8')):
            parser.error('private deployment detail found in: ' + name)
        contents[name] = data
    # Validate before creating anything. Include public instruction sources so the
    # exported repository can run the same exporter again without local context.
    output.mkdir(mode=0o755)
    for name, data in contents.items():
        target = output / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        shutil.copymode(ROOT / name, target)
        if name in MAPPINGS:
            (output / MAPPINGS[name]).write_bytes(data)
    manifest = {p.relative_to(output).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in sorted(output.rglob('*')) if p.is_file()}
    (output / 'PUBLICATION.json').write_text(json.dumps({
        'files_sha256': manifest,
        'license_included': 'LICENSE' in manifest,
        'git_initialized': False,
        'published': False,
    }, indent=2) + '\n')
    print(f'Exported {len(manifest)} files to {output}; license included: {"LICENSE" in manifest}')


if __name__ == '__main__':
    main()
