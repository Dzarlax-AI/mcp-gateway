import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).with_name('prepare_github.py')
spec = importlib.util.spec_from_file_location('publication_export', SCRIPT)
publication = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publication)


class PublicationExportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / 'workspace'
        self.root.mkdir()
        self.output = self.base / 'export'
        for name in publication.FILES:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('synthetic publication fixture\n')
        shutil.copy2(SCRIPT, self.root / 'scripts/prepare_github.py')
        self.write('cmd/server/main.go', 'package main\n')
        self.write('internal/widget/view.js', '// synthetic runtime asset\n')
        self.write('AGENTS.md', '# Current instructions\nKeep current rotation rules.\n')
        self.write('docs/repository/AGENTS.public.md', '# Stale instructions\n')
        self.write('docs/repository/gitignore.public', 'stale-ignore\n')

    def write(self, name, data):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(data)

    def test_complete_export_preserves_current_instructions_and_excludes_private_files(self):
        for name in ('.env', 'config/local.json', '.git/config',
                     'docs/local/operator.md', 'docs/verification/private.json',
                     'docs/ai-plans/private.html', 'deploy/mcp-gateway/runtime.private.json',
                     'scripts/unreviewed.py', 'internal/widget/local.token'):
            self.write(name, 'synthetic private sentinel\n')
        count = publication.export(self.root, self.output)
        manifest = json.loads((self.output / 'PUBLICATION.json').read_text())
        expected = set(publication.FILES) | {'cmd/server/main.go', 'internal/widget/view.js'}
        self.assertEqual(set(manifest['files_sha256']), expected)
        self.assertEqual(count, len(expected))
        self.assertEqual((self.output / 'AGENTS.md').read_bytes(),
                         (self.root / 'AGENTS.md').read_bytes())
        self.assertEqual((self.output / '.gitignore').read_bytes(),
                         (self.root / '.gitignore').read_bytes())
        self.assertFalse((self.output / 'docs/repository').exists())
        for name, digest in manifest['files_sha256'].items():
            data = (self.output / name).read_bytes()
            self.assertEqual(data, (self.root / name).read_bytes())
            self.assertEqual(hashlib.sha256(data).hexdigest(), digest)
            self.assertNotIn(b'synthetic private sentinel', data)
        self.assertFalse(manifest['git_initialized'])
        self.assertFalse(manifest['published'])

    def test_export_can_reexport_itself_with_identical_bytes(self):
        publication.export(self.root, self.output)
        second = self.base / 'second'
        subprocess.run([sys.executable, str(self.output / 'scripts/prepare_github.py'),
                        '--output', str(second)], check=True, capture_output=True)
        first_files = {p.relative_to(self.output).as_posix(): p.read_bytes()
                       for p in self.output.rglob('*') if p.is_file()}
        second_files = {p.relative_to(second).as_posix(): p.read_bytes()
                        for p in second.rglob('*') if p.is_file()}
        self.assertEqual(first_files, second_files)

    def test_current_publication_inputs_can_export(self):
        publication.export(SCRIPT.parent.parent, self.output)
        manifest = json.loads((self.output / 'PUBLICATION.json').read_text())
        self.assertIn('scripts/test_prepare_github.py', manifest['files_sha256'])
        self.assertIn('internal/admin/permissions.js', manifest['files_sha256'])
        self.assertIn('scripts/test_permission_actions.cjs', manifest['files_sha256'])
        self.assertIn('docs/deployment/agent-acl.md', manifest['files_sha256'])
        self.assertIn('internal/readpolicy/contracts/calendar-mcp-v1.json',
                      manifest['files_sha256'])

    def test_missing_contract_fails_before_creating_output(self):
        (self.root / 'internal/readpolicy/contracts/calendar-mcp-v1.json').unlink()
        with self.assertRaises(publication.ExportError):
            publication.export(self.root, self.output)
        self.assertFalse(self.output.exists())

    def test_symlink_file_and_parent_are_refused(self):
        for name in ('README.md', 'docs/deployment'):
            with self.subTest(name=name):
                source = self.root / name
                saved = self.base / ('saved-' + source.name)
                source.rename(saved)
                source.symlink_to(saved, target_is_directory=saved.is_dir())
                with self.assertRaises(publication.ExportError):
                    publication.export(self.root, self.output)
                self.assertFalse(self.output.exists())
                source.unlink()
                saved.rename(source)

    def test_sensitive_content_and_invalid_encoding_are_refused(self):
        bad_inputs = [('/' + 'Users/' + 'fixture/Projects/private').encode(),
                      ('-----BEGIN ' + 'RSA PRIVATE KEY-----').encode(), b'\xff']
        for data in bad_inputs:
            with self.subTest(data_type=type(data).__name__):
                (self.root / 'README.md').write_bytes(data)
                with self.assertRaises(publication.ExportError):
                    publication.export(self.root, self.output)
                self.assertFalse(self.output.exists())

    def test_existing_output_and_in_tree_output_are_refused(self):
        self.output.mkdir()
        sentinel = self.output / 'keep'
        sentinel.write_text('preserve')
        with self.assertRaises(publication.ExportError):
            publication.export(self.root, self.output)
        self.assertEqual(sentinel.read_text(), 'preserve')
        with self.assertRaises(publication.ExportError):
            publication.export(self.root, self.root / 'generated')
        self.assertFalse((self.root / 'generated').exists())
        dangling = self.base / 'dangling'
        dangling.symlink_to(self.base / 'missing')
        with self.assertRaises(publication.ExportError):
            publication.export(self.root, dangling)


if __name__ == '__main__':
    unittest.main()
