import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class PublicHeadersTest(unittest.TestCase):
    def test_private_credentials_and_rejections(self):
        with tempfile.TemporaryDirectory() as directory:
            token_file = Path(directory) / 'token'
            script = Path(__file__).with_name('codex_public_headers.py')
            token = 'synthetic-disposable-token-' + 'x' * 32
            for case in ('valid', 'missing', 'permissions', 'short', 'whitespace', 'oversized', 'symlink'):
                with self.subTest(case=case):
                    if token_file.exists() or token_file.is_symlink():
                        token_file.unlink()
                    data = {'short': 'short', 'whitespace': token + '\n', 'oversized': 'x' * 4097}.get(case, token)
                    if case == 'symlink':
                        target = Path(directory) / 'target'
                        target.write_text(token)
                        target.chmod(0o600)
                        token_file.symlink_to(target)
                    elif case != 'missing':
                        token_file.write_text(data)
                        token_file.chmod(0o644 if case == 'permissions' else 0o600)
                    env = dict(os.environ, GATEWAY_PUBLIC_TOKEN_FILE=str(token_file))
                    result = subprocess.run([sys.executable, str(script)], env=env, capture_output=True, text=True)
                    if case == 'valid':
                        self.assertEqual(result.returncode, 0)
                        self.assertEqual(json.loads(result.stdout), {'Authorization': 'Bearer ' + token})
                        self.assertEqual(result.stderr, '')
                    else:
                        self.assertNotEqual(result.returncode, 0)
                        self.assertEqual(result.stdout, '')
                        self.assertNotIn(data, result.stderr)
                        self.assertNotIn(str(token_file), result.stderr)


if __name__ == '__main__':
    unittest.main()
