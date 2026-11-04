"""Exercise the real pinned command dispatcher without credentials or network."""
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SDK = ROOT / 'build/Gcloud.app/Contents/Resources/google-cloud-sdk'
RUNNER = '''
import runpy, sys, types
sys.modules['_automic_vault'] = types.SimpleNamespace(request=lambda *a: (_ for _ in ()).throw(RuntimeError('unexpected credential request')))
script = sys.argv.pop(1)
runpy.run_path(script, run_name='__main__')
'''

class CLITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        (self.root / 'google-cloud-sdk').symlink_to(SDK)
        for name in ('bootstrap.py', 'av_store.py'):
            shutil.copy(ROOT / 'isotope' / name, self.root / name)
        self.env = {'HOME': self.temp.name, 'PATH': '/usr/bin:/bin', 'CLOUDSDK_CONFIG': str(self.root / 'config')}

    def run_cli(self, *args, env=None):
        return subprocess.run([sys.executable, '-I', '-S', '-c', RUNNER, str(self.root / 'bootstrap.py'), *args],
                              env=dict(self.env, **(env or {})), capture_output=True, text=True, timeout=30)

    def test_version_and_account_listing_need_no_secret(self):
        for args in [('--version',), ('auth', 'list', '--format=json')]:
            result = self.run_cli(*args)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn('unexpected credential', result.stderr)

    def test_help_does_not_login(self):
        result = self.run_cli('auth', 'login', '--help')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_bypass_inputs_cannot_change_the_bound_invocation(self):
        for args, env in [
            (('auth', 'login', '--update-adc'), {}),
            (('auth', 'login', '--cred-file=/tmp/credentials.json'), {}),
            (('auth', 'application-default', 'login'), {}),
            (('--flags-file=/tmp/flags.yaml',), {}),
            (('components', 'install', 'anything'), {}),
            (('--version',), {'GOCLOUD_PAYLOAD': '{}'}),
            (('--version',), {'CLOUDSDK_AUTH_ACCESS_TOKEN': 'fake-token'}),
        ]:
            result = self.run_cli(*args, env=env)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('not supported' if args != ('--version',) else 'Unsupported', result.stderr)

    def test_python_environment_cannot_load_user_code(self):
        marker = self.root / 'executed'
        (self.root / 'sitecustomize.py').write_text('open(' + repr(str(marker)) + ', "w").write("bad")')
        result = self.run_cli('--version', env={'PYTHONPATH': str(self.root), 'PYTHONSTARTUP': str(self.root / 'sitecustomize.py')})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(marker.exists())

if __name__ == '__main__':
    unittest.main()
