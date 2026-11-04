import json
import os
import pathlib
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
SDK = ROOT / 'build/Gcloud.app/Contents/Resources/google-cloud-sdk'
sys.path[:0] = [str(ROOT / 'isotope'), str(SDK / 'lib'), str(SDK / 'lib/third_party')]
sys.modules['_automic_vault'] = types.SimpleNamespace(request=None)
import av_store
from googlecloudsdk.core import config, properties
from googlecloudsdk.core.credentials import creds, store as upstream
from googlecloudsdk.core.credentials.google_auth_credentials import Credentials


def credential(refresh='refresh-fixture'):
    return Credentials(token='access-fixture', refresh_token=refresh,
                       token_uri='https://oauth2.googleapis.com/token',
                       client_id=config.CLOUDSDK_CLIENT_ID,
                       client_secret=config.CLOUDSDK_CLIENT_NOTSOSECRET,
                       scopes=['https://www.googleapis.com/auth/cloud-platform'])


class CustodyTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.environment = patch.dict(os.environ, {'CLOUDSDK_CONFIG': self.directory.name}, clear=True)
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.values = {}
        self.calls = []
        self.rpc = patch.object(av_store._automic_vault, 'request', self.request)
        self.rpc.start()
        self.addCleanup(self.rpc.stop)
        self.store = av_store.Store()
        self.account = 'user@example.com'
        self.key = av_store.secret_name(self.account)

    def request(self, operation, key, value=None, expected=None):
        self.calls.append(operation)
        if operation == 'keys':
            return self.values.get(key)
        if self.values.get(key) != expected:
            raise RuntimeError('credential changed')
        if operation == 'gcloud-save':
            self.values[key] = value
        else:
            self.values.pop(key, None)

    def test_login_load_logout_use_custody_and_no_token_files(self):
        self.store.Store(self.account, credential())
        loaded = self.store.Load(self.account)
        self.assertEqual(loaded.refresh_token, 'refresh-fixture')
        self.assertIsNone(loaded.token)
        self.assertEqual(self.store.GetAccounts(), {self.account})
        self.store.Remove(self.account)
        self.assertIsNone(self.store.Load(self.account))
        for path in pathlib.Path(self.directory.name).rglob('*'):
            if path.is_file():
                self.assertNotIn('refresh-fixture', path.read_text())
                self.assertNotIn('access-fixture', path.read_text())
        self.assertFalse((pathlib.Path(self.directory.name) / 'credentials.db').exists())
        self.assertFalse((pathlib.Path(self.directory.name) / 'access_tokens.db').exists())

    def test_denial_does_not_become_missing_or_fallback(self):
        with patch.object(av_store._automic_vault, 'request', side_effect=RuntimeError('denied')):
            with self.assertRaisesRegex(RuntimeError, 'denied'):
                self.store.Load(self.account)
            with self.assertRaisesRegex(RuntimeError, 'denied'):
                self.store.Store(self.account, credential())
        self.assertFalse(self.store.index.exists())

    def test_refresh_persists_rotation_but_not_access_token(self):
        self.store.Store(self.account, credential())
        def refresh(instance, request):
            instance.token = 'new-access-fixture'
            instance._refresh_token = 'rotated-fixture'
        with patch.object(Credentials, 'refresh', refresh):
            loaded = self.store.Load(self.account)
            loaded.refresh(None)
        self.assertIn('rotated-fixture', self.values[self.key])
        self.assertNotIn('new-access-fixture', self.values[self.key])

    def test_refresh_and_logout_reject_newer_login(self):
        self.store.Store(self.account, credential())
        self.store.Load(self.account)
        self.values[self.key] = av_store.serialize(credential('newer-login'))
        with self.assertRaisesRegex(RuntimeError, 'changed'):
            self.store.Remove(self.account)
        self.assertIn('newer-login', self.values[self.key])

    def test_failed_rotation_aborts_operation(self):
        self.store.Store(self.account, credential())
        def refresh(instance, request):
            instance._refresh_token = 'rotated'
        with patch.object(Credentials, 'refresh', refresh):
            loaded = self.store.Load(self.account)
            self.values[self.key] = av_store.serialize(credential('newer-login'))
            with self.assertRaisesRegex(RuntimeError, 'changed'):
                loaded.refresh(None)

    def test_untrusted_serialized_credentials_rejected_before_deserialization(self):
        value = json.loads(av_store.serialize(credential()))
        for field, replacement in [('type', 'external_account'), ('token_uri', 'https://attacker.example/token'), ('client_id', 'different')]:
            changed = dict(value, **{field: replacement})
            self.values[self.key] = json.dumps(changed)
            with self.assertRaises(ValueError):
                self.store.Load(self.account)
        self.values[self.key] = '{malformed'
        with self.assertRaises(ValueError):
            self.store.Load(self.account)

    def test_endpoint_override_rejected_before_rpc(self):
        with patch.dict(os.environ, {'CLOUDSDK_API_ENDPOINT_OVERRIDES_STORAGE': 'https://attacker.example/'}):
            with self.assertRaisesRegex(ValueError, 'endpoint'):
                self.store.Load(self.account)
        self.assertEqual(self.calls, [])

    def test_namespace_is_bounded_and_collision_free(self):
        self.assertNotEqual(av_store.secret_name('a@b'), av_store.secret_name('A@b'))
        for name in ['', 'a\0b', 'x' * 241, '\n', '\ud800']:
            with self.assertRaises((ValueError, UnicodeError)):
                av_store.secret_name(name)

    def test_upstream_login_store_cannot_create_legacy_credentials(self):
        av_store.install()
        av_store.store = self.store
        upstream.Store(credential(), self.account)
        self.assertIn(self.key, self.values)
        self.assertFalse((pathlib.Path(self.directory.name) / 'legacy_credentials').exists())
        with self.assertRaises(ValueError):
            creds.ADC(credential()).DumpADCToFile(file_path=str(pathlib.Path(self.directory.name) / 'adc.json'))
        with self.assertRaises(ValueError):
            creds.SqliteCredentialStore('/tmp/never-created')
        with self.assertRaises(ValueError):
            creds.AccessTokenCache('/tmp/never-created')

if __name__ == '__main__':
    unittest.main()
