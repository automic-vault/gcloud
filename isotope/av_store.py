"""User OAuth custody for the signed gcloud Isotope; no plaintext fallback."""
import json
import os
import pathlib
import tempfile

from googlecloudsdk.core import config, properties
from googlecloudsdk.core.credentials import creds
from googlecloudsdk.core.credentials import google_auth_credentials
import _automic_vault

PREFIX = 'GCLOUD_AUTH_'
TOKEN_URIS = {'https://oauth2.googleapis.com/token', 'https://accounts.google.com/o/oauth2/token'}


def secret_name(account):
    if not isinstance(account, str) or not account or len(account.encode('utf-8')) > 240 or any(ord(c) < 32 or ord(c) == 127 for c in account):
        raise ValueError('Invalid gcloud account')
    return PREFIX + account.encode('utf-8').hex().upper()


def validate_configuration():
    """Resolve properties after upstream parsing, before any protected load."""
    values = properties.VALUES
    for name in values.auth.AllProperties(include_hidden=True):
        if values.auth.Property(name).IsExplicitlySet():
            raise ValueError('Unsupported gcloud Isotope auth override: ' + name)
    if values.core.universe_domain.Get() != 'googleapis.com':
        raise ValueError('gcloud Isotope supports the default Google universe only')
    for section, names in (
        ('auth', ('credential_file_override', 'access_token_file', 'impersonate_service_account', 'login_config_file')),
        ('core', ('custom_ca_certs_file',)),
        ('proxy', ('type', 'address', 'port', 'username', 'password')),
    ):
        for name in names:
            prop = getattr(getattr(values, section), name, None)
            if prop is not None and prop.Get():
                raise ValueError('Unsupported gcloud Isotope configuration: ' + section + '/' + name)
    if values.auth.token_host.Get() not in TOKEN_URIS:
        raise ValueError('Unsupported OAuth token endpoint')
    for name in values.api_endpoint_overrides.AllProperties(include_hidden=True):
        if values.api_endpoint_overrides.Property(name).Get():
            raise ValueError('gcloud Isotope does not support API endpoint overrides')
    if values.core.log_http.GetBool():
        raise ValueError('gcloud Isotope does not support HTTP credential logging')


def request(operation, account, value=None, expected=None):
    context = json.dumps({
        'account': account,
        'project': properties.VALUES.core.project.Get(),
        'billing_project': properties.VALUES.billing.quota_project.Get(),
        'universe': properties.VALUES.core.universe_domain.Get(),
    }, sort_keys=True)
    return _automic_vault.request(operation, secret_name(account), value, expected, context)


def prepare_command(**kwargs):
    from googlecloudsdk.core.configurations import named_configs
    snapshot = named_configs.ActivePropertiesFile.Load()
    named_configs.ActivePropertiesFile.Load = staticmethod(lambda: snapshot)
    validate_configuration()


def validate_payload(value):
    data = json.loads(value)
    allowed = {'type', 'client_id', 'client_secret', 'refresh_token', 'revoke_uri', 'scopes', 'token_uri', 'rapt_token', 'universe_domain'}
    if not isinstance(data, dict) or set(data) - allowed or data.get('type') != 'authorized_user':
        raise ValueError('Only user OAuth credentials are supported')
    if data.get('universe_domain') != 'googleapis.com':
        raise ValueError('Unsupported OAuth universe')
    if data.get('token_uri') not in TOKEN_URIS or data.get('revoke_uri') != 'https://oauth2.googleapis.com/revoke':
        raise ValueError('Unsupported OAuth endpoint')
    for field in ('client_id', 'client_secret', 'refresh_token'):
        if not isinstance(data.get(field), str) or not data[field] or '\0' in data[field]:
            raise ValueError('Invalid OAuth credential')
    if data['client_id'] != config.CLOUDSDK_CLIENT_ID or data['client_secret'] != config.CLOUDSDK_CLIENT_NOTSOSECRET:
        raise ValueError('Only the upstream gcloud user OAuth client is supported')
    scopes = data.get('scopes')
    if scopes is not None and (not isinstance(scopes, list) or any(not isinstance(s, str) for s in scopes)):
        raise ValueError('Invalid OAuth scopes')
    if data.get('rapt_token') is not None and not isinstance(data['rapt_token'], str):
        raise ValueError('Invalid reauthentication token')
    return data


def serialize(credential):
    if not isinstance(credential, google_auth_credentials.Credentials):
        raise ValueError('Only user OAuth credentials are supported')
    data = json.loads(creds.ToJsonGoogleAuth(credential))
    data['rapt_token'] = getattr(credential, 'rapt_token', None)
    value = json.dumps(data, sort_keys=True, separators=(',', ':'))
    validate_payload(value)
    return value


class Store:
    def __init__(self):
        self.original = {}

    @property
    def index(self):
        return pathlib.Path(config.Paths().global_config_dir) / 'av_accounts.json'

    def GetAccounts(self):
        try:
            with self.index.open() as stream:
                value = stream.read(65537)
        except FileNotFoundError:
            return set()
        if len(value) > 65536:
            raise ValueError('Invalid gcloud account index')
        accounts = json.loads(value)
        if not isinstance(accounts, list) or len(accounts) > 128:
            raise ValueError('Invalid gcloud account index')
        for account in accounts:
            secret_name(account)
        return set(accounts)

    def GetAccountsWithUniverseDomain(self):
        return {account: ['googleapis.com'] for account in self.GetAccounts()}

    def _index(self, account, present):
        accounts = self.GetAccounts()
        accounts.add(account) if present else accounts.discard(account)
        self.index.parent.mkdir(parents=True, exist_ok=True)
        fd, name = tempfile.mkstemp(prefix='.av-accounts-', dir=self.index.parent)
        try:
            with os.fdopen(fd, 'w') as stream:
                json.dump(sorted(accounts), stream)
            os.replace(name, self.index)
        finally:
            if os.path.exists(name):
                os.unlink(name)

    def Load(self, account):
        validate_configuration()
        value = request('keys', account)
        self.original[account] = value
        if value is None:
            return None
        data = validate_payload(value)
        credential = creds.FromJsonGoogleAuth(value)
        credential._rapt_token = data.get('rapt_token')
        original_refresh = credential.refresh
        expected = value

        def refresh(http_request):
            nonlocal expected
            validate_configuration()
            original_refresh(http_request)
            updated = serialize(credential)
            if updated != expected:
                try:
                    request('gcloud-save', account, updated, expected)
                except Exception:
                    credential.token = None
                    credential.expiry = None
                    raise
                if self.original.get(account) == expected:
                    self.original[account] = updated
                expected = updated

        credential.refresh = refresh
        return credential

    def Store(self, account, credential):
        validate_configuration()
        value = serialize(credential)
        if account not in self.original:
            self.original[account] = request('keys', account)
        request('gcloud-save', account, value, self.original[account])
        self.original[account] = value
        self._index(account, True)

    def Remove(self, account):
        validate_configuration()
        if account not in self.original:
            self.original[account] = request('keys', account)
        request('gcloud-delete', account, None, self.original[account])
        self.original[account] = None
        self._index(account, False)


store = Store()


def get_store(store_file=None, access_token_file=None, cache_only_rapt=False):
    if store_file is not None or access_token_file is not None:
        raise ValueError('Custom credential stores are unsupported')
    return store


def forbidden(*args, **kwargs):
    raise ValueError('This authentication or credential-export path is not supported by the gcloud Isotope')


def revoke(account=None):
    from googlecloudsdk.core.credentials import store as upstream
    account = account or properties.VALUES.core.account.Get()
    if not account:
        raise ValueError('Select a gcloud account to revoke')
    credential = upstream.Load(account, prevent_refresh=True)
    revoked = False
    try:
        upstream.RevokeCredentials(credential)
        revoked = True
    except google_auth_credentials.TokenRevokeError as error:
        if not error.args or error.args[0] not in ('invalid_token', 'invalid_request'):
            raise
    store.Remove(account)
    # Upstream Revoke also deletes legacy_credentials/<account>. Those files
    # belong to other installations and are outside this custody transaction.
    return revoked


def install():
    """Installed before upstream dispatch; replacing stores never enables fallback."""
    from googlecloudsdk.core.credentials import store as upstream
    from googlecloudsdk import gcloud_main
    # This pre-run hook runs after global flags, before the command or any ECP
    # helper. Freeze the config in memory and do not launch external proxies.
    gcloud_main.StartECPProxyManager = prepare_command
    creds.GetCredentialStore = get_store
    creds.MaybeAttachAccessTokenCacheStoreGoogleAuth = lambda credential, **kwargs: credential
    creds.SqliteCredentialStore = forbidden
    creds.AccessTokenCache = forbidden
    creds.ADC.DumpADCToFile = forbidden
    upstream.Revoke = revoke
    upstream._LegacyGenerator.WriteTemplate = lambda self: None
    upstream._LegacyGenerator.Clean = lambda self: None
    upstream._LoadFromFileOverride = forbidden
    upstream._LoadAccessTokenCredsFromValue = forbidden
    upstream._LoadAccessTokenCredsFromFile = forbidden
    # Check effective properties before any store/provider can select credentials.
    load = upstream.Load
    def checked_load(*args, **kwargs):
        validate_configuration()
        return load(*args, **kwargs)
    upstream.Load = checked_load
    upstream.STATIC_CREDENTIAL_PROVIDERS.GetCredentials = lambda account: None
