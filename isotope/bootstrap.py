"""Only entry point into the sealed SDK; Python flags are never interpreted."""
import os
import pathlib
import sys

resources = pathlib.Path(__file__).parent
sdk = resources / 'google-cloud-sdk'
sys.path[:0] = [str(resources), str(sdk / 'lib'), str(sdk / 'lib/third_party')]

# Fail before login or command dispatch can create alternate credential files.
for arg in sys.argv[1:]:
    if arg.split('=', 1)[0] in {
        '--flags-file', '--cred-file', '--login-config', '--update-adc', '--remote-bootstrap',
        '--access-token-file', '--impersonate-service-account', '--log-http',
    } or arg in {'application-default', 'activate-service-account', 'components', 'interactive', 'init', 'alpha', 'beta', 'preview'}:
        raise SystemExit('This command or option is not supported by the gcloud Isotope: ' + arg.split('=', 1)[0])

for name in list(os.environ):
    if name.startswith(('PYTHON', 'CLOUDSDK_PYTHON', 'DYLD_')):
        del os.environ[name]
    elif name.startswith('CLOUDSDK_') and name not in {
        'CLOUDSDK_CONFIG', 'CLOUDSDK_ACTIVE_CONFIG_NAME', 'CLOUDSDK_CORE_PROJECT',
        'CLOUDSDK_CORE_ACCOUNT', 'CLOUDSDK_CORE_DISABLE_PROMPTS',
    }:
        raise SystemExit('Unsupported gcloud Isotope environment setting: ' + name)
    elif name.startswith('GOCLOUD_'):
        raise SystemExit('Unsupported gcloud Isotope parser setting: ' + name)
    elif name in {'GOOGLE_APPLICATION_CREDENTIALS', 'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY',
                  'http_proxy', 'https_proxy', 'all_proxy', 'REQUESTS_CA_BUNDLE', 'CURL_CA_BUNDLE', 'SSL_CERT_FILE', 'SSL_CERT_DIR'}:
        raise SystemExit('Unsupported gcloud Isotope environment setting: ' + name)

os.environ['CLOUDSDK_COMPONENT_MANAGER_DISABLE_UPDATE_CHECK'] = '1'
os.environ['CLOUDSDK_CORE_DISABLE_USAGE_REPORTING'] = 'true'
os.environ['CLOUDSDK_CORE_DISABLE_FILE_LOGGING'] = 'true'
import av_store
av_store.install()
import gcloud
gcloud.main()
