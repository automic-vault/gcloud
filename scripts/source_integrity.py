"""Verify pinned source archives against publisher-owned metadata."""
import base64
import hashlib
import json
import os
import urllib.parse
import urllib.request


def _json(url):
    headers = {'Accept': 'application/vnd.github+json', 'User-Agent': 'automic-vault-gcloud-builder'}
    if token := os.environ.get('GITHUB_TOKEN'):
        headers['Authorization'] = 'Bearer ' + token
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=60) as response:
        return json.load(response)


def verify_publisher_metadata(name, entry):
    if metadata := entry.get('gcs'):
        url = 'https://storage.googleapis.com/storage/v1/b/{}/o/{}'.format(
            urllib.parse.quote(metadata['bucket'], safe=''),
            urllib.parse.quote(metadata['object'], safe=''))
        published = _json(url)
        expected = {
            'generation': metadata['generation'],
            'size': metadata['size'],
            'md5Hash': metadata['md5'],
            'crc32c': metadata['crc32c'],
        }
        if any(published.get(key) != value for key, value in expected.items()):
            raise ValueError(name + ' Google Cloud Storage metadata mismatch')
        if entry['url'] != published.get('mediaLink'):
            raise ValueError(name + ' URL is not the verified Google Cloud Storage object generation')
    elif metadata := entry.get('github'):
        release = _json('https://api.github.com/repos/{}/releases/tags/{}'.format(
            metadata['repository'], urllib.parse.quote(metadata['tag'], safe='')))
        asset = next((asset for asset in release['assets'] if asset['name'] == metadata['asset']), None)
        if (asset is None or asset.get('digest') != 'sha256:' + entry['sha256']
                or asset.get('browser_download_url') != entry['url']):
            raise ValueError(name + ' GitHub release digest mismatch')
    else:
        raise ValueError(name + ' has no publisher metadata')


def verify_download(name, entry, path):
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != entry['sha256']:
        raise ValueError(name + ' archive SHA-256 mismatch')
    if metadata := entry.get('gcs'):
        digest = base64.b64encode(hashlib.md5(data).digest()).decode()
        if digest != metadata['md5']:
            raise ValueError(name + ' archive Google Cloud Storage MD5 mismatch')
