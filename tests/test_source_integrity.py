import json
import pathlib
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import source_integrity


class Response:
    def __init__(self, value):
        self.value = value

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def read(self, *_):
        return json.dumps(self.value).encode()


class SourceIntegrityTests(unittest.TestCase):
    def test_gcs_metadata_and_both_download_digests_are_required(self):
        data = b'official archive'
        entry = {
            'url': 'https://example.invalid/archive?generation=123&alt=media',
            'sha256': '764884ced8d4b07eac08febddb267116e3422a66ce76eb6dddb016e36d7cd286',
            'gcs': {'bucket': 'bucket', 'object': 'archive', 'generation': '123',
                    'size': '16', 'md5': 'zc6fJC7gihDmcyfxVKakeQ==', 'crc32c': 'crc'},
        }
        with patch.object(source_integrity.urllib.request, 'urlopen', return_value=Response({
            'generation': '123', 'size': '16', 'md5Hash': entry['gcs']['md5'], 'crc32c': 'crc',
            'mediaLink': entry['url']})):
            source_integrity.verify_publisher_metadata('gcloud', entry)
            entry['gcs']['generation'] = 'changed'
            with self.assertRaisesRegex(ValueError, 'metadata mismatch'):
                source_integrity.verify_publisher_metadata('gcloud', entry)
        with tempfile.NamedTemporaryFile() as archive:
            archive.write(data)
            archive.flush()
            entry['gcs']['generation'] = '123'
            source_integrity.verify_download('gcloud', entry, pathlib.Path(archive.name))

    def test_github_digest_must_match_the_pinned_sha(self):
        entry = {'url': 'https://example.invalid/python', 'sha256': 'abc',
                 'github': {'repository': 'owner/repo', 'tag': 'tag', 'asset': 'python.tgz'}}
        with patch.object(source_integrity.urllib.request, 'urlopen', return_value=Response({
            'assets': [{'name': 'python.tgz', 'digest': 'sha256:abc',
                        'browser_download_url': entry['url']}]})):
            source_integrity.verify_publisher_metadata('python', entry)
        with patch.object(source_integrity.urllib.request, 'urlopen', return_value=Response({
            'assets': [{'name': 'python.tgz', 'digest': 'sha256:different',
                        'browser_download_url': entry['url']}]})):
            with self.assertRaisesRegex(ValueError, 'GitHub release digest'):
                source_integrity.verify_publisher_metadata('python', entry)


if __name__ == '__main__':
    unittest.main()
