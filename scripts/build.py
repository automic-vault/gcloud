#!/usr/bin/env python3
"""Build the pinned, sealed arm64 gcloud Isotope without running SDK installers."""
import hashlib
import json
import os
import pathlib
import plistlib
import shutil
import subprocess
import sys
import tarfile
import urllib.request

if sys.version_info < (3, 12):
    raise SystemExit('Build with Python 3.12 or later (secure archive extraction is required)')

ROOT = pathlib.Path(__file__).resolve().parents[1]
BUILD = ROOT / 'build'
LOCK = json.loads((ROOT / 'upstream.json').read_text())
BUNDLE = BUILD / 'Gcloud.app'
identity = os.environ.get('CODESIGN_IDENTITY', 'Developer ID Application: Max Howell (ZU76A67LGU)')

def run(*args):
    subprocess.run([str(a) for a in args], check=True)

def fetch(name):
    entry = LOCK[name]
    path = BUILD / (name + '.tar.gz')
    if not path.exists():
        with urllib.request.urlopen(entry['url'], timeout=60) as response, path.open('wb') as out:
            shutil.copyfileobj(response, out)
    if hashlib.sha256(path.read_bytes()).hexdigest() != entry['sha256']:
        raise ValueError(name + ' archive digest mismatch')
    return path

BUILD.mkdir(exist_ok=True)
inputs = {name: fetch(name) for name in LOCK}
if BUNDLE.exists():
    shutil.rmtree(BUNDLE)
contents = BUNDLE / 'Contents'
resources = contents / 'Resources'
frameworks = resources
(resources).mkdir(parents=True)
(contents / 'MacOS').mkdir()
for name, destination in [('gcloud', resources), ('python', frameworks)]:
    with tarfile.open(inputs[name]) as archive:
        archive.extractall(destination, filter='data')
python = frameworks / 'python'
sdk = resources / 'google-cloud-sdk'
# The Isotope offers gcloud only. No alternate executable can act as its Gate Client.
for path in [sdk / 'bin', sdk / 'platform', python / 'bin', python / 'lib/python3.13/site-packages']:
    if path.exists():
        shutil.rmtree(path)
for path in BUNDLE.rglob('__pycache__'):
    shutil.rmtree(path)
for path in BUNDLE.rglob('*.pyc'):
    path.unlink()
for name in ('av_store.py', 'bootstrap.py'):
    shutil.copy2(ROOT / 'isotope' / name, resources / name)
run(sys.executable, '-m', 'unittest', 'discover', '-s', ROOT / 'tests', '-v')
run('clang++', '-std=c++17', '-mmacosx-version-min=14.0', '-fblocks',
    '-I' + str(python / 'include/python3.13'), ROOT / 'isotope/main.cc',
    '-L' + str(python / 'lib'), '-lpython3.13', '-framework', 'CoreFoundation',
    '-framework', 'Security', '-Wl,-rpath,@executable_path/../Resources/python/lib',
    '-o', contents / 'MacOS/gcloud')
info = {'CFBundleIdentifier': 'com.automicvault.gcloud', 'CFBundleExecutable': 'gcloud',
        'CFBundlePackageType': 'APPL', 'CFBundleVersion': LOCK['gcloud']['version'],
        'LSMinimumSystemVersion': '14.0'}
(contents / 'Info.plist').write_bytes(plistlib.dumps(info))
magic = {b'\xcf\xfa\xed\xfe', b'\xce\xfa\xed\xfe', b'\xca\xfe\xba\xbe', b'\xbe\xba\xfe\xca'}
for path in BUNDLE.rglob('*'):
    if path.is_symlink():
        if not path.resolve().is_relative_to(BUNDLE.resolve()):
            raise ValueError('Escaping bundle link: ' + str(path))
        continue
    if path.is_file():
        with path.open('rb') as stream:
            native = stream.read(4) in magic
        path.chmod(0o755 if native or path.stat().st_mode & 0o111 else 0o644)
        if native and path != contents / 'MacOS/gcloud':
            if path.suffix == '.dylib':
                # Homebrew preserves @rpath IDs, but rewrites bare Tcl IDs.
                # Normalize before signing so staging preserves the resource seal.
                run('/usr/bin/install_name_tool', '-id',
                    '@rpath/' + str(path.relative_to(python / 'lib')), path)
            run('/usr/bin/codesign', '--force', '--sign', identity, '--options', 'runtime', '--timestamp', path)
    elif path.is_dir():
        path.chmod(0o755)
run('/usr/bin/codesign', '--force', '--sign', identity, '--options', 'runtime', '--timestamp', BUNDLE)
run('/usr/bin/codesign', '--verify', '--deep', '--strict', '--all-architectures', BUNDLE)
archive = BUILD / ('cli-' + LOCK['gcloud']['version'] + '.tgz')
run('/usr/bin/tar', '-czf', archive, '-C', BUILD, 'Gcloud.app')
print(hashlib.sha256(archive.read_bytes()).hexdigest(), archive)
