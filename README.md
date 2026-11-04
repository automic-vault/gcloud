# gcloud Isotope

Google Cloud CLI with user OAuth credentials in Automic Vault custody.

This repository builds a pinned Google distribution with a small credential-store
adapter and a native, signed Python entry point. `upstream.json` pins both source
inputs by SHA-256; generated SDK and Python trees stay in `build/`.

## Supported workflow

Use the av4 build containing the gcloud gate. Revoke existing upstream sessions
before switching, install the protected Isotope with `av harden gcloud`, then:

```sh
gcloud auth login
gcloud projects list
gcloud auth revoke
```

Each credential read initially requires Approval. Login and credential mutation
also require Approval. Access tokens stay in memory. Refresh-token rotation uses
conditional replacement; logout cannot delete a newer login. No denied request
falls back to disk credentials.

The first version supports ordinary user OAuth in the default Google universe.
ADC, federation, service-account credentials, impersonation, auth/endpoint/proxy
overrides, flags files, remote-bootstrap login, `init`, alpha/beta/preview,
interactive mode, component installation, and companion tools are unsupported.
Use `auth login` and explicit configuration commands instead of `init`.
Existing credentials, ADC files, and backups remain exposed until separately
revoked or removed. This build does not automatically migrate or delete them.

The native Target verifies root ownership, effective write protection, and the
complete bundle signature before running Python. Python runs in isolated mode
without user site packages or startup hooks. The installed path is fixed at
`/opt/av/gcloud/Gcloud.app/Contents/MacOS/gcloud`. A build-tree copy intentionally
refuses to run; an ordinary Python interpreter is not a Gate Client.

## Build and verify

On Apple Silicon macOS, with Python 3.12+ and the AV Developer ID identity:

```sh
python3 scripts/build.py
python3 -m unittest discover -s tests -v
```

The build downloads and verifies the locked archives, compiles the native
entry point, signs all native resources with Hardened Runtime and no exceptions,
seals the bundle, and writes `build/cli-592.0.0.tgz`. The full distribution and
component licence notices remain in the bundle.

Before publication, update the tap formula's SHA-256 to the exact archive and run:

```sh
cd ../..
brew ruby Scripts/test-formula-install.rb Formula/gcloud-isotope.rb Isotopes/gcloud/build/cli-592.0.0.tgz
```

Also run av's focused Rust installer tests, signed-archive verification test,
Swift gcloud tests, and secret-mutation self-check. A protected installation and
real OAuth login/refresh/logout with the updated AV app are required before
shipping; mocked custody tests do not establish that end-to-end boundary.

Publish the signed archive from the `automic-vault/gcloud` repository and pin its
URL and digest in the signed Isotopes tap. A local build is not a published release.
Upgrades are manual: review the new SDK command and credential surfaces, update
the two input pins as needed, and repeat these checks. The tap's generic GitHub
fork updater does not update Google's archive distribution.

Security terminology and boundaries follow the canonical
[domain language](https://github.com/automic-vault/automic-vault/blob/main/docs/domain-language.md),
[architecture](https://github.com/automic-vault/automic-vault/blob/main/docs/architecture.md),
and [gcloud ADR](https://github.com/automic-vault/automic-vault/blob/main/docs/adr/0082-gcloud-isotope-custody.md).
