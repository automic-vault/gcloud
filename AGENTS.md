This is a security product. Follow the canonical domain language, architecture,
and positioning in ../../../av/docs. Read those documents before changing a
security boundary or product claims. Record security decisions in that repo.

Keep the patch against the pinned Google release small and reproducible. Never
fall back to upstream credential files after an AV error. Run the Python tests,
build the signed bundle, and verify the packaged artifact before publication.
Do not commit credentials, signing keys, or generated build artifacts.
