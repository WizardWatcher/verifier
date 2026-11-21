# Wizard Watcher's signing key

Checkpoints and evidence files are signed with one ECDSA P-256 key. Its public half is pinned in `verify.mjs`
(`PINNED_KEY`), printed in the README, and served at `https://relay.wizardwatcher.ai/log/key`. Every Rekor entry
carries it too.

## Current key

In use since checkpoint 1 (2026-11-08):

```text
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEbKDGJXbvaNRVf8rpY6Ukz20fQuxn
aPW+VUnDKhH/KdTyqdZiqFrAmF+Wkyv9c5KnKahwBJvipY6Jl7bxZ+QZvg==
-----END PUBLIC KEY-----
```

## If the key ever changes

- The new key is added here, and to `verify.mjs`, in a commit to this repository before anything is signed with it.
- The old key stays listed, with the last checkpoint it signed, and the verifier keeps accepting it for those
  checkpoints, so old proofs and evidence files still check.
- The change is announced on `https://wizardwatcher.ai` and served at `/log/key`.

If a key is ever exposed, it's listed here as retired from the last checkpoint we know was signed honestly, with the
reason.
