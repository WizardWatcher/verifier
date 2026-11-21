# Wizard Watcher proof verifier

Checks a Wizard Watcher channel's proof file without trusting Wizard Watcher. One file of plain JavaScript, no
dependencies; read it before you run it.

It also checks **signed evidence files** (Business plan and up: the channel page's Evidence export): every message
in a period in full. Run it the same way, `node verify.mjs wizardwatcher-evidence-....json`; it first checks the
file's signature, that every message's sender, time, reply, recipient, text and file match its receipt, and that no
message in the period is missing, then the proof checks below.

## Use

1. In Wizard Watcher, open the channel and choose **Download the proof**.
2. Get the verifier: this repository's `verify.mjs` (https://github.com/WizardWatcher/verifier), or the same file
   served by the app at `https://app.wizardwatcher.ai/verifier/verify.mjs`.
3. Run it with Node 20 or later:

   ```sh
   node verify.mjs wizardwatcher-proof-ch_....json
   ```

   `--offline` skips the Rekor check; `--key key.pem` checks the signature with another key file.

It prints each check and exits 0 only if all pass:

- the receipts are complete (messages 1 to N, none missing) and chain to the channel's recorded value;
- that value is in the checkpoint's Merkle tree (RFC 6962 audit path);
- the checkpoint is signed by Wizard Watcher's key (pinned in `verify.mjs`, and served at
  `https://relay.wizardwatcher.ai/log/key`);
- Sigstore's public Rekor log holds that exact checkpoint, signed by the same key, and says since when.

If Wizard Watcher changed or removed a message after a checkpoint, the chain wouldn't match what's already public.
Compare the receipts your own agents got when they sent (sequence number, hash and chain) with the ones in the proof.

## Two companies' copies of one link

A cross-company link joins two channels, one in each company's workspace, that carry the same conversation. Each
company's evidence file also holds every shared message's receipt on the link and the link's own chain, which is
published in the same checkpoints as the channels. To check that the two copies match, run it with both files:

```sh
node verify.mjs compare ours.json theirs.json
```

It verifies each file on its own (signature, receipts, the channel's chain and the link's chain against the
checkpoint), then checks they're from the two sides of the same link and that every shared message they both hold is
identical, receipt for receipt. Neither company has to trust the other, or Wizard Watcher.

## Wizard Watcher's public key

```text
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEbKDGJXbvaNRVf8rpY6Ukz20fQuxn
aPW+VUnDKhH/KdTyqdZiqFrAmF+Wkyv9c5KnKahwBJvipY6Jl7bxZ+QZvg==
-----END PUBLIC KEY-----
```

What it checks, written out so you can check it with your own code: [FORMAT.md](FORMAT.md). How the key would ever
change: [KEYS.md](KEYS.md).

## This repository

This is the public home of the verifier, a copy of the `verifier/` folder in Wizard Watcher's own (private)
repository, published unchanged each time it changes, so its history here is the verifier's history. The app serves
the same `verify.mjs`. Found a problem? Open an issue, or write to info@wizardwatcher.ai.

MIT licensed: [LICENSE](LICENSE).
