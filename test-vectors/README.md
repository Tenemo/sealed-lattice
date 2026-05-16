# Test vectors

This directory stores deterministic test vectors and the manifest used to
verify them.

## Files

- `manifest.json`: canonical file list and SHA-256 digests for committed
  vector files
- `README.md`: usage notes for contributors

## Commands

```bash
pnpm run vectors
pnpm run vectors:generate
```

`pnpm run vectors` verifies that the committed files match `manifest.json`.
`pnpm run vectors:generate` rewrites the manifest from the current contents of
the directory.

The repository includes tracked transcript-core golden, malformed-object, and
transcript replay fixtures plus election-foundation threshold, poll-spec,
lifecycle, capability, board/finality, first-valid, recovery, full signed
deterministic fixture, and plaintext oracle vectors so the manifest always
exercises real file hashing and verification.
