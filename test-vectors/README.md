# Test vectors

This directory stores deterministic test vectors and the manifest used to verify them.

## Files

- `manifest.json`: canonical file list and SHA-256 hashes for committed vector files
- `README.md`: usage notes for contributors

## Commands

```bash
pnpm run vectors
pnpm run vectors:generate
```

`pnpm run vectors` verifies that the committed files match `manifest.json`. `pnpm run vectors:generate` rewrites the manifest from the current contents of the directory.

The repository currently includes tracked plaintext oracle vectors for comparator polynomials, field arithmetic, Shamir recovery, sparse targets, and top-k derivation so the manifest always exercises real file hashing and verification.
