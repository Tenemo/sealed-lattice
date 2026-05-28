# Ballot privacy test vectors

These files are generated public-only regression fixtures. They are not runtime assets and must not be shipped in the published runtime package.

The vector files intentionally contain only public proof, statement, profile, hash, and rejection-case data. They must not contain witnesses, secret keys, private keys, prover randomness, receiver state, decrypted payloads, aggregate openings, bridge witnesses, or decrypted ballots.

The JSON files are minified intentionally. They are marked as generated and non-diffable in `.gitattributes` so pull requests stay reviewable while the fixtures remain committed and reproducible.

Use this command to verify the committed files against `test-vectors/manifest.json`:

```bash
pnpm run vectors
```

Use the specific generator scripts to refresh individual vector families:

```bash
pnpm exec tsx --tsconfig tsconfig.base.json tools/ballot-privacy-vectors/generate-encoded-relation-vectors.mts
pnpm exec tsx --tsconfig tsconfig.base.json tools/ballot-privacy-vectors/generate-receiver-key-proof-vectors.mts
pnpm exec tsx tools/lazer-oracle/generate-vectors.ts --profile demo-linear
pnpm exec tsx tools/lazer-oracle/generate-vectors.ts --profile receiver-key-linear
pnpm exec tsx tools/lazer-oracle/generate-vectors.ts --profile ballot-field-linear
```

The LaZer-backed vectors are refreshed only through the Docker/Sage oracle path. Do not regenerate them in normal CI. Normal CI should verify committed hashes and run tests; oracle refreshes should be explicit maintenance work.

After refreshing any vector file, regenerate the manifest:

```bash
pnpm run vectors:generate
pnpm run vectors
```
