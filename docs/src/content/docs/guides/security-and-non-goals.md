---
title: Security and non-goals
description: The current claim boundary of the sealed-lattice workspace.
sidebar:
    order: 4
---

`sealed-lattice` currently ships a development verification package, not a published voting workflow. The selected direction is direct BGV-encrypted ballots with public ciphertext aggregation, mandatory mobile evaluator replay, target finality, and target-bound threshold decryption.

## What the current release guarantees

- the workspace layout is explicit and package-boundary checked
- the published package identity is stable
- the public runtime facade remains intentionally narrow while the final direct API is built
- the election foundation verifies signed-root envelopes for the current board, finality, roster-manifest, cast receipt, close record, and recovery helpers
- the Rust transcript-core builds, the published SDK loader verifies the packaged kernel hash before instantiation, and unpinned local WASM loader use requires an explicit test-only opt-in
- docs, smoke checks, browser coverage, vector manifest verification, and release workflow continue to verify the current boundary

## What it does not guarantee yet

- no complete threshold voting workflow is published yet
- no production ballot generation, casting, aggregation, evaluator replay, target-bound decryption, or result release API is public yet
- no voting correctness or secrecy claim is added by transcript-core fixture verification
- the internal direct encrypted ballot proof is not claim-bearing until soundness, zero-knowledge, Fiat-Shamir/QROM, public proof transport, and mobile evidence close
- direct encrypted sparse target projection is not complete for every supported top count
- target-bound decryption is not implemented as an accepted direct-path rule
- no caller should rely on private package names or future public subpaths becoming stable

## Direct-path security boundary

The final direct path must preserve these rules:

```text
Every ballot is encrypted before publication.
Ballot validity proofs are zero-knowledge and sound under the accepted profile.
Accepted ballot ciphertexts aggregate by public ciphertext addition.
Evaluator correctness is verified by deterministic mobile replay.
Only finalized and replay-matched C_target may be threshold-decrypted.
Individual ballots, aggregate scores, C_topK, ranks, comparisons, masks, and evaluator intermediates must not be opened.
```

## Caller responsibilities

- treat the current public package as a development verification package, not as a usable voting library
- keep application logic off unpublished internal package names
- do not assume the current internal package split implies frozen future public APIs
- do not build protocol, proof-generation, transport, or decryption assumptions around unpublished APIs
