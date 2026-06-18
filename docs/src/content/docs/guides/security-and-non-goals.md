---
title: Security and non-goals
description: The current claim boundary of the sealed-lattice workspace.
sidebar:
    order: 4
---

`sealed-lattice` currently ships a development verification package, not a published voting workflow. The selected direction is active-static secure-with-abort collective BGV setup, direct encrypted ballots, ballot validity proofs for the fixed encrypted-ballot relation, public ciphertext aggregation, bounded-domain mobile evaluator replay, unanimous target finality for the first profile, and one-shot target-bound threshold decryption of `C_target` only.

## What the current release guarantees

- the workspace layout is explicit and package-boundary checked
- the published package identity is stable
- the public runtime facade remains intentionally narrow while the final direct API is built
- the election foundation component helpers verify signed-root envelopes for the current board, finality, roster-manifest, cast receipt, close record, and recovery helpers
- public encrypted ballot package creation, package verification, and public ciphertext aggregation are exposed as development evidence from accepted public-key material and an accepted setup handoff
- the Rust transcript-core builds, the published SDK loader verifies the packaged kernel hash before instantiation, and unpinned local WASM loader use requires an explicit test-only opt-in
- docs, smoke checks, browser coverage, vector manifest verification, and release workflow continue to verify the current boundary

## What it does not guarantee yet

- no complete threshold voting workflow is published yet
- no production setup ceremony, ballot generation, casting, aggregation, evaluator replay, target-bound decryption, or result release API is public yet
- no voting correctness or secrecy claim is added by transcript-core fixture verification
- active-static setup is not claim-bearing until the `CollectiveBgvSetup-v1` public verifier accepts a full-profile setup with repo-owned setup proof accounting, per-RNS-prime VSS package integration, same-secret proof verification, public-key proofs, evaluation-key proofs, key transport, and downstream integration bindings
- independent external validation is not a prerequisite for the active-static setup prototype claim, but production use would still require separate production hardening and review
- the direct encrypted ballot package path is not claim-bearing until setup closure, final evidence capture, soundness and zero-knowledge review, public proof transport evidence, and current QROM accounting metadata are recorded for the selected proof profile; QROM-strength closure, mobile-compatible proof readiness, and supported-phone evidence remain later targets rather than direct ballot proof closure requirements
- bounded-domain encrypted sparse target projection is not complete for every supported top count
- target-bound decryption is not implemented as an accepted direct-path rule
- no caller should rely on private package names or future public subpaths becoming stable

## Direct-path security boundary

The final direct path must preserve these rules:

```text
Every ballot is encrypted before publication.
Setup is active-static secure with abort, not robust-liveness secure.
Accepted ballot validity proofs must be zero-knowledge and sound under the selected proof profile.
Accepted ballot ciphertexts aggregate by public ciphertext addition.
Evaluator correctness is verified by deterministic bounded-domain mobile replay.
C_topK is encrypted under the collective key, but it is not an authorized decryption target.
Only finalized and replay-matched C_target may be threshold-decrypted.
Individual ballots, aggregate scores, C_topK, ranks, comparisons, masks, and evaluator intermediates must not be opened.
Smudging/noise and proof-bearing target-decryption shares remain mandatory.
```

## Caller responsibilities

- treat the current public package as a development verification package, not as a usable voting library
- keep application logic off unpublished internal package names
- do not assume the current internal package split implies frozen future public APIs
- do not build setup, VSS, protocol, proof-generation, transport, or decryption assumptions around unpublished APIs
