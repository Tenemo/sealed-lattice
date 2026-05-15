---
title: Security and non-goals
description: The current claim boundary of the sealed-lattice workspace.
sidebar:
    order: 4
---

`sealed-lattice` currently ships a stable package boundary, transcript core
fixture verification, and deterministic election foundation helpers, not a published
voting API.

## What the current release guarantees

- the workspace layout is explicit and package-boundary checked
- the published package identity is stable
- the public runtime facade exposes transcript core fixture verification plus deterministic election foundation helpers
- the election foundation verifies ML-DSA-65 signed-root envelopes for the current board, finality, roster-manifest, cast receipt, close record, and recovery helpers
- the Rust transcript core builds and the internal WASM loader path works in Node and browsers
- local replay record, target-accepted-record, and decryption-share shell checks remain internal protocol coverage
- target-bound decryption capabilities fail closed unless a threshold profile includes an Appendix-C-certified share-selection profile and the relevant proof certificates are explicitly present
- docs, smoke checks, browser coverage, vector manifest verification, and release workflow continue to verify the current boundary

## What it does not guarantee yet

- no threshold voting workflow is published yet
- no ballot, tally, proof, semantic target-acceptance, or decryption API is public yet
- no voting correctness or secrecy claim is added by the transcript core fixture path
- no caller should rely on private package names or future public subpaths becoming stable

## Caller responsibilities

- treat the current public package as a transcript core fixture verifier and election foundation, not as a usable voting library yet
- keep application logic off unpublished internal package names
- do not assume the current internal package split implies frozen future public APIs
- do not build protocol, proof, or transport assumptions around unpublished APIs
