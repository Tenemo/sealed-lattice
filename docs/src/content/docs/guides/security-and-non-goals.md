---
title: Security and non-goals
description: The current claim boundary of the sealed-lattice workspace.
sidebar:
    order: 4
---

`sealed-lattice` currently ships a stable package boundary and safe-by-default helpers for transcript-core fixture verification, election foundation checks, and verification-oriented ballot privacy APIs, not a published voting workflow.

## What the current release guarantees

- the workspace layout is explicit and package-boundary checked
- the published package identity is stable
- the public runtime facade exposes transcript-core fixture verification plus election foundation checks
- the public runtime facade verifies supported receiver-key proofs, ballot proof records, and proof-byte-bearing scoped relation packages through the packaged Rust/WASM backend
- the election foundation verifies ML-DSA-65 signed-root envelopes for the current board, finality, roster-manifest, cast receipt, close record, and recovery helpers
- the Rust transcript-core builds, the published SDK loader verifies the packaged kernel hash before instantiation, and unpinned local WASM loader use requires an explicit test-only opt-in
- internal Rust/WASM commands derive reserved protocol digests and check the current `GF(65537)` interpolation/comparison relations used by the TypeScript reference layer
- local replay record, target-accepted-record, and decryption-share shell checks remain internal protocol coverage
- target-bound decryption capabilities fail closed unless a threshold profile includes a target-bound share-selection profile and the relevant proof certificates are explicitly present
- docs, smoke checks, browser coverage, vector manifest verification, and release workflow continue to verify the current boundary

## What it does not guarantee yet

- no threshold voting workflow is published yet
- no ballot generation, casting, aggregation, tally, proof construction, semantic target-acceptance, or decryption API is public yet
- no voting correctness or secrecy claim is added by the transcript-core fixture path
- ballot privacy verification covers receiver-key proof, ballot proof-record, and proof-byte-bearing scoped relation package checks only; it is not a complete voting workflow
- internal deterministic PVSS ballot-algebra helpers are test infrastructure and do not provide production ballot confidentiality
- no caller should rely on private package names or future public subpaths becoming stable

## Caller responsibilities

- treat the current public package as transcript-core fixture verification, election foundation checks, receiver-key proof verification, ballot proof-record verification, and proof-byte-bearing package verification, not as a usable voting library yet
- keep application logic off unpublished internal package names
- do not assume the current internal package split implies frozen future public APIs
- do not build protocol, proof-generation, or transport assumptions around unpublished APIs
