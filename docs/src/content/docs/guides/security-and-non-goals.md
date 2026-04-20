---
title: Security and non-goals
description: The current claim boundary of the sealed-lattice workspace.
sidebar:
    order: 4
---

`sealed-lattice` currently ships a stable package boundary and verification
shell, not a published voting API.

## What the current release guarantees

- the workspace layout is explicit and package-boundary checked
- the published package identity is stable
- the public runtime facade is intentionally empty and documented as such
- the Rust placeholder crate builds and the internal WASM loader path works in Node and browsers
- docs, smoke checks, browser coverage, vector manifest verification, and release workflow continue to verify the current boundary

## What it does not guarantee yet

- no threshold voting workflow is published yet
- no transcript, manifest, ballot, tally, or proof API is public yet
- no cryptographic correctness or secrecy claim is added by the placeholder Rust/WASM path
- no caller should rely on private package names or future public subpaths becoming stable

## Caller responsibilities

- treat the current public package as a stable shell, not as a usable protocol library yet
- keep application logic off unpublished internal package names
- do not assume the current internal package split implies frozen future public APIs
- do not build protocol, proof, or transport assumptions around unpublished APIs
