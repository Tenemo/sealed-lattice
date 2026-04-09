---
title: Security and non-goals
description: Security boundary for the current sealed-lattice package surface.
sidebar:
  order: 3
---

`sealed-lattice` is a hardened research prototype. It is not audited production voting software.

## Current guarantees

- The current root package exposes a narrow, documented API.
- Hashing fails closed when the required Web Crypto surface is absent.
- Deterministic vectors and browser parity tests verify the currently shipped helper.
- Packaging, docs, and the narrow public package surface are verified so the package does not drift silently.

## Current non-goals

- production-readiness claims
- audit claims
- lattice encryption
- threshold decryption
- transport authenticity
- verifiable proofs
- voter privacy guarantees beyond the current digest helper

Future PQ capability areas remain intentionally unpublished until their misuse-resistant boundaries are clear enough to freeze.
