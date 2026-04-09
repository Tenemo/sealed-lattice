---
title: Security and non-goals
description: Security boundary for the current sealed-lattice scaffold.
sidebar:
  order: 3
---

`sealed-lattice` is a hardened research prototype scaffold. It is not audited production voting software.

## Current guarantees

- The phase-one root package exposes a narrow, documented API.
- Hashing fails closed when the required Web Crypto surface is absent.
- Deterministic vectors and browser parity tests verify the currently shipped helper.
- Packaging, docs, and exported subpaths are verified so the scaffold does not drift silently.

## Current non-goals

- production-readiness claims
- audit claims
- lattice encryption
- threshold decryption
- transport authenticity
- verifiable proofs
- voter privacy guarantees beyond the current digest helper

The public placeholder subpaths exist to freeze the package shape early. They do not claim cryptographic completeness.
