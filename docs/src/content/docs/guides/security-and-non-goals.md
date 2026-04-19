---
title: Security and non-goals
description: The intended security boundary of the current sealed-lattice public API surface.
sidebar:
    order: 4
---

`sealed-lattice` is a hardened research prototype for browser-native
post-quantum voting work. The current public API surface is intentionally narrow
and it is not audited production voting software.

## What the package tries to guarantee

- The root package exposes a narrow, documented API.
- Hashing fails closed when the required Web Crypto surface is absent.
- Deterministic vectors and browser parity tests verify the shipped helper.
- Packaging, docs generation, and tarball checks verify that the public API surface does not drift silently.

## What the package does not guarantee by itself

- It does not provide lattice encryption yet.
- It does not provide threshold key generation or decryption yet.
- It does not provide transport authenticity or protocol orchestration yet.
- It does not provide proof systems or public protocol payload boundaries yet.
- It does not make broader production-readiness or audit claims.

## What callers still need to do

- Treat the current package as a stable shell, not as a finished PQ voting stack.
- Pin supported runtimes that expose native Web Crypto digest support.
- Keep future transport, threshold, proof, and protocol expectations out of production assumptions until those contracts are actually published.
- Verify broader application security properties outside this package.

## Scope boundary

The current milestone stabilizes the repo, docs, tests, coverage, packaging,
and the narrow public API surface before wider post-quantum capability areas
are frozen.

Future PQ modules remain intentionally unpublished until their misuse-resistant
boundaries are clear enough to commit publicly.
