---
title: Security and non-goals
description: The current claim boundary of the sealed-lattice workspace.
sidebar:
    order: 4
---

The canonical public security posture lives in the repository [security policy](https://github.com/Tenemo/sealed-lattice/blob/master/SECURITY.md).

This page intentionally does not maintain a separate threat model, retry policy, audit statement, or cryptographic caveat list. Use the repository policy before treating any verification result as security evidence.

## Caller responsibilities

- treat the current public package as a development verification package
- keep the participant mobile-browser claim path explicit
- keep application logic off unpublished internal package names
- do not assume the current internal package split implies frozen future public APIs
- do not build setup, VSS, protocol, proof-generation, transport, or decryption assumptions around unpublished APIs
