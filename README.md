# sealed-lattice

[![npm version](https://badge.fury.io/js/sealed-lattice.svg)](https://badge.fury.io/js/sealed-lattice)
[![npm downloads](https://img.shields.io/npm/dm/sealed-lattice)](https://www.npmjs.com/package/sealed-lattice)

---

[![CI](https://img.shields.io/github/actions/workflow/status/Tenemo/sealed-lattice/ci.yml?branch=master&label=passing%20tests)](https://github.com/Tenemo/sealed-lattice/actions/workflows/ci.yml)
[![Tests coverage](https://img.shields.io/endpoint?url=https://tenemo.github.io/sealed-lattice/coverage-badge.json)](https://tenemo.github.io/sealed-lattice/coverage-summary.json)
[![Documentation build](https://img.shields.io/github/actions/workflow/status/Tenemo/sealed-lattice/pages.yml?branch=master&label=docs)](https://github.com/Tenemo/sealed-lattice/actions/workflows/pages.yml)

---

[![Node version](https://img.shields.io/badge/node-%E2%89%A524.14.1-5FA04E?logo=node.js&logoColor=white)](https://nodejs.org/)
[![License](https://img.shields.io/github/license/Tenemo/sealed-lattice)](LICENSE)

---

`sealed-lattice` is a browser-native TypeScript scaffold for post-quantum voting research prototypes.

Phase one ships:

- a real `sha256Hex` helper on the safe root package and `./core`
- a typed `UnsupportedRuntimeError` for missing Web Crypto support
- reserved public subpaths for `./proofs`, `./protocol`, `./runtime`, `./serialize`, `./threshold`, and `./transport`
- the same repo, docs, testing, and publish workflow shape used by `threshold-elgamal`

This repository is a hardened research prototype scaffold. It is not audited production voting software.

## Release status

This repository currently tracks phase one of the `sealed-lattice` implementation.

The public surface is intentionally narrow while the repo, CI, docs, tests, coverage, and packaging experience are brought up to parity with the existing classical baseline. Lattice cryptography, threshold flows, transport payloads, proofs, and protocol types are planned but not shipped yet.

## Installation

```bash
pnpm add sealed-lattice
```

## Runtime requirements

- Use ESM imports such as `import { sha256Hex } from 'sealed-lattice'`. The published package does not expose CommonJS `require()` entry points.
- Browsers need `globalThis.crypto.subtle` and `TextEncoder`.
- Node requires version `24.14.1` or newer with `globalThis.crypto`.

## Safe quickstart

```typescript
import { sha256Hex } from "sealed-lattice";

const digest = await sha256Hex("sealed-lattice");

console.log(digest);
```

The root package currently exposes only `sha256Hex` and `UnsupportedRuntimeError`.

## Public subpaths

- `sealed-lattice`
- `sealed-lattice/core`
- `sealed-lattice/proofs`
- `sealed-lattice/protocol`
- `sealed-lattice/runtime`
- `sealed-lattice/serialize`
- `sealed-lattice/threshold`
- `sealed-lattice/transport`

Only the root package and `./core` currently expose callable functionality. The other subpaths are phase-one placeholders that resolve, build, and document correctly while their real APIs are deferred to later milestones.

## Documentation

- Hosted documentation site: [tenemo.github.io/sealed-lattice](https://tenemo.github.io/sealed-lattice/)
- Get started: [tenemo.github.io/sealed-lattice/guides/getting-started](https://tenemo.github.io/sealed-lattice/guides/getting-started/)
- Runtime and compatibility: [tenemo.github.io/sealed-lattice/guides/runtime-and-compatibility](https://tenemo.github.io/sealed-lattice/guides/runtime-and-compatibility/)
- Security and non-goals: [tenemo.github.io/sealed-lattice/guides/security-and-non-goals](https://tenemo.github.io/sealed-lattice/guides/security-and-non-goals/)
- API reference: [tenemo.github.io/sealed-lattice/api](https://tenemo.github.io/sealed-lattice/api/)

## Development

```bash
pnpm install --frozen-lockfile
pnpm run vectors:core
pnpm run ci
```

For the phase-one digest microbenchmark, run:

```bash
pnpm run bench:micro
```

## License

This project is licensed under MPL-2.0. See [LICENSE](LICENSE).
