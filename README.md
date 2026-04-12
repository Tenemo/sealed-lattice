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

`sealed-lattice` is a browser-native TypeScript package for post-quantum voting research prototypes.

The current implementation ships:

- a real `sha256Hex` helper on the safe root package
- a typed `UnsupportedRuntimeError` for missing Web Crypto support
- the same repo, docs, testing, and publish workflow shape used by `threshold-elgamal`
- a deliberately narrow public surface while the lattice-native architecture is still being proven

This repository is a hardened research prototype. It is not audited production voting software.

## Release status

This repository currently tracks the initial public `sealed-lattice` surface.

The public surface is intentionally narrow while the repo, CI, docs, tests, coverage, and packaging experience are brought up to parity with the existing classical baseline. Lattice cryptography, threshold flows, transport payloads, proofs, protocol types, and any future subpath structure are still being designed and are not frozen yet.

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

## Public package boundary

- `sealed-lattice`

No additional public subpaths are promised yet. Future capability areas such as runtime helpers, serialization, transport, threshold coordination, proofs, and protocol types remain internal design space until the post-quantum flow and misuse-resistant contracts are stable.

## Documentation

- Hosted documentation site: [tenemo.github.io/sealed-lattice](https://tenemo.github.io/sealed-lattice/)
- Get started: [tenemo.github.io/sealed-lattice/guides/getting-started](https://tenemo.github.io/sealed-lattice/guides/getting-started/)
- Runtime and compatibility: [tenemo.github.io/sealed-lattice/guides/runtime-and-compatibility](https://tenemo.github.io/sealed-lattice/guides/runtime-and-compatibility/)
- Security and non-goals: [tenemo.github.io/sealed-lattice/guides/security-and-non-goals](https://tenemo.github.io/sealed-lattice/guides/security-and-non-goals/)
- API reference: [tenemo.github.io/sealed-lattice/api](https://tenemo.github.io/sealed-lattice/api/)

## Development

```bash
pnpm install --frozen-lockfile
pnpm run lint
pnpm run tsc
pnpm exec knip
pnpm run test
pnpm run build
pnpm run smoke:pack
pnpm run verify:docs
pnpm run docs:build:site
pnpm exec tsx ./tools/ci/verify-docs-build.ts
```

For the current digest microbenchmark, run:

```bash
pnpm run bench:micro
```

## License

This project is licensed under MPL-2.0. See [LICENSE](LICENSE).
