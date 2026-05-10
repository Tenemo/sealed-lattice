# sealed-lattice

WORK IN PROGRESS - protocol-facing APIs remain under implementation. Versions below 1.0.0 are not suitable for production or real elections.

---

[![npm version](https://img.shields.io/npm/v/sealed-lattice?color=5FA04E)](https://www.npmjs.com/package/sealed-lattice)
[![npm downloads](https://img.shields.io/npm/dm/sealed-lattice?color=5FA04E)](https://www.npmjs.com/package/sealed-lattice)

---

[![CI](https://img.shields.io/github/actions/workflow/status/Tenemo/sealed-lattice/ci.yml?branch=master&label=passing%20tests&color=5FA04E)](https://github.com/Tenemo/sealed-lattice/actions/workflows/ci.yml)
[![Tests coverage](https://img.shields.io/endpoint?url=https://tenemo.github.io/sealed-lattice/coverage-badge.json)](https://tenemo.github.io/sealed-lattice/coverage-summary.json)
[![Documentation build](https://img.shields.io/github/actions/workflow/status/Tenemo/sealed-lattice/pages.yml?branch=master&label=docs&color=5FA04E)](https://github.com/Tenemo/sealed-lattice/actions/workflows/pages.yml)

---

[![Node version](https://img.shields.io/badge/node-%E2%89%A524.14.1-5FA04E?logo=node.js&logoColor=white)](https://nodejs.org/)
[![License](https://img.shields.io/github/license/Tenemo/sealed-lattice?color=5FA04E)](LICENSE)

---

`sealed-lattice` is a browser-first, mobile-first, post-quantum threshold
homomorphic voting library workspace.

The repository uses a private Turborepo workspace with one published package
and five private internal packages:

- `sealed-lattice`
- `@sealed-lattice/types`
- `@sealed-lattice/protocol`
- `@sealed-lattice/crypto`
- `@sealed-lattice/wasm`
- `@sealed-lattice/testkit`

The workspace also contains `crates/sealed-lattice-kernel`, the Rust transcript
core used by the native test and WASM loading path.

## Current public boundary

The published `sealed-lattice` package currently exposes a safe transcript core
fixture verifier plus the threshold, lifecycle, poll specification, and capability
shell.

This keeps packaging, documentation, smoke checks, transcript fixtures, and
release flow stable while the broader voting API remains future implementation.

- workspace layout and package boundaries
- packaging and tarball smoke checks
- TypeScript, ESLint, browser, and Node verification
- Astro documentation and TypeDoc generation
- transcript core test vector manifest verification
- the Rust-to-WASM transcript core toolchain

## Documentation

- Hosted documentation site: [tenemo.github.io/sealed-lattice](https://tenemo.github.io/sealed-lattice/)
- Guides index: [tenemo.github.io/sealed-lattice/guides](https://tenemo.github.io/sealed-lattice/guides/)
- Protocol spec: [tenemo.github.io/sealed-lattice/spec](https://tenemo.github.io/sealed-lattice/spec/)
- API reference: [tenemo.github.io/sealed-lattice/api](https://tenemo.github.io/sealed-lattice/api/)

## Workspace layout

```text
sealed-lattice/
  docs/
  implementation-documentation/
  packages/
    sdk/
    protocol/
    crypto/
    wasm/
    testkit/
  crates/
    sealed-lattice-kernel/
  tools/
  typedoc/
```

## Installation

```bash
pnpm add sealed-lattice
```

The package exports the current transcript core fixture verifier and safe
protocol shell helpers. It is not a usable voting library yet.

## Development

```bash
pnpm install
pnpm run check
pnpm run vectors
pnpm exec playwright install chromium firefox webkit
pnpm run test
pnpm run verify:docs
pnpm run docs:build:site
pnpm run smoke:pack
pnpm run smoke:pack:npm
pnpm run build
```

## License

This project is licensed under MPL-2.0. See [LICENSE](LICENSE).
