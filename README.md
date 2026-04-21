# sealed-lattice

WORK IN PROGRESS - all versions below 1.0.0 are considered inherently unsafe, unfinished and not ready for usage, even for research purposes. Full release coming soon, work is actively in progress.

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
and four private internal packages:

- `sealed-lattice`
- `@sealed-lattice/protocol`
- `@sealed-lattice/crypto`
- `@sealed-lattice/wasm`
- `@sealed-lattice/testkit`

The workspace also contains `crates/sealed-lattice-kernel`, a Rust placeholder
crate used to prove the native-test and WASM-loading path.

## Current public boundary

The published `sealed-lattice` package currently imports successfully but
exposes no runtime API.

This keeps packaging, documentation, smoke checks, and release flow stable
while the broader public API is still being built.

- workspace layout and package boundaries
- packaging and tarball smoke checks
- TypeScript, ESLint, browser, and Node verification
- Astro documentation and TypeDoc generation
- generic test vector manifest verification
- the Rust-to-WASM placeholder toolchain

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

The package imports successfully, but it intentionally exports no runtime API.

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

## Documentation

- Hosted documentation site: [tenemo.github.io/sealed-lattice](https://tenemo.github.io/sealed-lattice/)
- Guides index: [tenemo.github.io/sealed-lattice/guides](https://tenemo.github.io/sealed-lattice/guides/)
- Protocol spec: [tenemo.github.io/sealed-lattice/spec](https://tenemo.github.io/sealed-lattice/spec/)
- API reference: [tenemo.github.io/sealed-lattice/api](https://tenemo.github.io/sealed-lattice/api/)

## Status

This repository currently ships a stable package boundary, explicit internal
package ownership, verification tooling, documentation generation, package
smoke checks, and a Rust/WASM placeholder path. The public runtime facade is
still intentionally empty.

## License

This project is licensed under MPL-2.0. See [LICENSE](LICENSE).
