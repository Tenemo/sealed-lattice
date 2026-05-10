# `@sealed-lattice/types`

Internal canonical type definitions for the sealed-lattice library. **Not
published.**

This package is the single source of truth for the public type surface shared
across `sealed-lattice`, `@sealed-lattice/protocol`, `@sealed-lattice/wasm`,
and `@sealed-lattice/testkit`. Workspace packages import from
`@sealed-lattice/types` directly.

At build time, `tools/ci/build-sdk-bridge.ts` inlines the types into the
published `sealed-lattice` package's `dist/` so consumers never see a reference
to this internal package.
