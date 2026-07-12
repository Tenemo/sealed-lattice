# `@sealed-lattice/types`

Internal canonical type definitions for the sealed-lattice library. **Not published.**

This package defines the public type surface shared across `sealed-lattice`, `@sealed-lattice/protocol`, and `@sealed-lattice/wasm`. Workspace packages import from `@sealed-lattice/types` directly.

At build time, the public SDK build bundles these declarations into the published `sealed-lattice` package's `dist/index.d.ts`, so consumers never see a reference to this internal package.
