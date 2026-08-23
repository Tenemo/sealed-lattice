# `@sealed-lattice/types`

Internal canonical type definitions for the sealed-lattice library. This package is not published.

It defines the type surface shared across `sealed-lattice`, `@sealed-lattice/protocol`, and `@sealed-lattice/wasm`. Workspace packages import from `@sealed-lattice/types` directly.

The public SDK build bundles these declarations into the published `sealed-lattice` package's `dist/index.d.ts`, so consumers never reference this internal package.
