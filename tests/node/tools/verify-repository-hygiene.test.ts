import { describe, expect, it } from 'vitest';

import {
    findTrackedBuildArtifactFailures,
    normalizeRepositoryRelativePath,
    parseTrackedRepositoryPaths,
} from '../../../tools/ci/verify-repository-hygiene';

describe('repository hygiene helpers', () => {
    it('normalizes repository-relative paths and parses git output', () => {
        expect(
            parseTrackedRepositoryPaths(
                'packages\\wasm\\dist\\index.js\0src\\index.ts\0',
            ),
        ).toEqual(['packages/wasm/dist/index.js', 'src/index.ts']);
        expect(
            normalizeRepositoryRelativePath('packages\\sdk\\dist\\index.js'),
        ).toBe('packages/sdk/dist/index.js');
    });

    it('flags tracked build artifacts and caches', () => {
        expect(
            findTrackedBuildArtifactFailures([
                'packages/sdk/dist/index.js',
                'coverage/lcov.info',
                'packages/wasm/dist/tsconfig.tsbuildinfo',
                'crates/sealed-lattice-kernel/target/debug/libsealed_lattice_kernel.rlib',
                '.turbo/cache/file.json',
                'docs/dist/index.html',
                'docs/.astro/entry.mjs',
                'docs/src/content/docs/api/reference/index.md',
                'docs/public/coverage-summary.json',
            ]),
        ).toEqual([
            'Tracked build artifact is forbidden (dist output): packages/sdk/dist/index.js',
            'Tracked build artifact is forbidden (coverage output): coverage/lcov.info',
            'Tracked build artifact is forbidden (dist output): packages/wasm/dist/tsconfig.tsbuildinfo',
            'Tracked build artifact is forbidden (TypeScript build info): packages/wasm/dist/tsconfig.tsbuildinfo',
            'Tracked build artifact is forbidden (Rust target output): crates/sealed-lattice-kernel/target/debug/libsealed_lattice_kernel.rlib',
            'Tracked build artifact is forbidden (Turbo cache output): .turbo/cache/file.json',
            'Tracked build artifact is forbidden (dist output): docs/dist/index.html',
            'Tracked build artifact is forbidden (Astro cache output): docs/.astro/entry.mjs',
            'Tracked build artifact is forbidden (generated docs reference output): docs/src/content/docs/api/reference/index.md',
            'Tracked build artifact is forbidden (coverage output): docs/public/coverage-summary.json',
        ]);
    });

    it('accepts tracked source files and documentation inputs', () => {
        expect(
            findTrackedBuildArtifactFailures([
                'package.json',
                'packages/wasm/src/index.ts',
                'docs/src/content/docs/guides/overview.mdx',
                'test-vectors/foundation/m01-byte-buffer-roundtrip.json',
            ]),
        ).toEqual([]);
    });
});
