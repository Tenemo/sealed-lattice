import { describe, expect, it } from 'vitest';

import {
    createIsolatedNpmEnvironment,
    extractPublishedKernelHash,
    hashPublishedKernelBytesSha256Hex,
    parsePackDryRunFilePaths,
    resolvePackedPackageNpmCacheDirectory,
    validatePublishedKernelIntegrity,
    validatePublishedPackageFilePaths,
    validatePublishedPackageMetadata,
} from '#tools/ci/verify-packed-package';

describe('packed package policy checks', () => {
    it('isolates npm cache writes inside the package-smoke temporary directory', () => {
        expect(
            createIsolatedNpmEnvironment('isolated-cache', {
                NPM_CONFIG_CACHE: 'ambient-cache',
                PATH: 'test-path',
            }),
        ).toEqual({
            npm_config_cache: 'isolated-cache',
            PATH: 'test-path',
        });
        expect(
            resolvePackedPackageNpmCacheDirectory('default-cache', {
                NPM_CONFIG_CACHE: 'configured-cache',
            }),
        ).toBe('configured-cache');
        expect(resolvePackedPackageNpmCacheDirectory('default-cache', {})).toBe(
            'default-cache',
        );
    });

    it('parses npm dry-run metadata into published file paths', () => {
        expect(
            parsePackDryRunFilePaths(
                JSON.stringify([
                    {
                        files: [
                            { path: 'dist/index.js' },
                            { path: 'LICENSE' },
                            { path: 'README.md' },
                        ],
                    },
                ]),
            ),
        ).toEqual(['dist/index.js', 'LICENSE', 'README.md']);
        expect(() => parsePackDryRunFilePaths('{}')).toThrow(
            'npm pack --dry-run --json returned an unexpected shape',
        );
    });

    it('rejects missing required files and leaked non-public artifacts', () => {
        const errors = validatePublishedPackageFilePaths([
            'README.md',
            'dist/index.js',
            'dist/internal/election-foundation/plaintext-oracle/index.js',
            'dist/internal/plaintext-oracle.d.ts',
            'dist/tsconfig.tsbuildinfo',
            'tools/lattigo-oracle/main.go',
            'go.mod',
        ]);

        expect(errors).toEqual(
            expect.arrayContaining([
                'Published package is missing required file: LICENSE',
                'Published package is missing required file: dist/index.d.ts',
                'Published package is missing required file: dist/index.js.map',
                'Published package is missing required file: dist/sealed-lattice-kernel.wasm',
                'Published package is missing required file: package.json',
                'Published package must not include TypeScript build metadata: dist/tsconfig.tsbuildinfo',
                'Published package must not include internal protocol runtime: dist/internal/election-foundation/plaintext-oracle/index.js',
                'Published package must not include test-only type support: dist/internal/plaintext-oracle.d.ts',
                'Published package must not include development oracle artifact: tools/lattigo-oracle/main.go',
                'Published package must not include development oracle artifact: go.mod',
            ]),
        );
    });

    it('requires sanitized package metadata and pinned kernel bytes', () => {
        expect(
            validatePublishedPackageMetadata(
                {
                    name: 'sealed-lattice',
                    description: 'wrong package summary',
                    devDependencies: {
                        '@sealed-lattice/types': 'workspace:*',
                    },
                    scripts: {
                        build: 'pnpm run build',
                    },
                },
                'Post-quantum threshold homomorphic voting library.',
            ),
        ).toEqual([
            'Published package metadata description must match the root package description',
            'Published package metadata must not include devDependencies',
            'Published package metadata must not include scripts',
        ]);

        const kernelBytes = Uint8Array.from([0]);
        const hash = hashPublishedKernelBytesSha256Hex(kernelBytes);
        const kernelRuntimeText = `const options = { expectedKernelSha256Hex: '${hash}' };`;

        expect(extractPublishedKernelHash(kernelRuntimeText)).toBe(hash);
        expect(
            validatePublishedKernelIntegrity(kernelRuntimeText, kernelBytes),
        ).toEqual([]);
        expect(
            validatePublishedKernelIntegrity(
                'const options = { expectedKernelSha256Hex: undefined };',
                kernelBytes,
            ),
        ).toEqual([
            'Published package kernel loader must pin the packaged transcript-core WASM hash',
        ]);
        const tamperedKernelBytes = Uint8Array.from([1]);
        expect(
            validatePublishedKernelIntegrity(
                kernelRuntimeText,
                tamperedKernelBytes,
            ),
        ).toEqual([
            `Published package kernel hash mismatch: expected ${hash}, received ${hashPublishedKernelBytesSha256Hex(tamperedKernelBytes)}`,
        ]);
    });
});
