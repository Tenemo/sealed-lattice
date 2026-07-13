import path from 'node:path';

import { describe, expect, it } from 'vitest';

import {
    createIsolatedNpmEnvironment,
    extractPublishedKernelHash,
    hashPublishedKernelBytesSha256Hex,
    parsePackMetadata,
    parsePackedPackageSmokeArguments,
    resolvePackedPackageNpmCacheDirectory,
    validatePublishedKernelIntegrity,
    validatePublishedPackageBundle,
    validatePublishedPackageFilePaths,
} from '#tools/ci/verify-packed-package';

describe('packed package policy checks', () => {
    it('accepts only an optional retained-tarball path', () => {
        expect(parsePackedPackageSmokeArguments([])).toEqual({});
        expect(
            parsePackedPackageSmokeArguments(['--out', 'package.tgz']),
        ).toEqual({ retainedTarballPath: path.resolve('package.tgz') });
        expect(
            parsePackedPackageSmokeArguments(['--', '--out', 'package.tgz']),
        ).toEqual({ retainedTarballPath: path.resolve('package.tgz') });
        expect(() => parsePackedPackageSmokeArguments(['--out'])).toThrow(
            'Usage: verify-packed-package.ts',
        );
    });

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

    it('parses the one npm tarball and its published file paths', () => {
        expect(
            parsePackMetadata(
                JSON.stringify([
                    {
                        filename: 'sealed-lattice-0.0.19.tgz',
                        files: [
                            { path: 'dist/index.js' },
                            { path: 'LICENSE' },
                            { path: 'README.md' },
                        ],
                        integrity: 'sha512-package',
                        name: 'sealed-lattice',
                        version: '0.0.19',
                    },
                ]),
            ),
        ).toEqual({
            filename: 'sealed-lattice-0.0.19.tgz',
            filePaths: ['dist/index.js', 'LICENSE', 'README.md'],
            integrity: 'sha512-package',
            name: 'sealed-lattice',
            version: '0.0.19',
        });
        expect(() => parsePackMetadata('{}')).toThrow(
            'npm pack --json returned an unexpected shape',
        );
    });

    it('requires the exact public package file set', () => {
        const expectedFilePaths = [
            'LICENSE',
            'README.md',
            'dist/index.d.ts',
            'dist/index.js',
            'dist/index.js.map',
            'dist/sealed-lattice-kernel.wasm',
            'package.json',
        ];

        expect(validatePublishedPackageFilePaths(expectedFilePaths)).toEqual(
            [],
        );
        expect(
            validatePublishedPackageFilePaths([
                ...expectedFilePaths.slice(1),
                'unexpected.txt',
            ]),
        ).toEqual([
            expect.stringContaining('Published package file set mismatch'),
        ]);
    });

    it('requires self-contained output with a resolved kernel token', () => {
        expect(
            validatePublishedPackageBundle({
                declarationSourceText:
                    "import type { Hash } from '@noble/hashes/utils.js';\nexport type Digest = Hash;",
                runtimeSourceText:
                    "import { sha256 } from '@noble/hashes/sha2.js';\nexport { sha256 };",
            }),
        ).toEqual([]);
        expect(
            validatePublishedPackageBundle({
                declarationSourceText:
                    "export type { VerificationResult } from '@sealed-lattice/types';",
                runtimeSourceText:
                    "import { validatePollSpec } from '@sealed-lattice/protocol';\nconst hash = __SEALED_LATTICE_KERNEL_NORMALIZED_SHA256_HEX__;",
            }),
        ).toEqual(
            expect.arrayContaining([
                'Published declaration output must bundle internal workspace import "@sealed-lattice/types"',
                'Published runtime output must bundle internal workspace import "@sealed-lattice/protocol"',
                'Published runtime output contains the unresolved WASM integrity token',
            ]),
        );
    });

    it('requires pinned kernel bytes', () => {
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
