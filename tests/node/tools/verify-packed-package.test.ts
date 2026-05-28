import { describe, expect, it } from 'vitest';

import {
    extractPublishedKernelDigest,
    hashPublishedKernelBytesSha256Hex,
    parsePackDryRunFilePaths,
    validatePublishedKernelIntegrity,
    validatePublishedPackageFilePaths,
    validatePublishedPackageMetadata,
} from '#tools/ci/verify-packed-package';

describe('packed package policy checks', () => {
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
            'dist/tsconfig.tsbuildinfo',
            'tools/lattigo-oracle/main.go',
            'go.mod',
        ]);

        expect(errors).toEqual(
            expect.arrayContaining([
                'Published package is missing required file: LICENSE',
                'Published package is missing required file: dist/kernel.js',
                'Published package must not include TypeScript build metadata: dist/tsconfig.tsbuildinfo',
                'Published package must not include internal protocol runtime: dist/internal/election-foundation/plaintext-oracle/index.js',
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
        const digest = hashPublishedKernelBytesSha256Hex(kernelBytes);
        const kernelRuntimeText = `const packagedTranscriptCoreKernelNormalizedSha256Hex = '${digest}';`;

        expect(extractPublishedKernelDigest(kernelRuntimeText)).toBe(digest);
        expect(
            validatePublishedKernelIntegrity(kernelRuntimeText, kernelBytes),
        ).toEqual([]);
        expect(
            validatePublishedKernelIntegrity(
                'const packagedTranscriptCoreKernelNormalizedSha256Hex = undefined;',
                kernelBytes,
            ),
        ).toEqual([
            'Published package kernel loader must pin the packaged transcript-core WASM digest',
        ]);
    });
});
