import path from 'node:path';

import { describe, expect, it } from 'vitest';

import {
    pinSdkKernelDigestInLoaderSource,
    resolveOutputFilePath,
} from '#tools/ci/build-wasm-kernel';

const repoRoot = path.resolve('C:\\repo\\sealed-lattice');

describe('WASM kernel build helpers', () => {
    it('resolves the default output inside the repository', () => {
        expect(resolveOutputFilePath([], repoRoot)).toBe(
            path.resolve(
                repoRoot,
                'packages',
                'wasm',
                'dist',
                'sealed-lattice-kernel.wasm',
            ),
        );
    });

    it('rejects absolute and escaping output paths', () => {
        expect(() =>
            resolveOutputFilePath(
                ['--out', path.resolve('C:\\outside.wasm')],
                repoRoot,
            ),
        ).toThrow('--out must be repository-relative');
        expect(() =>
            resolveOutputFilePath(['--out', '..\\outside.wasm'], repoRoot),
        ).toThrow('--out must resolve inside the repository');
    });

    it('pins the built SDK loader digest from a generated build artifact', () => {
        const sourceText = [
            'const transcriptCoreKernelUrl = new URL("./sealed-lattice-kernel.wasm", import.meta.url);',
            'const packagedTranscriptCoreKernelNormalizedSha256Hex = undefined;',
            'export const loadTranscriptCoreKernel = createTranscriptCoreKernelLoader(transcriptCoreKernelUrl, { expectedKernelSha256Hex: packagedTranscriptCoreKernelNormalizedSha256Hex });',
        ].join('\n');
        const digest = 'a'.repeat(64);

        expect(pinSdkKernelDigestInLoaderSource(sourceText, digest)).toContain(
            `const packagedTranscriptCoreKernelNormalizedSha256Hex = '${digest}';`,
        );
    });

    it('updates an already pinned SDK loader digest and rejects missing assignments', () => {
        const oldDigest = 'b'.repeat(64);
        const newDigest = 'c'.repeat(64);
        const sourceText = `const packagedTranscriptCoreKernelNormalizedSha256Hex = '${oldDigest}';`;

        expect(pinSdkKernelDigestInLoaderSource(sourceText, newDigest)).toBe(
            `const packagedTranscriptCoreKernelNormalizedSha256Hex = '${newDigest}';`,
        );
        expect(() =>
            pinSdkKernelDigestInLoaderSource(
                'const unrelated = undefined;',
                newDigest,
            ),
        ).toThrow(
            'Cannot pin the transcript-core kernel digest because packages/sdk/dist/kernel.js does not contain the expected digest assignment.',
        );
        expect(() =>
            pinSdkKernelDigestInLoaderSource(sourceText, 'not-a-digest'),
        ).toThrow('Cannot pin an invalid transcript-core kernel digest');
    });
});
