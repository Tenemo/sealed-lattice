import path from 'node:path';

import { describe, expect, it } from 'vitest';

import {
    cargoFeatureArgumentsForCommandSurface,
    pinKernelHashInLoaderSource,
    resolveOutputFilePath,
    resolveWasmCommandSurface,
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

    it('resolves the command surface and Cargo feature arguments', () => {
        expect(
            resolveWasmCommandSurface(
                [],
                path.resolve(
                    repoRoot,
                    'packages',
                    'wasm',
                    'dist',
                    'sealed-lattice-kernel.wasm',
                ),
                repoRoot,
            ),
        ).toBe('internal-development');
        expect(
            resolveWasmCommandSurface(
                [],
                path.resolve(
                    repoRoot,
                    'packages',
                    'sdk',
                    'dist',
                    'sealed-lattice-kernel.wasm',
                ),
                repoRoot,
            ),
        ).toBe('public-sdk');
        expect(
            resolveWasmCommandSurface(
                ['--command-surface', 'public-sdk'],
                path.resolve(repoRoot, 'custom.wasm'),
                repoRoot,
            ),
        ).toBe('public-sdk');
        expect(() =>
            resolveWasmCommandSurface(
                ['--command-surface', 'unknown'],
                path.resolve(repoRoot, 'custom.wasm'),
                repoRoot,
            ),
        ).toThrow(
            '--command-surface must be internal-development or public-sdk',
        );

        expect(
            cargoFeatureArgumentsForCommandSurface('internal-development'),
        ).toEqual(['--features', 'target-decryption-development-commands']);
        expect(cargoFeatureArgumentsForCommandSurface('public-sdk')).toEqual(
            [],
        );
    });

    it('pins the built SDK loader hash from a generated build artifact', () => {
        const sourceText = [
            'const transcriptCoreKernelUrl = new URL("./sealed-lattice-kernel.wasm", import.meta.url);',
            'const packagedTranscriptCoreKernelNormalizedSha256Hex = undefined;',
            'export const loadTranscriptCoreKernel = createTranscriptCoreKernelLoader(transcriptCoreKernelUrl, { expectedKernelSha256Hex: packagedTranscriptCoreKernelNormalizedSha256Hex });',
        ].join('\n');
        const hash = 'a'.repeat(64);

        expect(pinKernelHashInLoaderSource(sourceText, hash)).toContain(
            [
                'const packagedTranscriptCoreKernelNormalizedSha256Hex =',
                `    '${hash}';`,
            ].join('\n'),
        );
    });

    it('updates an already pinned SDK loader hash and rejects missing assignments', () => {
        const oldHash = 'b'.repeat(64);
        const newHash = 'c'.repeat(64);
        const sourceText = `const packagedTranscriptCoreKernelNormalizedSha256Hex = '${oldHash}';`;

        expect(pinKernelHashInLoaderSource(sourceText, newHash)).toBe(
            [
                'const packagedTranscriptCoreKernelNormalizedSha256Hex =',
                `    '${newHash}';`,
            ].join('\n'),
        );
        expect(pinKernelHashInLoaderSource(sourceText, oldHash)).toBe(
            [
                'const packagedTranscriptCoreKernelNormalizedSha256Hex =',
                `    '${oldHash}';`,
            ].join('\n'),
        );
        expect(() =>
            pinKernelHashInLoaderSource(
                'const unrelated = undefined;',
                newHash,
            ),
        ).toThrow(
            'Cannot pin the transcript-core kernel hash because the loader file does not contain the expected hash assignment.',
        );
        expect(() =>
            pinKernelHashInLoaderSource(sourceText, 'not-a-hash'),
        ).toThrow('Cannot pin an invalid transcript-core kernel hash');
    });
});
