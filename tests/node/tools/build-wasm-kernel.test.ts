import path from 'node:path';

import { describe, expect, it } from 'vitest';

import { resolveOutputFilePath } from '../../../tools/ci/build-wasm-kernel';

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
});
