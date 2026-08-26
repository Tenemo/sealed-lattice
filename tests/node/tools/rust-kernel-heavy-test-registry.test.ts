import { describe, expect, it } from 'vitest';

import {
    activeHeavyRustKernelTests,
    buildHeavyRustKernelTestMatrix,
    validateHeavyRustKernelTestRegistry,
} from '#tools/ci/rust-kernel-heavy-test-registry.mjs';

describe('heavy Rust kernel test registry', () => {
    it('keeps the active source-controlled registry canonical and matrix-ready', () => {
        expect(
            validateHeavyRustKernelTestRegistry(activeHeavyRustKernelTests),
        ).toEqual(activeHeavyRustKernelTests);
        expect(
            buildHeavyRustKernelTestMatrix(activeHeavyRustKernelTests),
        ).toEqual({
            include: activeHeavyRustKernelTests.map((testFilter) => ({
                testFilter,
            })),
        });
    });

    it('refuses malformed, duplicate, and noncanonical registry entries', () => {
        for (const invalidRegistry of [
            ['ordinary_test'],
            ['heavy_rust_kernel_Uppercase'],
            ['heavy_rust_kernel_trailing_'],
            ['heavy_rust_kernel_one', 'heavy_rust_kernel_one'],
            ['heavy_rust_kernel_two', 'heavy_rust_kernel_one'],
        ]) {
            expect(() =>
                validateHeavyRustKernelTestRegistry(invalidRegistry),
            ).toThrow();
        }
    });
});
