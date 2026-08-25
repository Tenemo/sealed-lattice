import { describe, expect, it } from 'vitest';

import { buildRustTestInventoryArguments } from '#tools/ci/rust-test-inventory';

describe('Rust test inventory command', () => {
    it('uses the requested release profile and feature set', () => {
        expect(
            buildRustTestInventoryArguments({
                cargoFeatures: ['example-feature'],
                ignoredOnly: true,
                useReleaseProfile: true,
            }),
        ).toEqual([
            'test',
            '--locked',
            '-p',
            'sealed-lattice-kernel',
            '--release',
            '--features',
            'example-feature',
            '--',
            '--ignored',
            '--list',
            '--format',
            'terse',
        ]);
    });

    it('keeps ordinary inventory in the test profile without an empty feature argument', () => {
        expect(
            buildRustTestInventoryArguments({
                cargoFeatures: [],
                ignoredOnly: false,
            }),
        ).toEqual([
            'test',
            '--locked',
            '-p',
            'sealed-lattice-kernel',
            '--',
            '--include-ignored',
            '--list',
            '--format',
            'terse',
        ]);
    });
});
