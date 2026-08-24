import { describe, expect, it } from 'vitest';

import { buildRustTestInventoryArguments } from '#tools/ci/rust-test-inventory';

describe('Rust test inventory command', () => {
    it('uses the owning release profile and feature set for measurement inventory', () => {
        expect(
            buildRustTestInventoryArguments({
                cargoFeatures: ['primitive-measurement-evidence'],
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
            'primitive-measurement-evidence',
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
