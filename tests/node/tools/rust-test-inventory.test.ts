import { describe, expect, it } from 'vitest';

import {
    classifyRustTestInventory,
    parseLibtestListOutput,
} from '#tools/ci/rust-test-inventory';

describe('Rust test inventory', () => {
    it('parses CRLF output, removes duplicates, and ignores Cargo summary noise', () => {
        const parsedTests = parseLibtestListOutput(
            [
                'foundation::tests::ordinary: test',
                'foundation::tests::ignored: test',
                'foundation::tests::ordinary: test',
                '',
                '2 tests, 0 benchmarks',
                'Doc-tests sealed_lattice_kernel',
                '',
            ].join('\r\n'),
        );

        expect(parsedTests).toEqual([
            'foundation::tests::ignored',
            'foundation::tests::ordinary',
        ]);
    });

    it('classifies only names present in the ignored inventory as ignored', () => {
        expect(
            classifyRustTestInventory({
                allTests: [
                    'foundation::tests::ignored',
                    'foundation::tests::ordinary',
                ],
                ignoredTests: ['foundation::tests::ignored'],
            }),
        ).toEqual([
            {
                ignored: true,
                testName: 'foundation::tests::ignored',
            },
            {
                ignored: false,
                testName: 'foundation::tests::ordinary',
            },
        ]);
    });
});
