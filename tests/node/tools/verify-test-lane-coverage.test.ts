import { describe, expect, it } from 'vitest';

import {
    validateDirectBallotSetupHandoffEvidenceLane,
    validateDirectBallotSetupHandoffPublicParityCommand,
    validateRustHeavyEvidenceTestSource,
    testLaneGroupsForRelativePath,
    validateTestLaneCoverage,
} from '#tools/ci/verify-test-lane-coverage';

describe('test lane coverage verification', () => {
    it('classifies the current lane patterns', () => {
        expect(
            testLaneGroupsForRelativePath(
                'packages/protocol/tests/node/election-foundation-lifecycle.test.ts',
            ),
        ).toEqual(['node-protocol']);
        expect(
            testLaneGroupsForRelativePath(
                'packages/wasm/tests/node/transcript-core-kernel/core-kernel-and-fixtures.kernel.test.ts',
            ),
        ).toEqual(['node-kernel']);
        expect(
            testLaneGroupsForRelativePath(
                'packages/wasm/tests/node/transcript-core-kernel/bgv-collective-setup.kernel.test.ts',
            ),
        ).toEqual(['node-kernel-heavy']);
        expect(
            testLaneGroupsForRelativePath(
                'packages/sdk/tests/browser/election-foundation-public-api.browser.test.ts',
            ),
        ).toEqual(['browser']);
        expect(
            testLaneGroupsForRelativePath('tests/node/tools/run-check.test.ts'),
        ).toEqual(['node-fast']);
    });

    it('rejects browser tests that are missing the browser suffix', () => {
        expect(
            validateTestLaneCoverage([
                'packages/sdk/tests/browser/election-foundation-public-api.test.ts',
            ]),
        ).toEqual([
            'packages/sdk/tests/browser/election-foundation-public-api.test.ts is not covered by any test lane. Browser tests must use the .browser.test.ts suffix, and kernel tests must use the .kernel.test.ts suffix in a kernel test directory.',
        ]);
    });

    it('requires claim evidence tests to stay in the manual heavy accepted-setup lane', () => {
        const requiredTest = {
            claimEvidence: 'test evidence',
            relativePath: 'crates/example.rs',
            testName: 'heavy_accepted_setup_output_drives_claim',
        };

        expect(
            validateRustHeavyEvidenceTestSource(
                requiredTest,
                [
                    '#[test]',
                    '#[ignore = "heavy accepted setup test"]',
                    'fn heavy_accepted_setup_output_drives_claim() {}',
                ].join('\n'),
            ),
        ).toEqual([]);

        expect(
            validateRustHeavyEvidenceTestSource(
                requiredTest,
                [
                    '#[test]',
                    'fn heavy_accepted_setup_output_drives_claim() {}',
                ].join('\n'),
            ),
        ).toEqual([
            'crates/example.rs must define heavy_accepted_setup_output_drives_claim as an ignored heavy accepted setup test for test evidence.',
        ]);
        expect(
            validateRustHeavyEvidenceTestSource(
                {
                    ...requiredTest,
                    testName: 'setup_output_drives_claim',
                },
                [
                    '#[test]',
                    '#[ignore = "heavy accepted setup test"]',
                    'fn setup_output_drives_claim() {}',
                ].join('\n'),
            ),
        ).toEqual([
            'setup_output_drives_claim must use the heavy_accepted_setup prefix so pnpm run test:rust:kernel:heavy includes it.',
        ]);
    });

    it('requires the manual setup-handoff evidence lane to keep SDK and WASM public parity tests', () => {
        expect(validateDirectBallotSetupHandoffEvidenceLane()).toEqual([]);

        expect(
            validateDirectBallotSetupHandoffPublicParityCommand([
                {
                    args: [
                        'pnpm.cjs',
                        'exec',
                        'vitest',
                        'run',
                        'packages/sdk/tests/node/direct-encrypted-ballot-public-api.test.ts',
                    ],
                    command: 'node',
                    description:
                        'Run direct ballot setup handoff SDK/WASM public package parity tests',
                },
            ]),
        ).toEqual([
            'direct ballot setup handoff public parity command must include packages/wasm/tests/node/transcript-core-kernel/kernel-memory-and-loader.kernel.test.ts.',
        ]);
    });
});
