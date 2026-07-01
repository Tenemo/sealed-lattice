import { describe, expect, it } from 'vitest';

import {
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
        ).toEqual(['node-kernel-fast']);
        expect(
            testLaneGroupsForRelativePath(
                'packages/wasm/tests/node/transcript-core-kernel/bgv-collective-setup/setup-package-verification.kernel.test.ts',
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
});
