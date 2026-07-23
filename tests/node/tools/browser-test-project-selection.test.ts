import { describe, expect, it } from 'vitest';

import {
    manualDesktopBrowserProofEvidenceTestGlobs,
    ordinaryDesktopBrowserExcludedTestGlobs,
    proofStorageWidthBrowserEvidenceInstanceDefinitions,
    proofStorageWidthBrowserEvidenceProjectName,
    proofStorageWidthBrowserEvidenceTestGlobs,
} from '#tools/ci/browser-test-project-selection';

describe('Browser test project selection', () => {
    it('owns proof-storage width evidence in one exact Chromium selector', () => {
        expect(proofStorageWidthBrowserEvidenceProjectName).toBe(
            'chromium-proof-storage-width-evidence',
        );
        expect(proofStorageWidthBrowserEvidenceTestGlobs).toEqual([
            'packages/wasm/tests/browser/proof-storage-width-evidence.manual.browser.test.ts',
        ]);
        expect(proofStorageWidthBrowserEvidenceInstanceDefinitions).toEqual([
            {
                browser: 'chromium',
                name: 'chromium-proof-storage-width-evidence',
            },
        ]);
        expect(
            proofStorageWidthBrowserEvidenceInstanceDefinitions.every(
                (instanceDefinition) =>
                    !('provider' in instanceDefinition) &&
                    !('persistentContext' in instanceDefinition),
            ),
        ).toBe(true);
    });

    it('excludes every manual evidence file from the ordinary desktop lane', () => {
        expect(ordinaryDesktopBrowserExcludedTestGlobs).toEqual([
            ...manualDesktopBrowserProofEvidenceTestGlobs,
            ...proofStorageWidthBrowserEvidenceTestGlobs,
        ]);
        expect(new Set(ordinaryDesktopBrowserExcludedTestGlobs).size).toBe(
            ordinaryDesktopBrowserExcludedTestGlobs.length,
        );
    });
});
