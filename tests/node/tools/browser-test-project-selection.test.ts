import { describe, expect, it } from 'vitest';

import {
    manualDesktopBrowserProofEvidenceTestGlobs,
    ordinaryDesktopBrowserExcludedTestGlobs,
} from '#tools/ci/browser-test-project-selection';

describe('Browser test project selection', () => {
    it('excludes every manual evidence file from the ordinary desktop lane', () => {
        expect(ordinaryDesktopBrowserExcludedTestGlobs).toEqual([
            ...manualDesktopBrowserProofEvidenceTestGlobs,
        ]);
        expect(new Set(ordinaryDesktopBrowserExcludedTestGlobs).size).toBe(
            ordinaryDesktopBrowserExcludedTestGlobs.length,
        );
    });
});
