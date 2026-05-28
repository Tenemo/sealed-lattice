import { describe, expect, it } from 'vitest';

import { canonicalErrorCodes, loadTranscriptCoreKernel } from '../../src/index';

describe('Canonical error code parity', () => {
    it('matches the Rust kernel enum exactly', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const fromKernel = kernel.listCanonicalErrorCodes();
        const fromBridge = [...canonicalErrorCodes].sort();
        const fromKernelSorted = [...fromKernel].sort();

        expect(fromKernelSorted).toEqual(fromBridge);
    });
});
