import { describe, expect, it } from 'vitest';

import { CanonicalStreamInternalError } from '#packages/wasm/src/canonical-stream-runtime';
import { loadFreshTranscriptCoreKernel } from '#packages/wasm/src/index';

describe('Accepted setup session in browser WASM', () => {
    it('closes explicitly cancelled and terminally refused sessions', async () => {
        const kernel = await loadFreshTranscriptCoreKernel();
        const cancelledSession = kernel.beginAcceptedSetupSession();

        cancelledSession.cancel();
        cancelledSession.cancel();
        expect(() =>
            cancelledSession.verifyCollectiveBgvSetup({ setupPackage: {} }),
        ).toThrowError(CanonicalStreamInternalError);

        const terminalSession = kernel.beginAcceptedSetupSession();
        expect(
            terminalSession.verifyCollectiveBgvSetup({ setupPackage: {} }),
        ).toEqual({
            isValid: false,
            refusalReason: 'outsideSupportedProfile',
        });
        expect(() =>
            terminalSession.verifyCollectiveBgvSetup({ setupPackage: {} }),
        ).toThrowError(CanonicalStreamInternalError);
    });
});
