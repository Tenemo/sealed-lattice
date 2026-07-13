import { describe, expect, it } from 'vitest';

import { setupRequest } from './bgv-passive-setup-fixtures.js';

import { loadTranscriptCoreKernel } from '#packages/wasm/src/index';

describe('BGV passive setup kernel command', () => {
    it('deterministically generates and verifies the development setup fixture', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const setup = kernel.generateBgvPassiveSetup(setupRequest);
        const repeated = kernel.generateBgvPassiveSetup(setupRequest);

        expect(repeated.setupPackageHash).toBe(setup.setupPackageHash);
        expect(() =>
            kernel.verifyBgvPassiveSetup({
                setupPackage: setup,
                expectedSetupPackageHash: setup.setupPackageHash,
                expectedRosterHash: setupRequest.rosterHash,
                expectedCollectivePublicKeyRoot:
                    setup.collectivePublicKey.collectivePublicKeyRoot,
                expectedRotSetHash: setup.evaluationKeys.record.rotSetHash,
                expectedEvaluationKeyRoot:
                    setup.evaluationKeys.evaluationKeyRoot,
            }),
        ).not.toThrow();
    });
});
