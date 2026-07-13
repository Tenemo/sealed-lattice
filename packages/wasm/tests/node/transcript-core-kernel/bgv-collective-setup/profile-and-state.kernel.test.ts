import { describe, expect, it } from 'vitest';

import { setupRequest, validHash } from '../bgv-passive-setup-fixtures.js';

import { createLocalTrusteeSetupStateCommitment } from '#packages/protocol/src/setup/local-trustee-setup-state';
import { type CollectiveBgvSetupContext } from '#packages/protocol/src/setup/vss-share-verification-records';
import { loadTranscriptCoreKernel } from '#packages/wasm/src/index';

describe('collective BGV setup kernel commands', () => {
    it('exposes the canonical logical-slot rotation schedule', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const parameters = kernel.describeCollectiveBgvSetupParameters();
        const expectedRotations = [
            3, 9, 81, 385, 2657, 6561, 16001, 17153, 18609, 31233, 34305, 36409,
            43691, 47297, 48385, 55105,
        ];

        expect(
            parameters.evaluatorKeySchedule.requiredGaloisKeySchedule,
        ).toEqual(
            expectedRotations.map((rotation) => ({ rotation, level: 16 })),
        );
        expect(parameters.evaluatorKeySchedule.requiredGaloisSetHash).toBe(
            'a0a69e93ae3165bd0213a2d1e418d08b5662be4e32b0f9ce2b187f753802a214ea70721b09342cc524da78168d9317c325c84f769d4b5c4d72d1f0d08e1db018',
        );
        expect(parameters.setupParametersHash).toBe(
            '9f470faca92f4ea8119273e516d3a0cab55d8036fa2690dfdf67aad78d653f1b539a063a2260c3c23da0940600151789a3deb0257f4cf5192dc30eccf5745cd2',
        );
    });

    it('verifies protocol-built local trustee setup state commitments', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const parameters = kernel.describeCollectiveBgvSetupParameters();
        const setupContext = {
            ceremonyId: setupRequest.ceremonyId,
            manifestHash: setupRequest.manifestHash,
            rosterHash: setupRequest.rosterHash,
            setupParametersHash: parameters.setupParametersHash,
            setupEpoch: 'setup-epoch-1',
        } satisfies CollectiveBgvSetupContext;
        const localStateCommitment = createLocalTrusteeSetupStateCommitment({
            setupContext,
            trusteeIdentity: 'trustee-3',
            trusteeRosterPosition: 3,
            thresholdShareCommitmentRecipientRoot: validHash('1'),
            aggregateThresholdShareRoot: validHash('2'),
        });

        expect(
            kernel.verifyLocalTrusteeSetupState({
                setupContext,
                localStateCommitment,
            }),
        ).toMatchObject({
            trusteeIdentity: 'trustee-3',
            trusteeRosterPosition: 3,
            localStateRoot: localStateCommitment.localStateRoot,
        });
    });
});
