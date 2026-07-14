import { describe, expect, it } from 'vitest';

import { createLocalTrusteeSetupStateCommitment } from '#packages/protocol/src/setup/local-trustee-setup-state';
import { type CollectiveBgvSetupContext } from '#packages/protocol/src/setup/vss-share-verification-records';
import { loadTranscriptCoreKernel } from '#packages/wasm/src/index';

const validHash = (fill: string): string => fill.repeat(128);
const setupRequest = {
    ceremonyId: 'ceremony-main',
    manifestHash: validHash('a'),
    rosterHash: validHash('b'),
} as const;

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
        expect(parameters.setupParametersHash).toBe(
            '7f9ebdddb630b12e5aa3bef13381d862eaa5f66b9309692b9239b67069308058dd59b95565860d5c31de77b3a93852d694545e9343f4fb3eef9f21860d35f4dc',
        );
    });

    it('verifies protocol-built local trustee setup state commitments', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const parameters = kernel.describeCollectiveBgvSetupParameters({
            participantCount: 4,
        });
        const setupContext = {
            ceremonyId: setupRequest.ceremonyId,
            manifestHash: setupRequest.manifestHash,
            rosterHash: setupRequest.rosterHash,
            setupParametersHash: parameters.setupParametersHash,
            setupEpoch: 'setup-epoch-1',
            participantCount: 4,
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
