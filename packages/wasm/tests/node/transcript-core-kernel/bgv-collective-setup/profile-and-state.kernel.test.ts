import { describe, expect, it } from 'vitest';

import { setupRequest, validHash } from '../bgv-passive-setup-fixtures.js';

import { createLocalTrusteeSetupStateCommitment } from '#packages/protocol/src/setup/local-trustee-setup-state';
import { type CollectiveBgvSetupContext } from '#packages/protocol/src/setup/vss-share-verification-records';
import { loadTranscriptCoreKernel } from '#packages/wasm/src/index';

describe('collective BGV setup kernel commands', () => {
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
            issuedVssAcceptanceRoot: validHash('4'),
            issuedVssComplaintRoots: [validHash('5'), validHash('6')],
        });

        expect(
            kernel.verifyLocalTrusteeSetupState({
                setupContext,
                localStateCommitment,
            }),
        ).toMatchObject({
            trusteeIdentity: 'trustee-3',
            trusteeRosterPosition: 3,
            trusteePoint: 4,
            localStateRoot: localStateCommitment.localStateRoot,
            deletionReceiptRoot: localStateCommitment.deletionReceiptRoot,
        });
    });
});
