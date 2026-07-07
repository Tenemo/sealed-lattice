import { describe, expect, it } from 'vitest';

import { setupRequest, validHash } from '../bgv-passive-setup-fixtures.js';

import { createLocalTrusteeSetupStateCommitment } from '#packages/protocol/src/setup/local-trustee-setup-state';
import { type CollectiveBgvSetupContext } from '#packages/protocol/src/setup/vss-share-verification-records';
import {
    loadTranscriptCoreKernel,
    TranscriptCoreKernelCommandError,
} from '#packages/wasm/src/index';

describe('collective BGV setup kernel commands', () => {
    it('describes the accepted setup parameters and verifier states', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const parameters = kernel.describeCollectiveBgvSetupParameters();

        expect(parameters).toMatchObject({
            objectType: 'SetupPackage',
            adversaryModel: 'active-static',
            livenessModel: 'secure-with-abort',
            sharingModel: 'recipient-verified-vss',
            sharingDomain: 'per-rns-prime',
            participantCount: 10,
            qSetupComplete: 10,
            qBallotRelease: 10,
            qFinal: 10,
            qDec: 4,
            transportSchemeId:
                'sealed-lattice-setup-binary-chunked-transport-v1',
        });
        expect(parameters.qShare).toMatchObject({
            objectType: 'QSharePrimeList',
        });
        expect(parameters.qShare.primes.length).toBeGreaterThan(0);
        expect(parameters.setupParametersHash).toHaveLength(128);
        expect(parameters.setupTransport).toMatchObject({
            objectType: 'SetupTransport',
            storageQuotaBytes: 2_147_483_648,
            largestSingleBufferBytes: 1_572_864,
            streamVerificationOrder: 'ascending-chunk-index',
            lazyLoadingPolicy: 'root-addressed-large-object-loading',
        });
        expect(parameters.carryAwareVssShareRelation).toMatchObject({
            objectType: 'CarryAwareVssShareRelation',
            carryWitnessDomain: 'non-negative-bounded-integer',
        });
        expect(parameters.commitment).toMatchObject({
            objectType: 'BdlopCommitment',
        });
        expect(parameters.commitment.messageEncoding).toMatchObject({
            integerEncoding: 'crt-lifted-integer-coefficients',
        });
        expect(parameters.commitment.assumptions).toMatchObject({
            hiding: 'Module-LWE over the selected commitment modulus limbs with short centered-ternary openings',
            binding:
                'Module-SIS over the selected commitment modulus limbs for the published BDLOP matrix',
        });
        expect(parameters.evaluatorKeySchedule).toMatchObject({
            objectType: 'EvaluatorKeySchedule',
        });
        expect(
            parameters.evaluatorKeySchedule.relinearizationLevelSchedule,
        ).not.toHaveLength(0);
        expect(
            parameters.evaluatorKeySchedule.requiredGaloisKeySchedule,
        ).not.toHaveLength(0);
        expect(
            parameters.evaluatorKeySchedule.requiredGaloisSetHash,
        ).toHaveLength(128);
        expect(parameters.phaseOrder).toHaveLength(15);
        expect(parameters.requiredFinalObjects).toContain(
            'setupTransportCertificate',
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
            issuedVssAcceptanceRoot: validHash('4'),
            issuedVssComplaintRoots: [validHash('5'), validHash('6')],
        });

        expect(
            kernel.verifyLocalTrusteeSetupState({
                setupContext,
                localStateCommitment,
            }),
        ).toMatchObject({
            operation: 'verifyLocalTrusteeSetupState',
            trusteeIdentity: 'trustee-3',
            trusteeRosterPosition: 3,
            trusteePoint: 4,
            localStateRoot: localStateCommitment.localStateRoot,
            deletionReceiptRoot: localStateCommitment.deletionReceiptRoot,
        });
    });

    it('routes local trustee setup state verification errors', async () => {
        const kernel = await loadTranscriptCoreKernel();

        expect(() => {
            kernel.verifyLocalTrusteeSetupState({
                setupContext: {},
                localStateCommitment: {},
            });
        }).toThrow(TranscriptCoreKernelCommandError);
        expect(() => {
            kernel.verifyLocalTrusteeSetupState({
                setupContext: {},
                localStateCommitment: {},
            });
        }).toThrow(/setupContext\.ceremonyId is required/);
    });
});
