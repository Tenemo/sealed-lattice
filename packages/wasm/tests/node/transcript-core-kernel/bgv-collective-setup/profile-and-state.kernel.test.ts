import { describe, expect, it } from 'vitest';

import { setupRequest, validHash } from '../bgv-passive-setup-fixtures.js';

import { setupTransportChunkSizeBytes } from './setup-fixture-primitives.js';

import { createLocalTrusteeSetupStateCommitment } from '#packages/protocol/src/setup/local-trustee-setup-state';
import { type CollectiveBgvSetupContext } from '#packages/protocol/src/setup/vss-share-verification-records';
import {
    loadTranscriptCoreKernel,
    TranscriptCoreKernelCommandError,
} from '#packages/wasm/src/index';

function expectRecord(value: unknown): Record<string, unknown> {
    expect(value).toBeTypeOf('object');
    expect(value).not.toBeNull();
    expect(Array.isArray(value)).toBe(false);
    return value as Record<string, unknown>;
}

describe('collective BGV setup kernel commands', () => {
    it('describes the accepted setup profile and compact verifier states', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const profile = kernel.describeCollectiveBgvSetupProfile();

        expect(profile).toMatchObject({
            setupProfileId: 'CollectiveBgvSetup-v1',
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
            transportProfileId:
                'sealed-lattice-setup-binary-chunked-transport-v1',
        });
        expect(profile.qShare).toMatchObject({
            objectType: 'QSharePrimeList',
            sharingDomain: 'per-rns-prime',
            primeOrder: 'profile-order',
        });
        expect(profile.qShare.primes.length).toBeGreaterThan(0);
        expect(profile.qShareHash).toHaveLength(128);
        expect(profile.publicVssCommitmentMaterialSizeProfile).toMatchObject({
            objectType: 'PublicVssCommitmentMaterialSizeProfile',
            ringDegree: 32768,
            fullMaterialCoefficientBytes: 1_604_321_280,
            fullMaterialCoefficientMebibytes: 1530,
        });
        expect(profile.publicVssCommitmentMaterialSizeProfileHash).toHaveLength(
            128,
        );
        expect(profile.setupTransportProfile).toMatchObject({
            objectType: 'SetupTransportProfile',
            transportProfileId:
                'sealed-lattice-setup-binary-chunked-transport-v1',
            chunkSizeBytes: setupTransportChunkSizeBytes,
            storageQuotaBytes: 2_147_483_648,
            largestSingleBufferBytes: 1_572_864,
            streamVerificationOrder: 'ascending-chunk-index',
            lazyLoadingPolicy: 'root-addressed-large-object-loading',
        });
        expect(profile.setupTransportProfileHash).toHaveLength(128);
        expect(profile.carryAwareVssShareRelationProfile).toMatchObject({
            objectType: 'CarryAwareVssShareRelationProfile',
            sharingDomain: 'per-rns-prime',
            carryWitnessDomain: 'non-negative-bounded-integer',
        });
        expect(profile.carryAwareVssShareRelationProfileHash).toHaveLength(128);
        expect(profile.commitmentProfile).toMatchObject({
            objectType: 'BdlopCommitmentProfile',
        });
        expect(profile.commitmentProfile.messageEncoding).toMatchObject({
            integerEncoding: 'crt-lifted-integer-coefficients',
        });
        expect(profile.commitmentProfile.assumptions).toMatchObject({
            hiding: 'Module-LWE over the selected commitment modulus limbs with short centered-ternary openings',
            binding:
                'Module-SIS over the selected commitment modulus limbs for the published BDLOP matrix',
            requiredCertificates: [
                'SetupCommitmentSecurityCertificate',
                'SetupProofAccountingCertificate',
            ],
        });
        expect(profile.commitmentProfileHash).toHaveLength(128);
        expect(profile.canonicalTargetBasis).toMatchObject({
            objectType: 'CanonicalTargetBasis',
            targetLevel: 6,
            primeOrder: 'profile-order-prefix',
            modulusSwitchSchedule: {
                sourceWorkingLevel: 15,
                terminalLevel: 6,
            },
            targetCiphertextRule:
                'target id and target order ciphertexts must both use the canonical target level',
        });
        expect(profile.canonicalTargetBasis.targetPrimes).toHaveLength(7);
        expect(profile.canonicalTargetBasisHash).toHaveLength(128);
        expect(profile.compactVssMatrixExpansionProfile).toMatchObject({
            objectType: 'CompactVssMatrixExpansionProfile',
            profileId: 'sealed-lattice-compact-vss-sparse-linear-v1',
            matrixKind: 'compact-vss-commitment-key',
            ringDegree: 32_768,
            commitmentModulusLimbIndices: [0, 1, 2],
            outputCoordinateCount: 16,
            projectionWeight: 32,
            randomnessColumnCount: 2,
            inputColumnLabels: [
                'message:0',
                'message:1',
                'randomness:0',
                'randomness:1',
            ],
            coordinateCountPerCommitment: 48,
            sampledMatrixResiduesPerCoordinate: 128,
            sampledProjectionIndicesPerCoordinate: 128,
            sampledMatrixResiduesPerCommitment: 6_144,
            sampledProjectionIndicesPerCommitment: 6_144,
            residueMultiplyAddsPerCommitment: 6_144,
        });
        expect(
            profile.compactVssMatrixExpansionProfile
                .matrixResiduePreimageFields,
        ).toEqual(
            expect.arrayContaining([
                'publicMatrixSeedHash',
                'inputColumn',
                'projectionTermIndex',
            ]),
        );
        expect(profile.compactVssMatrixExpansionProfileHash).toHaveLength(128);
        const certificateInputBinding =
            profile.compactVssParameterCertificateInputBinding;
        expect(certificateInputBinding).toMatchObject({
            objectType: 'CompactVssParameterCertificateInputBinding',
            objectVersion: 2,
            profileId: 'sealed-lattice-compact-vss-sparse-linear-v1',
            participantCount: 10,
            sourceRnsLimbCount: 17,
            targetRnsLimbCount: 7,
            thresholdDegree: 4,
            ringDegree: 32_768,
            commitmentRelation: {
                relation:
                    'C = A_message_0 * m_0 + A_message_1 * m_1 + A_randomness * r mod q_c',
                outputCoordinateCount: 16,
                messageWidth: 2,
                randomnessWidth: 2,
                projectionWeight: 32,
                coordinateCountPerCommitment: 48,
                inputColumnLabels: [
                    'message:0',
                    'message:1',
                    'randomness:0',
                    'randomness:1',
                ],
            },
            commonCommitmentKey: {
                sparseProjectionShape: {
                    inputColumnCount: 4,
                    projectionWeight: 32,
                    coordinateCountPerCommitment: 48,
                    sampledMatrixResiduesPerCoordinate: 128,
                    sampledProjectionIndicesPerCoordinate: 128,
                    sampledMatrixResiduesPerCommitment: 6_144,
                    sampledProjectionIndicesPerCommitment: 6_144,
                },
            },
            sameSecretBridgeInput: {
                targetBasisHash: profile.canonicalTargetBasisHash,
                targetBasisLimbOrder: 'profile-order-prefix',
            },
        });
        expect(
            certificateInputBinding.normInputClasses.map((entry) =>
                String(entry.className),
            ),
        ).toStrictEqual([
            'shamirScalarL1Amplification',
            'messageEncodingNorm',
            'openingRandomnessNorm',
            'aggregateDealerCount',
        ]);
        expect(certificateInputBinding.normInputClasses[0]).toMatchObject({
            maximumRecipientTrusteePoint: 10,
            shamirCoefficientCount: 4,
            maximumOneSourceShamirScalarL1: 1_111,
            oneRecipientAggregateShamirScalarL1: 11_110,
        });
        expect(certificateInputBinding.normInputClasses[1]).toMatchObject({
            sourceCoefficientUpperBoundMultiplier: 1,
            recipientShareCoefficientUpperBoundMultiplier: 1,
            aggregateCoefficientUpperBoundMultiplier: 10,
        });
        expect(certificateInputBinding.parameterReviewInputs).toMatchObject({
            inputVersion: 1,
            openingWitnessRows: [
                expect.objectContaining({
                    rowId: 'compact-vss-fresh-opening-witness',
                    witnessCoefficientCount: 131_072,
                    randomnessDifferenceInfinityBound: 2,
                }),
                expect.objectContaining({
                    rowId: 'compact-vss-aggregate-opening-witness',
                    messageCoefficientUpperBoundMultiplier: 10,
                    randomnessDifferenceInfinityBound: 20,
                }),
            ],
            linearRelationRows: [
                expect.objectContaining({
                    rowId: 'compact-vss-recipient-share-shamir-evaluation',
                    combinedRelationTermL1: 1_112,
                }),
                expect.objectContaining({
                    rowId: 'compact-vss-aggregate-threshold-public-sum',
                    combinedRelationTermL1: 11,
                }),
                expect.objectContaining({
                    rowId: 'compact-vss-one-recipient-aggregate-from-source-coefficients',
                    oneRecipientAggregateShamirScalarL1: 11_110,
                }),
            ],
            targetBasisReductionRows: [
                expect.objectContaining({
                    rowId: 'compact-vss-same-secret-bridge-target-reduction',
                    sourceSignedRepresentativeInfinityBound: 1,
                    targetBasisHash: profile.canonicalTargetBasisHash,
                }),
            ],
        });
        expect(certificateInputBinding.estimatorInputRows).toEqual([
            expect.objectContaining({
                rowId: 'compact-vss-module-sis-binding-input',
                problem: 'Module-SIS',
                outputCoordinateCount: 16,
                projectionWeight: 32,
                sampledMatrixResiduesPerCommitment: 6_144,
                sampledProjectionIndicesPerCommitment: 6_144,
            }),
            expect.objectContaining({
                rowId: 'compact-vss-module-lwe-hiding-input',
                problem: 'Module-LWE',
                outputCoordinateCount: 16,
                projectionWeight: 32,
                sampledMatrixResiduesPerCommitment: 6_144,
                sampledProjectionIndicesPerCommitment: 6_144,
            }),
        ]);
        const sameSecretBridgeInput = expectRecord(
            certificateInputBinding.sameSecretBridgeInput,
        );
        expect(sameSecretBridgeInput.targetRnsPrimes).toHaveLength(7);
        const {
            compactVssParameterCertificateInputBindingHash: bindingHash,
            ...certificateInputBindingBody
        } = certificateInputBinding;
        expect(bindingHash).toBe(
            profile.compactVssParameterCertificateInputBindingHash,
        );
        expect(profile.compactVssParameterCertificateInputBindingHash).toBe(
            kernel.deriveProtocolHash({
                namespace: 'CompactVssParameterCertificateInputBindingHash',
                value: certificateInputBindingBody,
            }),
        );
        expect(profile.currentVssMaterialBaselineReport).toMatchObject({
            objectType: 'CurrentVssMaterialBaselineReport',
            materialRecordCount: 680,
            singleCommitmentCoefficientBytes: 2_359_296,
            fullMaterialCoefficientBytes: 1_604_321_280,
            exactBinaryTransportBytes: 1_604_341_697,
            binaryTransportMetadataBytes: 20_417,
            publicVerificationMemoryEstimate: {
                lowerBoundBytes: 3_407_872,
                largestWasmBoundaryCopyBytes: 1_572_864,
            },
            trusteePointScalarBounds: {
                oneSourceMaximumShamirScalarL1: 1_111,
                oneRecipientAggregateShamirScalarL1: 11_110,
            },
            normModel: {
                shamirScalarL1Amplification: 1_111,
                aggregateDealerCount: 10,
            },
        });
        expect(profile.evaluatorKeyScheduleProfile).toMatchObject({
            objectType: 'EvaluatorKeyScheduleProfile',
        });
        expect(
            profile.evaluatorKeyScheduleProfile.relinearizationLevelSchedule,
        ).not.toHaveLength(0);
        expect(
            profile.evaluatorKeyScheduleProfile.requiredGaloisKeySchedule,
        ).not.toHaveLength(0);
        expect(
            profile.evaluatorKeyScheduleProfile.requiredGaloisSetHash,
        ).toHaveLength(128);
        expect(profile.evaluatorKeyScheduleProfileHash).toHaveLength(128);
        expect(profile.phaseOrder).toHaveLength(15);
        expect(profile.requiredFinalObjects).toContain(
            'setupTransportCertificate',
        );
    });

    it('verifies protocol-built local trustee setup state commitments', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const profile = kernel.describeCollectiveBgvSetupProfile();
        const setupContext = {
            ceremonyId: setupRequest.ceremonyId,
            manifestHash: setupRequest.manifestHash,
            rosterHash: setupRequest.rosterHash,
            setupProfileHash: profile.setupProfileHash,
            qShareHash: profile.qShareHash,
            carryAwareVssShareRelationProfileHash:
                profile.carryAwareVssShareRelationProfileHash,
            commitmentProfileHash: profile.commitmentProfileHash,
            setupEpoch: 'setup-epoch-1',
        } satisfies CollectiveBgvSetupContext;
        const localStateCommitment = createLocalTrusteeSetupStateCommitment({
            setupContext,
            trusteeIdentity: 'trustee-3',
            trusteeRosterPosition: 3,
            thresholdShareCommitmentRecipientRoot: validHash('1'),
            aggregateThresholdShareRoot: validHash('2'),
            targetDecryptionProofWitnessRoot: validHash('3'),
            issuedVssAcceptanceRoot: validHash('4'),
            issuedVssComplaintRoots: [validHash('5'), validHash('6')],
        });

        expect(
            kernel.verifyLocalTrusteeSetupState({
                setupContext,
                localStateCommitment,
            }),
        ).toMatchObject({
            ok: true,
            operation: 'verifyLocalTrusteeSetupState',
            trusteeIdentity: 'trustee-3',
            trusteeRosterPosition: 3,
            trusteePoint: 4,
            localStateRoot: localStateCommitment.localStateRoot,
            deletionReceiptRoot: localStateCommitment.deletionReceiptRoot,
            targetDecryptionProofWitnessRoot:
                localStateCommitment.targetDecryptionProofWitnessRoot,
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
