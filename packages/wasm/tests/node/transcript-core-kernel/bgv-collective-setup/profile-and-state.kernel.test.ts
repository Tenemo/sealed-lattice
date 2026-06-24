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
            ringDegreeStatus: 'profile-ring',
            fullMaterialCoefficientBytes: 1_604_321_280,
            fullMaterialCoefficientMebibytes: 1530,
            streamingRequirement:
                'binary-chunked-stream-verification-with-one-commitment-resident',
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
            targetDecryptionReadiness:
                'refused until smudging proof coverage, recombination proof coverage, target proof backend, and verifier activation are complete',
        });
        expect(profile.canonicalTargetBasis.targetPrimes).toHaveLength(7);
        expect(profile.canonicalTargetBasisHash).toHaveLength(128);
        expect(profile.compactVssProfileBudget).toMatchObject({
            objectType: 'CompactVssProfileBudget',
            publicVerifier: {
                publicSetupDownloadBudgetBytes: 67_108_864,
                publicSetupProofBudgetBytes: 33_554_432,
                largestWasmBoundaryCopyBudgetBytes: 1_572_864,
            },
            recipientTrustee: {
                privateMailboxBudgetBytes: 67_108_864,
            },
            sourceTrustee: {
                totalUploadBudgetBytes: 268_435_456,
                provingTimeBudgetMilliseconds: 600_000,
            },
            persistentLocalState: {
                persistentStateBudgetBytes: 33_554_432,
                proofWitnessBudgetBytes: 16_777_216,
            },
        });
        expect(profile.compactVssProfileBudget.accountingRules).toMatchObject({
            privateMailboxBytes:
                'private recipient envelopes are reported separately from public verifier setup bytes',
            persistentProofWitnessBytes:
                'the restorable target-proof witness is reported separately from setup download bytes',
        });
        expect(profile.compactVssMatrixExpansionProfile).toMatchObject({
            objectType: 'CompactVssMatrixExpansionProfile',
            profileId: 'SealedLattice-CompactLinearCommitment-Development-v1',
            developmentScope:
                'development-only-not-certified-for-production-use',
            matrixKind: 'compact-vss-commitment-key',
            ringDegree: 32_768,
            commitmentModulusLimbIndices: [0, 1, 2],
            outputCoordinateCount: 16,
            projectionWeight: 32,
            randomnessColumnCount: 2,
            inputColumnLabels: ['message', 'randomness:0', 'randomness:1'],
            coordinateCountPerCommitment: 48,
            sampledMatrixResiduesPerCoordinate: 96,
            sampledProjectionIndicesPerCoordinate: 96,
            sampledMatrixResiduesPerCommitment: 4_608,
            sampledProjectionIndicesPerCommitment: 4_608,
            residueMultiplyAddsPerCommitment: 4_608,
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
            profileId: 'SealedLattice-CompactLinearCommitment-Development-v1',
            developmentScope:
                'development-only-not-certified-for-production-use',
            participantCount: 10,
            sourceRnsLimbCount: 17,
            targetRnsLimbCount: 7,
            thresholdDegree: 4,
            ringDegree: 32_768,
            commitmentRelation: {
                relation: 'C = A0 * m + A1 * r mod q_c',
                outputCoordinateCount: 16,
                messageWidth: 1,
                randomnessWidth: 2,
                inputColumnLabels: ['message', 'randomness:0', 'randomness:1'],
            },
            sameSecretBridgeInput: {
                targetBasisHash: profile.canonicalTargetBasisHash,
                targetBasisLimbOrder: 'profile-order-prefix',
            },
            proofCoverageInputs: {
                targetDecryptionProof:
                    'recipient-owned restored compact aggregate opening material must generate the target-bound decryption share proof without dealer state',
                recombination:
                    'target result acceptance requires denominator-cleared Lagrange recombination and decoding-margin verification',
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
            'proofExtractedOpeningNorm',
            'targetDecryptionOpeningNorm',
            'targetDecryptionRecombinationCoefficientAmplification',
        ]);
        expect(certificateInputBinding.normInputClasses[0]).toMatchObject({
            maximumRecipientTrusteePoint: 10,
            shamirCoefficientCount: 4,
            maximumOneSourceShamirScalarL1: 1_111,
            oneRecipientAggregateShamirScalarL1: 11_110,
        });
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
        expect(profile.compactVssParameterEvidence).toMatchObject({
            objectType: 'CompactVssParameterEvidence',
            profileId: 'SealedLattice-CompactLinearCommitment-Development-v1',
            developmentScope:
                'development-only-not-certified-for-production-use',
            evidenceKind: 'static-development-parameter-search-inputs',
            certificateInputBindingHash:
                profile.compactVssParameterCertificateInputBindingHash,
            commitmentShape: {
                ringDegree: 32_768,
                outputCoordinateCount: 16,
                projectionWeight: 32,
                randomnessColumnCount: 2,
                encodingRule:
                    'messages are exact canonical residues; low-bit compression and CRT packing are absent',
            },
            sampleCounts: {
                sourceCoefficientCommitments: 680,
                recipientShareCommitments: 700,
                aggregateThresholdCommitments: 70,
                totalCommitments: 1_450,
                publicSampleCount: 1_450,
            },
            normInputs: {
                maximumOneSourceShamirScalarL1: 1_111,
                oneRecipientAggregateShamirScalarL1: 11_110,
                aggregateDealerCount: 10,
                certificateInputClasses: {
                    shamirScalarL1Amplification: {
                        maximumRecipientTrusteePoint: 10,
                        shamirCoefficientCount: 4,
                    },
                    messageEncodingNorm: {
                        messageSource: 'canonical per-prime share residues',
                    },
                    targetDecryptionRecombinationCoefficientAmplification: {
                        currentEvidence:
                            'smudging and denominator-cleared recombination reports are hash-bound now; certificate-grade proof binding and norm bounds remain open',
                    },
                },
            },
            securityAssumptionInputs: {
                privacyGame:
                    'public share commitments reveal only recipient-authorized shares when the future ZK linkage proof is simulator sound for at most three corrupted recipients',
            },
            sameSecretBridgeInput: {
                targetBasisHash: profile.canonicalTargetBasisHash,
                existingSameSecretRelation:
                    'vss-constant-commitments-open-to-one-short-secret-across-q-share-limbs',
                currentStatementBinding:
                    'compact same-secret bridge statement sets bind target-basis compact constant coefficient roots to data-basis same-secret statement and proof roots; the bridge proof backend remains open',
                requiredStatementInputs: {
                    targetBasisLimbOrder: {
                        targetRnsLimbCount: 7,
                    },
                    matrixKeyBinding: 'publicMatrixSeedHash',
                    sameSecretProfile: 'same-secret-linkage-anchor',
                },
                boundary:
                    'the bridge proof is not implemented, so Q_share equals Q_target remains inactive',
            },
        });
        const requiredStatementInputs = expectRecord(
            profile.compactVssParameterEvidence.sameSecretBridgeInput
                .requiredStatementInputs,
        );
        const dataBasisProofRoots = requiredStatementInputs.dataBasisProofRoots;
        expect(Array.isArray(dataBasisProofRoots)).toBe(true);
        expect(dataBasisProofRoots).toContain('trusteeSecretCommitmentRoot');
        expect(
            profile.compactVssParameterEvidence.certificateBoundary,
        ).toContain('not a parameter certificate');
        expect(
            profile.compactVssParameterEvidence.missingCertificateInputs,
        ).toContain('reviewed MLWE estimator output for hiding');
        expect(
            profile.compactVssParameterEvidence.missingCertificateInputs,
        ).toContain(
            'target-decryption proof backend and verifier activation for compact statements',
        );
        expect(profile.compactVssParameterEvidenceHash).toHaveLength(128);
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
        expect(
            profile.currentVssMaterialBaselineReport.localStateMaterialClasses,
        ).toMatchObject({
            retainedAfterAggregation: [
                'aggregate-threshold-share-sealed',
                'target-decryption-proof-witness-sealed',
                'issued-vss-acceptance-roots',
                'issued-vss-complaint-roots',
                'setup-context',
            ],
            deletedAfterAggregation: [
                'raw-per-source-trustee-vss-shares',
                'raw-per-source-trustee-vss-openings',
                'private-vss-envelope-payloads-after-aggregation',
            ],
        });
        expect(profile.compactVssDevelopmentMeasurement).toMatchObject({
            objectType: 'CompactVssCommitmentMeasurement',
            profileId: 'SealedLattice-CompactLinearCommitment-Development-v1',
            developmentScope:
                'development-only-not-certified-for-production-use',
            sourceRnsLimbCount: 17,
            targetRnsLimbCount: 7,
            singleCompactCommitmentBytes: 384,
            fullCoefficientCommitmentBytes: 261_120,
            recipientShareCommitmentBytes: 268_800,
            aggregateThresholdCommitmentBytes: 26_880,
            totalCompactPublicCommitmentBytes: 556_800,
            currentFullCoefficientTransportBytes: 1_604_341_697,
            byteAccountingScope:
                'compact public commitment bodies only: source coefficient commitments, source-to-recipient share commitments, and recipient aggregate-threshold commitments',
            measuredPublicCommitmentRoles: [
                'source coefficient commitments',
                'source-to-recipient share commitments',
                'recipient aggregate-threshold commitments',
            ],
            projectionWeight: 32,
            byteReduction: {
                removedBytes: 1_603_784_897,
            },
            cpuWorkModel: {
                residueMultiplyAddsPerCommitment: 4_608,
                totalCommitments: 1_450,
                totalResidueMultiplyAdds: 6_681_600,
            },
        });
        expect(
            profile.compactVssDevelopmentMeasurement.excludedByteCategories,
        ).toEqual(
            expect.arrayContaining([
                'public share-linkage zero-knowledge proof bytes',
                'compact same-secret bridge proof bytes',
                'private mailbox share and opening-credential bytes',
            ]),
        );
        expect(
            profile.compactVssPrivateWitnessPayloadMeasurement,
        ).toMatchObject({
            objectType: 'CompactVssPrivateWitnessPayloadMeasurement',
            profileId: 'SealedLattice-CompactLinearCommitment-Development-v1',
            developmentScope:
                'development-only-not-certified-for-production-use',
            measurementKind:
                'static-development-compact-vss-private-opening-payload-accounting',
            participantCount: 10,
            targetRnsLimbCount: 7,
            oneSourceRecipientCredentialPayloadBytes: 786_432,
            oneRecipientPrivateMailboxCredentialPayloadBytes: 55_050_240,
            oneRecipientPersistentAggregateCredentialPayloadBytes: 5_505_024,
            allRecipientsPrivateMailboxCredentialPayloadBytes: 550_502_400,
            allRecipientsPersistentAggregateCredentialPayloadBytes: 55_050_240,
            largestSingleCredentialPayloadBytes: 786_432,
            byteAccountingScope:
                'compact private opening payload vectors only: one share vector plus opening-randomness vectors for each source-recipient target limb, and one aggregate opening payload per persisted recipient limb',
        });
        expect(
            profile.compactVssPrivateWitnessPayloadMeasurement
                .excludedByteCategories,
        ).toEqual(
            expect.arrayContaining([
                'mailbox KEM, AEAD, nonce, tag, and associated-data overhead',
                'encrypted local-state wrapper overhead',
                'future target-decryption proof bytes',
            ]),
        );
        expect(
            profile.compactVssPrivateWitnessPayloadMeasurement.budgetComparison,
        ).toMatchObject({
            privateMailboxBudgetBytes: 67_108_864,
            oneRecipientPrivateMailboxPayloadFractionOfBudget: 0.8203125,
            persistentProofWitnessBudgetBytes: 16_777_216,
            oneRecipientPersistentAggregatePayloadFractionOfBudget: 0.328125,
        });
        expect(profile.evaluatorKeyScheduleProfile).toMatchObject({
            objectType: 'EvaluatorKeyScheduleProfile',
            genericKeySwitchPolicy: 'refused-unless-explicitly-required',
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
        expect(profile.verifierStatuses).toEqual([
            'accepted',
            'pending',
            'refused',
            'aborted',
            'forkDetected',
            'outsideProfile',
        ]);
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
