import { describe, expect, it } from 'vitest';

import {
    contextFields,
    createSameSecretConsistencyStatementSet,
    createVssCoefficientCommitmentBundle,
    galoisShareMaterial,
    hashFromKernel,
    loadPublicTranscriptCoreKernel,
    participantCount,
    phaseTranscriptFixture,
    publicKeyShareMaterialContribution,
    publicKeyShareSuccinctProofMaterial,
    publicSetupApi,
    qSharePrimes,
    relinearizationShareMaterial,
    requiredGaloisKeySchedule,
    sameSecretProofMaterial,
    sameSecretProofReferencesFromSet,
    setupContextFromKernel,
    setupTransportChunkSizeBytes,
    vssFixtureRingDegree,
    vssFixtureThresholdDegree,
    vssSourceTrusteeOpeningState,
} from './support.js';

describe('accepted setup public package API in Node', () => {
    it('assembles public key and evaluation-key records from proof material only', async () => {
        const kernel = await loadPublicTranscriptCoreKernel();
        const setupParameters = kernel.describeCollectiveBgvSetupParameters();
        const bgvParameters = kernel.describeBgvRnsParameters();
        const setupContext = setupContextFromKernel(kernel);
        const publicMatrixSeedHash = hashFromKernel(
            kernel,
            'key-record-public-matrix-seed',
        );
        const publicDerivations =
            kernel.deriveCollectiveBgvSetupPublicDerivations({
                publicMatrixSeedHash,
            });
        const publicKeyCrpRoot = publicDerivations.crpRoots.publicKeyCrpRoot;
        const publicAPolynomialRoot =
            publicDerivations.bgvPublicA.publicPolynomialRoot;
        const relinearizationCrpRoot =
            publicDerivations.crpRoots.relinearizationCrpRoot;
        const galoisKeyCrpRoot = publicDerivations.crpRoots.galoisKeyCrpRoot;
        const vssCoefficientCommitmentBundle =
            createVssCoefficientCommitmentBundle({
                setupContext: setupContext,
                publicMatrixSeedHash,
                setupCommitmentComputer: (commitmentOpeningInput) =>
                    kernel.computeSetupCommitmentFromOpening(
                        commitmentOpeningInput,
                    ),
                qSharePrimes,
                ringDegree: vssFixtureRingDegree,
                participantCount,
                thresholdDegree: vssFixtureThresholdDegree,
                sourceTrusteeOpeningStates: Array.from(
                    { length: participantCount },
                    (_unused, sourceTrusteeRosterPosition) =>
                        vssSourceTrusteeOpeningState(
                            sourceTrusteeRosterPosition,
                        ),
                ),
            });
        const vssCoefficientCommitments =
            vssCoefficientCommitmentBundle.commitmentSet;
        const vssCoefficientCommitmentMaterial =
            vssCoefficientCommitmentBundle.materialSet;
        const sameSecretConsistency = createSameSecretConsistencyStatementSet({
            setupContext: setupContext,
            qSharePrimes,
            participantCount,
            thresholdDegree: vssFixtureThresholdDegree,
            vssCoefficientCommitments,
        });
        const publicKeyShareMaterialContributions = Array.from(
            { length: participantCount },
            (_unused, shareRosterPosition) =>
                publicKeyShareMaterialContribution(shareRosterPosition),
        );
        const shareContributions = publicKeyShareMaterialContributions.map(
            (materialContribution) => ({
                trusteeIdentity: materialContribution.trusteeIdentity,
                trusteeRosterPosition:
                    materialContribution.trusteeRosterPosition,
                shareCoefficientVectorHash512ByLimb: (
                    materialContribution.shareCoefficientVectorsByLimb as readonly Record<
                        string,
                        unknown
                    >[]
                ).map((coefficientVector) => ({
                    rnsLimbIndex: coefficientVector.rnsLimbIndex,
                    rnsPrime: coefficientVector.rnsPrime,
                    component: coefficientVector.component,
                    coefficientVectorHash512:
                        coefficientVector.coefficientVectorHash512,
                })),
            }),
        );

        const publicKeyShares = publicSetupApi.createPublicKeyShareSet({
            setupContext,
            qSharePrimes,
            participantCount,
            publicMatrixSeedHash,
            publicKeyCrpRoot,
            publicAPolynomialRoot,
            sameSecretConsistency,
            shareContributions,
        });
        const publicKeyShareProofs =
            publicSetupApi.createPublicKeyShareProofSet({
                setupContext,
                qSharePrimes,
                participantCount,
                publicMatrixSeedHash,
                publicKeyCrpRoot,
                publicAPolynomialRoot,
                sameSecretConsistency,
                publicKeyShares,
            });
        const sameSecretProofs = publicSetupApi.createSameSecretProofSet({
            setupContext,
            qSharePrimes,
            participantCount,
            sameSecretConsistency,
            vssCoefficientCommitmentMaterial,
            proofMaterials: (
                sameSecretConsistency.statementRecords as readonly Record<
                    string,
                    unknown
                >[]
            ).map((statementRecord) =>
                sameSecretProofMaterial(kernel, statementRecord),
            ),
        });
        const publicKeyShareMaterial =
            publicSetupApi.createPublicKeyShareMaterialSet({
                setupContext,
                qSharePrimes,
                participantCount,
                ringDegree: vssFixtureRingDegree,
                publicMatrixSeedHash,
                publicKeyCrpRoot,
                publicAPolynomialRoot,
                publicKeyShares,
                materialContributions: publicKeyShareMaterialContributions,
            });
        const publicKeyShareSuccinctProofs =
            publicSetupApi.createPublicKeyShareSuccinctProofSet({
                setupContext,
                qSharePrimes,
                participantCount,
                publicMatrixSeedHash,
                publicKeyCrpRoot,
                publicAPolynomialRoot,
                sameSecretConsistency,
                sameSecretProofs,
                publicKeyShares,
                publicKeyShareProofs,
                publicKeyShareMaterial,
                proofMaterials: (
                    publicKeyShareProofs.proofRecords as readonly Record<
                        string,
                        unknown
                    >[]
                ).map((proofRecord) =>
                    publicKeyShareSuccinctProofMaterial(kernel, proofRecord),
                ),
            });
        const evaluatorKeySchedule = publicSetupApi.createEvaluatorKeySchedule({
            setupContext,
            qSharePrimes,
            participantCount,
            publicMatrixSeedHash,
            relinearizationCrpRoot,
            galoisKeyCrpRoot,
            sameSecretConsistency,
            publicKeyShares,
            publicKeyShareProofs,
            requiredGaloisKeySchedule,
        });
        const relinearizationLevelSchedule =
            evaluatorKeySchedule.relinearizationLevelSchedule as readonly {
                readonly level: number;
            }[];
        const sameSecretProofReferences =
            sameSecretProofReferencesFromSet(sameSecretProofs);
        const commonEvaluationKeyInput = {
            setupContext,
            qSharePrimes,
            participantCount,
            evaluatorKeySchedule,
            sameSecretProofSetRoot: sameSecretProofs.sameSecretProofSetRoot,
            sameSecretProofFamilyBindingRoot:
                sameSecretConsistency.sameSecretProofFamilyBindingRoot,
            publicKeyShareSuccinctProofSetRoot:
                publicKeyShareSuccinctProofs.publicKeyShareSuccinctProofSetRoot,
            sameSecretProofReferences,
        };
        const relinearizationLevels = relinearizationLevelSchedule.map(
            (scheduleEntry) => scheduleEntry.level,
        );
        const roundOneContributions = sameSecretProofReferences.flatMap(
            (reference) =>
                relinearizationLevels.map((level) => {
                    const contributionLabel = `${String(reference.trusteeRosterPosition)}-${String(level)}`;
                    const roundOneShareRoot = hashFromKernel(
                        kernel,
                        `round-one-share-${contributionLabel}`,
                    );

                    return {
                        trusteeRosterPosition: reference.trusteeRosterPosition,
                        level,
                        roundOneShareRoot,
                        shareMaterial: relinearizationShareMaterial(
                            kernel,
                            evaluatorKeySchedule,
                            roundOneShareRoot,
                            `round-one-${contributionLabel}`,
                            'round-one',
                            level,
                        ),
                    };
                }),
        );
        const roundTwoContributions = sameSecretProofReferences.flatMap(
            (reference) =>
                relinearizationLevels.map((level) => {
                    const contributionLabel = `${String(reference.trusteeRosterPosition)}-${String(level)}`;
                    const roundTwoShareRoot = hashFromKernel(
                        kernel,
                        `round-two-share-${contributionLabel}`,
                    );

                    return {
                        trusteeRosterPosition: reference.trusteeRosterPosition,
                        level,
                        roundTwoShareRoot,
                        shareMaterial: relinearizationShareMaterial(
                            kernel,
                            evaluatorKeySchedule,
                            roundTwoShareRoot,
                            `round-two-${contributionLabel}`,
                            'round-two',
                            level,
                        ),
                    };
                }),
        );
        const relinearizationKeyShareRounds =
            publicSetupApi.createRelinearizationKeyShareRounds({
                ...commonEvaluationKeyInput,
                roundOneContributions,
                roundTwoContributions,
            });
        const galoisKeyShareBatches =
            publicSetupApi.createGaloisKeyShareBatches({
                ...commonEvaluationKeyInput,
                batchContributions: sameSecretProofReferences.map(
                    (reference) => ({
                        trusteeRosterPosition: reference.trusteeRosterPosition,
                        galoisKeyShares: requiredGaloisKeySchedule.map(
                            (scheduleEntry) => {
                                const galoisKeyShareRoot = hashFromKernel(
                                    kernel,
                                    `galois-share-${String(reference.trusteeRosterPosition)}-${String(scheduleEntry.rotation)}`,
                                );

                                return {
                                    rotation: scheduleEntry.rotation,
                                    level: scheduleEntry.level,
                                    galoisKeyShareRoot,
                                    shareMaterial: galoisShareMaterial(
                                        kernel,
                                        evaluatorKeySchedule,
                                        galoisKeyShareRoot,
                                        `${String(reference.trusteeRosterPosition)}-${String(scheduleEntry.rotation)}`,
                                        scheduleEntry.rotation,
                                        scheduleEntry.level,
                                    ),
                                };
                            },
                        ),
                    }),
                ),
            });
        const publicEvaluationKeys =
            publicSetupApi.createPublicEvaluationKeySet({
                ...commonEvaluationKeyInput,
                relinearizationKeyShareRounds,
                galoisKeyShareBatches,
            });
        const trusteeEvaluationKeyProofsWithoutRoot = {
            objectType: 'TrusteeEvaluationKeyProofSet',
            relinearizationKeyShareRoundsRoot:
                relinearizationKeyShareRounds.relinearizationKeyShareRoundsRoot,
            proofRecords: [],
        };
        const trusteeEvaluationKeyProofs = {
            ...trusteeEvaluationKeyProofsWithoutRoot,
            trusteeEvaluationKeyProofSetRoot: kernel.deriveCanonicalObjectHash({
                value: trusteeEvaluationKeyProofsWithoutRoot,
            }),
        };
        const privateVssEnvelopeCommitmentRoot = hashFromKernel(
            kernel,
            'package-private-vss-envelope-root',
        );
        const transportedCompanionObjects = [
            {
                objectName: 'sameSecretProofMaterial',
                objectRole: 'same-secret-proof-material',
                objectRoot: sameSecretProofs.sameSecretProofSetRoot,
            },
            {
                objectName: 'publicKeyShareMaterial',
                objectRole: 'public-key-share-material',
                objectRoot:
                    publicKeyShareMaterial.publicKeyShareMaterialSetRoot,
            },
            {
                objectName: 'publicKeyShareProofMaterial',
                objectRole: 'public-key-share-proof-material',
                objectRoot:
                    publicKeyShareSuccinctProofs.publicKeyShareSuccinctProofSetRoot,
            },
            {
                objectName: 'evaluationKeyShareComponentMaterial',
                objectRole: 'evaluation-key-share-component-material',
                objectRoot:
                    relinearizationKeyShareRounds.relinearizationKeyShareRoundsRoot,
            },
            {
                objectName: 'evaluationKeyShareProofMaterial',
                objectRole: 'evaluation-key-share-proof-material',
                objectRoot:
                    trusteeEvaluationKeyProofs.trusteeEvaluationKeyProofSetRoot,
            },
            {
                objectName: 'publicEvaluationKeyMaterial',
                objectRole: 'public-evaluation-key-material',
                objectRoot: hashFromKernel(
                    kernel,
                    'public-evaluation-key-material-root',
                ),
            },
        ].map((transportedObject, transportedObjectIndex) => ({
            ...transportedObject,
            byteLength: 4 + transportedObjectIndex,
            fullObjectHash: hashFromKernel(
                kernel,
                `transported-companion-full-object-${String(transportedObjectIndex)}`,
            ),
            chunkRoot: hashFromKernel(
                kernel,
                `transported-companion-chunk-root-${String(transportedObjectIndex)}`,
            ),
            chunkHashes: [
                hashFromKernel(
                    kernel,
                    `transported-companion-chunk-${String(transportedObjectIndex)}`,
                ),
            ],
        }));
        const transportedCompanionByteLength =
            transportedCompanionObjects.reduce(
                (totalByteLength, transportedObject) =>
                    totalByteLength + transportedObject.byteLength,
                0,
            );
        const setupTransport = {
            fullObjectHash: hashFromKernel(
                kernel,
                'setup-transport-full-object',
            ),
            chunkHashes: [
                hashFromKernel(kernel, 'setup-transport-companion-chunk'),
            ],
            transportedObjects: transportedCompanionObjects,
        };
        const setupCertificates = publicSetupApi.createSetupCertificates({
            setupParameters: setupParameters,
            bgvParameters: bgvParameters,
            transport: setupTransport,
        });
        expect(() =>
            publicSetupApi.createSetupCertificates({
                setupParameters: setupParameters,
                bgvParameters: bgvParameters,
                transport: {
                    ...setupTransport,
                    transportedObjects: [
                        transportedCompanionObjects[0],
                        {
                            ...transportedCompanionObjects[1],
                            objectRoot:
                                transportedCompanionObjects[0].objectRoot,
                        },
                    ],
                },
            }),
        ).toThrow(/duplicate object roots/u);
        expect(() =>
            publicSetupApi.createSetupCertificates({
                setupParameters: setupParameters,
                bgvParameters: bgvParameters,
                transport: {
                    ...setupTransport,
                    transportedObjects: [
                        {
                            ...transportedCompanionObjects[0],
                            byteLength: setupTransportChunkSizeBytes + 1,
                        },
                    ],
                },
            }),
        ).toThrow(/chunkHashes length/u);
        const setupTransportCertificate =
            setupCertificates.setupTransportCertificate as Record<
                string,
                unknown
            >;
        const commonRandomnessWithoutRoot = {
            objectType: 'SetupCommonRandomness',
            ceremonyId: setupContext.ceremonyId,
            manifestHash: setupContext.manifestHash,
            rosterHash: setupContext.rosterHash,
            setupParametersHash: setupContext.setupParametersHash,
            setupEpoch: setupContext.setupEpoch,
            publicMatrixSeedHash,
            publicDerivations,
            commitRecords: [],
            revealRecords: [],
        } as const;
        // The public VSS sets are stand-ins at the shape level: the
        // package assembly validates object types, versions, and root formats,
        // while the kernel verifier recomputes and verifies the real
        // commitments and proofs.
        const vssPublicCoefficientCommitmentSet = {
            objectType: 'VssPublicCoefficientCommitmentSet',
            coefficientCommitmentRoot: hashFromKernel(
                kernel,
                'coefficient-commitment-root',
            ),
        };
        const vssPublicRecipientShareCommitmentSet = {
            objectType: 'VssPublicRecipientShareCommitmentSet',
            recipientShareCommitmentRoot: hashFromKernel(
                kernel,
                'recipient-share-commitment-root',
            ),
        };
        const vssPublicAggregateThresholdCommitmentSet = {
            objectType: 'VssPublicAggregateThresholdCommitmentSet',
            aggregateThresholdCommitmentRoot: hashFromKernel(
                kernel,
                'aggregate-threshold-commitment-root',
            ),
        };
        const vssShareLinkageStatement = {
            objectType: 'VssShareLinkageStatement',
            statementRoot: hashFromKernel(
                kernel,
                'share-linkage-statement-root',
            ),
        };
        const vssShareLinkageProofMaterialSet = {
            objectType: 'VssShareLinkageProofMaterialSet',
            proofMaterialSetRoot: hashFromKernel(
                kernel,
                'share-linkage-proof-material-set-root',
            ),
        };
        const sameSecretBridgeStatementSet = {
            objectType: 'VssSameSecretBridgeStatementSet',
            sameSecretBridgeStatementSetRoot: hashFromKernel(
                kernel,
                'same-secret-bridge-statement-set-root',
            ),
        };
        const sameSecretBridgeProofMaterialSet = {
            objectType: 'VssSameSecretBridgeProofMaterialSet',
            proofMaterialSetRoot: hashFromKernel(
                kernel,
                'same-secret-bridge-proof-material-set-root',
            ),
        };
        const thresholdShareCommitments = {
            objectType: 'ThresholdShareCommitmentBinding',
            thresholdShareCommitmentRoot: hashFromKernel(
                kernel,
                'threshold-share-commitment-root',
            ),
        };
        const setupPackageInput = {
            setupContext,
            qShare: setupParameters.qShare,
            phaseTranscript: phaseTranscriptFixture(kernel, setupContext),
            commonRandomness: {
                ...commonRandomnessWithoutRoot,
                commonRandomnessRoot: kernel.deriveCanonicalObjectHash({
                    value: commonRandomnessWithoutRoot,
                }),
            },
            vssPublicCoefficientCommitmentSet,
            vssPublicRecipientShareCommitmentSet,
            vssPublicAggregateThresholdCommitmentSet,
            vssShareLinkageStatement,
            vssShareLinkageProofMaterialSet,
            sameSecretBridgeStatementSet,
            sameSecretBridgeProofMaterialSet,
            thresholdShareCommitments,
            privateVssEnvelopeCommitments: {
                objectType: 'PrivateVssEnvelopeCommitmentSet',
                ...contextFields(setupContext),
                privateVssEnvelopeCommitmentRoot,
                envelopeReferences: [
                    {
                        objectType: 'PrivateVssEnvelopeCommitment',
                        ...contextFields(setupContext),
                        sourceTrusteeIdentity: 'trustee-0',
                        sourceTrusteeRosterPosition: 0,
                        recipientIdentity: 'trustee-1',
                        recipientRosterPosition: 1,
                        privateEnvelopeCommitmentRoot: hashFromKernel(
                            kernel,
                            'package-private-envelope-commitment',
                        ),
                        encryptedEnvelopeHash: hashFromKernel(
                            kernel,
                            'package-encrypted-envelope',
                        ),
                        privateEnvelopeHash: hashFromKernel(
                            kernel,
                            'package-private-envelope',
                        ),
                        localVerificationRoot: hashFromKernel(
                            kernel,
                            'package-local-verification',
                        ),
                        encryptedEnvelope: {
                            objectType: 'EncryptedPrivateVssShareEnvelope',
                            ciphertextBytesHex: '00',
                        },
                        transportedPrivateVssShareProofMaterial: {
                            objectType:
                                'SetupTransportedPrivateVssShareProofMaterialSet',
                        },
                    },
                ],
            },
            vssShareAcceptances: {
                objectType: 'VssShareAcceptanceSet',
                ...contextFields(setupContext),
                privateVssEnvelopeCommitmentRoot,
                acceptanceRecords: [],
                vssShareAcceptanceRoot: hashFromKernel(
                    kernel,
                    'package-acceptance-root',
                ),
            },
            sameSecretConsistency,
            sameSecretProofs,
            publicKeyShares,
            publicKeyShareProofs,
            publicKeyShareMaterial,
            publicKeyShareSuccinctProofs,
            evaluatorKeySchedule,
            relinearizationKeyShareRounds,
            galoisKeyShareBatches,
            trusteeEvaluationKeyProofs,
            evaluationKeys: publicEvaluationKeys,
            setupCertificateInput: {
                setupParameters: setupParameters,
                bgvParameters: bgvParameters,
                transport: setupTransport,
            },
        };
        const setupPackage =
            publicSetupApi.createSetupPackage(setupPackageInput);
        const { setupPackageHash, ...setupPackageHashInput } = setupPackage;

        expect(publicKeyShares).toMatchObject({
            objectType: 'PublicKeyShareSet',
            publicMatrixSeedHash,
        });
        expect(relinearizationKeyShareRounds.objectType).toBe(
            'RelinearizationKeyShareRounds',
        );
        expect(
            Array.isArray(relinearizationKeyShareRounds.roundOneRecords),
        ).toBe(true);
        expect(
            Array.isArray(relinearizationKeyShareRounds.roundTwoRecords),
        ).toBe(true);
        expect(galoisKeyShareBatches).toHaveLength(participantCount);
        expect(publicEvaluationKeys).toMatchObject({
            objectType: 'PublicEvaluationKeySet',
            relinearizationKeyShareRoundsRoot:
                relinearizationKeyShareRounds.relinearizationKeyShareRoundsRoot,
        });
        expect(setupPackage).toMatchObject({
            objectType: 'SetupPackage',
            setupContext,
            collectivePublicKey: {
                objectType: 'CollectivePublicKey',
                publicKeyShareMaterialSetRoot:
                    publicKeyShareMaterial.publicKeyShareMaterialSetRoot,
                publicKeyShareSuccinctProofSetRoot:
                    publicKeyShareSuccinctProofs.publicKeyShareSuccinctProofSetRoot,
            },
            privateVssEnvelopeCommitmentRoot,
            evaluationKeys: publicEvaluationKeys,
            setupTransportCertificate,
        });
        expect(setupPackage.collectivePublicKeyRoot).toBe(
            (setupPackage.collectivePublicKey as Record<string, unknown>)
                .collectivePublicKeyRoot,
        );
        expect(setupPackage.setupTransportCertificate).toMatchObject({
            chunkSizeBytes: setupTransportChunkSizeBytes,
            chunkCount: transportedCompanionObjects.length,
            totalByteLength: transportedCompanionByteLength,
        });
        expect(
            (setupPackage.setupTransportCertificate as Record<string, unknown>)
                .transportedObjects,
        ).toMatchObject(
            transportedCompanionObjects.map(
                (transportedObject, transportedObjectIndex) => ({
                    objectName: transportedObject.objectName,
                    objectRole: transportedObject.objectRole,
                    objectRoot: transportedObject.objectRoot,
                    byteLength: transportedObject.byteLength,
                    chunkStartIndex: transportedObjectIndex,
                    chunkCount: 1,
                    chunkHashes: transportedObject.chunkHashes,
                    fullObjectHash: transportedObject.fullObjectHash,
                    encoding: 'binary',
                    loadingPolicy: 'stream-verified-before-object-use',
                }),
            ),
        );
        expect(
            (setupPackage.thresholdShareCommitments as Record<string, unknown>)
                .thresholdShareCommitmentRoot,
        ).toMatch(/^[0-9a-f]{128}$/u);
        expect(setupPackageHash).toBe(
            kernel.deriveCanonicalObjectHash({
                value: setupPackageHashInput,
            }),
        );
        expect(() =>
            publicSetupApi.createSetupPackage({
                ...setupPackageInput,
                thresholdShareCommitments: {
                    ...thresholdShareCommitments,
                    objectType: 'ThresholdShareCommitmentSet',
                },
            }),
        ).toThrow(/ThresholdShareCommitmentBinding/u);
        for (const requiredPublicKeyClosureField of [
            'sameSecretProofs',
            'publicKeyShareMaterial',
            'publicKeyShareSuccinctProofs',
        ]) {
            const incompleteSetupPackageInput = {
                ...setupPackageInput,
            };
            delete incompleteSetupPackageInput[
                requiredPublicKeyClosureField as keyof typeof incompleteSetupPackageInput
            ];

            expect(() =>
                publicSetupApi.createSetupPackage(incompleteSetupPackageInput),
            ).toThrow(
                new RegExp(
                    `${requiredPublicKeyClosureField} must be an object`,
                    'u',
                ),
            );
        }
    });
});
