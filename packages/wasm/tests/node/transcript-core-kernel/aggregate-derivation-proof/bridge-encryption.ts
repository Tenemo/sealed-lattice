import { expect, it } from 'vitest';

import { loadTranscriptCoreKernel } from '../../../../src/index';

import { canonicalJson, deriveProtocolHash } from '#packages/crypto/src/index';
import {
    createPendingBridgeProofRecordFromBridgeEvidence,
    type PendingBridgeProofRecordFromEvidenceInput,
} from '#packages/protocol/src/ballot-privacy/aggregate-bridge/structure-verification.js';
import {
    buildAggregateDerivationStatement,
    createAggregateDerivationComponent,
    deriveBridgeProofTargetContractHash,
    sumAggregateDerivationWitnesses,
} from '#packages/protocol/src/ballot-privacy/index';
import { verifyBridgeProof as verifyPublicSdkBridgeProof } from '#packages/sdk/dist/index.js';

type AggregateComponentContext = {
    readonly component: ReturnType<typeof createAggregateDerivationComponent>;
    readonly kernel: Awaited<ReturnType<typeof loadTranscriptCoreKernel>>;
    readonly statement: ReturnType<
        typeof buildAggregateDerivationStatement
    >['statement'];
    readonly witness: ReturnType<typeof sumAggregateDerivationWitnesses>;
};

type AggregateBridgeEncryptionTestInput = {
    readonly aggregateHeavyStepTimeoutMs: number;
    readonly getAggregateComponentContext: () => AggregateComponentContext;
    readonly runAggregateTestStep: <T>(
        name: string,
        action: () => T | Promise<T>,
    ) => Promise<T>;
};

export const registerAggregateBridgeEncryptionTest = (
    input: AggregateBridgeEncryptionTestInput,
): void => {
    const {
        aggregateHeavyStepTimeoutMs,
        getAggregateComponentContext,
        runAggregateTestStep,
    } = input;
    const runBridgeTestStep = <T>(
        name: string,
        action: () => T | Promise<T>,
    ): Promise<T> => runAggregateTestStep(`M9 bridge: ${name}`, action);

    it(
        'generates M9 bridge encryption evidence without public witness material',
        async () => {
            await runAggregateTestStep(
                'Generate M9 bridge encryption evidence',
                async () => {
                    const { component, kernel, statement, witness } =
                        getAggregateComponentContext();
                    const setupPackage = await runBridgeTestStep(
                        'generate BGV passive setup',
                        () =>
                            kernel.generateBgvPassiveSetup({
                                ceremonyId: statement.ceremonyId,
                                manifestHash: statement.manifestHash,
                                participants: Array.from(
                                    { length: statement.participantCount },
                                    (_unusedValue, participantIndex) => ({
                                        boardPosition: participantIndex + 3,
                                        rosterPosition: participantIndex,
                                        trusteeIdentity: `receiver-${participantIndex}`,
                                    }),
                                ),
                                rosterHash: statement.rosterHash,
                                setupSeed: 'm9-bridge-test-seed',
                                thresholdProfileHash:
                                    statement.thresholdProfileHash,
                            }),
                    );
                    const aggregateSelectionPolicyHash = deriveProtocolHash(
                        'AggregateSelectionPolicyHash',
                        {
                            purpose: 'm9-kernel-bridge-test-selection-policy',
                            statementHash:
                                statement.aggregateDerivationStatementHash,
                        },
                    );
                    const bridgeWitnessPrivacyProfileHash = deriveProtocolHash(
                        'BridgeWitnessPrivacyProfileHash',
                        {
                            purpose: 'm9-kernel-bridge-test-witness-privacy',
                            statementHash:
                                statement.aggregateDerivationStatementHash,
                        },
                    );
                    const heParamHash = deriveProtocolHash('HEParamHash', {
                        purpose: 'm9-kernel-bridge-test-he-param',
                        statementHash:
                            statement.aggregateDerivationStatementHash,
                    });
                    const bridgeEncryption = await runBridgeTestStep(
                        'generate bridge encryption proof',
                        () =>
                            kernel.generateAggregateBridgeEncryption({
                                aggregateSelectionPolicyHash,
                                aggregateDerivationComponent: component,
                                aggregateWitness: witness,
                                bridgeWitnessPrivacyProfileHash,
                                heParamHash,
                                includeCanonicalBytesHex: true,
                                proverRandomnessHex: '77'.repeat(32),
                                setupPackage,
                            }) as Record<string, unknown>,
                    );
                    if (bridgeEncryption.ok !== true) {
                        throw new Error(
                            `Bridge encryption generation failed: ${JSON.stringify(bridgeEncryption)}`,
                        );
                    }

                    expect(bridgeEncryption).toMatchObject({
                        bridgeProofVerificationStatus:
                            'BridgeProofRelationChecked',
                        ok: true,
                        operation: 'generateAggregateBridgeEncryption',
                    });
                    expect(bridgeEncryption.statusLabels).toEqual([
                        'AggregateBridgePlaintextAssembled',
                        'AggregateBridgeCiphertextGenerated',
                        'CollectivePublicKeyRootBound',
                        'CoefficientDomainCanonical',
                        'BridgeProofRelationChecked',
                        'BridgeProofImplementationEvidenceOnly',
                        'SharedWitnessZeroKnowledgeResponseDistributionChecked',
                        'BgvRandomnessErrorSupportPolynomialChecked',
                        'BridgeProofClaimClosureMissing',
                        'RepresentativeBridgeMatrixRowEvidence',
                    ]);
                    expect(bridgeEncryption).toMatchObject({
                        bridgeClaimClosureVerified: false,
                        bridgeClaimVerificationStatus:
                            'BridgeProofClaimClosureMissing',
                        bridgeVariantEvidenceStatus:
                            'representative-row-evidence',
                    });
                    expect(
                        String(
                            bridgeEncryption.encryptedAggregateShareCiphertextRoot,
                        ),
                    ).toHaveLength(128);
                    expect(
                        String(bridgeEncryption.bridgeProofProfileHash),
                    ).toHaveLength(128);
                    expect(
                        String(bridgeEncryption.bridgeProofStatementHash),
                    ).toHaveLength(128);
                    expect(
                        String(bridgeEncryption.bridgeProofTargetContractHash),
                    ).toHaveLength(128);
                    const bridgeProofPayload = JSON.parse(
                        Buffer.from(
                            String(bridgeEncryption.bridgeProofBytesHex),
                            'hex',
                        ).toString('utf8'),
                    ) as Record<string, unknown>;
                    const bridgeProofStatement =
                        bridgeProofPayload.bridgeProofStatement as Record<
                            string,
                            unknown
                        >;
                    const bridgeProofTargetContract =
                        bridgeProofStatement.bridgeProofTargetContract as Record<
                            string,
                            unknown
                        >;
                    const expectedTargetContractHash =
                        deriveBridgeProofTargetContractHash({
                            aggregateQuotientCoordinateCount: 220,
                            aggregateReducedCoordinateCount: 220,
                        });
                    expect(bridgeProofPayload.bridgeProofProfileHash).toBe(
                        bridgeEncryption.bridgeProofProfileHash,
                    );
                    expect(bridgeProofPayload.bridgeProofStatementHash).toBe(
                        bridgeEncryption.bridgeProofStatementHash,
                    );
                    expect(
                        bridgeProofPayload.bridgeProofTargetContractHash,
                    ).toBe(bridgeEncryption.bridgeProofTargetContractHash);
                    expect(
                        bridgeProofPayload.bridgeProofTargetContractHash,
                    ).toBe(expectedTargetContractHash);
                    expect(
                        deriveProtocolHash('BridgeProofRecordHash', {
                            contract: bridgeProofTargetContract,
                            purpose:
                                'sealed-lattice-aggregate-bridge-proof-target-contract-v1',
                        }),
                    ).toBe(expectedTargetContractHash);
                    expect(bridgeProofPayload).toMatchObject({
                        objectType: 'SealedLatticeAggregateBridgeRelationProof',
                        bridgeSharedWitnessProof: {
                            objectType: 'AggregateBridgeSharedWitnessProof',
                            proofModel:
                                'fiat-shamir-linear-shared-response-rejection-sampled-v1',
                            relationCheckCount: 2,
                            maskAbsoluteBoundExclusive:
                                '1766847064778384329583297500742918515827483896875618958121606201292619776',
                            responseAbsoluteBoundExclusive:
                                '1766847064778384329583297500742918515822291600017084130493075704963399680',
                            responseBoundModel:
                                'uniform-240-bit-mask-common-output-rejection-sampled-v1',
                            responseBoundStatus:
                                'SharedWitnessResponseDistributionBoundsChecked',
                            responseDistributionStatus:
                                'SharedWitnessResponseDistributionRejectionSampled',
                            responseEncoding:
                                'signed-i256-little-endian-hex-v1',
                            responseShiftBoundExclusive:
                                '5192296858534827628530496329220096',
                            sameHiddenAggregateCoordinatesLinked: true,
                        },
                        bgvRandomnessBoundProofStatusEvidence: {
                            bgvRandomnessBoundProofStatus:
                                'BgvRandomnessErrorSupportPolynomialChecked',
                            bridgeClaimClosureAccepted: false,
                            objectType:
                                'AggregateBridgeBgvRandomnessBoundProofStatus',
                            proofModel:
                                'fiat-shamir-same-response-support-polynomial-v1',
                            sameSharedWitnessResponseTranscript: true,
                            statusModel:
                                'development-bgv-randomness-bound-proof-status-v1',
                            verifierBoundednessProofChecked: true,
                        },
                        sharedWitnessZeroKnowledgeStatusEvidence: {
                            bridgeClaimClosureAccepted: false,
                            objectType:
                                'AggregateBridgeSharedWitnessZeroKnowledgeStatus',
                            sharedWitnessZeroKnowledgeStatus:
                                'SharedWitnessZeroKnowledgeResponseDistributionChecked',
                            simulatorProofChecked: true,
                            statusModel:
                                'shared-witness-zero-knowledge-response-distribution-status-v1',
                        },
                        singleContributionBridgeRelationChecked: true,
                    });
                    expect(
                        String(bridgeProofPayload.bridgeSharedWitnessProofHash),
                    ).toHaveLength(128);
                    expect(
                        String(
                            bridgeProofPayload.bgvRandomnessBoundProofStatusHash,
                        ),
                    ).toHaveLength(128);
                    expect(
                        String(
                            bridgeProofPayload.sharedWitnessZeroKnowledgeStatusHash,
                        ),
                    ).toHaveLength(128);
                    expect(bridgeProofPayload).toMatchObject({
                        aggregateQuotientCoordinateCount: 220,
                        aggregateReducedCoordinateCount: 220,
                        aggregateRelationChallengeHex: expect.any(
                            String,
                        ) as string,
                        aggregateRelationCommitmentHash: expect.any(
                            String,
                        ) as string,
                        aggregateRelationSubproofSizeBytes: expect.any(
                            Number,
                        ) as number,
                    });
                    expect(
                        String(
                            bridgeProofPayload.aggregateRelationChallengeHex,
                        ),
                    ).toHaveLength(48);
                    expect(
                        String(
                            bridgeProofPayload.aggregateRelationCommitmentHash,
                        ),
                    ).toHaveLength(128);
                    expect(
                        bridgeProofPayload.bridgeProofStatement,
                    ).toMatchObject({
                        aggregateDerivationComponentHash:
                            component.aggregateDerivationComponentHash,
                        aggregateShareCommitmentHash:
                            component.aggregateCommitment
                                .aggregateShareCommitmentHash,
                        aggregateSelectionPolicyHash,
                        bgvEncryptionProofSubrelation:
                            'SealedLatticeDevelopmentCiphertextEquationRelation',
                        bridgeWitnessPrivacyProfileHash,
                        bridgeProofTargetContractHash:
                            bridgeEncryption.bridgeProofTargetContractHash,
                        heParamHash,
                        objectType: 'AggregateBridgeProofStatement',
                        bridgeProofTargetContract: {
                            ciphertextCoefficientEquationCount: 1_048_576,
                            dataPrimeCount: 16,
                            naiveLinearExpansionBackendStatus:
                                'InfeasibleForEncryptedAggregateBridgeClaim',
                            plaintextRootProofBindingStatus:
                                'PlaintextRootProofBindingChecked',
                            proofFriendlyPlaintextBindingRequired: true,
                            publicPlaintextRootAcceptedAsClosureEvidence: false,
                            sharedWitnessCheckCount: 2,
                            sharedWitnessSoundnessBits: 128,
                            sharedWitnessZeroKnowledgeStatus:
                                'SharedWitnessZeroKnowledgeResponseDistributionChecked',
                            bgvRandomnessBoundProofStatus:
                                'BgvRandomnessErrorSupportPolynomialChecked',
                            bridgeClaimClosureStatus:
                                'BridgeProofClaimClosureMissing',
                            sameWitnessLinkageModel:
                                'SingleTranscriptSharedWitnessOrExplicitSameWitnessLinkRequired',
                            sampledDiagnosticsAcceptedForVerification: false,
                            separateSubproofsAcceptedForClosure: false,
                            separateSubproofsClosureStatus:
                                'RejectedForAggregateBridgeClaimClosure',
                            sharedWitnessLayout: {
                                aggregateIntegerShareCoordinateCount: 220,
                                aggregateQuotientCoordinateCount: 220,
                                aggregateReducedCoordinateCount: 220,
                                aggregateRelationRowCount: 224,
                                bgvCiphertextEquationRowCount: 1_048_576,
                                bridgeProofProfileId:
                                    'EncryptedAggregateBridge-v1',
                                commitmentOpeningCoordinateCount: 64,
                                encryptionErrorCoefficientCount: 65_536,
                                encryptionRandomizerCoefficientCount: 32_768,
                                layoutModel: 'single-shared-response-vector-v1',
                                objectType:
                                    'AggregateBridgeSharedWitnessLayout',
                                objectVersion: 1,
                                plaintextCoefficientColumnRole:
                                    'bgv-batch-encoding-and-bgv-encryption-message',
                                plaintextCoefficientCount: 32_768,
                                plaintextEncodingQuotientCount: 0,
                                plaintextEncodingRelationRowCount: 32_768,
                                sameWitnessLinkageModel:
                                    'SingleTranscriptSharedWitnessOrExplicitSameWitnessLinkRequired',
                                separateSubproofsAcceptedForClosure: false,
                                sharedReducedCoordinateColumnRole:
                                    'aggregate-reduction-and-bgv-plaintext-slot',
                                sharedResponseScalarCount: 131_796,
                            },
                            sharedWitnessLayoutHash: expect.any(
                                String,
                            ) as string,
                        },
                        sampledPublicRelationCheckPolicyHash: expect.any(
                            String,
                        ) as string,
                        relationRequirements: {
                            sampledOnlyBridgeVerificationAccepted: false,
                            sharedWitnessBindingRequired: true,
                        },
                    });
                    expect(
                        bridgeEncryption.sampledPublicRelationCheckPolicy,
                    ).toMatchObject({
                        acceptedForBridgeProofVerification: false,
                        diagnosticOnly: true,
                        fullBridgeProofRequired: true,
                        sampledOnlyBridgeVerificationAccepted: false,
                    });
                    expect(bridgeProofPayload.scopedBridgeRelationClosure).toBe(
                        false,
                    );
                    expect(JSON.stringify(bridgeEncryption)).not.toMatch(
                        /aggregateIntegerShareVector|aggregateOpeningRandomness|layoutPlaintextWitness|bgvPlaintext|encryptionRandomness|encryptionError|sourceWitnessCoefficients/u,
                    );
                    expect(
                        kernel.validateBgvCiphertextObject({
                            canonicalBytesHex: String(
                                bridgeEncryption.canonicalBytesHex,
                            ),
                            expectedCiphertextRoot: String(
                                bridgeEncryption.ciphertextRoot,
                            ),
                        }),
                    ).toMatchObject({
                        ok: true,
                        objectKind: 'ciphertext',
                    });
                    const bridgeVerification = await runBridgeTestStep(
                        'verify bridge evidence through the kernel',
                        () =>
                            kernel.verifyAggregateBridgeEncryption({
                                aggregateSelectionPolicyHash,
                                aggregateDerivationComponent: component,
                                bridgeEncryption,
                                bridgeWitnessPrivacyProfileHash,
                                heParamHash,
                                setupPackage,
                            }) as Record<string, unknown>,
                    );
                    expect(bridgeVerification).toMatchObject({
                        backendAvailable: true,
                        bridgeEvidenceVerificationStatus:
                            'BridgeProofEvidenceChecked',
                        bridgeProofVerificationStatus:
                            'BridgeProofRelationChecked',
                        ok: true,
                        operation: 'verifyAggregateBridgeEncryption',
                    });
                    expect(bridgeVerification.statusLabels).toEqual([
                        'BridgeProofEvidenceChecked',
                        'BridgeProofRelationChecked',
                        'M9SingleContributionBridgeRelationChecked',
                        'BridgeProofImplementationEvidenceOnly',
                        'SharedWitnessZeroKnowledgeResponseDistributionChecked',
                        'BgvRandomnessErrorSupportPolynomialChecked',
                        'BridgeProofClaimClosureMissing',
                        'FinalBridgeTheoremPending',
                        'RepresentativeBridgeMatrixRowEvidence',
                    ]);
                    expect(bridgeVerification).toMatchObject({
                        bridgeClaimClosureVerified: false,
                        bridgeClaimVerificationStatus:
                            'BridgeProofClaimClosureMissing',
                        bridgeVariantEvidenceStatus:
                            'representative-row-evidence',
                    });
                    expect(String(bridgeVerification.bridgeProofRoot)).toBe(
                        String(bridgeEncryption.bridgeProofRoot),
                    );
                    expect(
                        String(bridgeVerification.bridgeSharedWitnessProofHash),
                    ).toBe(
                        String(bridgeProofPayload.bridgeSharedWitnessProofHash),
                    );
                    expect(
                        String(
                            bridgeVerification.bgvRandomnessBoundProofStatusHash,
                        ),
                    ).toBe(
                        String(
                            bridgeProofPayload.bgvRandomnessBoundProofStatusHash,
                        ),
                    );
                    expect(
                        String(
                            bridgeVerification.sharedWitnessZeroKnowledgeStatusHash,
                        ),
                    ).toBe(
                        String(
                            bridgeProofPayload.sharedWitnessZeroKnowledgeStatusHash,
                        ),
                    );
                    expect(
                        String(
                            bridgeVerification.bridgeProofTargetContractHash,
                        ),
                    ).toBe(
                        String(bridgeEncryption.bridgeProofTargetContractHash),
                    );
                    const publicSdkBridgeVerification = await runBridgeTestStep(
                        'verify bridge evidence through the public SDK',
                        () =>
                            verifyPublicSdkBridgeProof({
                                aggregateDerivationComponent: component,
                                aggregateSelectionPolicyHash,
                                bridgeEncryption,
                                bridgeWitnessPrivacyProfileHash,
                                heParamHash,
                                setupPackage,
                            }),
                    );
                    expect(publicSdkBridgeVerification).toMatchObject({
                        bridgeClaimClosureVerified: false,
                        bridgeProofVerificationStatus:
                            'BridgeProofRelationChecked',
                        ok: true,
                        operation: 'verifyAggregateBridgeEncryption',
                    });
                    expect(publicSdkBridgeVerification.statusLabels).toEqual(
                        bridgeVerification.statusLabels,
                    );

                    type PublicSdkBridgeVerificationInput = Parameters<
                        typeof verifyPublicSdkBridgeProof
                    >[0];
                    const expectPublicSdkBridgeVerificationRejected = async (
                        mutation: Partial<PublicSdkBridgeVerificationInput>,
                        expectedMessagePattern: RegExp,
                    ): Promise<Record<string, unknown>> => {
                        const verification = await verifyPublicSdkBridgeProof({
                            aggregateDerivationComponent:
                                mutation.aggregateDerivationComponent ??
                                component,
                            aggregateSelectionPolicyHash:
                                mutation.aggregateSelectionPolicyHash ??
                                aggregateSelectionPolicyHash,
                            bridgeEncryption:
                                mutation.bridgeEncryption ?? bridgeEncryption,
                            bridgeWitnessPrivacyProfileHash:
                                mutation.bridgeWitnessPrivacyProfileHash ??
                                bridgeWitnessPrivacyProfileHash,
                            heParamHash: mutation.heParamHash ?? heParamHash,
                            setupPackage: mutation.setupPackage ?? setupPackage,
                        });

                        expect(verification).toMatchObject({
                            ok: false,
                            operation: 'verifyAggregateBridgeEncryption',
                        });
                        expect(verification.refusedObjects).toEqual(
                            expect.arrayContaining([
                                expect.objectContaining({
                                    code: 'BallotPackageInvalid',
                                    message: expect.stringMatching(
                                        expectedMessagePattern,
                                    ) as string,
                                }),
                            ]),
                        );
                        expect(verification).not.toMatchObject({
                            bridgeClaimClosureVerified: true,
                        });

                        return verification as Record<string, unknown>;
                    };

                    await runBridgeTestStep(
                        'run public SDK bridge rejection checks',
                        async () => {
                            const publicSdkSampledOnlyVerification =
                                await expectPublicSdkBridgeVerificationRejected(
                                    {
                                        bridgeEncryption: {
                                            ...bridgeEncryption,
                                            bridgeProofVerificationStatus:
                                                'BridgeProofBackendPending',
                                        },
                                    },
                                    /verifier-checked bridge encryption status/iu,
                                );
                            expect(
                                publicSdkSampledOnlyVerification.refusedObjects,
                            ).toEqual(
                                expect.arrayContaining([
                                    expect.objectContaining({
                                        message:
                                            'M9 bridge relation proof requires verifier-checked bridge encryption status',
                                    }),
                                ]),
                            );
                            await expectPublicSdkBridgeVerificationRejected(
                                {
                                    aggregateSelectionPolicyHash:
                                        deriveProtocolHash(
                                            'AggregateSelectionPolicyHash',
                                            {
                                                purpose:
                                                    'm9-kernel-bridge-test-public-sdk-wrong-selection-policy',
                                                statementHash:
                                                    statement.aggregateDerivationStatementHash,
                                            },
                                        ),
                                },
                                /selection policy|proof statement|statement hash/iu,
                            );
                            await expectPublicSdkBridgeVerificationRejected(
                                {
                                    bridgeEncryption: {
                                        ...bridgeEncryption,
                                        bridgeProofBytesHash: '0'.repeat(128),
                                    },
                                },
                                /proof bytes hash|proof root|hash/iu,
                            );
                            await expectPublicSdkBridgeVerificationRejected(
                                {
                                    bridgeEncryption: {
                                        ...bridgeEncryption,
                                        bridgeProofBytesHex: '00',
                                    },
                                },
                                /proof bytes|JSON|canonical|malformed/iu,
                            );
                        },
                    );
                    await runBridgeTestStep(
                        'build pending bridge proof record',
                        () => {
                            const pendingBridgeProofRecord =
                                createPendingBridgeProofRecordFromBridgeEvidence(
                                    {
                                        aggregateDerivationComponent: component,
                                        aggregateSelectionPolicyHash,
                                        bridgeEncryptionEvidence:
                                            bridgeEncryption as PendingBridgeProofRecordFromEvidenceInput['bridgeEncryptionEvidence'],
                                        bridgeEvidenceVerification:
                                            bridgeVerification as PendingBridgeProofRecordFromEvidenceInput['bridgeEvidenceVerification'],
                                        bridgeWitnessPrivacyProfileHash,
                                        heParamHash,
                                        setupPackage:
                                            setupPackage as PendingBridgeProofRecordFromEvidenceInput['setupPackage'],
                                    },
                                );
                            expect(pendingBridgeProofRecord).toMatchObject({
                                bridgeProofTargetContractHash:
                                    bridgeEncryption.bridgeProofTargetContractHash,
                                bridgeProofVerificationStatus:
                                    'BridgeProofRelationChecked',
                                encryptedAggregateShareCiphertextRoot:
                                    bridgeEncryption.encryptedAggregateShareCiphertextRoot,
                                proofRoot: bridgeVerification.bridgeProofRoot,
                                proofStatementHash:
                                    bridgeVerification.bridgeProofStatementHash,
                            });
                        },
                    );

                    const expectBridgeVerificationRejected = (
                        mutatedBridgeEncryption: Record<string, unknown>,
                    ): void => {
                        expect(
                            kernel.verifyAggregateBridgeEncryption({
                                aggregateSelectionPolicyHash,
                                aggregateDerivationComponent: component,
                                bridgeEncryption: mutatedBridgeEncryption,
                                bridgeWitnessPrivacyProfileHash,
                                heParamHash,
                                setupPackage,
                            }),
                        ).toMatchObject({
                            ok: false,
                            operation: 'verifyAggregateBridgeEncryption',
                        });
                    };
                    const replaceLastHexDigit = (value: unknown): string => {
                        const hex = String(value);
                        const replacement = hex.endsWith('0') ? '1' : '0';

                        return `${hex.slice(0, -1)}${replacement}`;
                    };
                    const refreshBridgeProofPayloadDerivedHashes = (
                        proofPayload: Record<string, unknown>,
                    ): void => {
                        if (
                            typeof proofPayload.bridgeSharedWitnessProof ===
                                'object' &&
                            proofPayload.bridgeSharedWitnessProof !== null
                        ) {
                            proofPayload.bridgeSharedWitnessProofHash =
                                deriveProtocolHash('BridgeProofRecordHash', {
                                    bridgeSharedWitnessProof:
                                        proofPayload.bridgeSharedWitnessProof,
                                    purpose:
                                        'sealed-lattice-aggregate-bridge-shared-witness-proof-hash-v1',
                                });
                        }
                        if (
                            typeof proofPayload.bridgeSharedWitnessProofHash ===
                            'string'
                        ) {
                            if (
                                typeof proofPayload.sharedWitnessZeroKnowledgeStatusEvidence ===
                                    'object' &&
                                proofPayload.sharedWitnessZeroKnowledgeStatusEvidence !==
                                    null
                            ) {
                                (
                                    proofPayload.sharedWitnessZeroKnowledgeStatusEvidence as Record<
                                        string,
                                        unknown
                                    >
                                ).bridgeSharedWitnessProofHash =
                                    proofPayload.bridgeSharedWitnessProofHash;
                            }
                            if (
                                typeof proofPayload.bgvRandomnessBoundProofStatusEvidence ===
                                    'object' &&
                                proofPayload.bgvRandomnessBoundProofStatusEvidence !==
                                    null
                            ) {
                                (
                                    proofPayload.bgvRandomnessBoundProofStatusEvidence as Record<
                                        string,
                                        unknown
                                    >
                                ).bridgeSharedWitnessProofHash =
                                    proofPayload.bridgeSharedWitnessProofHash;
                            }
                        }
                        if (
                            typeof proofPayload.sharedWitnessZeroKnowledgeStatusEvidence ===
                                'object' &&
                            proofPayload.sharedWitnessZeroKnowledgeStatusEvidence !==
                                null
                        ) {
                            proofPayload.sharedWitnessZeroKnowledgeStatusHash =
                                deriveProtocolHash('BridgeProofRecordHash', {
                                    purpose:
                                        'sealed-lattice-aggregate-bridge-shared-witness-zero-knowledge-status-v1',
                                    sharedWitnessZeroKnowledgeStatusEvidence:
                                        proofPayload.sharedWitnessZeroKnowledgeStatusEvidence,
                                });
                        }
                        if (
                            typeof proofPayload.bgvRandomnessBoundProofStatusEvidence ===
                                'object' &&
                            proofPayload.bgvRandomnessBoundProofStatusEvidence !==
                                null
                        ) {
                            proofPayload.bgvRandomnessBoundProofStatusHash =
                                deriveProtocolHash('BridgeProofRecordHash', {
                                    bgvRandomnessBoundProofStatusEvidence:
                                        proofPayload.bgvRandomnessBoundProofStatusEvidence,
                                    purpose:
                                        'sealed-lattice-aggregate-bridge-bgv-randomness-bound-status-v1',
                                });
                        }
                    };
                    const bridgeEncryptionWithUpdatedProofPayload = (
                        proofOverrides: Record<string, unknown>,
                        bridgeOverrides: Record<string, unknown>,
                    ): Record<string, unknown> => {
                        const proofPayload = {
                            ...(JSON.parse(
                                Buffer.from(
                                    String(
                                        bridgeEncryption.bridgeProofBytesHex,
                                    ),
                                    'hex',
                                ).toString('utf8'),
                            ) as Record<string, unknown>),
                            ...proofOverrides,
                        };
                        refreshBridgeProofPayloadDerivedHashes(proofPayload);
                        const bridgePayload = {
                            ...bridgeEncryption,
                            ...bridgeOverrides,
                        };
                        const bridgeProofBytesHex = Buffer.from(
                            canonicalJson(proofPayload),
                            'utf8',
                        ).toString('hex');
                        const bridgeProofBytesHash = deriveProtocolHash(
                            'ProofBytesHash',
                            {
                                proofBytesHex: bridgeProofBytesHex,
                                purpose:
                                    'sealed-lattice-aggregate-bridge-encryption-proof-bytes-v1',
                            },
                        );
                        const bridgeProofRoot = deriveProtocolHash(
                            'BridgeProofRecordHash',
                            {
                                aggregateDerivationComponentHash:
                                    component.aggregateDerivationComponentHash,
                                aggregateDerivationStatementHash:
                                    statement.aggregateDerivationStatementHash,
                                bridgeProofProfileHash:
                                    bridgePayload.bridgeProofProfileHash,
                                bridgeProofStatementHash:
                                    bridgePayload.bridgeProofStatementHash,
                                bgvPublicKeyRoot:
                                    bridgePayload.bgvPublicKeyRoot,
                                collectivePublicKeyRoot:
                                    bridgePayload.collectivePublicKeyRoot,
                                encryptedAggregateShareCiphertextRoot:
                                    bridgePayload.encryptedAggregateShareCiphertextRoot,
                                ...(typeof proofPayload.bridgeSharedWitnessProofHash ===
                                'string'
                                    ? {
                                          bridgeSharedWitnessProofHash:
                                              proofPayload.bridgeSharedWitnessProofHash,
                                      }
                                    : {}),
                                ...(typeof proofPayload.sharedWitnessZeroKnowledgeStatusHash ===
                                'string'
                                    ? {
                                          sharedWitnessZeroKnowledgeStatusHash:
                                              proofPayload.sharedWitnessZeroKnowledgeStatusHash,
                                      }
                                    : {}),
                                ...(typeof proofPayload.bgvRandomnessBoundProofStatusHash ===
                                'string'
                                    ? {
                                          bgvRandomnessBoundProofStatusHash:
                                              proofPayload.bgvRandomnessBoundProofStatusHash,
                                      }
                                    : {}),
                                proofBytesHash: bridgeProofBytesHash,
                                purpose:
                                    'sealed-lattice-aggregate-bridge-encryption-proof-root-v1',
                            },
                        );

                        return {
                            ...bridgePayload,
                            bridgeProofBytesHash,
                            bridgeProofBytesHex,
                            ...(typeof proofPayload.bridgeSharedWitnessProofHash ===
                            'string'
                                ? {
                                      bridgeSharedWitnessProofHash:
                                          proofPayload.bridgeSharedWitnessProofHash,
                                  }
                                : {}),
                            ...(typeof proofPayload.sharedWitnessZeroKnowledgeStatusHash ===
                            'string'
                                ? {
                                      sharedWitnessZeroKnowledgeStatusHash:
                                          proofPayload.sharedWitnessZeroKnowledgeStatusHash,
                                  }
                                : {}),
                            ...(typeof proofPayload.bgvRandomnessBoundProofStatusHash ===
                            'string'
                                ? {
                                      bgvRandomnessBoundProofStatusHash:
                                          proofPayload.bgvRandomnessBoundProofStatusHash,
                                  }
                                : {}),
                            bridgeProofRoot,
                        };
                    };
                    await runBridgeTestStep(
                        'run cheap bridge verifier rejection checks',
                        () => {
                            expect(
                                kernel.verifyAggregateBridgeEncryption({
                                    aggregateSelectionPolicyHash:
                                        deriveProtocolHash(
                                            'AggregateSelectionPolicyHash',
                                            {
                                                purpose:
                                                    'm9-kernel-bridge-test-wrong-selection-policy',
                                                statementHash:
                                                    statement.aggregateDerivationStatementHash,
                                            },
                                        ),
                                    aggregateDerivationComponent: component,
                                    bridgeEncryption,
                                    bridgeWitnessPrivacyProfileHash,
                                    heParamHash,
                                    setupPackage,
                                }),
                            ).toMatchObject({
                                ok: false,
                                operation: 'verifyAggregateBridgeEncryption',
                            });
                            expect(
                                kernel.verifyAggregateBridgeEncryption({
                                    aggregateSelectionPolicyHash,
                                    aggregateDerivationComponent: component,
                                    bridgeEncryption,
                                    bridgeWitnessPrivacyProfileHash:
                                        deriveProtocolHash(
                                            'BridgeWitnessPrivacyProfileHash',
                                            {
                                                purpose:
                                                    'm9-kernel-bridge-test-wrong-witness-privacy',
                                                statementHash:
                                                    statement.aggregateDerivationStatementHash,
                                            },
                                        ),
                                    heParamHash,
                                    setupPackage,
                                }),
                            ).toMatchObject({
                                ok: false,
                                operation: 'verifyAggregateBridgeEncryption',
                            });
                            expect(
                                kernel.verifyAggregateBridgeEncryption({
                                    aggregateSelectionPolicyHash,
                                    aggregateDerivationComponent: component,
                                    bridgeEncryption,
                                    bridgeWitnessPrivacyProfileHash,
                                    heParamHash: deriveProtocolHash(
                                        'HEParamHash',
                                        {
                                            purpose:
                                                'm9-kernel-bridge-test-wrong-he-param',
                                            statementHash:
                                                statement.aggregateDerivationStatementHash,
                                        },
                                    ),
                                    setupPackage,
                                }),
                            ).toMatchObject({
                                ok: false,
                                operation: 'verifyAggregateBridgeEncryption',
                            });
                            expectBridgeVerificationRejected({
                                ...bridgeEncryption,
                                bgvPlaintext: [1, 2, 3],
                            });
                            expectBridgeVerificationRejected({
                                ...bridgeEncryption,
                                bridgeProofVerificationStatus:
                                    'BridgeProofBackendPending',
                            });
                            expectBridgeVerificationRejected({
                                ...bridgeEncryption,
                                privateMaterialDisclosure: {
                                    ...(bridgeEncryption.privateMaterialDisclosure as Record<
                                        string,
                                        unknown
                                    >),
                                    encryptionRandomizerMaterialExported: true,
                                },
                            });
                            expectBridgeVerificationRejected({
                                ...bridgeEncryption,
                                bridgeProofBytesHash: '0'.repeat(128),
                            });
                            expectBridgeVerificationRejected({
                                ...bridgeEncryption,
                                bridgeProofStatementHash: '0'.repeat(128),
                            });
                            expectBridgeVerificationRejected({
                                ...bridgeEncryption,
                                bridgeProofTargetContractHash: '0'.repeat(128),
                            });
                            expectBridgeVerificationRejected({
                                ...bridgeEncryption,
                                bridgeProofBytesHex: replaceLastHexDigit(
                                    bridgeEncryption.bridgeProofBytesHex,
                                ),
                            });
                        },
                    );
                    await runBridgeTestStep(
                        'run ciphertext and setup bridge rejection checks',
                        () => {
                            expectBridgeVerificationRejected({
                                ...bridgeEncryption,
                                canonicalBytesHex: replaceLastHexDigit(
                                    bridgeEncryption.canonicalBytesHex,
                                ),
                            });
                            expectBridgeVerificationRejected({
                                ...bridgeEncryption,
                                collectivePublicKeyRoot: '0'.repeat(128),
                            });
                            expectBridgeVerificationRejected({
                                ...bridgeEncryption,
                                profileHash: '0'.repeat(128),
                            });
                            expectBridgeVerificationRejected(
                                bridgeEncryptionWithUpdatedProofPayload(
                                    {
                                        plaintextRoot: '0'.repeat(128),
                                    },
                                    {
                                        plaintextRoot: '0'.repeat(128),
                                    },
                                ),
                            );
                        },
                    );
                    await runBridgeTestStep(
                        'run bridge proof payload mutation checks',
                        () => {
                            expectBridgeVerificationRejected(
                                bridgeEncryptionWithUpdatedProofPayload(
                                    {
                                        bridgeProofStatementHash: '0'.repeat(
                                            128,
                                        ),
                                    },
                                    {
                                        bridgeProofStatementHash: '0'.repeat(
                                            128,
                                        ),
                                    },
                                ),
                            );
                            expectBridgeVerificationRejected(
                                bridgeEncryptionWithUpdatedProofPayload(
                                    {
                                        bridgeProofStatement: {
                                            ...(bridgeProofPayload.bridgeProofStatement as Record<
                                                string,
                                                unknown
                                            >),
                                            postVotingClosedContextHash:
                                                '0'.repeat(128),
                                        },
                                    },
                                    {},
                                ),
                            );
                            expectBridgeVerificationRejected(
                                bridgeEncryptionWithUpdatedProofPayload(
                                    {
                                        bridgeProofStatement: {
                                            ...bridgeProofStatement,
                                            bridgeProofTargetContract: {
                                                ...bridgeProofTargetContract,
                                                sampledDiagnosticsAcceptedForVerification: true,
                                            },
                                        },
                                    },
                                    {},
                                ),
                            );
                            expectBridgeVerificationRejected(
                                bridgeEncryptionWithUpdatedProofPayload(
                                    {
                                        aggregateRelationChallengeHex:
                                            '0'.repeat(48),
                                    },
                                    {},
                                ),
                            );
                            expectBridgeVerificationRejected(
                                bridgeEncryptionWithUpdatedProofPayload(
                                    {
                                        aggregateRelationCommitmentHash:
                                            '0'.repeat(128),
                                    },
                                    {},
                                ),
                            );
                            expectBridgeVerificationRejected(
                                bridgeEncryptionWithUpdatedProofPayload(
                                    {
                                        aggregateRelationSubproofSizeBytes: 1,
                                    },
                                    {},
                                ),
                            );
                            expectBridgeVerificationRejected(
                                bridgeEncryptionWithUpdatedProofPayload(
                                    {
                                        aggregateReducedCoordinateCount: 219,
                                    },
                                    {},
                                ),
                            );
                        },
                    );

                    await runBridgeTestStep(
                        'reject wrong bridge witness',
                        () => {
                            const wrongWitness = {
                                ...witness,
                                aggregateIntegerShareVector:
                                    witness.aggregateIntegerShareVector.map(
                                        (coordinate, coordinateIndex) =>
                                            coordinateIndex === 0
                                                ? coordinate + 1
                                                : coordinate,
                                    ),
                            };
                            expect(
                                kernel.generateAggregateBridgeEncryption({
                                    aggregateSelectionPolicyHash,
                                    aggregateDerivationComponent: component,
                                    aggregateWitness: wrongWitness,
                                    bridgeWitnessPrivacyProfileHash,
                                    heParamHash,
                                    proverRandomnessHex: '77'.repeat(32),
                                    setupPackage,
                                }),
                            ).toMatchObject({
                                ok: false,
                                operation: 'generateAggregateBridgeEncryption',
                                unresolvedReason: 'BallotPackageInvalid',
                            });
                        },
                    );
                },
            );
        },
        aggregateHeavyStepTimeoutMs,
    );
};
