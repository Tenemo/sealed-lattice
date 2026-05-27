import { expect, it } from 'vitest';

import { loadTranscriptCoreKernel } from '../../../../src/index';

import {
    canonicalJson,
    deriveProtocolDigest,
} from '#packages/crypto/src/index';
import {
    createPendingBridgeProofRecordFromBridgeEvidence,
    type PendingBridgeProofRecordFromEvidenceInput,
} from '#packages/protocol/src/ballot-privacy/aggregate-bridge/structure-verification.js';
import {
    buildAggregateDerivationStatement,
    createAggregateDerivationComponent,
    sumAggregateDerivationWitnesses,
} from '#packages/protocol/src/ballot-privacy/index';

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

    it(
        'generates M9 bridge encryption evidence without public witness material',
        async () => {
            await runAggregateTestStep(
                'Generate M9 bridge encryption evidence',
                () => {
                    const { component, kernel, statement, witness } =
                        getAggregateComponentContext();
                    const setupPackage = kernel.generateBgvPassiveSetup({
                        ceremonyId: statement.ceremonyId,
                        manifestDigest: statement.manifestDigest,
                        participants: Array.from(
                            { length: statement.participantCount },
                            (_unusedValue, participantIndex) => ({
                                boardPosition: participantIndex + 3,
                                rosterPosition: participantIndex,
                                trusteeIdentity: `receiver-${participantIndex}`,
                            }),
                        ),
                        rosterDigest: statement.rosterDigest,
                        setupSeed: 'm9-bridge-test-seed',
                        thresholdProfileDigest:
                            statement.thresholdProfileDigest,
                    });
                    const aggregateSelectionPolicyDigest = deriveProtocolDigest(
                        'AggregateSelectionPolicyDigest',
                        {
                            purpose: 'm9-kernel-bridge-test-selection-policy',
                            statementDigest:
                                statement.aggregateDerivationStatementDigest,
                        },
                    );
                    const bridgeWitnessPrivacyProfileDigest =
                        deriveProtocolDigest(
                            'BridgeWitnessPrivacyProfileDigest',
                            {
                                purpose:
                                    'm9-kernel-bridge-test-witness-privacy',
                                statementDigest:
                                    statement.aggregateDerivationStatementDigest,
                            },
                        );
                    const heParamDigest = deriveProtocolDigest(
                        'HEParamDigest',
                        {
                            purpose: 'm9-kernel-bridge-test-he-param',
                            statementDigest:
                                statement.aggregateDerivationStatementDigest,
                        },
                    );
                    const bridgeEncryption =
                        kernel.generateAggregateBridgeEncryption({
                            aggregateSelectionPolicyDigest,
                            aggregateDerivationComponent: component,
                            aggregateWitness: witness,
                            bridgeWitnessPrivacyProfileDigest,
                            heParamDigest,
                            includeCanonicalBytesHex: true,
                            proverRandomnessHex: '77'.repeat(32),
                            setupPackage,
                        }) as Record<string, unknown>;
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
                        'SharedWitnessZeroKnowledgeProofMissing',
                        'BgvRandomnessBoundProofMissing',
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
                        String(bridgeEncryption.bridgeProofProfileDigest),
                    ).toHaveLength(128);
                    expect(
                        String(bridgeEncryption.bridgeProofStatementDigest),
                    ).toHaveLength(128);
                    expect(
                        String(
                            bridgeEncryption.bridgeProofTargetContractDigest,
                        ),
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
                    expect(bridgeProofPayload.bridgeProofProfileDigest).toBe(
                        bridgeEncryption.bridgeProofProfileDigest,
                    );
                    expect(bridgeProofPayload.bridgeProofStatementDigest).toBe(
                        bridgeEncryption.bridgeProofStatementDigest,
                    );
                    expect(
                        bridgeProofPayload.bridgeProofTargetContractDigest,
                    ).toBe(bridgeEncryption.bridgeProofTargetContractDigest);
                    expect(bridgeProofPayload).toMatchObject({
                        objectType: 'SealedLatticeAggregateBridgeRelationProof',
                        bridgeSharedWitnessProof: {
                            objectType: 'AggregateBridgeSharedWitnessProof',
                            proofModel: 'fiat-shamir-linear-shared-response-v1',
                            relationCheckCount: 2,
                            responseEncoding:
                                'signed-i128-little-endian-hex-v1',
                            sameHiddenAggregateCoordinatesLinked: true,
                        },
                        singleContributionBridgeRelationChecked: true,
                    });
                    expect(bridgeProofPayload).toMatchObject({
                        aggregateQuotientCoordinateCount: 220,
                        aggregateReducedCoordinateCount: 220,
                        aggregateRelationChallengeHex: expect.any(
                            String,
                        ) as string,
                        aggregateRelationCommitmentDigest: expect.any(
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
                            bridgeProofPayload.aggregateRelationCommitmentDigest,
                        ),
                    ).toHaveLength(128);
                    expect(
                        bridgeProofPayload.bridgeProofStatement,
                    ).toMatchObject({
                        aggregateDerivationComponentDigest:
                            component.aggregateDerivationComponentDigest,
                        aggregateShareCommitmentDigest:
                            component.aggregateCommitment
                                .aggregateShareCommitmentDigest,
                        aggregateSelectionPolicyDigest,
                        bgvEncryptionProofSubrelation:
                            'SealedLatticeDevelopmentCiphertextEquationRelation',
                        bridgeWitnessPrivacyProfileDigest,
                        bridgeProofTargetContractDigest:
                            bridgeEncryption.bridgeProofTargetContractDigest,
                        heParamDigest,
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
                                'SharedWitnessZeroKnowledgeProofMissing',
                            bgvRandomnessBoundProofStatus:
                                'BgvRandomnessBoundProofMissing',
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
                            sharedWitnessLayoutDigest: expect.any(
                                String,
                            ) as string,
                        },
                        sampledPublicRelationCheckPolicyDigest: expect.any(
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
                    const bridgeVerification =
                        kernel.verifyAggregateBridgeEncryption({
                            aggregateSelectionPolicyDigest,
                            aggregateDerivationComponent: component,
                            bridgeEncryption,
                            bridgeWitnessPrivacyProfileDigest,
                            heParamDigest,
                            setupPackage,
                        }) as Record<string, unknown>;
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
                        'SharedWitnessZeroKnowledgeProofMissing',
                        'BgvRandomnessBoundProofMissing',
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
                        String(
                            bridgeVerification.bridgeProofTargetContractDigest,
                        ),
                    ).toBe(
                        String(
                            bridgeEncryption.bridgeProofTargetContractDigest,
                        ),
                    );
                    const pendingBridgeProofRecord =
                        createPendingBridgeProofRecordFromBridgeEvidence({
                            aggregateDerivationComponent: component,
                            aggregateSelectionPolicyDigest,
                            bridgeEncryptionEvidence:
                                bridgeEncryption as PendingBridgeProofRecordFromEvidenceInput['bridgeEncryptionEvidence'],
                            bridgeEvidenceVerification:
                                bridgeVerification as PendingBridgeProofRecordFromEvidenceInput['bridgeEvidenceVerification'],
                            bridgeWitnessPrivacyProfileDigest,
                            heParamDigest,
                            setupPackage:
                                setupPackage as PendingBridgeProofRecordFromEvidenceInput['setupPackage'],
                        });
                    expect(pendingBridgeProofRecord).toMatchObject({
                        bridgeProofTargetContractDigest:
                            bridgeEncryption.bridgeProofTargetContractDigest,
                        bridgeProofVerificationStatus:
                            'BridgeProofRelationChecked',
                        encryptedAggregateShareCiphertextRoot:
                            bridgeEncryption.encryptedAggregateShareCiphertextRoot,
                        proofRoot: bridgeVerification.bridgeProofRoot,
                        proofStatementDigest:
                            bridgeVerification.bridgeProofStatementDigest,
                    });

                    const expectBridgeVerificationRejected = (
                        mutatedBridgeEncryption: Record<string, unknown>,
                    ): void => {
                        expect(
                            kernel.verifyAggregateBridgeEncryption({
                                aggregateSelectionPolicyDigest,
                                aggregateDerivationComponent: component,
                                bridgeEncryption: mutatedBridgeEncryption,
                                bridgeWitnessPrivacyProfileDigest,
                                heParamDigest,
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
                        const bridgePayload = {
                            ...bridgeEncryption,
                            ...bridgeOverrides,
                        };
                        const bridgeProofBytesHex = Buffer.from(
                            canonicalJson(proofPayload),
                            'utf8',
                        ).toString('hex');
                        const bridgeProofBytesDigest = deriveProtocolDigest(
                            'ProofBytesDigest',
                            {
                                proofBytesHex: bridgeProofBytesHex,
                                purpose:
                                    'sealed-lattice-aggregate-bridge-encryption-proof-bytes-v1',
                            },
                        );
                        const bridgeProofRoot = deriveProtocolDigest(
                            'BridgeProofRecordDigest',
                            {
                                aggregateDerivationComponentDigest:
                                    component.aggregateDerivationComponentDigest,
                                aggregateDerivationStatementDigest:
                                    statement.aggregateDerivationStatementDigest,
                                bridgeProofProfileDigest:
                                    bridgePayload.bridgeProofProfileDigest,
                                bridgeProofStatementDigest:
                                    bridgePayload.bridgeProofStatementDigest,
                                bgvPublicKeyRoot:
                                    bridgePayload.bgvPublicKeyRoot,
                                collectivePublicKeyRoot:
                                    bridgePayload.collectivePublicKeyRoot,
                                encryptedAggregateShareCiphertextRoot:
                                    bridgePayload.encryptedAggregateShareCiphertextRoot,
                                proofBytesDigest: bridgeProofBytesDigest,
                                purpose:
                                    'sealed-lattice-aggregate-bridge-encryption-proof-root-v1',
                            },
                        );

                        return {
                            ...bridgePayload,
                            bridgeProofBytesDigest,
                            bridgeProofBytesHex,
                            bridgeProofRoot,
                        };
                    };
                    expect(
                        kernel.verifyAggregateBridgeEncryption({
                            aggregateSelectionPolicyDigest:
                                deriveProtocolDigest(
                                    'AggregateSelectionPolicyDigest',
                                    {
                                        purpose:
                                            'm9-kernel-bridge-test-wrong-selection-policy',
                                        statementDigest:
                                            statement.aggregateDerivationStatementDigest,
                                    },
                                ),
                            aggregateDerivationComponent: component,
                            bridgeEncryption,
                            bridgeWitnessPrivacyProfileDigest,
                            heParamDigest,
                            setupPackage,
                        }),
                    ).toMatchObject({
                        ok: false,
                        operation: 'verifyAggregateBridgeEncryption',
                    });
                    expect(
                        kernel.verifyAggregateBridgeEncryption({
                            aggregateSelectionPolicyDigest,
                            aggregateDerivationComponent: component,
                            bridgeEncryption,
                            bridgeWitnessPrivacyProfileDigest:
                                deriveProtocolDigest(
                                    'BridgeWitnessPrivacyProfileDigest',
                                    {
                                        purpose:
                                            'm9-kernel-bridge-test-wrong-witness-privacy',
                                        statementDigest:
                                            statement.aggregateDerivationStatementDigest,
                                    },
                                ),
                            heParamDigest,
                            setupPackage,
                        }),
                    ).toMatchObject({
                        ok: false,
                        operation: 'verifyAggregateBridgeEncryption',
                    });
                    expect(
                        kernel.verifyAggregateBridgeEncryption({
                            aggregateSelectionPolicyDigest,
                            aggregateDerivationComponent: component,
                            bridgeEncryption,
                            bridgeWitnessPrivacyProfileDigest,
                            heParamDigest: deriveProtocolDigest(
                                'HEParamDigest',
                                {
                                    purpose:
                                        'm9-kernel-bridge-test-wrong-he-param',
                                    statementDigest:
                                        statement.aggregateDerivationStatementDigest,
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
                        bridgeProofBytesDigest: '0'.repeat(128),
                    });
                    expectBridgeVerificationRejected({
                        ...bridgeEncryption,
                        bridgeProofStatementDigest: '0'.repeat(128),
                    });
                    expectBridgeVerificationRejected({
                        ...bridgeEncryption,
                        bridgeProofTargetContractDigest: '0'.repeat(128),
                    });
                    expectBridgeVerificationRejected({
                        ...bridgeEncryption,
                        bridgeProofBytesHex: replaceLastHexDigit(
                            bridgeEncryption.bridgeProofBytesHex,
                        ),
                    });
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
                        profileDigest: '0'.repeat(128),
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
                    expectBridgeVerificationRejected(
                        bridgeEncryptionWithUpdatedProofPayload(
                            {
                                bridgeProofStatementDigest: '0'.repeat(128),
                            },
                            {
                                bridgeProofStatementDigest: '0'.repeat(128),
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
                                    postVotingClosedContextDigest: '0'.repeat(
                                        128,
                                    ),
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
                                aggregateRelationChallengeHex: '0'.repeat(48),
                            },
                            {},
                        ),
                    );
                    expectBridgeVerificationRejected(
                        bridgeEncryptionWithUpdatedProofPayload(
                            {
                                aggregateRelationCommitmentDigest: '0'.repeat(
                                    128,
                                ),
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
                            aggregateSelectionPolicyDigest,
                            aggregateDerivationComponent: component,
                            aggregateWitness: wrongWitness,
                            bridgeWitnessPrivacyProfileDigest,
                            heParamDigest,
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
        aggregateHeavyStepTimeoutMs,
    );
};
