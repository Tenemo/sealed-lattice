import { verifyBridgeProof as verifyPublicSdkBridgeProof } from 'sealed-lattice';
import { expect, it } from 'vitest';

import { canonicalJson, deriveProtocolHash } from '#packages/crypto/src/index';
import {
    createPendingBridgeProofRecordFromBridgeEvidence,
    type PendingBridgeProofRecordFromEvidenceInput,
} from '#packages/protocol/src/ballot-privacy/aggregate-bridge/structure-verification.js';
import {
    buildAggregateDerivationStatement,
    createAggregateDerivationComponent,
    deriveBridgeProofChallengeContextHash,
    deriveBridgeProofTargetContractHash,
    sumAggregateDerivationWitnesses,
} from '#packages/protocol/src/ballot-privacy/index';
import { loadTranscriptCoreKernel } from '#packages/wasm/src/index';

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

const privateBridgeWitnessFieldNames: ReadonlySet<string> = new Set([
    'aggregateIntegerShareVector',
    'aggregateOpeningRandomness',
    'layoutPlaintextWitness',
    'bgvPlaintext',
    'encryptionRandomness',
    'encryptionError',
    'sourceWitnessCoefficients',
] as const);

const deriveBridgeTestSupportHash = (
    purpose: string,
    statementHash: string,
): string =>
    deriveProtocolHash('ChallengeDomainHash', {
        purpose,
        statementHash,
    });

const expectNoPrivateBridgeWitnessFields = (
    value: unknown,
    currentPath = 'bridgeEncryption',
): void => {
    if (Array.isArray(value)) {
        value.forEach((entry, entryIndex) => {
            expectNoPrivateBridgeWitnessFields(
                entry,
                `${currentPath}[${entryIndex}]`,
            );
        });
        return;
    }

    if (typeof value === 'string') {
        for (const privateFieldName of privateBridgeWitnessFieldNames) {
            expect(
                value.includes(`"${privateFieldName}":`),
                `${currentPath} must not contain a raw private witness field named ${privateFieldName}`,
            ).toBe(false);
        }
        return;
    }

    if (typeof value !== 'object' || value === null) {
        return;
    }

    for (const [fieldName, fieldValue] of Object.entries(
        value as Record<string, unknown>,
    )) {
        expect(
            privateBridgeWitnessFieldNames.has(fieldName),
            `${currentPath}.${fieldName} must not expose private witness material`,
        ).toBe(false);
        expectNoPrivateBridgeWitnessFields(
            fieldValue,
            `${currentPath}.${fieldName}`,
        );
    }
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
    ): Promise<T> =>
        runAggregateTestStep(`encrypted aggregate bridge: ${name}`, action);

    it(
        'generates encrypted aggregate bridge encryption evidence without public witness material',
        async () => {
            await runAggregateTestStep(
                'Generate encrypted aggregate bridge encryption evidence',
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
                                setupSeed:
                                    'encrypted-aggregate-bridge-test-seed',
                                thresholdProfileHash:
                                    statement.thresholdProfileHash,
                            }),
                    );
                    const aggregateSelectionPolicyHash = deriveProtocolHash(
                        'ChallengeDomainHash',
                        {
                            purpose:
                                'encrypted-aggregate-bridge-kernel-test-selection-policy',
                            statementHash:
                                statement.aggregateDerivationStatementHash,
                        },
                    );
                    const bridgeWitnessPrivacyProfileHash = deriveProtocolHash(
                        'ChallengeDomainHash',
                        {
                            purpose:
                                'encrypted-aggregate-bridge-kernel-test-witness-privacy',
                            statementHash:
                                statement.aggregateDerivationStatementHash,
                        },
                    );
                    const heParamHash = deriveBridgeTestSupportHash(
                        'encrypted-aggregate-bridge-kernel-test-he-param',
                        statement.aggregateDerivationStatementHash,
                    );
                    expect(() =>
                        kernel.generateAggregateBridgeEncryption({
                            aggregateSelectionPolicyHash,
                            aggregateDerivationComponent: component,
                            aggregateWitness: witness,
                            bridgeWitnessPrivacyProfileHash,
                            heParamHash,
                            proverRandomnessHex: '77'.repeat(32),
                            encryptionRandomnessSeedHex: '88'.repeat(32),
                            setupPackage,
                        }),
                    ).toThrow(/developmentRandomnessOverrideAcknowledged/u);
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
                                encryptionRandomnessSeedHex: '88'.repeat(32),
                                developmentRandomnessOverrideAcknowledged: true,
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
                        'BgvPublicKeyCoefficientMaterialBound',
                        'DecryptableBgvCiphertextConvention',
                        'TargetThresholdDecryptabilityCompatibilityCertified',
                        'CoefficientDomainCanonical',
                        'BridgeProofRelationChecked',
                        'BridgeProofImplementationEvidenceOnly',
                        'SharedWitnessZeroKnowledgeResponseDistributionChecked',
                        'BgvRandomnessErrorSupportPolynomialChecked',
                        'PlaintextCanonicalLiftProofChecked',
                        'AggregateDerivationFullVerificationPreconditionNotBound',
                        'BridgeProofClaimClosureMissing',
                        'RepresentativeBridgeMatrixRowEvidence',
                    ]);
                    expect(bridgeEncryption).toMatchObject({
                        bridgeClaimClosureVerified: false,
                        bridgeClaimVerificationStatus:
                            'BridgeProofClaimClosureMissing',
                        bgvEncryptionKeyMaterialKind:
                            'passive-transcript-derived-collective-public-key',
                        developmentKeyOnly: false,
                        proverRandomnessSource:
                            'development-deterministic-fixture',
                        encryptionRandomnessSeedSource:
                            'development-deterministic-fixture',
                        randomnessSourceEvidence: {
                            callerSuppliedDevelopmentRandomness: true,
                            claimBearingEntropyEvidence: false,
                            encryptionRandomnessSeedSource:
                                'development-deterministic-fixture',
                            objectType:
                                'AggregateBridgeRandomnessSourceEvidence',
                            objectVersion: 1,
                            proverRandomnessSource:
                                'development-deterministic-fixture',
                        },
                        thresholdDecryptable: true,
                        claimBearingBridgeEncryption: false,
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
                        String(
                            bridgeEncryption.bridgeProofChallengeContextHash,
                        ),
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
                            aggregateDerivationVerificationScope:
                                'AggregateDerivationFullVerificationPreconditionNotBound',
                        });
                    const expectedChallengeContextHash =
                        deriveBridgeProofChallengeContextHash({
                            bridgeProofProfileHash: String(
                                bridgeEncryption.bridgeProofProfileHash,
                            ),
                            bridgeProofStatementHash: String(
                                bridgeEncryption.bridgeProofStatementHash,
                            ),
                            bridgeProofTargetContractHash: String(
                                bridgeEncryption.bridgeProofTargetContractHash,
                            ),
                        });
                    expect(bridgeProofPayload.bridgeProofProfileHash).toBe(
                        bridgeEncryption.bridgeProofProfileHash,
                    );
                    expect(bridgeProofPayload.bridgeProofStatementHash).toBe(
                        bridgeEncryption.bridgeProofStatementHash,
                    );
                    expect(
                        bridgeProofPayload.bridgeProofChallengeContextHash,
                    ).toBe(bridgeEncryption.bridgeProofChallengeContextHash);
                    expect(
                        bridgeProofPayload.bridgeProofChallengeContextHash,
                    ).toBe(expectedChallengeContextHash);
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
                            bridgeProofChallengeContextHash:
                                expectedChallengeContextHash,
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
                            'SealedLatticePassiveCollectiveCiphertextEquationRelation',
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
                            plaintextCanonicalLiftProofStatus:
                                'PlaintextCanonicalLiftProofChecked',
                            proofFriendlyPlaintextBindingRequired: true,
                            publicPlaintextRootAcceptedAsClosureEvidence: false,
                            sharedWitnessCheckCount: 2,
                            sharedWitnessChallengeEntropyBits: 128,
                            sharedWitnessRejectionAttemptLimit: 64,
                            sharedWitnessGrindingDiscountBitsPerCheck: 6,
                            sharedWitnessRejectionRetryLossBits: 12,
                            sharedWitnessFullMatrixUnionBoundBits: 9,
                            sharedWitnessRandomOracleQueryBoundBits: 0,
                            sharedWitnessProofSystemLossBits: 0,
                            sharedWitnessChallengeBiasBits: 0,
                            sharedWitnessTargetBindingSoundnessBits: 128,
                            sharedWitnessUnadjustedWeakestRelationSoundnessBitsFloor: 186,
                            sharedWitnessEffectiveBindingSoundnessBitsFloor: 165,
                            sharedWitnessEffectiveBindingBelowTarget: false,
                            sharedWitnessWeakestRelation:
                                'BGVBatchEncode65537IntegerLiftedInverseNegacyclicNtt',
                            sharedWitnessWeakestRelationModuli: [
                                140_737_487_306_753, 140_737_486_716_929,
                            ],
                            sharedWitnessWeakestRelationModulusProduct:
                                '19807040250408114080301121537',
                            plaintextEncodingProofModuli: [
                                140_737_487_306_753, 140_737_486_716_929,
                            ],
                            plaintextEncodingProofModulusProduct:
                                '19807040250408114080301121537',
                            plaintextEncodingProofModulusProductBitsFloor: 93,
                            sharedWitnessZeroKnowledgeStatus:
                                'SharedWitnessZeroKnowledgeResponseDistributionChecked',
                            bgvEncryptionKeyMaterialKind:
                                'passive-transcript-derived-collective-public-key',
                            developmentKeyOnly: false,
                            thresholdDecryptable: true,
                            claimBearingBridgeEncryption: false,
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
                                plaintextEncodingQuotientCount: 32_768,
                                plaintextEncodingRelationRowCount: 32_768,
                                sameWitnessLinkageModel:
                                    'SingleTranscriptSharedWitnessOrExplicitSameWitnessLinkRequired',
                                separateSubproofsAcceptedForClosure: false,
                                sharedReducedCoordinateColumnRole:
                                    'aggregate-reduction-and-bgv-plaintext-slot',
                                sharedResponseScalarCount: 164_564,
                            },
                            sharedWitnessLayoutHash: expect.any(
                                String,
                            ) as string,
                        },
                        sampledPublicRelationCheckPolicyHash: expect.any(
                            String,
                        ) as string,
                        relationRequirements: {
                            bgvEncryptionKeyMaterialKind:
                                'passive-transcript-derived-collective-public-key',
                            developmentKeyOnly: false,
                            thresholdDecryptable: true,
                            claimBearingBridgeEncryption: false,
                            sampledOnlyBridgeVerificationAccepted: false,
                            sharedWitnessBindingRequired: true,
                            sharedWitnessChallengeEntropyBits: 128,
                            sharedWitnessRejectionAttemptLimit: 64,
                            sharedWitnessGrindingDiscountBitsPerCheck: 6,
                            sharedWitnessRejectionRetryLossBits: 12,
                            sharedWitnessFullMatrixUnionBoundBits: 9,
                            sharedWitnessRandomOracleQueryBoundBits: 0,
                            sharedWitnessProofSystemLossBits: 0,
                            sharedWitnessChallengeBiasBits: 0,
                            sharedWitnessTargetBindingSoundnessBits: 128,
                            sharedWitnessUnadjustedWeakestRelationSoundnessBitsFloor: 186,
                            sharedWitnessEffectiveBindingSoundnessBitsFloor: 165,
                            sharedWitnessEffectiveBindingBelowTarget: false,
                            sharedWitnessWeakestRelation:
                                'BGVBatchEncode65537IntegerLiftedInverseNegacyclicNtt',
                            sharedWitnessWeakestRelationModuli: [
                                140_737_487_306_753, 140_737_486_716_929,
                            ],
                            sharedWitnessWeakestRelationModulusProduct:
                                '19807040250408114080301121537',
                            plaintextEncodingProofModuli: [
                                140_737_487_306_753, 140_737_486_716_929,
                            ],
                            plaintextEncodingProofModulusProduct:
                                '19807040250408114080301121537',
                            plaintextEncodingProofModulusProductBitsFloor: 93,
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
                    expectNoPrivateBridgeWitnessFields(bridgeEncryption);
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
                        'EncryptedAggregateSingleContributionBridgeRelationChecked',
                        'BridgeProofImplementationEvidenceOnly',
                        'BgvPublicKeyCoefficientMaterialBound',
                        'DecryptableBgvCiphertextConvention',
                        'TargetThresholdDecryptabilityCompatibilityCertified',
                        'SharedWitnessZeroKnowledgeResponseDistributionChecked',
                        'BgvRandomnessErrorSupportPolynomialChecked',
                        'PlaintextCanonicalLiftProofChecked',
                        'AggregateDerivationFullVerificationPreconditionNotBound',
                        'BridgeProofClaimClosureMissing',
                        'FinalBridgeTheoremPending',
                        'RepresentativeBridgeMatrixRowEvidence',
                    ]);
                    expect(bridgeVerification).toMatchObject({
                        bridgeClaimClosureVerified: false,
                        bridgeClaimVerificationStatus:
                            'BridgeProofClaimClosureMissing',
                        bgvEncryptionKeyMaterialKind:
                            'passive-transcript-derived-collective-public-key',
                        developmentKeyOnly: false,
                        thresholdDecryptable: true,
                        claimBearingBridgeEncryption: false,
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
                    expect(
                        String(
                            bridgeVerification.bridgeProofChallengeContextHash,
                        ),
                    ).toBe(expectedChallengeContextHash);
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

                        return verification;
                    };

                    await runBridgeTestStep(
                        'reject public SDK sampled-only bridge status',
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
                                            'encrypted aggregate bridge relation proof requires verifier-checked bridge encryption status',
                                    }),
                                ]),
                            );
                        },
                    );
                    await runBridgeTestStep(
                        'reject public SDK wrong bridge selection policy',
                        async () => {
                            await expectPublicSdkBridgeVerificationRejected(
                                {
                                    aggregateSelectionPolicyHash:
                                        deriveProtocolHash(
                                            'ChallengeDomainHash',
                                            {
                                                purpose:
                                                    'encrypted-aggregate-bridge-kernel-test-public-sdk-wrong-selection-policy',
                                                statementHash:
                                                    statement.aggregateDerivationStatementHash,
                                            },
                                        ),
                                },
                                /selection policy|proof statement|statement hash/iu,
                            );
                        },
                    );
                    await runBridgeTestStep(
                        'reject public SDK malformed bridge proof hash',
                        async () => {
                            await expectPublicSdkBridgeVerificationRejected(
                                {
                                    bridgeEncryption: {
                                        ...bridgeEncryption,
                                        bridgeProofBytesHash: '0'.repeat(128),
                                    },
                                },
                                /proof bytes hash|proof root|hash/iu,
                            );
                        },
                    );
                    await runBridgeTestStep(
                        'reject public SDK malformed bridge proof bytes',
                        async () => {
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
                                        setupPackage: setupPackage,
                                    },
                                );
                            expect(pendingBridgeProofRecord).toMatchObject({
                                bridgeProofChallengeContextHash:
                                    expectedChallengeContextHash,
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
                        proofOverrides: Record<string, unknown>,
                    ): void => {
                        const proofOverrideHasField = (
                            fieldName: string,
                        ): boolean =>
                            Object.prototype.hasOwnProperty.call(
                                proofOverrides,
                                fieldName,
                            );
                        const sharedWitnessProofChanged = proofOverrideHasField(
                            'bridgeSharedWitnessProof',
                        );
                        const sharedWitnessProofHashChanged =
                            sharedWitnessProofChanged
                                ? true
                                : proofOverrideHasField(
                                      'bridgeSharedWitnessProofHash',
                                  );
                        if (
                            sharedWitnessProofChanged &&
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
                            sharedWitnessProofHashChanged &&
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
                            (sharedWitnessProofHashChanged
                                ? true
                                : proofOverrideHasField(
                                      'sharedWitnessZeroKnowledgeStatusEvidence',
                                  )) &&
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
                            (sharedWitnessProofHashChanged
                                ? true
                                : proofOverrideHasField(
                                      'bgvRandomnessBoundProofStatusEvidence',
                                  )) &&
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
                        refreshBridgeProofPayloadDerivedHashes(
                            proofPayload,
                            proofOverrides,
                        );
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
                                bridgeProofChallengeContextHash:
                                    bridgePayload.bridgeProofChallengeContextHash,
                                bgvPublicKeyRoot:
                                    bridgePayload.bgvPublicKeyRoot,
                                collectivePublicKeyRoot:
                                    bridgePayload.collectivePublicKeyRoot,
                                collectivePublicKeyCoefficientRoot:
                                    bridgePayload.collectivePublicKeyCoefficientRoot,
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
                                            'ChallengeDomainHash',
                                            {
                                                purpose:
                                                    'encrypted-aggregate-bridge-kernel-test-wrong-selection-policy',
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
                                        deriveBridgeTestSupportHash(
                                            'encrypted-aggregate-bridge-kernel-test-wrong-witness-privacy',
                                            statement.aggregateDerivationStatementHash,
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
                                    heParamHash: deriveBridgeTestSupportHash(
                                        'encrypted-aggregate-bridge-kernel-test-wrong-he-param',
                                        statement.aggregateDerivationStatementHash,
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
                                bridgeProofChallengeContextHash: '0'.repeat(
                                    128,
                                ),
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
                            expectBridgeVerificationRejected({
                                ...bridgeEncryption,
                                plaintextRoot: '0'.repeat(128),
                            });
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
                                        bridgeProofChallengeContextHash:
                                            '0'.repeat(128),
                                    },
                                    {
                                        bridgeProofChallengeContextHash:
                                            '0'.repeat(128),
                                    },
                                ),
                            );
                            expectBridgeVerificationRejected(
                                bridgeEncryptionWithUpdatedProofPayload(
                                    {
                                        bridgeSharedWitnessProof: {
                                            ...(bridgeProofPayload.bridgeSharedWitnessProof as Record<
                                                string,
                                                unknown
                                            >),
                                            bridgeProofChallengeContextHash:
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
                                    encryptionRandomnessSeedHex: '88'.repeat(
                                        32,
                                    ),
                                    developmentRandomnessOverrideAcknowledged: true,
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
