import {
    loadTranscriptCoreKernel,
    type TranscriptCoreKernel,
} from '../../../src/index';

import type { NamedFixture } from './shared.js';
import {
    ballotFieldLinearProofBackendVectors,
    cloneJsonValue,
    expandBallotFieldLinearProofVectorCase,
    findFixture,
} from './shared.js';

type JsonRecord = Record<string, unknown>;

type EncodedScoreFieldBallotProofRecordFixture = {
    readonly componentIds: readonly string[];
    readonly createBallotProof: (
        statement: JsonRecord,
        linearStatement: JsonRecord,
        componentBundleStatement?: JsonRecord,
        componentProofBundle?: JsonRecord,
    ) => JsonRecord;
    readonly createComponentBundleStatement: (
        linearStatement: JsonRecord,
        statement: JsonRecord,
        options?: { readonly fullCoverage?: boolean },
    ) => JsonRecord;
    readonly createComponentProofBundle: (
        componentBundleStatement: JsonRecord,
        componentProofs: readonly JsonRecord[],
    ) => JsonRecord;
    readonly createComponentProofInputs: (
        componentProofs: readonly JsonRecord[],
    ) => readonly JsonRecord[];
    readonly createComponentProofRecord: (
        linearStatement: JsonRecord,
        statement: JsonRecord,
        componentStatement: JsonRecord,
        componentId: string,
    ) => JsonRecord;
    readonly createComponentProofStatement: (input: {
        readonly componentId: string;
        readonly componentProofStatementDigest?: string;
        readonly componentStatementDigest: string;
        readonly proofStatementFormat: string;
    }) => JsonRecord;
    readonly digest: (label: string) => string;
    readonly incompleteComponentBundleStatement: JsonRecord;
    readonly kernel: TranscriptCoreKernel;
    readonly mutatedBallotProof: JsonRecord;
    readonly mutatedLinearStatement: JsonRecord;
    readonly proofBoundToIncompleteComponentBundle: JsonRecord;
    readonly proofBytesHex: string;
    readonly publicRandomnessHex: string;
    readonly statement: JsonRecord;
    readonly validBallotProof: JsonRecord;
    readonly validLinearStatement: JsonRecord;
    readonly validProofCase: JsonRecord;
};

export const createEncodedScoreFieldBallotProofRecordFixture =
    async (): Promise<EncodedScoreFieldBallotProofRecordFixture> => {
        const kernel = await loadTranscriptCoreKernel();
        const ballotFieldLinearProofCases =
            ballotFieldLinearProofBackendVectors.cases as readonly (Record<
                string,
                unknown
            > &
                NamedFixture)[];
        const validProofCase = expandBallotFieldLinearProofVectorCase(
            findFixture(
                ballotFieldLinearProofCases,
                'valid-encoded-score-field-linear-proof',
            ),
        );
        const mutatedTargetCase = expandBallotFieldLinearProofVectorCase(
            findFixture(
                ballotFieldLinearProofCases,
                'mutated-encoded-score-field-target-vector',
            ),
        );
        const proofBytesHex = String(validProofCase.proofHex);
        const publicRandomnessHex = String(validProofCase.publicRandomnessHex);
        const proofSizeBytes = proofBytesHex.length / 2;
        const digest = (label: string): string =>
            kernel.deriveProtocolDigest({
                namespace: 'ChallengeDomainDigest',
                value: {
                    label,
                    purpose:
                        'encoded-score-field-ballot-proof-record-wasm-test',
                },
            });
        const deriveProofBytesDigestForTest = (
            proofBytesHexForTest: string,
        ): string =>
            kernel.deriveProtocolDigest({
                namespace: 'ProofBytesDigest',
                value: {
                    objectType: 'ProofBytes',
                    objectVersion: 1,
                    proofBytesHex: proofBytesHexForTest,
                    proofSizeBytes: proofBytesHexForTest.length / 2,
                },
            });
        const deriveBallotProofEncodingDigestForTest = (
            proofEncoding: unknown,
        ): string =>
            kernel.deriveProtocolDigest({
                namespace: 'ChallengeDomainDigest',
                value: {
                    proofEncoding,
                    purpose: 'ballot-proof-linear-proof-encoding-profile-v1',
                },
            });
        const deriveBallotProofParameterSetDigestForTest = (
            parameterSet: unknown,
        ): string =>
            kernel.deriveProtocolDigest({
                namespace: 'ChallengeDomainDigest',
                value: {
                    parameterSet,
                    purpose: 'ballot-proof-linear-proof-parameter-set-v1',
                },
            });
        const deriveBallotProofPublicRandomnessDigestForTest = (
            componentPublicRandomnessHex: string,
        ): string =>
            kernel.deriveProtocolDigest({
                namespace: 'ChallengeDomainDigest',
                value: {
                    publicRandomnessHex: componentPublicRandomnessHex,
                    purpose: 'ballot-proof-linear-proof-public-randomness-v1',
                },
            });
        const createStatement = (): Record<string, unknown> => {
            const receiverReferences = Array.from(
                { length: 20 },
                (_unusedValue, receiverIndex) => {
                    const receiverRosterPosition = receiverIndex + 1;

                    return {
                        receiverIdentity: `receiver-${receiverRosterPosition}`,
                        receiverRosterPosition,
                    };
                },
            );
            const statementPayload = {
                actionContextDigest: digest('action-context'),
                aggregateInputEncodingProfileDigest: digest(
                    'aggregate-input-encoding-profile',
                ),
                ballotPackageDigest: digest('ballot-package'),
                ballotProofProfileDigest: digest('ballot-proof-profile'),
                ballotScoreEncodingProfileDigest: digest(
                    'ballot-score-encoding-profile',
                ),
                ballotShareLayoutProfileDigest: digest(
                    'ballot-share-layout-profile',
                ),
                ceremonyId: 'ceremony-encoded-score-field-ballot-proof-record',
                challengeDomainDigest: digest('challenge-domain'),
                duplicateBallotPolicyDigest: digest('duplicate-policy'),
                encodedAggregateLayoutDigest: digest(
                    'encoded-aggregate-layout',
                ),
                encodedShareVectorLayoutDigest: digest(
                    'encoded-share-vector-layout',
                ),
                manifestDigest: digest('manifest'),
                objectType: 'BallotProofStatement',
                objectVersion: 1,
                optionCount: 20,
                pollSpecDigest: digest('poll-spec'),
                receiverEncryptionProfileDigest: digest(
                    'receiver-encryption-profile',
                ),
                receiverKeyProofRoot: digest('receiver-key-proof-root'),
                receiverKeyRoot: digest('receiver-key-root'),
                receiverPayloads: receiverReferences.map(
                    (receiverReference) => ({
                        ...receiverReference,
                        receiverPayloadCiphertextRoot: digest(
                            `receiver-ciphertext-${receiverReference.receiverRosterPosition}`,
                        ),
                        receiverPayloadDigest: digest(
                            `receiver-payload-${receiverReference.receiverRosterPosition}`,
                        ),
                    }),
                ),
                receiverPublicKeys: receiverReferences.map(
                    (receiverReference) => ({
                        ...receiverReference,
                        receiverPublicKeyDigest: digest(
                            `receiver-public-key-${receiverReference.receiverRosterPosition}`,
                        ),
                    }),
                ),
                rosterDigest: digest('roster'),
                rosterExternalAcceptanceDigest: digest('external-acceptance'),
                scoreDomainDigest: digest('score-domain'),
                scoreMembershipProfileDigest: digest(
                    'score-membership-profile',
                ),
                shareCommitmentMessageBoundCertDigest: digest(
                    'share-commitment-bound-cert',
                ),
                shareCommitmentProfileDigest: digest(
                    'share-commitment-profile',
                ),
                shareCommitments: receiverReferences.map(
                    (receiverReference) => ({
                        ...receiverReference,
                        shareCommitmentDigest: digest(
                            `share-commitment-${receiverReference.receiverRosterPosition}`,
                        ),
                    }),
                ),
                shareVectorWidth: 220,
                thresholdProfileDigest: digest('threshold-profile'),
                tiePolicyDigest: digest('tie-policy'),
                topOptionCount: 3,
                voterIdentityDigest: digest('voter-1'),
                voterRosterPosition: 1,
                voterSigningKeyDigest: digest('voter-signing-key'),
            };

            return {
                ...statementPayload,
                ballotProofStatementDigest: kernel.deriveProtocolDigest({
                    namespace: 'BallotProofStatementDigest',
                    value: statementPayload,
                }),
            };
        };
        const createLinearStatement = (
            statement: Record<string, unknown>,
            vectorCase: Record<string, unknown>,
        ): Record<string, unknown> => {
            const statementMatrixCoefficients =
                vectorCase.statementMatrixCoefficients;
            const targetVectorCoefficients =
                vectorCase.targetVectorCoefficients;
            const linearStatementPayload = {
                ...cloneJsonValue(
                    ballotFieldLinearProofBackendVectors.linearStatement,
                ),
                ballotProofStatementDigest:
                    statement.ballotProofStatementDigest,
                matrixCoefficientRepresentation:
                    vectorCase.matrixCoefficientRepresentation,
                statementMatrixCoefficients,
                statementMatrixDigest: kernel.deriveProtocolDigest({
                    namespace: 'ChallengeDomainDigest',
                    value: {
                        purpose: 'ballot-proof-linear-statement-matrix-v1',
                        statementMatrixCoefficients,
                    },
                }),
                targetCoefficientRepresentation:
                    vectorCase.targetCoefficientRepresentation,
                targetVectorCoefficients,
                targetVectorDigest: kernel.deriveProtocolDigest({
                    namespace: 'ChallengeDomainDigest',
                    value: {
                        purpose: 'ballot-proof-linear-target-vector-v1',
                        targetVectorCoefficients,
                    },
                }),
            } as Record<string, unknown>;
            delete linearStatementPayload.statementDigest;

            return {
                ...linearStatementPayload,
                statementDigest: kernel.deriveProtocolDigest({
                    namespace: 'ChallengeDomainDigest',
                    value: {
                        payload: linearStatementPayload,
                        purpose: 'ballot-proof-linear-proof-statement-v1',
                    },
                }),
            };
        };
        const createBallotProof = (
            statement: Record<string, unknown>,
            linearStatement: Record<string, unknown>,
            componentBundleStatement?: Record<string, unknown>,
            componentProofBundle?: Record<string, unknown>,
        ): Record<string, unknown> => {
            const proofBytesDigest = kernel.deriveProtocolDigest({
                namespace: 'ProofBytesDigest',
                value: {
                    objectType: 'ProofBytes',
                    objectVersion: 1,
                    proofBytesHex,
                    proofSizeBytes,
                },
            });
            const proofEncodingProfileDigest = kernel.deriveProtocolDigest({
                namespace: 'ChallengeDomainDigest',
                value: {
                    proofEncoding: validProofCase.proofEncoding,
                    purpose: 'ballot-proof-linear-proof-encoding-profile-v1',
                },
            });
            const proofParameterSetDigest = kernel.deriveProtocolDigest({
                namespace: 'ChallengeDomainDigest',
                value: {
                    parameterSet: validProofCase.parameterSet,
                    purpose: 'ballot-proof-linear-proof-parameter-set-v1',
                },
            });
            const publicRandomnessDigest = kernel.deriveProtocolDigest({
                namespace: 'ChallengeDomainDigest',
                value: {
                    publicRandomnessHex,
                    purpose: 'ballot-proof-linear-proof-public-randomness-v1',
                },
            });
            const proofRoot = kernel.deriveProtocolDigest({
                namespace: 'BallotProofRecordDigest',
                value: {
                    linearStatementDigest: linearStatement.statementDigest,
                    proofBytesDigest,
                    proofEncodingProfileDigest,
                    proofParameterSetDigest,
                    publicRandomnessDigest,
                    purpose: 'ballot-proof-linear-proof-record-root-v1',
                },
            });
            const proofPayloadWithoutChallenge = {
                backendStatementDigest: linearStatement.backendStatementDigest,
                ballotProofProfileDigest: statement.ballotProofProfileDigest,
                ballotProofStatementDigest:
                    statement.ballotProofStatementDigest,
                ...(componentBundleStatement === undefined
                    ? {}
                    : {
                          componentBundleStatementDigest:
                              componentBundleStatement.componentBundleStatementDigest,
                      }),
                ...(componentProofBundle === undefined
                    ? {}
                    : {
                          componentProofBundleDigest:
                              componentProofBundle.componentProofBundleDigest,
                      }),
                linearStatementDigest: linearStatement.statementDigest,
                objectType: 'BallotProofRecord',
                objectVersion: 1,
                proofBackend: 'LocalLinearLatticeRelation',
                proofBytesDigest,
                proofEncodingProfileDigest,
                proofParameterSetDigest,
                proofRoot,
                proofSizeBytes,
                publicRandomnessDigest,
                relationStatementDigest:
                    linearStatement.relationStatementDigest,
                statementMatrixDigest: linearStatement.statementMatrixDigest,
                targetVectorDigest: linearStatement.targetVectorDigest,
            };
            const challengeDigest = kernel.deriveProtocolDigest({
                namespace: 'ChallengeDomainDigest',
                value: {
                    backendStatementDigest:
                        proofPayloadWithoutChallenge.backendStatementDigest,
                    ballotProofStatementDigest:
                        statement.ballotProofStatementDigest,
                    challengeDomainDigest: statement.challengeDomainDigest,
                    ...(componentBundleStatement === undefined
                        ? {}
                        : {
                              componentBundleStatementDigest:
                                  componentBundleStatement.componentBundleStatementDigest,
                          }),
                    ...(componentProofBundle === undefined
                        ? {}
                        : {
                              componentProofBundleDigest:
                                  componentProofBundle.componentProofBundleDigest,
                          }),
                    linearStatementDigest:
                        proofPayloadWithoutChallenge.linearStatementDigest,
                    proofBytesDigest:
                        proofPayloadWithoutChallenge.proofBytesDigest,
                    proofEncodingProfileDigest:
                        proofPayloadWithoutChallenge.proofEncodingProfileDigest,
                    proofParameterSetDigest:
                        proofPayloadWithoutChallenge.proofParameterSetDigest,
                    proofRoot: proofPayloadWithoutChallenge.proofRoot,
                    publicRandomnessDigest:
                        proofPayloadWithoutChallenge.publicRandomnessDigest,
                    relationStatementDigest:
                        proofPayloadWithoutChallenge.relationStatementDigest,
                    statementMatrixDigest:
                        proofPayloadWithoutChallenge.statementMatrixDigest,
                    targetVectorDigest:
                        proofPayloadWithoutChallenge.targetVectorDigest,
                },
            });
            const proofPayload = {
                ...proofPayloadWithoutChallenge,
                challengeDigest,
            };

            return {
                ...proofPayload,
                ballotProofRecordDigest: kernel.deriveProtocolDigest({
                    namespace: 'BallotProofRecordDigest',
                    value: proofPayload,
                }),
            };
        };
        const componentIds = [
            'score-and-shamir-field-component',
            'payload-plaintext-field-component',
            'share-commitment-component',
            'receiver-encryption-component',
            'receiver-key-binding-component',
        ];
        const createComponentStatement = (
            linearStatement: Record<string, unknown>,
            statement: Record<string, unknown>,
            componentId: string,
            componentIndex: number,
            proofLoweringStatus: string,
        ): Record<string, unknown> => {
            const componentPayload = {
                backendStatementDigest: linearStatement.backendStatementDigest,
                ballotProofStatementDigest:
                    statement.ballotProofStatementDigest,
                coefficientModulus: '65537',
                componentDigest: digest(`${componentId}-component`),
                componentId,
                matrixDigest: digest(`${componentId}-matrix`),
                objectType: 'BallotProofComponentStatement',
                objectVersion: 1,
                proofLoweringStatus,
                relationStatementDigest:
                    linearStatement.relationStatementDigest,
                rowBatchMatrixDigests: [digest(`${componentId}-row-matrix`)],
                rowBatchNames: [`${componentId}-rows`],
                rowBatchTargetVectorDigests: [
                    digest(`${componentId}-row-target`),
                ],
                rowCount: 1,
                rowKinds: ['EncodedScoreFieldRows'],
                targetVectorDigest: digest(`${componentId}-target`),
                variableColumnCount: 1,
                variableColumnIndices: [componentIndex],
            };

            return {
                ...componentPayload,
                componentStatementDigest: kernel.deriveProtocolDigest({
                    namespace: 'ChallengeDomainDigest',
                    value: {
                        payload: componentPayload,
                        purpose: 'ballot-proof-component-statement-v1',
                    },
                }),
            };
        };
        const createComponentBundleStatement = (
            linearStatement: Record<string, unknown>,
            statement: Record<string, unknown>,
            options: { readonly fullCoverage?: boolean } = {},
        ): Record<string, unknown> => {
            const componentStatements = componentIds.map(
                (componentId, componentIndex) =>
                    createComponentStatement(
                        linearStatement,
                        statement,
                        componentId,
                        componentIndex,
                        options.fullCoverage === true || componentIndex === 0
                            ? 'explicitRowsAvailable'
                            : 'digestExpandedRowsPending',
                    ),
            );
            const componentBundlePayload = {
                backendStatementDigest: linearStatement.backendStatementDigest,
                ballotProofStatementDigest:
                    statement.ballotProofStatementDigest,
                bundleCoverage:
                    options.fullCoverage === true
                        ? 'full-encoded-score-ballot-relation'
                        : 'component-bundle-incomplete',
                componentStatements,
                objectType: 'BallotProofComponentBundleStatement',
                objectVersion: 1,
                relationLabel: 'BallotPrivacyPvssRelation',
                relationStatementDigest:
                    linearStatement.relationStatementDigest,
                requiredComponentIds: componentIds,
            };

            return {
                ...componentBundlePayload,
                componentBundleStatementDigest: kernel.deriveProtocolDigest({
                    namespace: 'ChallengeDomainDigest',
                    value: {
                        payload: componentBundlePayload,
                        purpose: 'ballot-proof-component-bundle-statement-v1',
                    },
                }),
            };
        };
        const createComponentProofStatement = (input: {
            readonly componentId: string;
            readonly componentProofStatementDigest?: string;
            readonly componentStatementDigest: string;
            readonly proofStatementFormat: string;
        }): Record<string, unknown> => {
            if (
                input.proofStatementFormat ===
                'dense-polynomial-matrix-linear-proof-v1'
            ) {
                const statementPayload = {
                    componentId: input.componentId,
                    componentStatementDigest: input.componentStatementDigest,
                    objectType: 'BallotProofLinearProofStatement',
                    objectVersion: 1,
                    proofStatementFormat: input.proofStatementFormat,
                };

                return {
                    ...statementPayload,
                    statementDigest: kernel.deriveProtocolDigest({
                        namespace: 'ChallengeDomainDigest',
                        value: {
                            payload: statementPayload,
                            purpose: 'ballot-proof-linear-proof-statement-v1',
                        },
                    }),
                };
            }
            if (
                input.proofStatementFormat ===
                'sparse-polynomial-matrix-linear-proof-v1'
            ) {
                const statementPayload = {
                    componentId: input.componentId,
                    componentStatementDigest: input.componentStatementDigest,
                    objectType:
                        'BallotProofSparseComponentLinearProofStatement',
                    objectVersion: 1,
                    proofStatementFormat: input.proofStatementFormat,
                };

                return {
                    ...statementPayload,
                    statementDigest: kernel.deriveProtocolDigest({
                        namespace: 'ChallengeDomainDigest',
                        value: {
                            payload: statementPayload,
                            purpose:
                                'ballot-proof-sparse-linear-proof-statement-v1',
                        },
                    }),
                };
            }
            const statementPayload = {
                backendStatementDigest: digest(`${input.componentId}-backend`),
                coefficientModulus:
                    input.componentId === 'share-commitment-component'
                        ? '18446744069414584321'
                        : input.componentId ===
                                'score-and-shamir-field-component' ||
                            input.componentId ===
                                'payload-plaintext-field-component'
                          ? '65537'
                          : '12289',
                componentId: input.componentId,
                componentStatementDigest: input.componentStatementDigest,
                denseCoefficientCount:
                    input.proofStatementFormat ===
                    'structured-module-lwe-linear-proof-v1'
                        ? '1024'
                        : null,
                matrixDigest: digest(`${input.componentId}-matrix`),
                objectType: 'BallotProofComponentProofStatementPlan',
                objectVersion: 1,
                proofBytesAvailability:
                    input.proofStatementFormat ===
                    'structured-module-lwe-linear-proof-v1'
                        ? 'requires-structured-proof-statement'
                        : 'public-zero-witness-binding-check',
                proofLoweringStatus: 'explicitRowsAvailable',
                proofStatementFormat: input.proofStatementFormat,
                proofSystemRingDegree:
                    input.proofStatementFormat ===
                    'structured-module-lwe-linear-proof-v1'
                        ? 64
                        : null,
                relation: 'A*w + t = 0',
                relationStatementDigest: digest(
                    `${input.componentId}-relation`,
                ),
                rowBatchMatrixDigests: [
                    digest(`${input.componentId}-row-matrix`),
                ],
                rowBatchNames: [
                    input.proofStatementFormat ===
                    'structured-module-lwe-linear-proof-v1'
                        ? 'receiver_payload_encryption_equation_rows'
                        : 'receiver_key_binding_rows',
                ],
                rowBatchTargetVectorDigests: [
                    digest(`${input.componentId}-row-target`),
                ],
                rowBatchTermCounts: [
                    input.proofStatementFormat ===
                    'structured-module-lwe-linear-proof-v1'
                        ? '1024'
                        : '0',
                ],
                rowCount: 1,
                sparseTermCount: null,
                sourceRingDegree:
                    input.proofStatementFormat ===
                    'structured-module-lwe-linear-proof-v1'
                        ? 256
                        : null,
                structuredCiphertextChunkCount:
                    input.proofStatementFormat ===
                    'structured-module-lwe-linear-proof-v1'
                        ? 1
                        : null,
                structuredReceiverCount:
                    input.proofStatementFormat ===
                    'structured-module-lwe-linear-proof-v1'
                        ? 1
                        : null,
                structuredWitnessTermCount:
                    input.proofStatementFormat ===
                    'structured-module-lwe-linear-proof-v1'
                        ? '1024'
                        : null,
                targetVectorDigest: digest(`${input.componentId}-target`),
                variableColumnCount:
                    input.proofStatementFormat ===
                    'structured-module-lwe-linear-proof-v1'
                        ? 1
                        : 0,
                variableColumnIndices:
                    input.proofStatementFormat ===
                    'structured-module-lwe-linear-proof-v1'
                        ? [0]
                        : [],
            };

            return {
                ...statementPayload,
                componentProofStatementDigest:
                    input.componentProofStatementDigest ??
                    kernel.deriveProtocolDigest({
                        namespace: 'ChallengeDomainDigest',
                        value: {
                            payload: statementPayload,
                            purpose:
                                'ballot-proof-component-proof-statement-plan-v1',
                        },
                    }),
            };
        };
        const createComponentProofInput = (
            componentId: string,
            componentStatementDigest: string,
        ): Record<string, unknown> => {
            const componentIndex = componentIds.indexOf(componentId);
            const publicRandomnessByte = (componentIndex + 1)
                .toString(16)
                .padStart(2, '0');
            const proofStatementFormat =
                componentId === 'receiver-encryption-component'
                    ? 'structured-module-lwe-linear-proof-v1'
                    : componentId === 'receiver-key-binding-component'
                      ? 'public-zero-witness-binding-check-v1'
                      : componentId === 'score-and-shamir-field-component'
                        ? 'dense-polynomial-matrix-linear-proof-v1'
                        : 'sparse-polynomial-matrix-linear-proof-v1';
            const componentProofStatementDigest = digest(
                `${componentId}-proof-statement`,
            );
            const proofStatement = createComponentProofStatement({
                componentId,
                componentProofStatementDigest:
                    proofStatementFormat ===
                        'structured-module-lwe-linear-proof-v1' ||
                    proofStatementFormat ===
                        'public-zero-witness-binding-check-v1'
                        ? undefined
                        : componentProofStatementDigest,
                componentStatementDigest,
                proofStatementFormat,
            });
            const suppliedComponentProofStatementDigest =
                proofStatement.componentProofStatementDigest;
            const boundComponentProofStatementDigest =
                typeof suppliedComponentProofStatementDigest === 'string'
                    ? suppliedComponentProofStatementDigest
                    : componentProofStatementDigest;
            const componentProofBytesHex =
                proofStatementFormat === 'public-zero-witness-binding-check-v1'
                    ? ''
                    : digest(`${componentId}-proof-bytes-material`);

            return {
                componentId,
                componentProofStatementDigest:
                    boundComponentProofStatementDigest,
                proofBytesHex: componentProofBytesHex,
                proofEncoding: {
                    profileId: 'ballot-proof-component-encoding-v1',
                    componentId,
                },
                proofParameterSet: {
                    profileId: 'ballot-proof-component-parameter-set-v1',
                    componentId,
                },
                proofStatement,
                proofStatementFormat,
                publicRandomnessHex: publicRandomnessByte.repeat(32),
                statementDigest: componentStatementDigest,
            };
        };
        const createComponentProofRecord = (
            linearStatement: Record<string, unknown>,
            statement: Record<string, unknown>,
            componentStatement: Record<string, unknown>,
            componentId: string,
        ): Record<string, unknown> => {
            const componentProofInput = createComponentProofInput(
                componentId,
                String(componentStatement.componentStatementDigest),
            );
            const proofBytesDigest = deriveProofBytesDigestForTest(
                String(componentProofInput.proofBytesHex),
            );
            const proofEncodingProfileDigest =
                deriveBallotProofEncodingDigestForTest(
                    componentProofInput.proofEncoding,
                );
            const proofParameterSetDigest =
                deriveBallotProofParameterSetDigestForTest(
                    componentProofInput.proofParameterSet,
                );
            const publicRandomnessDigest =
                deriveBallotProofPublicRandomnessDigestForTest(
                    String(componentProofInput.publicRandomnessHex),
                );
            const proofRoot = kernel.deriveProtocolDigest({
                namespace: 'ChallengeDomainDigest',
                value: {
                    componentId,
                    componentProofStatementDigest:
                        componentProofInput.componentProofStatementDigest,
                    componentStatementDigest:
                        componentStatement.componentStatementDigest,
                    proofBytesDigest,
                    proofEncodingProfileDigest,
                    proofParameterSetDigest,
                    proofStatementFormat:
                        componentProofInput.proofStatementFormat,
                    publicRandomnessDigest,
                    purpose: 'ballot-proof-component-proof-root-v1',
                    statementDigest:
                        componentStatement.componentStatementDigest,
                },
            });
            const proofRecordPayload = {
                backendStatementDigest: linearStatement.backendStatementDigest,
                ballotProofStatementDigest:
                    statement.ballotProofStatementDigest,
                componentId,
                componentProofStatementDigest:
                    componentProofInput.componentProofStatementDigest,
                componentStatementDigest:
                    componentStatement.componentStatementDigest,
                objectType: 'BallotProofComponentProofRecord',
                objectVersion: 1,
                proofBackend: 'LocalLinearLatticeRelation',
                proofBytesDigest,
                proofEncodingProfileDigest,
                proofParameterSetDigest,
                proofRoot,
                proofSizeBytes:
                    String(componentProofInput.proofBytesHex).length / 2,
                publicRandomnessDigest,
                relationStatementDigest:
                    linearStatement.relationStatementDigest,
            };

            return {
                ...proofRecordPayload,
                componentProofRecordDigest: kernel.deriveProtocolDigest({
                    namespace: 'ChallengeDomainDigest',
                    value: {
                        payload: proofRecordPayload,
                        purpose: 'ballot-proof-component-proof-record-v1',
                    },
                }),
            };
        };
        const createComponentProofInputs = (
            componentProofs: readonly Record<string, unknown>[],
        ): readonly Record<string, unknown>[] =>
            componentProofs.map((componentProof) =>
                createComponentProofInput(
                    String(componentProof.componentId),
                    String(componentProof.componentStatementDigest),
                ),
            );
        const createComponentProofBundle = (
            componentBundleStatement: Record<string, unknown>,
            componentProofs: readonly Record<string, unknown>[],
        ): Record<string, unknown> => {
            const proofBundlePayload = {
                backendStatementDigest:
                    componentBundleStatement.backendStatementDigest,
                ballotProofStatementDigest:
                    componentBundleStatement.ballotProofStatementDigest,
                bundleCoverage: componentBundleStatement.bundleCoverage,
                componentBundleStatementDigest:
                    componentBundleStatement.componentBundleStatementDigest,
                componentProofs,
                objectType: 'BallotProofComponentProofBundle',
                objectVersion: 1,
                relationStatementDigest:
                    componentBundleStatement.relationStatementDigest,
                requiredComponentIds: componentIds,
            };

            return {
                ...proofBundlePayload,
                componentProofBundleDigest: kernel.deriveProtocolDigest({
                    namespace: 'ChallengeDomainDigest',
                    value: {
                        payload: proofBundlePayload,
                        purpose: 'ballot-proof-component-proof-bundle-v1',
                    },
                }),
            };
        };
        const statement = createStatement();
        const validLinearStatement = createLinearStatement(
            statement,
            validProofCase,
        );
        const validBallotProof = createBallotProof(
            statement,
            validLinearStatement,
        );
        const mutatedLinearStatement = createLinearStatement(
            statement,
            mutatedTargetCase,
        );
        const mutatedBallotProof = createBallotProof(
            statement,
            mutatedLinearStatement,
        );
        const incompleteComponentBundleStatement =
            createComponentBundleStatement(validLinearStatement, statement);
        const proofBoundToIncompleteComponentBundle = createBallotProof(
            statement,
            validLinearStatement,
            incompleteComponentBundleStatement,
        );

        return {
            componentIds,
            createBallotProof,
            createComponentBundleStatement,
            createComponentProofBundle,
            createComponentProofInputs,
            createComponentProofRecord,
            createComponentProofStatement,
            digest,
            incompleteComponentBundleStatement,
            kernel,
            mutatedBallotProof,
            mutatedLinearStatement,
            proofBoundToIncompleteComponentBundle,
            proofBytesHex,
            publicRandomnessHex,
            statement,
            validBallotProof,
            validLinearStatement,
            validProofCase,
        };
    };
