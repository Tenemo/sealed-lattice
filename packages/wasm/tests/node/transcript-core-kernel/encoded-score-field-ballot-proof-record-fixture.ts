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
        readonly componentProofStatementHash?: string;
        readonly componentStatementHash: string;
        readonly proofStatementFormat: string;
    }) => JsonRecord;
    readonly hash: (label: string) => string;
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
        const hash = (label: string): string =>
            kernel.deriveProtocolHash({
                namespace: 'ChallengeDomainHash',
                value: {
                    label,
                    purpose:
                        'encoded-score-field-ballot-proof-record-wasm-test',
                },
            });
        const deriveProofBytesHashForTest = (
            proofBytesHexForTest: string,
        ): string =>
            kernel.deriveProtocolHash({
                namespace: 'ProofBytesHash',
                value: {
                    objectType: 'ProofBytes',
                    objectVersion: 1,
                    proofBytesHex: proofBytesHexForTest,
                    proofSizeBytes: proofBytesHexForTest.length / 2,
                },
            });
        const deriveBallotProofEncodingHashForTest = (
            proofEncoding: unknown,
        ): string =>
            kernel.deriveProtocolHash({
                namespace: 'ChallengeDomainHash',
                value: {
                    proofEncoding,
                    purpose: 'ballot-proof-linear-proof-encoding-profile-v1',
                },
            });
        const deriveBallotProofParameterSetHashForTest = (
            parameterSet: unknown,
        ): string =>
            kernel.deriveProtocolHash({
                namespace: 'ChallengeDomainHash',
                value: {
                    parameterSet,
                    purpose: 'ballot-proof-linear-proof-parameter-set-v1',
                },
            });
        const deriveBallotProofPublicRandomnessHashForTest = (
            componentPublicRandomnessHex: string,
        ): string =>
            kernel.deriveProtocolHash({
                namespace: 'ChallengeDomainHash',
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
                actionContextHash: hash('action-context'),
                aggregateInputEncodingProfileHash: hash(
                    'aggregate-input-encoding-profile',
                ),
                ballotPackageHash: hash('ballot-package'),
                ballotProofProfileHash: hash('ballot-proof-profile'),
                ballotScoreEncodingProfileHash: hash(
                    'ballot-score-encoding-profile',
                ),
                ballotShareLayoutProfileHash: hash(
                    'ballot-share-layout-profile',
                ),
                ceremonyId: 'ceremony-encoded-score-field-ballot-proof-record',
                challengeDomainHash: hash('challenge-domain'),
                duplicateBallotPolicyHash: hash('duplicate-policy'),
                encodedAggregateLayoutHash: hash('encoded-aggregate-layout'),
                encodedShareVectorLayoutHash: hash(
                    'encoded-share-vector-layout',
                ),
                manifestHash: hash('manifest'),
                objectType: 'BallotProofStatement',
                objectVersion: 1,
                optionCount: 20,
                pollSpecHash: hash('poll-spec'),
                receiverEncryptionProfileHash: hash(
                    'receiver-encryption-profile',
                ),
                receiverKeyProofRoot: hash('receiver-key-proof-root'),
                receiverKeyRoot: hash('receiver-key-root'),
                receiverPayloads: receiverReferences.map(
                    (receiverReference) => ({
                        ...receiverReference,
                        receiverPayloadCiphertextRoot: hash(
                            `receiver-ciphertext-${receiverReference.receiverRosterPosition}`,
                        ),
                        receiverPayloadHash: hash(
                            `receiver-payload-${receiverReference.receiverRosterPosition}`,
                        ),
                    }),
                ),
                receiverPublicKeys: receiverReferences.map(
                    (receiverReference) => ({
                        ...receiverReference,
                        receiverPublicKeyHash: hash(
                            `receiver-public-key-${receiverReference.receiverRosterPosition}`,
                        ),
                    }),
                ),
                rosterHash: hash('roster'),
                rosterExternalAcceptanceHash: hash('external-acceptance'),
                scoreDomainHash: hash('score-domain'),
                scoreMembershipProfileHash: hash('score-membership-profile'),
                shareCommitmentMessageBoundCertHash: hash(
                    'share-commitment-bound-cert',
                ),
                shareCommitmentProfileHash: hash('share-commitment-profile'),
                shareCommitments: receiverReferences.map(
                    (receiverReference) => ({
                        ...receiverReference,
                        shareCommitmentHash: hash(
                            `share-commitment-${receiverReference.receiverRosterPosition}`,
                        ),
                    }),
                ),
                shareVectorWidth: 220,
                thresholdProfileHash: hash('threshold-profile'),
                tiePolicyHash: hash('tie-policy'),
                topOptionCount: 3,
                voterIdentityHash: hash('voter-1'),
                voterRosterPosition: 1,
                voterSigningKeyHash: hash('voter-signing-key'),
            };

            return {
                ...statementPayload,
                ballotProofStatementHash: kernel.deriveProtocolHash({
                    namespace: 'BallotProofStatementHash',
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
                ballotProofStatementHash: statement.ballotProofStatementHash,
                matrixCoefficientRepresentation:
                    vectorCase.matrixCoefficientRepresentation,
                statementMatrixCoefficients,
                statementMatrixHash: kernel.deriveProtocolHash({
                    namespace: 'ChallengeDomainHash',
                    value: {
                        purpose: 'ballot-proof-linear-statement-matrix-v1',
                        statementMatrixCoefficients,
                    },
                }),
                targetCoefficientRepresentation:
                    vectorCase.targetCoefficientRepresentation,
                targetVectorCoefficients,
                targetVectorHash: kernel.deriveProtocolHash({
                    namespace: 'ChallengeDomainHash',
                    value: {
                        purpose: 'ballot-proof-linear-target-vector-v1',
                        targetVectorCoefficients,
                    },
                }),
            } as Record<string, unknown>;
            delete linearStatementPayload.statementHash;

            return {
                ...linearStatementPayload,
                statementHash: kernel.deriveProtocolHash({
                    namespace: 'ChallengeDomainHash',
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
            const proofBytesHash = kernel.deriveProtocolHash({
                namespace: 'ProofBytesHash',
                value: {
                    objectType: 'ProofBytes',
                    objectVersion: 1,
                    proofBytesHex,
                    proofSizeBytes,
                },
            });
            const proofEncodingProfileHash = kernel.deriveProtocolHash({
                namespace: 'ChallengeDomainHash',
                value: {
                    proofEncoding: validProofCase.proofEncoding,
                    purpose: 'ballot-proof-linear-proof-encoding-profile-v1',
                },
            });
            const proofParameterSetHash = kernel.deriveProtocolHash({
                namespace: 'ChallengeDomainHash',
                value: {
                    parameterSet: validProofCase.parameterSet,
                    purpose: 'ballot-proof-linear-proof-parameter-set-v1',
                },
            });
            const publicRandomnessHash = kernel.deriveProtocolHash({
                namespace: 'ChallengeDomainHash',
                value: {
                    publicRandomnessHex,
                    purpose: 'ballot-proof-linear-proof-public-randomness-v1',
                },
            });
            const proofRoot = kernel.deriveProtocolHash({
                namespace: 'BallotProofRecordHash',
                value: {
                    linearStatementHash: linearStatement.statementHash,
                    proofBytesHash,
                    proofEncodingProfileHash,
                    proofParameterSetHash,
                    publicRandomnessHash,
                    purpose: 'ballot-proof-linear-proof-record-root-v1',
                },
            });
            const proofPayloadWithoutChallenge = {
                backendStatementHash: linearStatement.backendStatementHash,
                ballotProofProfileHash: statement.ballotProofProfileHash,
                ballotProofStatementHash: statement.ballotProofStatementHash,
                ...(componentBundleStatement === undefined
                    ? {}
                    : {
                          componentBundleStatementHash:
                              componentBundleStatement.componentBundleStatementHash,
                      }),
                ...(componentProofBundle === undefined
                    ? {}
                    : {
                          componentProofBundleHash:
                              componentProofBundle.componentProofBundleHash,
                      }),
                linearStatementHash: linearStatement.statementHash,
                objectType: 'BallotProofRecord',
                objectVersion: 1,
                proofBackend: 'LocalLinearLatticeRelation',
                proofBytesHash,
                proofEncodingProfileHash,
                proofParameterSetHash,
                proofRoot,
                proofSizeBytes,
                publicRandomnessHash,
                relationStatementHash: linearStatement.relationStatementHash,
                statementMatrixHash: linearStatement.statementMatrixHash,
                targetVectorHash: linearStatement.targetVectorHash,
            };
            const challengeHash = kernel.deriveProtocolHash({
                namespace: 'ChallengeDomainHash',
                value: {
                    backendStatementHash:
                        proofPayloadWithoutChallenge.backendStatementHash,
                    ballotProofStatementHash:
                        statement.ballotProofStatementHash,
                    challengeDomainHash: statement.challengeDomainHash,
                    ...(componentBundleStatement === undefined
                        ? {}
                        : {
                              componentBundleStatementHash:
                                  componentBundleStatement.componentBundleStatementHash,
                          }),
                    ...(componentProofBundle === undefined
                        ? {}
                        : {
                              componentProofBundleHash:
                                  componentProofBundle.componentProofBundleHash,
                          }),
                    linearStatementHash:
                        proofPayloadWithoutChallenge.linearStatementHash,
                    proofBytesHash: proofPayloadWithoutChallenge.proofBytesHash,
                    proofEncodingProfileHash:
                        proofPayloadWithoutChallenge.proofEncodingProfileHash,
                    proofParameterSetHash:
                        proofPayloadWithoutChallenge.proofParameterSetHash,
                    proofRoot: proofPayloadWithoutChallenge.proofRoot,
                    publicRandomnessHash:
                        proofPayloadWithoutChallenge.publicRandomnessHash,
                    relationStatementHash:
                        proofPayloadWithoutChallenge.relationStatementHash,
                    statementMatrixHash:
                        proofPayloadWithoutChallenge.statementMatrixHash,
                    targetVectorHash:
                        proofPayloadWithoutChallenge.targetVectorHash,
                },
            });
            const proofPayload = {
                ...proofPayloadWithoutChallenge,
                challengeHash,
            };

            return {
                ...proofPayload,
                ballotProofRecordHash: kernel.deriveProtocolHash({
                    namespace: 'BallotProofRecordHash',
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
                backendStatementHash: linearStatement.backendStatementHash,
                ballotProofStatementHash: statement.ballotProofStatementHash,
                coefficientModulus: '65537',
                componentHash: hash(`${componentId}-component`),
                componentId,
                matrixHash: hash(`${componentId}-matrix`),
                objectType: 'BallotProofComponentStatement',
                objectVersion: 1,
                proofLoweringStatus,
                relationStatementHash: linearStatement.relationStatementHash,
                rowBatchMatrixHashes: [hash(`${componentId}-row-matrix`)],
                rowBatchNames: [`${componentId}-rows`],
                rowBatchTargetVectorHashes: [hash(`${componentId}-row-target`)],
                rowCount: 1,
                rowKinds: ['EncodedScoreFieldRows'],
                targetVectorHash: hash(`${componentId}-target`),
                variableColumnCount: 1,
                variableColumnIndices: [componentIndex],
            };

            return {
                ...componentPayload,
                componentStatementHash: kernel.deriveProtocolHash({
                    namespace: 'ChallengeDomainHash',
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
                            : 'HashExpandedRowsPending',
                    ),
            );
            const componentBundlePayload = {
                backendStatementHash: linearStatement.backendStatementHash,
                ballotProofStatementHash: statement.ballotProofStatementHash,
                bundleCoverage:
                    options.fullCoverage === true
                        ? 'full-encoded-score-ballot-relation'
                        : 'component-bundle-incomplete',
                componentStatements,
                objectType: 'BallotProofComponentBundleStatement',
                objectVersion: 1,
                relationLabel: 'BallotPrivacyPvssRelation',
                relationStatementHash: linearStatement.relationStatementHash,
                requiredComponentIds: componentIds,
            };

            return {
                ...componentBundlePayload,
                componentBundleStatementHash: kernel.deriveProtocolHash({
                    namespace: 'ChallengeDomainHash',
                    value: {
                        payload: componentBundlePayload,
                        purpose: 'ballot-proof-component-bundle-statement-v1',
                    },
                }),
            };
        };
        const createComponentProofStatement = (input: {
            readonly componentId: string;
            readonly componentProofStatementHash?: string;
            readonly componentStatementHash: string;
            readonly proofStatementFormat: string;
        }): Record<string, unknown> => {
            if (
                input.proofStatementFormat ===
                'dense-polynomial-matrix-linear-proof-v1'
            ) {
                const statementPayload = {
                    componentId: input.componentId,
                    componentStatementHash: input.componentStatementHash,
                    objectType: 'BallotProofLinearProofStatement',
                    objectVersion: 1,
                    proofStatementFormat: input.proofStatementFormat,
                };

                return {
                    ...statementPayload,
                    statementHash: kernel.deriveProtocolHash({
                        namespace: 'ChallengeDomainHash',
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
                    componentStatementHash: input.componentStatementHash,
                    objectType:
                        'BallotProofSparseComponentLinearProofStatement',
                    objectVersion: 1,
                    proofStatementFormat: input.proofStatementFormat,
                };

                return {
                    ...statementPayload,
                    statementHash: kernel.deriveProtocolHash({
                        namespace: 'ChallengeDomainHash',
                        value: {
                            payload: statementPayload,
                            purpose:
                                'ballot-proof-sparse-linear-proof-statement-v1',
                        },
                    }),
                };
            }
            const statementPayload = {
                backendStatementHash: hash(`${input.componentId}-backend`),
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
                componentStatementHash: input.componentStatementHash,
                denseCoefficientCount:
                    input.proofStatementFormat ===
                    'structured-module-lwe-linear-proof-v1'
                        ? '1024'
                        : null,
                matrixHash: hash(`${input.componentId}-matrix`),
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
                relationStatementHash: hash(`${input.componentId}-relation`),
                rowBatchMatrixHashes: [hash(`${input.componentId}-row-matrix`)],
                rowBatchNames: [
                    input.proofStatementFormat ===
                    'structured-module-lwe-linear-proof-v1'
                        ? 'receiver_payload_encryption_equation_rows'
                        : 'receiver_key_binding_rows',
                ],
                rowBatchTargetVectorHashes: [
                    hash(`${input.componentId}-row-target`),
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
                targetVectorHash: hash(`${input.componentId}-target`),
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
                componentProofStatementHash:
                    input.componentProofStatementHash ??
                    kernel.deriveProtocolHash({
                        namespace: 'ChallengeDomainHash',
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
            componentStatementHash: string,
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
            const componentProofStatementHash = hash(
                `${componentId}-proof-statement`,
            );
            const proofStatement = createComponentProofStatement({
                componentId,
                componentProofStatementHash:
                    proofStatementFormat ===
                        'structured-module-lwe-linear-proof-v1' ||
                    proofStatementFormat ===
                        'public-zero-witness-binding-check-v1'
                        ? undefined
                        : componentProofStatementHash,
                componentStatementHash,
                proofStatementFormat,
            });
            const suppliedComponentProofStatementHash =
                proofStatement.componentProofStatementHash;
            const boundComponentProofStatementHash =
                typeof suppliedComponentProofStatementHash === 'string'
                    ? suppliedComponentProofStatementHash
                    : componentProofStatementHash;
            const componentProofBytesHex =
                proofStatementFormat === 'public-zero-witness-binding-check-v1'
                    ? ''
                    : hash(`${componentId}-proof-bytes-material`);

            return {
                componentId,
                componentProofStatementHash: boundComponentProofStatementHash,
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
                statementHash: componentStatementHash,
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
                String(componentStatement.componentStatementHash),
            );
            const proofBytesHash = deriveProofBytesHashForTest(
                String(componentProofInput.proofBytesHex),
            );
            const proofEncodingProfileHash =
                deriveBallotProofEncodingHashForTest(
                    componentProofInput.proofEncoding,
                );
            const proofParameterSetHash =
                deriveBallotProofParameterSetHashForTest(
                    componentProofInput.proofParameterSet,
                );
            const publicRandomnessHash =
                deriveBallotProofPublicRandomnessHashForTest(
                    String(componentProofInput.publicRandomnessHex),
                );
            const proofRoot = kernel.deriveProtocolHash({
                namespace: 'ChallengeDomainHash',
                value: {
                    componentId,
                    componentProofStatementHash:
                        componentProofInput.componentProofStatementHash,
                    componentStatementHash:
                        componentStatement.componentStatementHash,
                    proofBytesHash,
                    proofEncodingProfileHash,
                    proofParameterSetHash,
                    proofStatementFormat:
                        componentProofInput.proofStatementFormat,
                    publicRandomnessHash,
                    purpose: 'ballot-proof-component-proof-root-v1',
                    statementHash: componentStatement.componentStatementHash,
                },
            });
            const proofRecordPayload = {
                backendStatementHash: linearStatement.backendStatementHash,
                ballotProofStatementHash: statement.ballotProofStatementHash,
                componentId,
                componentProofStatementHash:
                    componentProofInput.componentProofStatementHash,
                componentStatementHash:
                    componentStatement.componentStatementHash,
                objectType: 'BallotProofComponentProofRecord',
                objectVersion: 1,
                proofBackend: 'LocalLinearLatticeRelation',
                proofBytesHash,
                proofEncodingProfileHash,
                proofParameterSetHash,
                proofRoot,
                proofSizeBytes:
                    String(componentProofInput.proofBytesHex).length / 2,
                publicRandomnessHash,
                relationStatementHash: linearStatement.relationStatementHash,
            };

            return {
                ...proofRecordPayload,
                componentProofRecordHash: kernel.deriveProtocolHash({
                    namespace: 'ChallengeDomainHash',
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
                    String(componentProof.componentStatementHash),
                ),
            );
        const createComponentProofBundle = (
            componentBundleStatement: Record<string, unknown>,
            componentProofs: readonly Record<string, unknown>[],
        ): Record<string, unknown> => {
            const proofBundlePayload = {
                backendStatementHash:
                    componentBundleStatement.backendStatementHash,
                ballotProofStatementHash:
                    componentBundleStatement.ballotProofStatementHash,
                bundleCoverage: componentBundleStatement.bundleCoverage,
                componentBundleStatementHash:
                    componentBundleStatement.componentBundleStatementHash,
                componentProofs,
                objectType: 'BallotProofComponentProofBundle',
                objectVersion: 1,
                relationStatementHash:
                    componentBundleStatement.relationStatementHash,
                requiredComponentIds: componentIds,
            };

            return {
                ...proofBundlePayload,
                componentProofBundleHash: kernel.deriveProtocolHash({
                    namespace: 'ChallengeDomainHash',
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
            hash,
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
