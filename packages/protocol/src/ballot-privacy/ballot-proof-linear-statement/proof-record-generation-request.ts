import type { BallotProofStatement } from '@sealed-lattice/types';

import {
    ballotPrivacyBackendProofComponentOrder,
    lowerBallotPrivacyRelationToBackendStatement,
    type BallotPrivacyBackendProofComponentId,
    type BallotPrivacyLoweredLinearRelationStatement,
    type BallotPrivacyRelationBackendPublicContext,
} from '../relation-backend-lowering.js';
import type { BallotPrivacyRelationCompilerInput } from '../relation-compiler.js';

import {
    buildBallotProofComponentBundleStatement,
    buildBallotProofComponentProofStatementDescriptors,
} from './component-bundle.js';
import { secretStateForStructuredShareCommitmentStatement } from './component-projections.js';
import { rowBatchesForComponent } from './component-statement-builder.js';
import { verifyBallotProofComponentExplicitRows } from './explicit-row-verification.js';
import {
    assertBallotStatementMatchesPublicContext,
    assertFullReceiverPayloadsAreExplicit,
    buildFullRelationLinearProofStatement,
    componentDescriptorById,
    componentStatementById,
    requiredComponentStatement,
    requiredComponentStatementDescriptor,
    secretStateForStructuredReceiverEncryptionStatement,
    sourceRingDegreeFromParameterSet,
    witnessBoundSquaredFromParameterSet,
} from './full-relation-statement.js';
import { buildPackedFieldSparseComponentLinearProofStatement } from './packed-payload-plaintext-statement.js';
import {
    assertProofEncodingMatchesStatement,
    assertProofParameterSetMatchesStatement,
    requireComponentContract,
    requireContractDecimalStringField,
    requireContractIntegerField,
    requireContractProfileId,
    requireObjectContract,
    requirePartialComponentContract,
    requireRandomnessHex,
} from './proof-contract-validation.js';
import {
    buildBallotProofStructuredReceiverEncryptionProofStatement,
    buildEncodedScoreFieldLinearProofProjection,
    secretStateForExplicitSparseStatement,
} from './receiver-encryption-proof-statement.js';
import { buildBallotProofSparseComponentLinearProofStatement } from './sparse-component-statement.js';
import type {
    BallotProofComponentBundleStatement,
    BallotProofComponentProofStatementDescriptor,
    BallotProofComponentProjectionWitness,
    BallotProofFullRelationLinearProofStatement,
    BallotProofRecordGenerationComponentProofInput,
    BallotProofRecordGenerationProofContracts,
    BallotProofRecordGenerationRandomness,
    BallotProofRecordGenerationRequest,
    BallotProofRecordGenerationSecretState,
    BallotProofSparseComponentLinearProofStatement,
    BallotProofStructuredReceiverEncryptionProofStatement,
    BallotProofStructuredShareCommitmentProofStatement,
    BallotProofComponentProofStatementFormat,
} from './statement-contracts.js';
import {
    componentProofEncodingProfileIds,
    componentProofParameterProfileIds,
    fullBallotProofEncodingProfileId,
    fullBallotProofParameterProfileId,
} from './statement-contracts.js';
import { componentById } from './witness-accessors.js';

type PreparedBallotProofRecordGenerationLowering = {
    readonly componentBundleStatement: BallotProofComponentBundleStatement;
    readonly componentProofStatements?: Readonly<
        Partial<Record<BallotPrivacyBackendProofComponentId, unknown>>
    >;
    readonly componentStatementDescriptors: readonly BallotProofComponentProofStatementDescriptor[];
    readonly loweredStatement: BallotPrivacyLoweredLinearRelationStatement;
};

const preparedLoweringOrBuild = (input: {
    readonly ballotProofStatementHash: string;
    readonly preparedLowering?: PreparedBallotProofRecordGenerationLowering;
    readonly publicContext: BallotPrivacyRelationBackendPublicContext;
    readonly relationInput: BallotPrivacyRelationCompilerInput;
}): PreparedBallotProofRecordGenerationLowering => {
    if (input.preparedLowering !== undefined) {
        const {
            componentBundleStatement,
            componentStatementDescriptors,
            loweredStatement,
        } = input.preparedLowering;
        if (
            componentBundleStatement.backendStatementHash !==
                loweredStatement.backendStatement.backendStatementHash ||
            componentBundleStatement.relationStatementHash !==
                loweredStatement.relationStatementHash ||
            componentBundleStatement.ballotProofStatementHash !==
                input.ballotProofStatementHash
        ) {
            throw new Error(
                'Prepared ballot proof lowering is not bound to the requested statement.',
            );
        }
        if (
            componentStatementDescriptors.length !==
            componentBundleStatement.componentStatements.length
        ) {
            throw new Error(
                'Prepared ballot proof lowering has an invalid descriptor count.',
            );
        }
        return input.preparedLowering;
    }

    const loweringResult = lowerBallotPrivacyRelationToBackendStatement({
        publicContext: input.publicContext,
        relationInput: input.relationInput,
    });
    if (!loweringResult.ok) {
        throw new Error(
            `Ballot privacy relation did not lower to a proof backend statement: ${loweringResult.refusedObjects
                .map((refusal) => refusal.message)
                .join('; ')}`,
        );
    }
    const loweredStatement = loweringResult.statement;
    const componentBundleStatement = buildBallotProofComponentBundleStatement({
        ballotProofStatementHash: input.ballotProofStatementHash,
        loweredStatement,
    });
    const componentStatementDescriptors =
        buildBallotProofComponentProofStatementDescriptors({
            ballotProofStatementHash: input.ballotProofStatementHash,
            componentBundleStatement,
            loweredStatement,
        });

    return {
        componentBundleStatement,
        componentStatementDescriptors,
        loweredStatement,
    };
};

const preparedComponentProofStatement = <Statement>(input: {
    readonly componentId: BallotPrivacyBackendProofComponentId;
    readonly expectedFormat: BallotProofComponentProofStatementFormat;
    readonly preparedLowering?: PreparedBallotProofRecordGenerationLowering;
}): Statement | undefined => {
    const proofStatement =
        input.preparedLowering?.componentProofStatements?.[input.componentId];
    if (proofStatement === undefined) {
        return undefined;
    }
    if (
        typeof proofStatement !== 'object' ||
        proofStatement === null ||
        !('proofStatementFormat' in proofStatement) ||
        proofStatement.proofStatementFormat !== input.expectedFormat ||
        !('statementHash' in proofStatement) ||
        typeof proofStatement.statementHash !== 'string'
    ) {
        throw new Error(
            `Prepared proof statement for ${input.componentId} is not bound to the expected component format.`,
        );
    }

    return proofStatement as Statement;
};

const validateGeneratedProofInputContracts = (input: {
    readonly componentProofInputs: readonly BallotProofRecordGenerationComponentProofInput[];
    readonly linearStatement: BallotProofFullRelationLinearProofStatement;
    readonly proofContracts: BallotProofRecordGenerationProofContracts;
}): void => {
    assertProofParameterSetMatchesStatement({
        coefficientModulus: input.linearStatement.coefficientModulus,
        expectedProfileId: fullBallotProofParameterProfileId,
        label: 'ballot proof parameter set',
        parameterSet: input.proofContracts.ballotProofParameterSet,
        sourceRingDegree: input.linearStatement.ringDegree,
        statementColumns: input.linearStatement.statementColumns,
        statementRows: input.linearStatement.statementRows,
    });
    assertProofEncodingMatchesStatement({
        encoding: input.proofContracts.ballotProofEncoding,
        expectedProfileId: fullBallotProofEncodingProfileId,
        label: 'ballot proof encoding',
        sourceRingDegree: input.linearStatement.ringDegree,
        statementColumns: input.linearStatement.statementColumns,
    });
    for (const componentProofInput of input.componentProofInputs) {
        if (
            componentProofInput.proofStatementFormat ===
            'public-binding-check-only-v1'
        ) {
            requireContractProfileId({
                contract: componentProofInput.proofParameterSet,
                expectedProfileId:
                    componentProofParameterProfileIds[
                        componentProofInput.componentId
                    ],
                label: `${componentProofInput.componentId} parameter set`,
            });
            requireContractProfileId({
                contract: componentProofInput.proofEncoding,
                expectedProfileId:
                    componentProofEncodingProfileIds[
                        componentProofInput.componentId
                    ],
                label: `${componentProofInput.componentId} proof encoding`,
            });
            continue;
        }
        const proofStatement = requireObjectContract(
            componentProofInput.proofStatement,
            `${componentProofInput.componentId} proof statement`,
        );
        const sourceRingDegree =
            componentProofInput.proofStatementFormat ===
                'structured-module-lwe-linear-proof-v1' ||
            componentProofInput.proofStatementFormat ===
                'structured-module-sis-share-commitment-v1' ||
            componentProofInput.proofStatementFormat ===
                'sparse-polynomial-matrix-linear-proof-v1'
                ? requireContractIntegerField({
                      contract: proofStatement,
                      fieldName: 'sourceRingDegree',
                      label: `${componentProofInput.componentId} proof statement`,
                  })
                : requireContractIntegerField({
                      contract: proofStatement,
                      fieldName: 'ringDegree',
                      label: `${componentProofInput.componentId} proof statement`,
                  });
        assertProofParameterSetMatchesStatement({
            coefficientModulus: requireContractDecimalStringField({
                contract: proofStatement,
                fieldName: 'coefficientModulus',
                label: `${componentProofInput.componentId} proof statement`,
            }),
            expectedProfileId:
                componentProofParameterProfileIds[
                    componentProofInput.componentId
                ],
            label: `${componentProofInput.componentId} parameter set`,
            parameterSet: componentProofInput.proofParameterSet,
            sourceRingDegree,
            statementColumns: requireContractIntegerField({
                contract: proofStatement,
                fieldName: 'statementColumns',
                label: `${componentProofInput.componentId} proof statement`,
            }),
            statementRows: requireContractIntegerField({
                contract: proofStatement,
                fieldName: 'statementRows',
                label: `${componentProofInput.componentId} proof statement`,
            }),
        });
        assertProofEncodingMatchesStatement({
            encoding: componentProofInput.proofEncoding,
            expectedProfileId:
                componentProofEncodingProfileIds[
                    componentProofInput.componentId
                ],
            label: `${componentProofInput.componentId} proof encoding`,
            sourceRingDegree,
            statementColumns: requireContractIntegerField({
                contract: proofStatement,
                fieldName: 'statementColumns',
                label: `${componentProofInput.componentId} proof statement`,
            }),
        });
    }
};

export const buildBallotProofRecordGenerationRequest = (input: {
    readonly preparedLowering?: PreparedBallotProofRecordGenerationLowering;
    readonly proofContracts: BallotProofRecordGenerationProofContracts;
    readonly projectionWitness: BallotProofComponentProjectionWitness;
    readonly publicContext: BallotPrivacyRelationBackendPublicContext;
    readonly randomness: BallotProofRecordGenerationRandomness;
    readonly relationInput: BallotPrivacyRelationCompilerInput;
    readonly statement: BallotProofStatement;
}): BallotProofRecordGenerationRequest => {
    assertBallotStatementMatchesPublicContext(input);
    assertFullReceiverPayloadsAreExplicit(input);
    requireRandomnessHex(
        input.randomness.publicRandomnessHex,
        'ballot proof public randomness',
    );
    requireRandomnessHex(
        input.randomness.proverRandomnessHex,
        'ballot proof prover randomness',
    );
    for (const componentId of ballotPrivacyBackendProofComponentOrder) {
        requireRandomnessHex(
            requireComponentContract(
                input.randomness.componentPublicRandomnessHexes,
                componentId,
                'component public randomness',
            ),
            `${componentId} public randomness`,
        );
        if (componentId !== 'receiver-key-binding-component') {
            requireRandomnessHex(
                requirePartialComponentContract(
                    input.randomness.componentProverRandomnessHexes,
                    componentId,
                    'component prover randomness',
                ),
                `${componentId} prover randomness`,
            );
        }
    }

    const {
        componentBundleStatement,
        componentStatementDescriptors,
        loweredStatement,
    } = preparedLoweringOrBuild({
        ballotProofStatementHash: input.statement.ballotProofStatementHash,
        preparedLowering: input.preparedLowering,
        publicContext: input.publicContext,
        relationInput: input.relationInput,
    });
    if (
        componentBundleStatement.bundleCoverage !==
        'full-encoded-score-ballot-relation'
    ) {
        throw new Error(
            'Ballot proof record generation requires every proof component to be explicitly lowered.',
        );
    }
    for (const componentId of ballotPrivacyBackendProofComponentOrder) {
        verifyBallotProofComponentExplicitRows({
            componentId,
            loweredStatement,
            projectionWitness: input.projectionWitness,
            relationInput: input.relationInput,
        });
    }

    const { linearStatement, secretState } =
        buildFullRelationLinearProofStatement({
            componentBundleStatement,
            loweredStatement,
            parameterSet: input.proofContracts.ballotProofParameterSet,
        });
    const componentStatementsById = componentStatementById(
        componentBundleStatement,
    );
    const componentDescriptorsById = componentDescriptorById(
        componentStatementDescriptors,
    );
    const componentSecretStates: Partial<
        Record<
            BallotPrivacyBackendProofComponentId,
            BallotProofRecordGenerationSecretState
        >
    > = {};
    const componentProofInputs = ballotPrivacyBackendProofComponentOrder.map(
        (componentId): BallotProofRecordGenerationComponentProofInput => {
            const componentStatement = requiredComponentStatement({
                componentId,
                componentStatementsById,
            });
            const componentStatementDescriptor =
                requiredComponentStatementDescriptor({
                    componentId,
                    componentDescriptorsById,
                });
            const proofParameterSet = requireComponentContract(
                input.proofContracts.componentProofParameterSets,
                componentId,
                'component proof parameter sets',
            );
            const proofEncoding = requireComponentContract(
                input.proofContracts.componentProofEncodings,
                componentId,
                'component proof encodings',
            );
            const publicRandomnessHex = requireComponentContract(
                input.randomness.componentPublicRandomnessHexes,
                componentId,
                'component public randomness',
            );

            if (componentId === 'score-and-shamir-field-component') {
                const sourceRingDegree = sourceRingDegreeFromParameterSet(
                    proofParameterSet,
                    `${componentId} parameter set`,
                );
                const witnessL2BoundSquared =
                    witnessBoundSquaredFromParameterSet(
                        proofParameterSet,
                        `${componentId} parameter set`,
                    );
                if (
                    componentStatementDescriptor.proofStatementFormat ===
                    'sparse-polynomial-matrix-linear-proof-v1'
                ) {
                    const sparseStatement =
                        preparedComponentProofStatement<BallotProofSparseComponentLinearProofStatement>(
                            {
                                componentId,
                                expectedFormat:
                                    'sparse-polynomial-matrix-linear-proof-v1',
                                preparedLowering: input.preparedLowering,
                            },
                        ) ??
                        (input.relationInput.optionCount > 1 &&
                        sourceRingDegree === 64
                            ? buildPackedFieldSparseComponentLinearProofStatement(
                                  {
                                      ballotProofStatementHash:
                                          input.statement
                                              .ballotProofStatementHash,
                                      componentId,
                                      loweredStatement,
                                      parameterProfileId:
                                          componentProofParameterProfileIds[
                                              componentId
                                          ],
                                      relationInput: input.relationInput,
                                      sourceRingDegree,
                                      witnessL2BoundSquared,
                                  },
                              )
                            : buildBallotProofSparseComponentLinearProofStatement(
                                  {
                                      ballotProofStatementHash:
                                          input.statement
                                              .ballotProofStatementHash,
                                      componentId,
                                      loweredStatement,
                                      parameterProfileId:
                                          componentProofParameterProfileIds[
                                              componentId
                                          ],
                                      sourceRingDegree,
                                      witnessL2BoundSquared,
                                  },
                              ));
                    if (
                        sparseStatement.proofStatementFormat !==
                        'sparse-polynomial-matrix-linear-proof-v1'
                    ) {
                        throw new Error(
                            'Encoded-score sparse proof statement used an invalid format.',
                        );
                    }
                    componentSecretStates[componentId] =
                        secretStateForExplicitSparseStatement({
                            componentId,
                            loweredStatement,
                            projectionWitness: input.projectionWitness,
                            relationInput: input.relationInput,
                            sparseStatement,
                        });

                    return {
                        componentId,
                        componentProofStatementHash:
                            sparseStatement.statementHash,
                        proofEncoding,
                        proofParameterSet,
                        proofStatement: sparseStatement,
                        proofStatementFormat:
                            sparseStatement.proofStatementFormat,
                        publicRandomnessHex,
                        statementHash:
                            componentStatement.componentStatementHash,
                    };
                }
                const projection = buildEncodedScoreFieldLinearProofProjection({
                    ballotProofStatementHash:
                        input.statement.ballotProofStatementHash,
                    loweredStatement,
                    parameterProfileId:
                        componentProofParameterProfileIds[componentId],
                    relationInput: input.relationInput,
                    sourceRingDegree,
                    witnessL2BoundSquared,
                });
                componentSecretStates[componentId] = {
                    sourceWitnessCoefficients:
                        projection.privateWitnessVectorCoefficients,
                };

                return {
                    componentId,
                    componentProofStatementHash:
                        projection.linearStatement.statementHash,
                    proofEncoding,
                    proofParameterSet,
                    proofStatement: projection.linearStatement,
                    proofStatementFormat:
                        'dense-polynomial-matrix-linear-proof-v1',
                    publicRandomnessHex,
                    statementHash: componentStatement.componentStatementHash,
                };
            }
            if (
                componentId === 'payload-plaintext-field-component' ||
                componentId === 'share-commitment-component'
            ) {
                const sourceRingDegree = sourceRingDegreeFromParameterSet(
                    proofParameterSet,
                    `${componentId} parameter set`,
                );
                const witnessL2BoundSquared =
                    witnessBoundSquaredFromParameterSet(
                        proofParameterSet,
                        `${componentId} parameter set`,
                    );
                const componentRowBatches = rowBatchesForComponent({
                    component: componentById({
                        componentId,
                        loweredStatement,
                    }),
                    loweredStatement,
                });
                const usesStructuredShareCommitmentRows =
                    componentId === 'share-commitment-component' &&
                    componentRowBatches.some(
                        (rowBatch) =>
                            rowBatch.batchKind ===
                            'StructuredModuleSisShareCommitmentRows',
                    );
                const sparseStatement =
                    preparedComponentProofStatement<
                        | BallotProofSparseComponentLinearProofStatement
                        | BallotProofStructuredShareCommitmentProofStatement
                    >({
                        componentId,
                        expectedFormat: usesStructuredShareCommitmentRows
                            ? 'structured-module-sis-share-commitment-v1'
                            : 'sparse-polynomial-matrix-linear-proof-v1',
                        preparedLowering: input.preparedLowering,
                    }) ??
                    (componentId === 'payload-plaintext-field-component' &&
                    input.relationInput.optionCount > 1 &&
                    sourceRingDegree === 64
                        ? buildPackedFieldSparseComponentLinearProofStatement({
                              ballotProofStatementHash:
                                  input.statement.ballotProofStatementHash,
                              componentId,
                              loweredStatement,
                              parameterProfileId:
                                  componentProofParameterProfileIds[
                                      componentId
                                  ],
                              relationInput: input.relationInput,
                              sourceRingDegree,
                              witnessL2BoundSquared,
                          })
                        : buildBallotProofSparseComponentLinearProofStatement({
                              ballotProofStatementHash:
                                  input.statement.ballotProofStatementHash,
                              componentId,
                              loweredStatement,
                              parameterProfileId:
                                  componentProofParameterProfileIds[
                                      componentId
                                  ],
                              sourceRingDegree,
                              witnessL2BoundSquared,
                          }));
                if (usesStructuredShareCommitmentRows) {
                    componentSecretStates[componentId] =
                        secretStateForStructuredShareCommitmentStatement({
                            projectionWitness: input.projectionWitness,
                            relationInput: input.relationInput,
                            structuredStatement:
                                sparseStatement as BallotProofStructuredShareCommitmentProofStatement,
                        });
                } else {
                    if (
                        sparseStatement.proofStatementFormat !==
                        'sparse-polynomial-matrix-linear-proof-v1'
                    ) {
                        throw new Error(
                            'Sparse proof statement used an invalid component format.',
                        );
                    }
                    componentSecretStates[componentId] =
                        secretStateForExplicitSparseStatement({
                            componentId,
                            loweredStatement,
                            projectionWitness: input.projectionWitness,
                            relationInput: input.relationInput,
                            sparseStatement,
                        });
                }

                return {
                    componentId,
                    componentProofStatementHash: sparseStatement.statementHash,
                    proofEncoding,
                    proofParameterSet,
                    proofStatement: sparseStatement,
                    proofStatementFormat: sparseStatement.proofStatementFormat,
                    publicRandomnessHex,
                    statementHash: componentStatement.componentStatementHash,
                };
            }
            if (componentId === 'receiver-encryption-component') {
                const structuredStatement =
                    preparedComponentProofStatement<BallotProofStructuredReceiverEncryptionProofStatement>(
                        {
                            componentId,
                            expectedFormat:
                                'structured-module-lwe-linear-proof-v1',
                            preparedLowering: input.preparedLowering,
                        },
                    ) ??
                    buildBallotProofStructuredReceiverEncryptionProofStatement({
                        ballotProofStatementHash:
                            input.statement.ballotProofStatementHash,
                        componentStatement,
                        loweredStatement,
                        parameterProfileId:
                            componentProofParameterProfileIds[componentId],
                        witnessL2BoundSquared:
                            witnessBoundSquaredFromParameterSet(
                                proofParameterSet,
                                `${componentId} parameter set`,
                            ),
                    });
                componentSecretStates[componentId] =
                    secretStateForStructuredReceiverEncryptionStatement({
                        projectionWitness: input.projectionWitness,
                        relationInput: input.relationInput,
                        structuredStatement,
                    });

                return {
                    componentId,
                    componentProofStatementHash:
                        structuredStatement.statementHash,
                    proofEncoding,
                    proofParameterSet,
                    proofStatement: structuredStatement,
                    proofStatementFormat:
                        'structured-module-lwe-linear-proof-v1',
                    publicRandomnessHex,
                    statementHash: componentStatement.componentStatementHash,
                };
            }

            return {
                componentId,
                componentProofStatementHash:
                    componentStatementDescriptor.componentProofStatementHash,
                proofEncoding,
                proofParameterSet,
                proofStatement: componentStatementDescriptor,
                proofStatementFormat: 'public-binding-check-only-v1',
                publicRandomnessHex,
                statementHash: componentStatement.componentStatementHash,
            };
        },
    );
    validateGeneratedProofInputContracts({
        componentProofInputs,
        linearStatement,
        proofContracts: input.proofContracts,
    });

    return {
        componentBundleStatement,
        componentProofInputs,
        componentSecretStates,
        componentStatementDescriptors,
        componentProverRandomnessHexes:
            input.randomness.componentProverRandomnessHexes,
        linearStatement,
        loweredStatement,
        parameterSet: input.proofContracts.ballotProofParameterSet,
        proofEncoding: input.proofContracts.ballotProofEncoding,
        proverRandomnessHex: input.randomness.proverRandomnessHex,
        publicRandomnessHex: input.randomness.publicRandomnessHex,
        secretState,
        statement: input.statement,
    };
};
