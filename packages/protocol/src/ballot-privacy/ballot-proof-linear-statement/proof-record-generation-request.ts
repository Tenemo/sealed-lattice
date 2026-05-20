import type { BallotProofStatement } from '@sealed-lattice/types';

import {
    ballotPrivacyBackendProofComponentOrder,
    lowerBallotPrivacyRelationToBackendStatement,
    type BallotPrivacyBackendProofComponentId,
    type BallotPrivacyRelationBackendPublicContext,
} from '../relation-backend-lowering.js';
import type { BallotPrivacyRelationCompilerInput } from '../relation-compiler.js';

import {
    buildBallotProofComponentBundleStatement,
    buildBallotProofComponentProofStatementPlans,
} from './component-bundle.js';
import { secretStateForStructuredShareCommitmentStatement } from './component-projections.js';
import {
    assertBallotStatementMatchesPublicContext,
    assertFullReceiverPayloadsAreExplicit,
    buildFullRelationLinearProofStatement,
    componentPlanById,
    componentStatementById,
    requiredComponentStatement,
    requiredComponentStatementPlan,
    secretStateForStructuredReceiverEncryptionStatement,
    sourceRingDegreeFromParameterSet,
    witnessBoundSquaredFromParameterSet,
} from './full-relation-statement.js';
import { buildPackedFieldSparseComponentLinearProofStatement } from './packed-payload-plaintext-statement.js';
import {
    assertProofEncodingMatchesStatement,
    assertProofParameterSetMatchesStatement,
    buildBallotProofStructuredReceiverEncryptionProofStatement,
    buildEncodedScoreFieldLinearProofProjection,
    requireComponentContract,
    requireContractDecimalStringField,
    requireContractIntegerField,
    requireContractProfileId,
    requireObjectContract,
    requirePartialComponentContract,
    requireRandomnessHex,
    secretStateForExplicitSparseStatement,
    verifyBallotProofComponentExplicitRows,
} from './receiver-encryption-proof-statement.js';
import { buildBallotProofSparseComponentLinearProofStatement } from './sparse-component-statement.js';
import type {
    BallotProofComponentProjectionWitness,
    BallotProofFullRelationLinearProofStatement,
    BallotProofRecordGenerationComponentProofInput,
    BallotProofRecordGenerationProofContracts,
    BallotProofRecordGenerationRandomness,
    BallotProofRecordGenerationRequest,
    BallotProofRecordGenerationSecretState,
    BallotProofStructuredShareCommitmentProofStatement,
} from './statement-contracts.js';
import {
    componentProofEncodingProfileIds,
    componentProofParameterProfileIds,
    fullBallotProofEncodingProfileId,
    fullBallotProofParameterProfileId,
} from './statement-contracts.js';
import { rowBatchesForComponent } from './statement-digests.js';
import { componentById } from './witness-accessors.js';

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
            'public-zero-witness-binding-check-v1'
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
        ballotProofStatementDigest: input.statement.ballotProofStatementDigest,
        loweredStatement,
    });
    if (
        componentBundleStatement.bundleCoverage !==
        'full-encoded-score-ballot-relation'
    ) {
        throw new Error(
            'Ballot proof record generation requires every proof component to be explicitly lowered.',
        );
    }
    const componentStatementPlans =
        buildBallotProofComponentProofStatementPlans({
            ballotProofStatementDigest:
                input.statement.ballotProofStatementDigest,
            componentBundleStatement,
            loweredStatement,
        });
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
    const componentPlansById = componentPlanById(componentStatementPlans);
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
            const componentStatementPlan = requiredComponentStatementPlan({
                componentId,
                componentPlansById,
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
                    componentStatementPlan.proofStatementFormat ===
                    'sparse-polynomial-matrix-linear-proof-v1'
                ) {
                    const sparseStatement =
                        input.relationInput.optionCount > 1 &&
                        sourceRingDegree === 64
                            ? buildPackedFieldSparseComponentLinearProofStatement(
                                  {
                                      ballotProofStatementDigest:
                                          input.statement
                                              .ballotProofStatementDigest,
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
                                      ballotProofStatementDigest:
                                          input.statement
                                              .ballotProofStatementDigest,
                                      componentId,
                                      loweredStatement,
                                      parameterProfileId:
                                          componentProofParameterProfileIds[
                                              componentId
                                          ],
                                      sourceRingDegree,
                                      witnessL2BoundSquared,
                                  },
                              );
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
                        componentProofStatementDigest:
                            sparseStatement.statementDigest,
                        proofEncoding,
                        proofParameterSet,
                        proofStatement: sparseStatement,
                        proofStatementFormat:
                            sparseStatement.proofStatementFormat,
                        publicRandomnessHex,
                        statementDigest:
                            componentStatement.componentStatementDigest,
                    };
                }
                const projection = buildEncodedScoreFieldLinearProofProjection({
                    ballotProofStatementDigest:
                        input.statement.ballotProofStatementDigest,
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
                    componentProofStatementDigest:
                        projection.linearStatement.statementDigest,
                    proofEncoding,
                    proofParameterSet,
                    proofStatement: projection.linearStatement,
                    proofStatementFormat:
                        'dense-polynomial-matrix-linear-proof-v1',
                    publicRandomnessHex,
                    statementDigest:
                        componentStatement.componentStatementDigest,
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
                const sparseStatement =
                    componentId === 'payload-plaintext-field-component' &&
                    input.relationInput.optionCount > 1 &&
                    sourceRingDegree === 64
                        ? buildPackedFieldSparseComponentLinearProofStatement({
                              ballotProofStatementDigest:
                                  input.statement.ballotProofStatementDigest,
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
                              ballotProofStatementDigest:
                                  input.statement.ballotProofStatementDigest,
                              componentId,
                              loweredStatement,
                              parameterProfileId:
                                  componentProofParameterProfileIds[
                                      componentId
                                  ],
                              sourceRingDegree,
                              witnessL2BoundSquared,
                          });
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
                    componentProofStatementDigest:
                        sparseStatement.statementDigest,
                    proofEncoding,
                    proofParameterSet,
                    proofStatement: sparseStatement,
                    proofStatementFormat: sparseStatement.proofStatementFormat,
                    publicRandomnessHex,
                    statementDigest:
                        componentStatement.componentStatementDigest,
                };
            }
            if (componentId === 'receiver-encryption-component') {
                const structuredStatement =
                    buildBallotProofStructuredReceiverEncryptionProofStatement({
                        ballotProofStatementDigest:
                            input.statement.ballotProofStatementDigest,
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
                    componentProofStatementDigest:
                        structuredStatement.statementDigest,
                    proofEncoding,
                    proofParameterSet,
                    proofStatement: structuredStatement,
                    proofStatementFormat:
                        'structured-module-lwe-linear-proof-v1',
                    publicRandomnessHex,
                    statementDigest:
                        componentStatement.componentStatementDigest,
                };
            }

            return {
                componentId,
                componentProofStatementDigest:
                    componentStatementPlan.componentProofStatementDigest,
                proofEncoding,
                proofParameterSet,
                proofStatement: componentStatementPlan,
                proofStatementFormat: 'public-zero-witness-binding-check-v1',
                publicRandomnessHex,
                statementDigest: componentStatement.componentStatementDigest,
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
        componentStatementPlans,
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
