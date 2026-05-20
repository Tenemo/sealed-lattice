import type { ProtocolDigest } from '@sealed-lattice/types';

import {
    type BallotPrivacyBackendProofComponentId,
    type BallotPrivacyLoweredLinearRelationStatement,
} from '../relation-backend-lowering.js';
import type { BallotPrivacyRelationCompilerInput } from '../relation-compiler.js';

import {
    projectedWitnessValue,
    receiverReferenceKey,
} from './component-bundle.js';
import {
    buildBallotProofComponentLinearProofProjection,
    verifyStructuredReceiverEncryptionRowBatch,
} from './component-projections.js';
import type {
    BackendRowBatchForComponentStatement,
    BallotProofComponentProjectionWitness,
    BallotProofComponentStatement,
    BallotProofExplicitComponentWitnessVerification,
    BallotProofRecordGenerationSecretState,
    BallotProofSparseComponentLinearProofStatement,
    BallotProofStructuredReceiverEncryptionProofStatement,
    EncodedScoreFieldLinearProofProjection,
    StructuredReceiverEncryptionCiphertextChunkStatement,
    StructuredReceiverEncryptionReceiverStatement,
} from './statement-contracts.js';
import {
    linearProofRelation,
    positiveModuloBigInt,
    receiverEncryptionModuleRank,
    thirtyTwoByteLowercaseHexPattern,
} from './statement-contracts.js';
import {
    deriveStructuredReceiverEncryptionStatementDigest,
    rowBatchesForComponent,
    witnessValueForVariable,
} from './statement-digests.js';
import {
    componentById,
    decimalBigInt,
    fieldVariableColumns,
    signedConstantPolynomial,
    signedPolynomialCoefficient,
    zeroPolynomial,
} from './witness-accessors.js';

export const buildBallotProofStructuredReceiverEncryptionProofStatement =
    (input: {
        readonly ballotProofStatementDigest?: ProtocolDigest;
        readonly componentStatement: BallotProofComponentStatement;
        readonly loweredStatement: BallotPrivacyLoweredLinearRelationStatement;
        readonly parameterProfileId: string;
        readonly witnessL2BoundSquared: string;
    }): BallotProofStructuredReceiverEncryptionProofStatement => {
        if (
            input.componentStatement.componentId !==
            'receiver-encryption-component'
        ) {
            throw new Error(
                'Structured receiver-encryption proof statements require the receiver-encryption component statement.',
            );
        }
        const component = componentById({
            componentId: 'receiver-encryption-component',
            loweredStatement: input.loweredStatement,
        });
        if (component.proofLoweringStatus !== 'explicitRowsAvailable') {
            throw new Error(
                'Structured receiver-encryption proof statements require explicit receiver-encryption rows.',
            );
        }
        const structuredRowBatches = rowBatchesForComponent({
            component,
            loweredStatement: input.loweredStatement,
        }).filter(
            (
                rowBatch,
            ): rowBatch is Extract<
                BackendRowBatchForComponentStatement,
                {
                    readonly batchKind: 'StructuredModuleLweReceiverEncryptionRows';
                }
            > =>
                rowBatch.batchKind ===
                'StructuredModuleLweReceiverEncryptionRows',
        );
        if (structuredRowBatches.length !== 1) {
            throw new Error(
                'Structured receiver-encryption proof statements require one structured row batch.',
            );
        }
        const structuredRowBatch = structuredRowBatches[0];
        if (component.variableColumnCount <= 0) {
            throw new Error(
                'Structured receiver-encryption proof statements require projected witness columns.',
            );
        }
        const sourceBackendColumnIndices = component.variableColumnIndices;
        const publicKeysByReceiver = new Map(
            input.loweredStatement.publicContext.receiverPublicKeys.map(
                (publicKey) => [receiverReferenceKey(publicKey), publicKey],
            ),
        );
        const payloadsByReceiver = new Map(
            input.loweredStatement.publicContext.receiverPayloads.map(
                (receiverPayload) => [
                    receiverReferenceKey(receiverPayload),
                    receiverPayload,
                ],
            ),
        );
        let nextPolynomialColumnIndex = 0;
        let nextPolynomialRowOffset = 0;
        const receiverRows = structuredRowBatch.receiverRows.map(
            (receiverRow): StructuredReceiverEncryptionReceiverStatement => {
                const receiverKey = receiverReferenceKey(receiverRow);
                const publicKey = publicKeysByReceiver.get(receiverKey);
                const receiverPayload = payloadsByReceiver.get(receiverKey);
                if (
                    publicKey?.publicKeyVector === undefined ||
                    publicKey.publicMatrixSeedDigest === undefined ||
                    receiverPayload?.ciphertextChunks === undefined
                ) {
                    throw new Error(
                        'Structured receiver-encryption proof statement is missing public key or ciphertext material.',
                    );
                }
                if (
                    receiverPayload.ciphertextChunks.length !==
                    receiverRow.ciphertextChunkCount
                ) {
                    throw new Error(
                        'Structured receiver-encryption ciphertext chunk count does not match the row descriptor.',
                    );
                }
                const rowOffsetWithinStatement = nextPolynomialRowOffset;
                const rowCount =
                    receiverRow.ciphertextChunkCount *
                    (receiverEncryptionModuleRank + 1);
                nextPolynomialRowOffset += rowCount;
                const ciphertextChunks = receiverPayload.ciphertextChunks.map(
                    (
                        ciphertextChunk,
                    ): StructuredReceiverEncryptionCiphertextChunkStatement => {
                        const randomnessPolynomialColumnIndices = Array.from(
                            { length: receiverEncryptionModuleRank },
                            () => nextPolynomialColumnIndex++,
                        );
                        const firstNoisePolynomialColumnIndices = Array.from(
                            { length: receiverEncryptionModuleRank },
                            () => nextPolynomialColumnIndex++,
                        );
                        const secondNoiseColumnIndex =
                            nextPolynomialColumnIndex++;
                        const plaintextPolynomialColumnIndex =
                            nextPolynomialColumnIndex++;

                        return {
                            chunkIndex: ciphertextChunk.chunkIndex,
                            firstCiphertextVector:
                                ciphertextChunk.firstCiphertextVector,
                            firstNoisePolynomialColumnIndices,
                            plaintextPolynomialColumnIndex,
                            randomnessPolynomialColumnIndices,
                            secondCiphertextPolynomial:
                                ciphertextChunk.secondCiphertextPolynomial,
                            secondNoiseColumnIndex,
                        };
                    },
                );

                return {
                    ciphertextChunkCount: receiverRow.ciphertextChunkCount,
                    ciphertextChunks,
                    plaintextBitLength: receiverRow.plaintextBitLength,
                    publicKeyVector: publicKey.publicKeyVector,
                    publicMatrixSeedDigest: publicKey.publicMatrixSeedDigest,
                    receiverIdentity: receiverRow.receiverIdentity,
                    receiverPayloadDigest: receiverRow.receiverPayloadDigest,
                    receiverPublicKeyDigest:
                        receiverRow.receiverPublicKeyDigest,
                    receiverRosterPosition: receiverRow.receiverRosterPosition,
                    rowCount,
                    rowOffsetWithinStatement,
                };
            },
        );
        const statementPayload: Omit<
            BallotProofStructuredReceiverEncryptionProofStatement,
            'statementDigest'
        > = {
            backendStatementDigest:
                input.loweredStatement.backendStatement.backendStatementDigest,
            ...(input.ballotProofStatementDigest === undefined
                ? {}
                : {
                      ballotProofStatementDigest:
                          input.ballotProofStatementDigest,
                  }),
            coefficientModulus: component.coefficientModulus,
            componentId: 'receiver-encryption-component',
            componentStatementDigest:
                input.componentStatement.componentStatementDigest,
            matrixDigest: input.componentStatement.matrixDigest,
            objectType: 'BallotProofStructuredReceiverEncryptionProofStatement',
            objectVersion: 1,
            parameterProfileId: input.parameterProfileId,
            proofStatementFormat: 'structured-module-lwe-linear-proof-v1',
            proofSystemRingDegree: 64,
            receiverEncryptionProfileDigest:
                input.loweredStatement.publicContext
                    .receiverEncryptionProfileDigest,
            receiverRows,
            relation: linearProofRelation,
            relationStatementDigest:
                input.loweredStatement.relationStatementDigest,
            sourceBackendColumnIndices,
            sourceRingDegree: 256,
            statementColumns: nextPolynomialColumnIndex,
            statementRows: nextPolynomialRowOffset,
            matrixCoefficientRepresentation: 'centeredSignedSourceModulus',
            targetCoefficientRepresentation: 'centeredSignedSourceModulus',
            targetVectorDigest: input.componentStatement.targetVectorDigest,
            witnessL2BoundSquared: input.witnessL2BoundSquared,
        };

        return {
            ...statementPayload,
            statementDigest:
                deriveStructuredReceiverEncryptionStatementDigest(
                    statementPayload,
                ),
        };
    };

export const verifyBallotProofComponentExplicitRows = (input: {
    readonly componentId: BallotPrivacyBackendProofComponentId;
    readonly loweredStatement: BallotPrivacyLoweredLinearRelationStatement;
    readonly projectionWitness?: BallotProofComponentProjectionWitness;
    readonly relationInput: BallotPrivacyRelationCompilerInput;
}): BallotProofExplicitComponentWitnessVerification => {
    const component = componentById({
        componentId: input.componentId,
        loweredStatement: input.loweredStatement,
    });
    if (component.proofLoweringStatus !== 'explicitRowsAvailable') {
        throw new Error(
            `Proof component ${component.componentId} is not fully lowered to explicit rows.`,
        );
    }
    const rowBatches = rowBatchesForComponent({
        component,
        loweredStatement: input.loweredStatement,
    });
    const coefficientModulus = decimalBigInt(
        component.coefficientModulus,
        'component coefficient modulus',
    );
    const variableColumnByBackendColumn = new Map(
        fieldVariableColumns(input.loweredStatement).map((variableColumn) => [
            variableColumn.columnIndex,
            variableColumn,
        ]),
    );
    let checkedRowCount = 0;

    for (const rowBatch of rowBatches) {
        if (rowBatch.batchKind === 'DigestExpandedRows') {
            throw new Error(
                `Proof component ${input.componentId} is not fully lowered to explicit rows.`,
            );
        }
        if (
            rowBatch.batchKind === 'StructuredModuleLweReceiverEncryptionRows'
        ) {
            checkedRowCount += verifyStructuredReceiverEncryptionRowBatch({
                loweredStatement: input.loweredStatement,
                projectionWitness: input.projectionWitness,
                relationInput: input.relationInput,
                rowBatch,
                startingRowIndex: checkedRowCount,
            });
            continue;
        }
        if (rowBatch.batchKind === 'StructuredModuleSisShareCommitmentRows') {
            checkedRowCount += rowBatch.rowCount;
            continue;
        }
        if (rowBatch.modulus !== component.coefficientModulus) {
            throw new Error(
                `Proof component ${input.componentId} row batch ${rowBatch.batchName} uses a mismatched modulus.`,
            );
        }
        for (const row of rowBatch.rows) {
            let rowSum = -decimalBigInt(row.target, 'linear row target');
            for (const term of row.terms) {
                const variableColumn = variableColumnByBackendColumn.get(
                    term.columnIndex,
                );
                if (variableColumn === undefined) {
                    throw new Error(
                        'Explicit row variable lookup is incomplete.',
                    );
                }
                rowSum +=
                    decimalBigInt(term.coefficient, 'linear term coefficient') *
                    witnessValueForVariable(
                        input.relationInput,
                        input.projectionWitness,
                        variableColumn,
                    );
            }
            if (positiveModuloBigInt(rowSum, coefficientModulus) !== 0n) {
                throw new Error(
                    `Proof component ${input.componentId} row ${checkedRowCount.toString()} is not satisfied by the private witness.`,
                );
            }
            checkedRowCount += 1;
        }
    }

    return {
        checkedRowBatchNames: rowBatches.map((rowBatch) => rowBatch.batchName),
        componentId: input.componentId,
        objectType: 'BallotProofExplicitComponentWitnessVerification',
        objectVersion: 1,
        relation: linearProofRelation,
        rowCount: checkedRowCount,
        verificationStatus: 'explicitRowsSatisfied',
    };
};

const secretStateForExplicitSparseStatement = (input: {
    readonly componentId:
        | 'score-and-shamir-field-component'
        | 'payload-plaintext-field-component'
        | 'share-commitment-component';
    readonly loweredStatement: BallotPrivacyLoweredLinearRelationStatement;
    readonly projectionWitness?: BallotProofComponentProjectionWitness;
    readonly relationInput: BallotPrivacyRelationCompilerInput;
    readonly sparseStatement: BallotProofSparseComponentLinearProofStatement;
}): BallotProofRecordGenerationSecretState => {
    const variableColumnByBackendColumn = new Map(
        fieldVariableColumns(input.loweredStatement).map((variableColumn) => [
            variableColumn.columnIndex,
            variableColumn,
        ]),
    );
    const sourceWitnessCoefficients =
        input.sparseStatement.sourceColumnPackings === undefined
            ? input.sparseStatement.sourceBackendColumnIndices.map(
                  (backendColumnIndex) => {
                      const variableColumn =
                          variableColumnByBackendColumn.get(backendColumnIndex);
                      if (variableColumn === undefined) {
                          throw new Error(
                              'Sparse projection variable lookup is incomplete.',
                          );
                      }

                      return signedConstantPolynomial({
                          coefficient: projectedWitnessValue({
                              componentId: input.componentId,
                              rawWitnessValue: witnessValueForVariable(
                                  input.relationInput,
                                  input.projectionWitness,
                                  variableColumn,
                              ),
                          }),
                          sourceRingDegree:
                              input.sparseStatement.sourceRingDegree,
                      });
                  },
              )
            : input.sparseStatement.sourceColumnPackings.map((packing) => {
                  if (
                      packing.columnIndex < 0 ||
                      packing.columnIndex >=
                          input.sparseStatement.statementColumns
                  ) {
                      throw new Error(
                          'Packed sparse projection column is outside the statement shape.',
                      );
                  }
                  const polynomial = zeroPolynomial(
                      input.sparseStatement.sourceRingDegree,
                  );
                  const seenCoefficientIndices = new Set<number>();
                  for (const binding of packing.bindings) {
                      if (
                          binding.coefficientIndex < 0 ||
                          binding.coefficientIndex >=
                              input.sparseStatement.sourceRingDegree ||
                          !seenCoefficientIndices.add(binding.coefficientIndex)
                      ) {
                          throw new Error(
                              'Packed sparse projection binding has an invalid coefficient slot.',
                          );
                      }
                      const variableColumn = variableColumnByBackendColumn.get(
                          binding.backendColumnIndex,
                      );
                      if (variableColumn === undefined) {
                          throw new Error(
                              'Packed sparse projection variable lookup is incomplete.',
                          );
                      }
                      polynomial[binding.coefficientIndex] =
                          signedPolynomialCoefficient(
                              projectedWitnessValue({
                                  componentId: input.componentId,
                                  rawWitnessValue: witnessValueForVariable(
                                      input.relationInput,
                                      input.projectionWitness,
                                      variableColumn,
                                  ),
                              }),
                          );
                  }

                  return polynomial;
              });
    verifyBallotProofComponentExplicitRows({
        componentId: input.componentId,
        loweredStatement: input.loweredStatement,
        projectionWitness: input.projectionWitness,
        relationInput: input.relationInput,
    });

    return {
        sourceWitnessCoefficients,
    };
};

export const buildEncodedScoreFieldLinearProofProjection = (input: {
    readonly ballotProofStatementDigest?: ProtocolDigest;
    readonly loweredStatement: BallotPrivacyLoweredLinearRelationStatement;
    readonly parameterProfileId: string;
    readonly relationInput: BallotPrivacyRelationCompilerInput;
    readonly sourceRingDegree: number;
    readonly witnessL2BoundSquared: string;
}): EncodedScoreFieldLinearProofProjection => {
    const projection = buildBallotProofComponentLinearProofProjection({
        ...input,
        componentId: 'score-and-shamir-field-component',
    });
    const sourceRowBatchName = projection.sourceRowBatchNames[0];
    if (sourceRowBatchName !== 'encoded_score_field_rows') {
        throw new Error('Encoded-score projection used the wrong row batch.');
    }

    return {
        linearStatement: projection.linearStatement,
        privateWitnessVectorCoefficients:
            projection.privateWitnessVectorCoefficients,
        sourceBackendColumnIndices: projection.sourceBackendColumnIndices,
        sourceRowBatchName,
    };
};

const requireObjectContract = (
    value: unknown,
    label: string,
): Readonly<Record<string, unknown>> => {
    if (value === null || typeof value !== 'object' || Array.isArray(value)) {
        throw new Error(`${label} must be an object.`);
    }

    return value as Readonly<Record<string, unknown>>;
};

const requireContractStringField = (input: {
    readonly contract: unknown;
    readonly fieldName: string;
    readonly label: string;
}): string => {
    const value = requireObjectContract(input.contract, input.label)[
        input.fieldName
    ];
    if (typeof value !== 'string' || value.length === 0) {
        throw new Error(`${input.label}.${input.fieldName} must be a string.`);
    }

    return value;
};

const requireContractIntegerField = (input: {
    readonly contract: unknown;
    readonly fieldName: string;
    readonly label: string;
}): number => {
    const value = requireObjectContract(input.contract, input.label)[
        input.fieldName
    ];
    if (
        typeof value !== 'number' ||
        !Number.isSafeInteger(value) ||
        value < 0 ||
        Object.is(value, -0)
    ) {
        throw new Error(
            `${input.label}.${input.fieldName} must be a non-negative safe integer.`,
        );
    }

    return value;
};

const requireContractDecimalStringField = (input: {
    readonly contract: unknown;
    readonly fieldName: string;
    readonly label: string;
}): string => {
    const value = requireObjectContract(input.contract, input.label)[
        input.fieldName
    ];
    if (typeof value === 'number') {
        if (!Number.isSafeInteger(value) || value < 0 || Object.is(value, -0)) {
            throw new Error(
                `${input.label}.${input.fieldName} must be a canonical unsigned decimal integer.`,
            );
        }

        return value.toString();
    }
    if (typeof value === 'string' && /^(0|[1-9][0-9]*)$/u.test(value)) {
        return value;
    }

    throw new Error(
        `${input.label}.${input.fieldName} must be a canonical unsigned decimal integer.`,
    );
};

const requireContractProfileId = (input: {
    readonly contract: unknown;
    readonly expectedProfileId: string;
    readonly label: string;
}): void => {
    const profileId = requireContractStringField({
        contract: input.contract,
        fieldName: 'profileId',
        label: input.label,
    });
    if (profileId !== input.expectedProfileId) {
        throw new Error(
            `${input.label} must use profile ${input.expectedProfileId}.`,
        );
    }
};

const requireRandomnessHex = (value: string, label: string): void => {
    if (!thirtyTwoByteLowercaseHexPattern.test(value)) {
        throw new Error(`${label} must be 32 lowercase hexadecimal bytes.`);
    }
};

const requireComponentContract = <Value>(
    values: Readonly<Record<BallotPrivacyBackendProofComponentId, Value>>,
    componentId: BallotPrivacyBackendProofComponentId,
    label: string,
): Value => {
    const value = values[componentId];
    if (value === undefined) {
        throw new Error(`${label}.${componentId} is required.`);
    }

    return value;
};

const requirePartialComponentContract = <Value>(
    values: Readonly<
        Partial<Record<BallotPrivacyBackendProofComponentId, Value>>
    >,
    componentId: BallotPrivacyBackendProofComponentId,
    label: string,
): Value => {
    const value = values[componentId];
    if (value === undefined) {
        throw new Error(`${label}.${componentId} is required.`);
    }

    return value;
};

const assertProofParameterSetMatchesStatement = (input: {
    readonly coefficientModulus: string;
    readonly expectedProfileId: string;
    readonly label: string;
    readonly parameterSet: unknown;
    readonly sourceRingDegree: number;
    readonly statementColumns: number;
    readonly statementRows: number;
}): void => {
    requireContractProfileId({
        contract: input.parameterSet,
        expectedProfileId: input.expectedProfileId,
        label: input.label,
    });
    const ringDegree = requireContractIntegerField({
        contract: input.parameterSet,
        fieldName: 'ringDegree',
        label: input.label,
    });
    if (ringDegree !== input.sourceRingDegree) {
        throw new Error(
            `${input.label}.ringDegree must match the proof statement source ring degree.`,
        );
    }
    const statementRows = requireContractIntegerField({
        contract: input.parameterSet,
        fieldName: 'statementRows',
        label: input.label,
    });
    if (statementRows !== input.statementRows) {
        throw new Error(
            `${input.label}.statementRows must match the proof statement row count.`,
        );
    }
    const statementColumns = requireContractIntegerField({
        contract: input.parameterSet,
        fieldName: 'statementColumns',
        label: input.label,
    });
    if (statementColumns !== input.statementColumns) {
        throw new Error(
            `${input.label}.statementColumns must match the proof statement column count.`,
        );
    }
    const coefficientModulus = requireContractDecimalStringField({
        contract: input.parameterSet,
        fieldName: 'coefficientModulus',
        label: input.label,
    });
    if (coefficientModulus !== input.coefficientModulus) {
        throw new Error(
            `${input.label}.coefficientModulus must match the proof statement modulus.`,
        );
    }
};

const assertProofEncodingMatchesStatement = (input: {
    readonly encoding: unknown;
    readonly expectedProfileId: string;
    readonly label: string;
    readonly sourceRingDegree: number;
    readonly statementColumns: number;
}): void => {
    requireContractProfileId({
        contract: input.encoding,
        expectedProfileId: input.expectedProfileId,
        label: input.label,
    });
    const shortResponseVectorLength = requireContractIntegerField({
        contract: input.encoding,
        fieldName: 'shortResponseVectorLength',
        label: input.label,
    });
    const proofRingDegree = requireContractIntegerField({
        contract: input.encoding,
        fieldName: 'ringDegree',
        label: input.label,
    });
    if (input.sourceRingDegree % proofRingDegree !== 0) {
        throw new Error(
            `${input.label}.ringDegree must divide the proof statement source ring degree.`,
        );
    }
    const sourcePolynomialSplitFactor =
        input.sourceRingDegree / proofRingDegree;
    const expectedShortResponseVectorLength =
        input.statementColumns * sourcePolynomialSplitFactor + 1;
    if (shortResponseVectorLength !== expectedShortResponseVectorLength) {
        throw new Error(
            `${input.label}.shortResponseVectorLength must match the split proof statement column count plus one.`,
        );
    }
};

export {
    secretStateForExplicitSparseStatement,
    requireObjectContract,
    requireContractIntegerField,
    requireContractDecimalStringField,
    requireContractProfileId,
    requireRandomnessHex,
    requireComponentContract,
    requirePartialComponentContract,
    assertProofParameterSetMatchesStatement,
    assertProofEncodingMatchesStatement,
};
