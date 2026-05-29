import type { ProtocolHash } from '@sealed-lattice/types';

import { type BallotPrivacyLoweredLinearRelationStatement } from '../relation-backend-lowering.js';
import type { BallotPrivacyRelationCompilerInput } from '../relation-compiler.js';

import {
    projectedWitnessValue,
    receiverReferenceKey,
} from './component-bundle.js';
import { buildBallotProofComponentLinearProofProjection } from './component-projections.js';
import { rowBatchesForComponent } from './component-statement-builder.js';
import { verifyBallotProofComponentExplicitRows } from './explicit-row-verification.js';
import type {
    BackendRowBatchForComponentStatement,
    BallotProofComponentProjectionWitness,
    BallotProofComponentStatement,
    BallotProofRecordGenerationSecretState,
    BallotProofSparseComponentLinearProofStatement,
    BallotProofStructuredReceiverEncryptionProofStatement,
    EncodedScoreFieldLinearProofProjection,
    StructuredReceiverEncryptionCiphertextChunkStatement,
    StructuredReceiverEncryptionReceiverStatement,
} from './statement-contracts.js';
import {
    linearProofRelation,
    receiverEncryptionModuleRank,
} from './statement-contracts.js';
import { deriveStructuredReceiverEncryptionStatementHash } from './statement-hashes.js';
import { witnessValueForVariable } from './statement-witness-values.js';
import {
    componentById,
    fieldVariableColumns,
    signedConstantPolynomial,
    signedPolynomialCoefficient,
    zeroPolynomial,
} from './witness-accessors.js';

export const buildBallotProofStructuredReceiverEncryptionProofStatement =
    (input: {
        readonly ballotProofStatementHash?: ProtocolHash;
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
                    publicKey.publicMatrixSeedHash === undefined ||
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
                    publicMatrixSeedHash: publicKey.publicMatrixSeedHash,
                    receiverIdentity: receiverRow.receiverIdentity,
                    receiverPayloadHash: receiverRow.receiverPayloadHash,
                    receiverPublicKeyHash: receiverRow.receiverPublicKeyHash,
                    receiverRosterPosition: receiverRow.receiverRosterPosition,
                    rowCount,
                    rowOffsetWithinStatement,
                };
            },
        );
        const statementPayload: Omit<
            BallotProofStructuredReceiverEncryptionProofStatement,
            'statementHash'
        > = {
            backendStatementHash:
                input.loweredStatement.backendStatement.backendStatementHash,
            ...(input.ballotProofStatementHash === undefined
                ? {}
                : {
                      ballotProofStatementHash: input.ballotProofStatementHash,
                  }),
            coefficientModulus: component.coefficientModulus,
            componentId: 'receiver-encryption-component',
            componentStatementHash:
                input.componentStatement.componentStatementHash,
            matrixHash: input.componentStatement.matrixHash,
            objectType: 'BallotProofStructuredReceiverEncryptionProofStatement',
            objectVersion: 1,
            parameterProfileId: input.parameterProfileId,
            proofStatementFormat: 'structured-module-lwe-linear-proof-v1',
            proofSystemRingDegree: 64,
            receiverEncryptionProfileHash:
                input.loweredStatement.publicContext
                    .receiverEncryptionProfileHash,
            receiverRows,
            relation: linearProofRelation,
            relationStatementHash: input.loweredStatement.relationStatementHash,
            sourceBackendColumnIndices,
            sourceRingDegree: 256,
            statementColumns: nextPolynomialColumnIndex,
            statementRows: nextPolynomialRowOffset,
            matrixCoefficientRepresentation: 'centeredSignedSourceModulus',
            targetCoefficientRepresentation: 'centeredSignedSourceModulus',
            targetVectorHash: input.componentStatement.targetVectorHash,
            witnessL2BoundSquared: input.witnessL2BoundSquared,
        };

        return {
            ...statementPayload,
            statementHash:
                deriveStructuredReceiverEncryptionStatementHash(
                    statementPayload,
                ),
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
    readonly ballotProofStatementHash?: ProtocolHash;
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

export { secretStateForExplicitSparseStatement };
