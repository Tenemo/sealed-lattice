import type { ProtocolHash } from '@sealed-lattice/types';

import { deriveReceiverPublicMatrix } from '../lattice-primitives.js';
import {
    type BallotPrivacyBackendProofComponent,
    type BallotPrivacyLoweredLinearRelationStatement,
} from '../relation-backend-lowering.js';
import type { BallotPrivacyRelationCompilerInput } from '../relation-compiler.js';

import {
    addModularProduct,
    assertProjectionSatisfiesRows,
    numberPolynomialCoefficient,
    numberVectorCoefficient,
    projectedWitnessValue,
    receiverPayloadPlaintextBits,
    receiverReferenceKey,
    validateSourceRingDegree,
} from './component-bundle.js';
import { rowBatchesForComponent } from './component-statement-builder.js';
import type {
    BackendRowBatchForComponentStatement,
    BallotProofComponentLinearProofProjection,
    BallotProofComponentProjectionWitness,
    BallotProofExplicitComponentId,
    BallotProofLinearProofStatement,
    BallotProofRecordGenerationSecretState,
    BallotProofStructuredShareCommitmentProofStatement,
    DensePolynomial,
    StructuredShareCommitmentReceiverStatement,
} from './statement-contracts.js';
import {
    linearProofRelation,
    negacyclicNumberCoefficient,
    polynomialCoefficient,
    positiveModulo,
    receiverEncryptionMessageScale,
    receiverEncryptionModuleDegree,
    receiverEncryptionModuleRank,
    receiverEncryptionModulus,
    shareCommitmentModuleDegree,
    shareCommitmentModuleRank,
} from './statement-contracts.js';
import {
    deriveLinearStatementHash,
    deriveStatementMatrixHash,
    deriveStructuredShareCommitmentStatementHash,
    deriveTargetVectorHash,
} from './statement-hashes.js';
import { witnessValueForVariable } from './statement-witness-values.js';
import {
    componentById,
    constantPolynomial,
    decimalBigInt,
    explicitRowBatchesForComponent,
    fieldVariableColumns,
    projectionCoverageForComponent,
    receiverEncryptionChunkWitness,
    shareCommitmentOpeningValue,
    signedConstantPolynomial,
    structuredShareCommitmentRowBatchByName,
    usedBackendColumnIndices,
    zeroPolynomial,
} from './witness-accessors.js';

const verifyStructuredReceiverEncryptionRowBatch = (input: {
    readonly loweredStatement: BallotPrivacyLoweredLinearRelationStatement;
    readonly projectionWitness:
        | BallotProofComponentProjectionWitness
        | undefined;
    readonly relationInput: BallotPrivacyRelationCompilerInput;
    readonly rowBatch: Extract<
        BackendRowBatchForComponentStatement,
        { readonly batchKind: 'StructuredModuleLweReceiverEncryptionRows' }
    >;
    readonly startingRowIndex: number;
}): number => {
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
    let checkedRowCount = 0;

    for (const receiverRow of input.rowBatch.receiverRows) {
        const receiverKey = receiverReferenceKey(receiverRow);
        const publicKey = publicKeysByReceiver.get(receiverKey);
        const receiverPayload = payloadsByReceiver.get(receiverKey);
        if (
            publicKey?.publicKeyVector === undefined ||
            publicKey.publicMatrixSeedHash === undefined ||
            receiverPayload?.ciphertextChunks === undefined
        ) {
            throw new Error(
                'Structured receiver encryption rows are missing public key or ciphertext material.',
            );
        }
        const publicMatrix = deriveReceiverPublicMatrix(
            input.loweredStatement.publicContext.receiverEncryptionProfileHash,
            publicKey.publicMatrixSeedHash,
        );
        const plaintextBits = receiverPayloadPlaintextBits({
            plaintextBitLength: receiverRow.plaintextBitLength,
            projectionWitness: input.projectionWitness,
            receiverRosterPosition: receiverRow.receiverRosterPosition,
            relationInput: input.relationInput,
        });

        for (const ciphertextChunk of receiverPayload.ciphertextChunks) {
            const chunkWitness = receiverEncryptionChunkWitness(
                input.projectionWitness,
                receiverRow.receiverRosterPosition,
                ciphertextChunk.chunkIndex,
            );
            for (
                let ciphertextVectorIndex = 0;
                ciphertextVectorIndex < receiverEncryptionModuleRank;
                ciphertextVectorIndex += 1
            ) {
                for (
                    let outputCoefficientIndex = 0;
                    outputCoefficientIndex < receiverEncryptionModuleDegree;
                    outputCoefficientIndex += 1
                ) {
                    let rowSum = positiveModulo(
                        -numberVectorCoefficient({
                            coefficientIndex: outputCoefficientIndex,
                            vector: ciphertextChunk.firstCiphertextVector,
                            vectorIndex: ciphertextVectorIndex,
                        }),
                        receiverEncryptionModulus,
                    );
                    for (
                        let randomnessVectorIndex = 0;
                        randomnessVectorIndex < receiverEncryptionModuleRank;
                        randomnessVectorIndex += 1
                    ) {
                        for (
                            let randomnessCoefficientIndex = 0;
                            randomnessCoefficientIndex <
                            receiverEncryptionModuleDegree;
                            randomnessCoefficientIndex += 1
                        ) {
                            rowSum = addModularProduct({
                                coefficient: negacyclicNumberCoefficient({
                                    outputCoefficientIndex,
                                    polynomial:
                                        publicMatrix[randomnessVectorIndex]?.[
                                            ciphertextVectorIndex
                                        ] ?? [],
                                    witnessCoefficientIndex:
                                        randomnessCoefficientIndex,
                                }),
                                currentValue: rowSum,
                                witness: numberVectorCoefficient({
                                    coefficientIndex:
                                        randomnessCoefficientIndex,
                                    vector: chunkWitness.encryptionRandomnessVector,
                                    vectorIndex: randomnessVectorIndex,
                                }),
                            });
                        }
                    }
                    rowSum = positiveModulo(
                        rowSum +
                            numberVectorCoefficient({
                                coefficientIndex: outputCoefficientIndex,
                                vector: chunkWitness.firstNoiseVector,
                                vectorIndex: ciphertextVectorIndex,
                            }),
                        receiverEncryptionModulus,
                    );
                    if (rowSum !== 0) {
                        throw new Error(
                            `Proof component receiver-encryption-component row ${(input.startingRowIndex + checkedRowCount).toString()} is not satisfied by the private witness.`,
                        );
                    }
                    checkedRowCount += 1;
                }
            }

            for (
                let outputCoefficientIndex = 0;
                outputCoefficientIndex < receiverEncryptionModuleDegree;
                outputCoefficientIndex += 1
            ) {
                let rowSum = positiveModulo(
                    -numberPolynomialCoefficient({
                        coefficientIndex: outputCoefficientIndex,
                        polynomial: ciphertextChunk.secondCiphertextPolynomial,
                    }),
                    receiverEncryptionModulus,
                );
                for (
                    let randomnessVectorIndex = 0;
                    randomnessVectorIndex < receiverEncryptionModuleRank;
                    randomnessVectorIndex += 1
                ) {
                    for (
                        let randomnessCoefficientIndex = 0;
                        randomnessCoefficientIndex <
                        receiverEncryptionModuleDegree;
                        randomnessCoefficientIndex += 1
                    ) {
                        rowSum = addModularProduct({
                            coefficient: negacyclicNumberCoefficient({
                                outputCoefficientIndex,
                                polynomial:
                                    publicKey.publicKeyVector[
                                        randomnessVectorIndex
                                    ] ?? [],
                                witnessCoefficientIndex:
                                    randomnessCoefficientIndex,
                            }),
                            currentValue: rowSum,
                            witness: numberVectorCoefficient({
                                coefficientIndex: randomnessCoefficientIndex,
                                vector: chunkWitness.encryptionRandomnessVector,
                                vectorIndex: randomnessVectorIndex,
                            }),
                        });
                    }
                }
                rowSum = positiveModulo(
                    rowSum +
                        numberPolynomialCoefficient({
                            coefficientIndex: outputCoefficientIndex,
                            polynomial: chunkWitness.secondNoisePolynomial,
                        }),
                    receiverEncryptionModulus,
                );
                const plaintextBitIndex =
                    ciphertextChunk.chunkIndex *
                        receiverEncryptionModuleDegree +
                    outputCoefficientIndex;
                if (plaintextBitIndex < plaintextBits.length) {
                    rowSum = positiveModulo(
                        rowSum +
                            receiverEncryptionMessageScale *
                                (plaintextBits[plaintextBitIndex] ?? 0),
                        receiverEncryptionModulus,
                    );
                }
                if (rowSum !== 0) {
                    throw new Error(
                        `Proof component receiver-encryption-component row ${(input.startingRowIndex + checkedRowCount).toString()} is not satisfied by the private witness.`,
                    );
                }
                checkedRowCount += 1;
            }
        }
    }

    return checkedRowCount;
};

export const buildBallotProofComponentLinearProofProjection = (input: {
    readonly ballotProofStatementHash?: ProtocolHash;
    readonly componentId: BallotProofExplicitComponentId;
    readonly loweredStatement: BallotPrivacyLoweredLinearRelationStatement;
    readonly parameterProfileId: string;
    readonly projectionWitness?: BallotProofComponentProjectionWitness;
    readonly relationInput: BallotPrivacyRelationCompilerInput;
    readonly sourceRingDegree: number;
    readonly witnessL2BoundSquared: string;
}): BallotProofComponentLinearProofProjection => {
    validateSourceRingDegree(input.sourceRingDegree);
    const component = componentById({
        componentId: input.componentId,
        loweredStatement: input.loweredStatement,
    });
    const componentRowBatches = rowBatchesForComponent({
        component,
        loweredStatement: input.loweredStatement,
    });
    if (
        input.componentId === 'share-commitment-component' &&
        componentRowBatches.some(
            (rowBatch) =>
                rowBatch.batchKind === 'StructuredModuleSisShareCommitmentRows',
        )
    ) {
        throw new Error(
            'Proof component share-commitment-component is not fully lowered to dense projection rows.',
        );
    }
    const rowBatches = explicitRowBatchesForComponent({
        component,
        loweredStatement: input.loweredStatement,
    });
    const coefficientModulus = decimalBigInt(
        component.coefficientModulus,
        'component coefficient modulus',
    );
    const invalidModulusBatch = rowBatches.find(
        (rowBatch) => rowBatch.modulus !== component.coefficientModulus,
    );
    if (invalidModulusBatch !== undefined) {
        throw new Error(
            `Proof component ${input.componentId} row batch ${invalidModulusBatch.batchName} uses a mismatched modulus.`,
        );
    }
    const explicitRows = rowBatches.flatMap((rowBatch) => rowBatch.rows);
    const sourceBackendColumnIndices = usedBackendColumnIndices(explicitRows);
    const projectedColumnByBackendColumn = new Map(
        sourceBackendColumnIndices.map((backendColumnIndex, projectedIndex) => [
            backendColumnIndex,
            projectedIndex,
        ]),
    );
    const variableColumnByBackendColumn = new Map(
        fieldVariableColumns(input.loweredStatement).map((variableColumn) => [
            variableColumn.columnIndex,
            variableColumn,
        ]),
    );
    const statementMatrixCoefficients = explicitRows.map((fieldRow) => {
        const row = Array.from(
            { length: sourceBackendColumnIndices.length },
            () => zeroPolynomial(input.sourceRingDegree),
        );
        for (const term of fieldRow.terms) {
            const projectedColumn = projectedColumnByBackendColumn.get(
                term.columnIndex,
            );
            if (projectedColumn === undefined) {
                throw new Error('Projection column lookup is incomplete.');
            }
            row[projectedColumn][0] = polynomialCoefficient({
                coefficient: decimalBigInt(
                    term.coefficient,
                    'linear term coefficient',
                ),
                coefficientModulus,
            });
        }

        return row;
    });
    const targetVectorCoefficients = explicitRows.map((fieldRow) =>
        constantPolynomial({
            coefficient: -decimalBigInt(fieldRow.target, 'linear row target'),
            coefficientModulus,
            sourceRingDegree: input.sourceRingDegree,
        }),
    );
    const privateWitnessVectorCoefficients = sourceBackendColumnIndices.map(
        (backendColumnIndex) => {
            const variableColumn =
                variableColumnByBackendColumn.get(backendColumnIndex);
            if (variableColumn === undefined) {
                throw new Error('Projection variable lookup is incomplete.');
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
                sourceRingDegree: input.sourceRingDegree,
            });
        },
    );

    assertProjectionSatisfiesRows({
        coefficientModulus,
        componentId: input.componentId,
        matrix: statementMatrixCoefficients,
        targetVector: targetVectorCoefficients,
        witnessVector: privateWitnessVectorCoefficients,
    });

    const statementMatrixHash = deriveStatementMatrixHash(
        statementMatrixCoefficients,
    );
    const targetVectorHash = deriveTargetVectorHash(targetVectorCoefficients);
    const statementPayload: Omit<
        BallotProofLinearProofStatement,
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
        objectType: 'BallotProofLinearProofStatement',
        objectVersion: 1,
        parameterProfileId: input.parameterProfileId,
        projectionCoverage: projectionCoverageForComponent(input.componentId),
        relation: linearProofRelation,
        relationStatementHash: input.loweredStatement.relationStatementHash,
        ringDegree: input.sourceRingDegree,
        statementColumns: sourceBackendColumnIndices.length,
        statementMatrixCoefficients,
        statementMatrixHash,
        statementRows: explicitRows.length,
        matrixCoefficientRepresentation: 'centeredSignedSourceModulus',
        targetCoefficientRepresentation: 'centeredSignedSourceModulus',
        targetVectorCoefficients,
        targetVectorHash,
        witnessL2BoundSquared: input.witnessL2BoundSquared,
    };

    return {
        componentId: input.componentId,
        linearStatement: {
            ...statementPayload,
            statementHash: deriveLinearStatementHash(statementPayload),
        },
        privateWitnessVectorCoefficients,
        sourceBackendColumnIndices,
        sourceRowBatchNames: rowBatches.map((rowBatch) => rowBatch.batchName),
    };
};

const buildStructuredShareCommitmentSparseStatement = (input: {
    readonly ballotProofStatementHash?: ProtocolHash;
    readonly component: BallotPrivacyBackendProofComponent;
    readonly loweredStatement: BallotPrivacyLoweredLinearRelationStatement;
    readonly parameterProfileId: string;
    readonly sourceRingDegree: number;
    readonly witnessL2BoundSquared: string;
}): BallotProofStructuredShareCommitmentProofStatement => {
    if (
        input.sourceRingDegree !== shareCommitmentModuleDegree &&
        input.sourceRingDegree !== 64
    ) {
        throw new Error(
            'Structured share-commitment proof statements must use the share-commitment module degree or its proof-ring split degree.',
        );
    }
    const structuredRowBatch = structuredShareCommitmentRowBatchByName(
        input.loweredStatement,
        'share_commitment_equation_rows',
    );
    const coefficientModulus = decimalBigInt(
        input.component.coefficientModulus,
        'share-commitment component coefficient modulus',
    );
    const sourceBackendColumnIndices = input.component.variableColumnIndices;
    const commitmentsByReceiver = new Map(
        input.loweredStatement.publicContext.shareCommitments.map(
            (shareCommitment) => [
                receiverReferenceKey(shareCommitment),
                shareCommitment,
            ],
        ),
    );
    const receiverRows = structuredRowBatch.shareCommitmentRows.map(
        (
            shareCommitmentRow,
            receiverIndex,
        ): StructuredShareCommitmentReceiverStatement => {
            const shareCommitment = commitmentsByReceiver.get(
                receiverReferenceKey(shareCommitmentRow),
            );
            if (shareCommitment?.commitmentPolynomialVector === undefined) {
                throw new Error(
                    'Structured share-commitment proof statement requires explicit commitment polynomial vectors.',
                );
            }
            if (
                shareCommitment.commitmentPolynomialVector.length !==
                shareCommitmentModuleRank
            ) {
                throw new Error(
                    'Structured share-commitment proof statement received a malformed commitment polynomial vector.',
                );
            }
            const rowSplitFactor =
                shareCommitmentModuleDegree / input.sourceRingDegree;
            const rowCount = shareCommitmentRow.rowCount * rowSplitFactor;

            return {
                commitmentPolynomialVector:
                    shareCommitment.commitmentPolynomialVector,
                receiverIdentity: shareCommitmentRow.receiverIdentity,
                receiverRosterPosition:
                    shareCommitmentRow.receiverRosterPosition,
                rowCount,
                rowOffsetWithinStatement: receiverIndex * rowCount,
            };
        },
    );
    if (
        sourceBackendColumnIndices.length !==
        receiverRows.length * (input.loweredStatement.shareVectorWidth + 64)
    ) {
        throw new Error(
            'Structured share-commitment proof statement source columns do not match the encoded share and opening layout.',
        );
    }
    if (coefficientModulus <= 0n) {
        throw new Error(
            'Structured share-commitment proof statement modulus is invalid.',
        );
    }
    const statementPayload: Omit<
        BallotProofStructuredShareCommitmentProofStatement,
        'statementHash'
    > = {
        backendStatementHash:
            input.loweredStatement.backendStatement.backendStatementHash,
        ...(input.ballotProofStatementHash === undefined
            ? {}
            : {
                  ballotProofStatementHash: input.ballotProofStatementHash,
              }),
        coefficientModulus: input.component.coefficientModulus,
        componentId: 'share-commitment-component',
        matrixHash: structuredRowBatch.matrixHash,
        objectType: 'BallotProofStructuredShareCommitmentProofStatement',
        objectVersion: 1,
        parameterProfileId: input.parameterProfileId,
        proofStatementFormat: 'structured-module-sis-share-commitment-v1',
        proofSystemRingDegree: 64,
        projectionCoverage: 'share-commitment-rows-only',
        receiverRows,
        relation: linearProofRelation,
        relationStatementHash: input.loweredStatement.relationStatementHash,
        shareCommitmentProfileHash:
            input.loweredStatement.publicContext.shareCommitmentProfileHash,
        shareVectorWidth: input.loweredStatement.shareVectorWidth,
        sourceBackendColumnIndices,
        sourceRingDegree: input.sourceRingDegree,
        statementColumns: sourceBackendColumnIndices.length,
        statementRows: receiverRows.reduce(
            (rowCount, receiverRow) => rowCount + receiverRow.rowCount,
            0,
        ),
        matrixCoefficientRepresentation: 'centeredSignedSourceModulus',
        targetCoefficientRepresentation: 'centeredSignedSourceModulus',
        targetVectorHash: structuredRowBatch.targetVectorHash,
        witnessL2BoundSquared: input.witnessL2BoundSquared,
    };

    return {
        ...statementPayload,
        statementHash:
            deriveStructuredShareCommitmentStatementHash(statementPayload),
    };
};

const secretStateForStructuredShareCommitmentStatement = (input: {
    readonly projectionWitness?: BallotProofComponentProjectionWitness;
    readonly relationInput: BallotPrivacyRelationCompilerInput;
    readonly structuredStatement: BallotProofStructuredShareCommitmentProofStatement;
}): BallotProofRecordGenerationSecretState => {
    const sourceWitnessCoefficients: DensePolynomial[] = [];
    for (const receiverRow of input.structuredStatement.receiverRows) {
        const receiver = input.relationInput.receivers.find(
            (candidate) =>
                candidate.receiverRosterPosition ===
                receiverRow.receiverRosterPosition,
        );
        if (receiver === undefined) {
            throw new Error(
                'Structured share-commitment receiver witness is missing.',
            );
        }
        for (const shareRepresentative of receiver.receiverShareVector) {
            sourceWitnessCoefficients.push(
                signedConstantPolynomial({
                    coefficient: BigInt(shareRepresentative),
                    sourceRingDegree:
                        input.structuredStatement.sourceRingDegree,
                }),
            );
        }
        for (
            let openingCoordinateIndex = 0;
            openingCoordinateIndex < 64;
            openingCoordinateIndex += 1
        ) {
            sourceWitnessCoefficients.push(
                signedConstantPolynomial({
                    coefficient: shareCommitmentOpeningValue(
                        input.projectionWitness,
                        receiverRow.receiverRosterPosition,
                        openingCoordinateIndex,
                    ),
                    sourceRingDegree:
                        input.structuredStatement.sourceRingDegree,
                }),
            );
        }
    }
    if (
        sourceWitnessCoefficients.length !==
        input.structuredStatement.statementColumns
    ) {
        throw new Error(
            'Structured share-commitment witness did not fill every statement column.',
        );
    }

    return {
        sourceWitnessCoefficients,
    };
};

export {
    verifyStructuredReceiverEncryptionRowBatch,
    buildStructuredShareCommitmentSparseStatement,
    secretStateForStructuredShareCommitmentStatement,
};
