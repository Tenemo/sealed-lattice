import { deriveProtocolDigest } from '@sealed-lattice/crypto';
import type { ProtocolDigest } from '@sealed-lattice/types';

import {
    type BallotPrivacyBackendProofComponent,
    type BallotPrivacyBackendProofComponentId,
    type BallotPrivacyLoweredLinearRelationStatement,
} from '../relation-backend-lowering.js';
import type { BallotPrivacyRelationCompilerInput } from '../relation-compiler.js';

import type {
    BackendRowBatchForComponentStatement,
    BallotProofComponentBundleStatement,
    BallotProofComponentProjectionWitness,
    BallotProofComponentProofBundlePayload,
    BallotProofComponentProofBytesAvailability,
    BallotProofComponentProofRecordPayload,
    BallotProofComponentProofStatementFormat,
    BallotProofComponentProofStatementPlan,
    BallotProofComponentStatement,
    BallotProofLinearProofStatement,
    BallotProofSparseComponentLinearProofStatement,
    BallotProofStructuredReceiverEncryptionProofStatement,
    BallotProofStructuredShareCommitmentProofStatement,
    DensePolynomialMatrix,
    DensePolynomialVector,
    FieldVariableColumn,
    SparseMatrixEntry,
    SparseTargetVectorEntry,
    StructuredShareCommitmentRowBatch,
} from './statement-contracts.js';
import {
    receiverEncryptionModuleDegree,
    receiverEncryptionModuleRank,
} from './statement-contracts.js';
import {
    quotientValue,
    receiverEncryptionChunkWitness,
    receiverEncryptionPolynomialCoefficient,
    receiverEncryptionVectorCoefficient,
    receiverPayloadPlaintextBitValue,
    receiverPayloadPlaintextOpeningValue,
    receiverPayloadPlaintextShareValue,
    receiverShareValue,
    shareCommitmentOpeningValue,
} from './witness-accessors.js';

const witnessValueForVariable = (
    relationInput: BallotPrivacyRelationCompilerInput,
    projectionWitness: BallotProofComponentProjectionWitness | undefined,
    variableColumn: FieldVariableColumn,
): bigint => {
    switch (variableColumn.variableRole) {
        case 'ScalarScoreConstant':
            if (variableColumn.optionIndex === undefined) {
                throw new Error(
                    'Scalar score variable is missing its option index.',
                );
            }

            return BigInt(
                relationInput.normalizedScores[variableColumn.optionIndex] ?? 0,
            );
        case 'ScoreBucketConstant':
            if (
                variableColumn.optionIndex === undefined ||
                variableColumn.scoreBucketValue === undefined
            ) {
                throw new Error(
                    'Score bucket variable is missing its indexes.',
                );
            }

            return BigInt(
                relationInput.scoreOneHotWitnesses[
                    variableColumn.optionIndex
                ]?.[variableColumn.scoreBucketValue - 1] ?? 0,
            );
        case 'ShamirCoefficient':
            if (
                variableColumn.encodedCoordinateIndex === undefined ||
                variableColumn.coefficientDegree === undefined
            ) {
                throw new Error(
                    'Shamir coefficient variable is missing its indexes.',
                );
            }

            return BigInt(
                relationInput.encodedCoordinateShamirCoefficients[
                    variableColumn.encodedCoordinateIndex
                ]?.[variableColumn.coefficientDegree - 1] ?? 0,
            );
        case 'ReceiverShare':
            if (
                variableColumn.receiverRosterPosition === undefined ||
                variableColumn.encodedCoordinateIndex === undefined
            ) {
                throw new Error(
                    'Receiver share variable is missing its indexes.',
                );
            }

            return BigInt(
                receiverShareValue(
                    relationInput,
                    variableColumn.receiverRosterPosition,
                    variableColumn.encodedCoordinateIndex,
                ),
            );
        case 'ShamirQuotient':
            if (
                variableColumn.receiverRosterPosition === undefined ||
                variableColumn.encodedCoordinateIndex === undefined
            ) {
                throw new Error(
                    'Shamir quotient variable is missing its indexes.',
                );
            }

            return BigInt(
                quotientValue(
                    relationInput,
                    variableColumn.receiverRosterPosition,
                    variableColumn.encodedCoordinateIndex,
                ),
            );
        case 'ReceiverPayloadPlaintextShare':
            if (
                variableColumn.receiverRosterPosition === undefined ||
                variableColumn.encodedCoordinateIndex === undefined
            ) {
                throw new Error(
                    'Receiver payload plaintext share variable is missing its indexes.',
                );
            }

            return receiverPayloadPlaintextShareValue(
                relationInput,
                projectionWitness,
                variableColumn.receiverRosterPosition,
                variableColumn.encodedCoordinateIndex,
            );
        case 'ReceiverPayloadPlaintextOpening':
            if (
                variableColumn.receiverRosterPosition === undefined ||
                variableColumn.openingCoordinateIndex === undefined
            ) {
                throw new Error(
                    'Opening variable is missing its receiver or coordinate index.',
                );
            }

            return receiverPayloadPlaintextOpeningValue(
                projectionWitness,
                variableColumn.receiverRosterPosition,
                variableColumn.openingCoordinateIndex,
            );
        case 'ReceiverPayloadPlaintextBit':
            return receiverPayloadPlaintextBitValue(
                relationInput,
                projectionWitness,
                variableColumn,
            );
        case 'ShareCommitmentOpening':
            if (
                variableColumn.receiverRosterPosition === undefined ||
                variableColumn.openingCoordinateIndex === undefined
            ) {
                throw new Error(
                    'Opening variable is missing its receiver or coordinate index.',
                );
            }

            return shareCommitmentOpeningValue(
                projectionWitness,
                variableColumn.receiverRosterPosition,
                variableColumn.openingCoordinateIndex,
            );
        case 'ReceiverEncryptionRandomness':
            if (
                variableColumn.receiverRosterPosition === undefined ||
                variableColumn.chunkIndex === undefined ||
                variableColumn.ciphertextVectorIndex === undefined ||
                variableColumn.polynomialCoefficientIndex === undefined
            ) {
                throw new Error(
                    'Receiver encryption randomness variable is missing its indexes.',
                );
            }

            return receiverEncryptionVectorCoefficient({
                coefficientIndex: variableColumn.polynomialCoefficientIndex,
                vector: receiverEncryptionChunkWitness(
                    projectionWitness,
                    variableColumn.receiverRosterPosition,
                    variableColumn.chunkIndex,
                ).encryptionRandomnessVector,
                vectorIndex: variableColumn.ciphertextVectorIndex,
            });
        case 'ReceiverEncryptionFirstNoise':
            if (
                variableColumn.receiverRosterPosition === undefined ||
                variableColumn.chunkIndex === undefined ||
                variableColumn.ciphertextVectorIndex === undefined ||
                variableColumn.polynomialCoefficientIndex === undefined
            ) {
                throw new Error(
                    'Receiver encryption first-noise variable is missing its indexes.',
                );
            }

            return receiverEncryptionVectorCoefficient({
                coefficientIndex: variableColumn.polynomialCoefficientIndex,
                vector: receiverEncryptionChunkWitness(
                    projectionWitness,
                    variableColumn.receiverRosterPosition,
                    variableColumn.chunkIndex,
                ).firstNoiseVector,
                vectorIndex: variableColumn.ciphertextVectorIndex,
            });
        case 'ReceiverEncryptionSecondNoise':
            if (
                variableColumn.receiverRosterPosition === undefined ||
                variableColumn.chunkIndex === undefined ||
                variableColumn.polynomialCoefficientIndex === undefined
            ) {
                throw new Error(
                    'Receiver encryption second-noise variable is missing its indexes.',
                );
            }

            return receiverEncryptionPolynomialCoefficient({
                coefficientIndex: variableColumn.polynomialCoefficientIndex,
                polynomial: receiverEncryptionChunkWitness(
                    projectionWitness,
                    variableColumn.receiverRosterPosition,
                    variableColumn.chunkIndex,
                ).secondNoisePolynomial,
            });
        default:
            return 0n;
    }
};

const deriveLinearStatementDigest = (
    statementPayload: Omit<BallotProofLinearProofStatement, 'statementDigest'>,
): ProtocolDigest =>
    deriveProtocolDigest('ChallengeDomainDigest', {
        payload: statementPayload,
        purpose: 'ballot-proof-linear-proof-statement-v1',
    });

const deriveSparseLinearStatementDigest = (
    statementPayload: Omit<
        BallotProofSparseComponentLinearProofStatement,
        'statementDigest'
    >,
): ProtocolDigest =>
    deriveProtocolDigest('ChallengeDomainDigest', {
        payload: statementPayload,
        purpose: 'ballot-proof-sparse-linear-proof-statement-v1',
    });

const deriveStructuredReceiverEncryptionStatementDigest = (
    statementPayload: Omit<
        BallotProofStructuredReceiverEncryptionProofStatement,
        'statementDigest'
    >,
): ProtocolDigest =>
    deriveProtocolDigest('ChallengeDomainDigest', {
        payload: statementPayload,
        purpose:
            'ballot-proof-structured-receiver-encryption-proof-statement-v1',
    });

const deriveStructuredShareCommitmentStatementDigest = (
    statementPayload: Omit<
        BallotProofStructuredShareCommitmentProofStatement,
        'statementDigest'
    >,
): ProtocolDigest =>
    deriveProtocolDigest('ChallengeDomainDigest', {
        payload: statementPayload,
        purpose: 'ballot-proof-structured-share-commitment-proof-statement-v1',
    });

const deriveComponentStatementDigest = (
    statementPayload: Omit<
        BallotProofComponentStatement,
        'componentStatementDigest'
    >,
): ProtocolDigest =>
    deriveProtocolDigest('ChallengeDomainDigest', {
        payload: statementPayload,
        purpose: 'ballot-proof-component-statement-v1',
    });

const deriveComponentBundleStatementDigest = (
    statementPayload: Omit<
        BallotProofComponentBundleStatement,
        'componentBundleStatementDigest'
    >,
): ProtocolDigest =>
    deriveProtocolDigest('ChallengeDomainDigest', {
        payload: statementPayload,
        purpose: 'ballot-proof-component-bundle-statement-v1',
    });

const deriveComponentProofRecordDigest = (
    proofRecordPayload: BallotProofComponentProofRecordPayload,
): ProtocolDigest =>
    deriveProtocolDigest('ChallengeDomainDigest', {
        payload: proofRecordPayload,
        purpose: 'ballot-proof-component-proof-record-v1',
    });

const deriveComponentProofBundleDigest = (
    proofBundlePayload: BallotProofComponentProofBundlePayload,
): ProtocolDigest =>
    deriveProtocolDigest('ChallengeDomainDigest', {
        payload: proofBundlePayload,
        purpose: 'ballot-proof-component-proof-bundle-v1',
    });

const deriveStatementMatrixDigest = (
    statementMatrixCoefficients: DensePolynomialMatrix,
): ProtocolDigest =>
    deriveProtocolDigest('ChallengeDomainDigest', {
        purpose: 'ballot-proof-linear-statement-matrix-v1',
        statementMatrixCoefficients,
    });

const deriveSparseStatementMatrixDigest = (
    sparseStatementMatrixEntries: readonly SparseMatrixEntry[],
): ProtocolDigest =>
    deriveProtocolDigest('ChallengeDomainDigest', {
        purpose: 'ballot-proof-sparse-linear-statement-matrix-v1',
        sparseStatementMatrixEntries,
    });

const deriveTargetVectorDigest = (
    targetVectorCoefficients: DensePolynomialVector,
): ProtocolDigest =>
    deriveProtocolDigest('ChallengeDomainDigest', {
        purpose: 'ballot-proof-linear-target-vector-v1',
        targetVectorCoefficients,
    });

const deriveSparseTargetVectorDigest = (
    targetVectorEntries: readonly SparseTargetVectorEntry[],
): ProtocolDigest =>
    deriveProtocolDigest('ChallengeDomainDigest', {
        purpose: 'ballot-proof-sparse-linear-target-vector-v1',
        targetVectorEntries,
    });

const deriveComponentMatrixDigest = (input: {
    readonly componentId: BallotPrivacyBackendProofComponentId;
    readonly rowBatchMatrixDigests: readonly ProtocolDigest[];
}): ProtocolDigest =>
    deriveProtocolDigest('ChallengeDomainDigest', {
        componentId: input.componentId,
        purpose: 'ballot-proof-component-matrix-v1',
        rowBatchMatrixDigests: input.rowBatchMatrixDigests,
    });

const deriveComponentTargetVectorDigest = (input: {
    readonly componentId: BallotPrivacyBackendProofComponentId;
    readonly rowBatchTargetVectorDigests: readonly ProtocolDigest[];
}): ProtocolDigest =>
    deriveProtocolDigest('ChallengeDomainDigest', {
        componentId: input.componentId,
        purpose: 'ballot-proof-component-target-vector-v1',
        rowBatchTargetVectorDigests: input.rowBatchTargetVectorDigests,
    });

const deriveComponentProofStatementDigest = (
    statementPayload: Omit<
        BallotProofComponentProofStatementPlan,
        'componentProofStatementDigest'
    >,
): ProtocolDigest =>
    deriveProtocolDigest('ChallengeDomainDigest', {
        payload: statementPayload,
        purpose: 'ballot-proof-component-proof-statement-plan-v1',
    });

const rowBatchesForComponent = (input: {
    readonly component: BallotPrivacyBackendProofComponent;
    readonly loweredStatement: BallotPrivacyLoweredLinearRelationStatement;
}): readonly BackendRowBatchForComponentStatement[] => {
    const rowBatchByName = new Map(
        input.loweredStatement.backendStatement.rowBatches.map((rowBatch) => [
            rowBatch.batchName,
            rowBatch,
        ]),
    );

    return input.component.rowBatchNames.map((rowBatchName) => {
        const rowBatch = rowBatchByName.get(rowBatchName);
        if (rowBatch === undefined) {
            throw new Error(
                `Proof component ${input.component.componentId} references missing row batch ${rowBatchName}.`,
            );
        }

        return rowBatch;
    });
};

const sourceRingDegreeForComponentProofStatement = (
    componentId: BallotPrivacyBackendProofComponentId,
): number | null => {
    switch (componentId) {
        case 'score-and-shamir-field-component':
        case 'payload-plaintext-field-component':
            return 64;
        case 'share-commitment-component':
        case 'receiver-encryption-component':
            return 256;
        case 'receiver-key-binding-component':
            return null;
    }
};

const proofSystemRingDegreeForComponentProofStatement = (
    componentId: BallotPrivacyBackendProofComponentId,
): number | null =>
    componentId === 'receiver-key-binding-component' ? null : 64;

const proofStatementFormatForComponent = (input: {
    readonly component: BallotPrivacyBackendProofComponent;
    readonly rowBatches: readonly BackendRowBatchForComponentStatement[];
}): BallotProofComponentProofStatementFormat => {
    if (
        input.component.componentId === 'receiver-key-binding-component' &&
        input.component.variableColumnCount === 0
    ) {
        return 'public-zero-witness-binding-check-v1';
    }
    if (
        input.rowBatches.some(
            (rowBatch) =>
                rowBatch.batchKind ===
                'StructuredModuleLweReceiverEncryptionRows',
        )
    ) {
        return 'structured-module-lwe-linear-proof-v1';
    }
    if (
        input.rowBatches.some(
            (rowBatch) =>
                rowBatch.batchKind === 'StructuredModuleSisShareCommitmentRows',
        )
    ) {
        return 'structured-module-sis-share-commitment-v1';
    }
    if (
        input.component.rowBatchNames.length === 1 &&
        input.component.rowBatchNames[0] === 'encoded_score_field_rows' &&
        input.component.rowCount <= 100
    ) {
        return 'dense-polynomial-matrix-linear-proof-v1';
    }

    return 'sparse-polynomial-matrix-linear-proof-v1';
};

const proofBytesAvailabilityForStatementFormat = (
    proofStatementFormat: BallotProofComponentProofStatementFormat,
): BallotProofComponentProofBytesAvailability => {
    switch (proofStatementFormat) {
        case 'dense-polynomial-matrix-linear-proof-v1':
            return 'available-for-small-dense-oracle';
        case 'sparse-polynomial-matrix-linear-proof-v1':
        case 'structured-module-sis-share-commitment-v1':
            return 'requires-sparse-proof-statement';
        case 'structured-module-lwe-linear-proof-v1':
            return 'requires-structured-proof-statement';
        case 'public-zero-witness-binding-check-v1':
            return 'public-zero-witness-binding-check';
    }
};

const explicitRowBatchTermCount = (
    rowBatch: Extract<
        BackendRowBatchForComponentStatement,
        { readonly batchKind: 'ExplicitSparseRows' }
    >,
): bigint =>
    rowBatch.rows.reduce(
        (termCount, row) => termCount + BigInt(row.terms.length),
        0n,
    );

const structuredReceiverEncryptionWitnessTermCounts = (
    rowBatch: Extract<
        BackendRowBatchForComponentStatement,
        { readonly batchKind: 'StructuredModuleLweReceiverEncryptionRows' }
    >,
): {
    readonly ciphertextChunkCount: number;
    readonly receiverCount: number;
    readonly witnessTermCount: bigint;
} => {
    let ciphertextChunkCount = 0;
    let witnessTermCount = 0n;
    for (const receiverRows of rowBatch.receiverRows) {
        ciphertextChunkCount += receiverRows.ciphertextChunkCount;
        const randomnessTermsPerPolynomialRow =
            receiverEncryptionModuleRank * receiverEncryptionModuleDegree;
        const firstCiphertextRowsPerChunk =
            receiverEncryptionModuleRank * receiverEncryptionModuleDegree;
        const firstCiphertextTermsPerChunk =
            firstCiphertextRowsPerChunk * (randomnessTermsPerPolynomialRow + 1);
        let secondCiphertextTermsForReceiver = 0;
        for (
            let chunkIndex = 0;
            chunkIndex < receiverRows.ciphertextChunkCount;
            chunkIndex += 1
        ) {
            const plaintextTermsForChunk = Math.min(
                receiverEncryptionModuleDegree,
                Math.max(
                    receiverRows.plaintextBitLength -
                        chunkIndex * receiverEncryptionModuleDegree,
                    0,
                ),
            );
            secondCiphertextTermsForReceiver +=
                receiverEncryptionModuleDegree *
                    (randomnessTermsPerPolynomialRow + 1) +
                plaintextTermsForChunk;
        }
        witnessTermCount +=
            BigInt(receiverRows.ciphertextChunkCount) *
                BigInt(firstCiphertextTermsPerChunk) +
            BigInt(secondCiphertextTermsForReceiver);
    }

    return {
        ciphertextChunkCount,
        receiverCount: rowBatch.receiverRows.length,
        witnessTermCount,
    };
};

const structuredShareCommitmentSparseTermCount = (
    rowBatch: StructuredShareCommitmentRowBatch,
): bigint => {
    if (rowBatch.shareCommitmentRows.length === 0) {
        return 0n;
    }
    if (
        rowBatch.variableColumnIndices.length %
            rowBatch.shareCommitmentRows.length !==
        0
    ) {
        throw new Error(
            'Structured share-commitment row batch variables are not balanced by receiver.',
        );
    }
    const variableCountPerReceiver =
        rowBatch.variableColumnIndices.length /
        rowBatch.shareCommitmentRows.length;

    return rowBatch.shareCommitmentRows.reduce(
        (termCount, shareCommitmentRow) =>
            termCount +
            BigInt(shareCommitmentRow.rowCount) *
                BigInt(variableCountPerReceiver),
        0n,
    );
};

const rowBatchTermCount = (
    rowBatch: BackendRowBatchForComponentStatement,
): bigint => {
    if (rowBatch.batchKind === 'ExplicitSparseRows') {
        return explicitRowBatchTermCount(rowBatch);
    }
    if (rowBatch.batchKind === 'StructuredModuleSisShareCommitmentRows') {
        return structuredShareCommitmentSparseTermCount(
            rowBatch as StructuredShareCommitmentRowBatch,
        );
    }
    if (rowBatch.batchKind === 'StructuredModuleLweReceiverEncryptionRows') {
        return structuredReceiverEncryptionWitnessTermCounts(rowBatch)
            .witnessTermCount;
    }

    return 0n;
};

const denseCoefficientCountForComponentProofStatement = (input: {
    readonly rowCount: number;
    readonly sourceRingDegree: number | null;
    readonly variableColumnCount: number;
}): string | null => {
    if (input.sourceRingDegree === null || input.variableColumnCount === 0) {
        return null;
    }

    return (
        BigInt(input.rowCount) *
        BigInt(input.variableColumnCount) *
        BigInt(input.sourceRingDegree)
    ).toString();
};

const buildComponentStatement = (input: {
    readonly ballotProofStatementDigest?: ProtocolDigest;
    readonly component: BallotPrivacyBackendProofComponent;
    readonly loweredStatement: BallotPrivacyLoweredLinearRelationStatement;
}): BallotProofComponentStatement => {
    const componentRowBatches = rowBatchesForComponent(input);
    const rowBatchMatrixDigests = componentRowBatches.map(
        (rowBatch) => rowBatch.matrixDigest,
    );
    const rowBatchTargetVectorDigests = componentRowBatches.map(
        (rowBatch) => rowBatch.targetVectorDigest,
    );
    const matrixDigest = deriveComponentMatrixDigest({
        componentId: input.component.componentId,
        rowBatchMatrixDigests,
    });
    const targetVectorDigest = deriveComponentTargetVectorDigest({
        componentId: input.component.componentId,
        rowBatchTargetVectorDigests,
    });
    const statementPayload: Omit<
        BallotProofComponentStatement,
        'componentStatementDigest'
    > = {
        backendStatementDigest:
            input.loweredStatement.backendStatement.backendStatementDigest,
        ...(input.ballotProofStatementDigest === undefined
            ? {}
            : {
                  ballotProofStatementDigest: input.ballotProofStatementDigest,
              }),
        coefficientModulus: input.component.coefficientModulus,
        componentDigest: input.component.componentDigest,
        componentId: input.component.componentId,
        matrixDigest,
        objectType: 'BallotProofComponentStatement',
        objectVersion: 1,
        proofLoweringStatus: input.component.proofLoweringStatus,
        relationStatementDigest: input.loweredStatement.relationStatementDigest,
        rowBatchMatrixDigests,
        rowBatchNames: input.component.rowBatchNames,
        rowBatchTargetVectorDigests,
        rowCount: input.component.rowCount,
        rowKinds: input.component.rowKinds,
        targetVectorDigest,
        variableColumnCount: input.component.variableColumnCount,
        variableColumnIndices: input.component.variableColumnIndices,
    };

    return {
        ...statementPayload,
        componentStatementDigest:
            deriveComponentStatementDigest(statementPayload),
    };
};

export {
    witnessValueForVariable,
    deriveLinearStatementDigest,
    deriveSparseLinearStatementDigest,
    deriveStructuredReceiverEncryptionStatementDigest,
    deriveStructuredShareCommitmentStatementDigest,
    deriveComponentBundleStatementDigest,
    deriveComponentProofRecordDigest,
    deriveComponentProofBundleDigest,
    deriveStatementMatrixDigest,
    deriveSparseStatementMatrixDigest,
    deriveTargetVectorDigest,
    deriveSparseTargetVectorDigest,
    deriveComponentProofStatementDigest,
    rowBatchesForComponent,
    sourceRingDegreeForComponentProofStatement,
    proofSystemRingDegreeForComponentProofStatement,
    proofStatementFormatForComponent,
    proofBytesAvailabilityForStatementFormat,
    structuredReceiverEncryptionWitnessTermCounts,
    rowBatchTermCount,
    denseCoefficientCountForComponentProofStatement,
    buildComponentStatement,
};
