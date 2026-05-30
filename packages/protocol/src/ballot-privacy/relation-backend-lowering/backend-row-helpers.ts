import { deriveProtocolHash } from '@sealed-lattice/crypto';
import type { ProtocolHash } from '@sealed-lattice/types';

import {
    deriveShareCommitmentMessageMatrix,
    deriveShareCommitmentRandomnessMatrix,
} from '../lattice-primitives.js';
import { fieldModulus } from '../plaintext-oracle-helpers.js';

import type {
    BallotPrivacyAlgebraicRelationRow,
    BallotPrivacyBackendStatementExplicitRow,
    BallotPrivacyBackendStatementRowBatch,
    BallotPrivacyBackendStatementTerm,
    BallotPrivacyBackendStatementVariableColumn,
    BallotPrivacyLinearRelationRow,
    BallotPrivacyLinearRelationVariable,
    ReceiverPayloadCiphertextChunkReference,
    ReceiverReference,
} from './backend-contracts.js';
import {
    explicitBackendMatrixHashPurpose,
    explicitBackendTargetVectorHashPurpose,
    receiverEncryptionFirstNoisePolynomialVariableName,
    receiverEncryptionModuleDegree,
    receiverEncryptionModuleRank,
    receiverEncryptionModulus,
    receiverEncryptionRandomnessPolynomialVariableName,
    receiverEncryptionSecondNoisePolynomialVariableName,
    receiverPayloadPlaintextPolynomialVariableName,
    receiverShareVariableName,
    shareCommitmentModuleDegree,
    shareCommitmentModuleRank,
    shareCommitmentModulus,
    shareCommitmentOpeningDimension,
    shareCommitmentOpeningVariableName,
} from './backend-contracts.js';
import { receiverReferenceKey } from './relation-row-builders.js';

const referencesByReceiver = <Reference extends ReceiverReference>(
    references: readonly Reference[],
): ReadonlyMap<string, Reference> =>
    new Map(
        references.map((reference) => [
            receiverReferenceKey(reference),
            reference,
        ]),
    );

const deriveAlgebraicTargetHash = (
    purpose: string,
    payload: unknown,
): ProtocolHash =>
    deriveProtocolHash('ChallengeDomainHash', {
        payload,
        purpose,
    });

const decimalString = (value: bigint | number | string): string =>
    String(value);

const shareCommitmentBigIntModulus = BigInt(shareCommitmentModulus);

// Forces a canonical non-negative Goldilocks representative ((v % q) + q) % q,
// since v may be negative after the X^256 = -1 wraparound negation below.
const canonicalShareCommitmentCoefficient = (value: bigint): string => {
    const reducedValue =
        ((value % shareCommitmentBigIntModulus) +
            shareCommitmentBigIntModulus) %
        shareCommitmentBigIntModulus;

    return reducedValue.toString();
};

const parseShareCommitmentPolynomialVector = (input: {
    readonly commitmentPolynomialVector: readonly (readonly string[])[];
    readonly receiverRosterPosition: number;
}): readonly (readonly bigint[])[] => {
    if (input.commitmentPolynomialVector.length !== shareCommitmentModuleRank) {
        throw new RangeError(
            `Receiver ${input.receiverRosterPosition} share commitment vector does not use the frozen module rank.`,
        );
    }

    return input.commitmentPolynomialVector.map(
        (commitmentPolynomial, vectorIndex) => {
            if (commitmentPolynomial.length !== shareCommitmentModuleDegree) {
                throw new RangeError(
                    `Receiver ${input.receiverRosterPosition} share commitment polynomial ${vectorIndex} does not use the frozen module degree.`,
                );
            }

            return commitmentPolynomial.map((coefficient, coefficientIndex) => {
                if (!/^(?:0|[1-9][0-9]*)$/u.test(coefficient)) {
                    throw new RangeError(
                        `Receiver ${input.receiverRosterPosition} share commitment coefficient ${vectorIndex}:${coefficientIndex} is not a canonical decimal integer.`,
                    );
                }
                const parsedCoefficient = BigInt(coefficient);
                if (parsedCoefficient >= shareCommitmentBigIntModulus) {
                    throw new RangeError(
                        `Receiver ${input.receiverRosterPosition} share commitment coefficient ${vectorIndex}:${coefficientIndex} is outside the commitment modulus.`,
                    );
                }

                return parsedCoefficient;
            });
        },
    );
};

const deriveBackendHash = (purpose: string, payload: unknown): ProtocolHash =>
    deriveProtocolHash('ChallengeDomainHash', {
        payload,
        purpose,
    });

const createVariableColumnLookup = (
    variables: readonly BallotPrivacyLinearRelationVariable[],
): ReadonlyMap<string, number> =>
    new Map(
        variables.map((variable, columnIndex) => [
            variable.variableName,
            columnIndex,
        ]),
    );

const requireColumnIndex = (
    columnLookup: ReadonlyMap<string, number>,
    variableName: string,
): number => {
    const columnIndex = columnLookup.get(variableName);
    if (columnIndex === undefined) {
        throw new RangeError(
            `Backend relation lowering is missing variable column ${variableName}.`,
        );
    }

    return columnIndex;
};

const backendVariableColumns = (
    variables: readonly BallotPrivacyLinearRelationVariable[],
): readonly BallotPrivacyBackendStatementVariableColumn[] =>
    variables.map((variable, columnIndex) => ({
        ...variable,
        columnIndex,
    }));

const compactReceiverEncryptionWitnessVariableColumns = (input: {
    readonly ciphertextChunkCount: number;
    readonly firstColumnIndex: number;
    readonly receiverRosterPosition: number;
}): readonly BallotPrivacyBackendStatementVariableColumn[] => {
    const columns: BallotPrivacyBackendStatementVariableColumn[] = [];
    let columnIndex = input.firstColumnIndex;

    for (
        let chunkIndex = 0;
        chunkIndex < input.ciphertextChunkCount;
        chunkIndex += 1
    ) {
        for (
            let vectorIndex = 0;
            vectorIndex < receiverEncryptionModuleRank;
            vectorIndex += 1
        ) {
            columns.push({
                chunkIndex,
                ciphertextVectorIndex: vectorIndex,
                columnIndex,
                receiverRosterPosition: input.receiverRosterPosition,
                variableName:
                    receiverEncryptionRandomnessPolynomialVariableName(
                        input.receiverRosterPosition,
                        chunkIndex,
                        vectorIndex,
                    ),
                variableRole: 'ReceiverEncryptionRandomnessPolynomial',
            });
            columnIndex += 1;
        }
        for (
            let vectorIndex = 0;
            vectorIndex < receiverEncryptionModuleRank;
            vectorIndex += 1
        ) {
            columns.push({
                chunkIndex,
                ciphertextVectorIndex: vectorIndex,
                columnIndex,
                receiverRosterPosition: input.receiverRosterPosition,
                variableName:
                    receiverEncryptionFirstNoisePolynomialVariableName(
                        input.receiverRosterPosition,
                        chunkIndex,
                        vectorIndex,
                    ),
                variableRole: 'ReceiverEncryptionFirstNoisePolynomial',
            });
            columnIndex += 1;
        }
        columns.push({
            chunkIndex,
            columnIndex,
            receiverRosterPosition: input.receiverRosterPosition,
            variableName: receiverEncryptionSecondNoisePolynomialVariableName(
                input.receiverRosterPosition,
                chunkIndex,
            ),
            variableRole: 'ReceiverEncryptionSecondNoisePolynomial',
        });
        columnIndex += 1;
        columns.push({
            chunkIndex,
            columnIndex,
            receiverRosterPosition: input.receiverRosterPosition,
            variableName: receiverPayloadPlaintextPolynomialVariableName(
                input.receiverRosterPosition,
                chunkIndex,
            ),
            variableRole: 'ReceiverPayloadPlaintextPolynomial',
        });
        columnIndex += 1;
    }

    return columns;
};

const backendTermsForLinearRow = (
    row: BallotPrivacyLinearRelationRow,
    columnLookup: ReadonlyMap<string, number>,
): readonly BallotPrivacyBackendStatementTerm[] =>
    row.terms.map((term) => ({
        coefficient: decimalString(term.coefficient),
        columnIndex: requireColumnIndex(columnLookup, term.variableName),
        variableName: term.variableName,
    }));

const buildExplicitSparseRowBatch = (input: {
    readonly batchName:
        | 'encoded_score_field_rows'
        | 'share_commitment_equation_rows'
        | 'receiver_payload_plaintext_binding_rows';
    readonly columnLookup: ReadonlyMap<string, number>;
    readonly rowKind:
        | 'EncodedScoreFieldRows'
        | 'ShareCommitmentEquationRows'
        | 'ReceiverPayloadPlaintextBindingRows';
    readonly rowOffset: number;
    readonly rows: readonly BallotPrivacyLinearRelationRow[];
}): BallotPrivacyBackendStatementRowBatch => {
    const rows = input.rows.map((row, rowIndex) => ({
        modulus: decimalString(row.modulus),
        rowIndex,
        rowKind: row.rowKind,
        rowName: row.rowName,
        target: decimalString(row.target),
        terms: backendTermsForLinearRow(row, input.columnLookup),
    }));
    const variableColumnIndices = [
        ...new Set(
            rows.flatMap((row) => row.terms.map((term) => term.columnIndex)),
        ),
    ].sort((leftColumn, rightColumn) => leftColumn - rightColumn);

    return {
        batchKind: 'ExplicitSparseRows',
        batchName: input.batchName,
        matrixHash: deriveBackendHash(explicitBackendMatrixHashPurpose, {
            rows: rows.map(({ rowIndex, rowKind, rowName, terms }) => ({
                rowIndex,
                rowKind,
                rowName,
                terms,
            })),
        }),
        modulus: decimalString(fieldModulus),
        rowCount: rows.length,
        rowKind: input.rowKind,
        rowOffset: input.rowOffset,
        rows,
        targetVectorHash: deriveBackendHash(
            explicitBackendTargetVectorHashPurpose,
            {
                targets: rows.map(({ rowIndex, rowKind, rowName, target }) => ({
                    rowIndex,
                    rowKind,
                    rowName,
                    target,
                })),
            },
        ),
        variableColumnIndices,
    };
};

// Expands a polynomial multiplication in Z_q[X]/(X^256+1) into a scalar coefficient
// matrix. A share at coordinate s contributes msg[out-s] to output coefficient `out`;
// when out < s the contributing term has wrapped past X^256, so the X^256 = -1 rule
// negates msg[degree+out-s].
const shareCommitmentMessageCoefficient = (input: {
    readonly messageMatrixPolynomial: readonly bigint[];
    readonly outputCoefficientIndex: number;
    readonly shareCoordinateIndex: number;
}): string => {
    if (input.outputCoefficientIndex >= input.shareCoordinateIndex) {
        return canonicalShareCommitmentCoefficient(
            input.messageMatrixPolynomial[
                input.outputCoefficientIndex - input.shareCoordinateIndex
            ] ?? 0n,
        );
    }

    return canonicalShareCommitmentCoefficient(
        -(
            input.messageMatrixPolynomial[
                shareCommitmentModuleDegree +
                    input.outputCoefficientIndex -
                    input.shareCoordinateIndex
            ] ?? 0n
        ),
    );
};

const shareCommitmentOpeningCoefficient = (input: {
    readonly randomnessMatrixPolynomial: readonly bigint[];
    readonly outputCoefficientIndex: number;
}): string =>
    canonicalShareCommitmentCoefficient(
        input.randomnessMatrixPolynomial[input.outputCoefficientIndex] ?? 0n,
    );

const validateReceiverPublicKeyVector = (input: {
    readonly publicKeyVector: readonly (readonly number[])[];
    readonly receiverRosterPosition: number;
}): void => {
    if (input.publicKeyVector.length !== receiverEncryptionModuleRank) {
        throw new RangeError(
            `Receiver ${input.receiverRosterPosition} public key vector does not use the frozen module rank.`,
        );
    }
    for (const [vectorIndex, polynomial] of input.publicKeyVector.entries()) {
        if (polynomial.length !== receiverEncryptionModuleDegree) {
            throw new RangeError(
                `Receiver ${input.receiverRosterPosition} public key polynomial ${vectorIndex} does not use the frozen module degree.`,
            );
        }
        for (const [coefficientIndex, coefficient] of polynomial.entries()) {
            if (
                !Number.isSafeInteger(coefficient) ||
                coefficient < 0 ||
                coefficient >= receiverEncryptionModulus
            ) {
                throw new RangeError(
                    `Receiver ${input.receiverRosterPosition} public key coefficient ${vectorIndex}:${coefficientIndex} is outside the receiver encryption modulus.`,
                );
            }
        }
    }
};

const validateReceiverPayloadCiphertextChunks = (input: {
    readonly ciphertextChunks: readonly ReceiverPayloadCiphertextChunkReference[];
    readonly receiverRosterPosition: number;
}): void => {
    input.ciphertextChunks.forEach((chunk, expectedChunkIndex) => {
        if (chunk.chunkIndex !== expectedChunkIndex) {
            throw new RangeError(
                `Receiver ${input.receiverRosterPosition} ciphertext chunks must be in canonical chunk order.`,
            );
        }
        if (
            chunk.firstCiphertextVector.length !== receiverEncryptionModuleRank
        ) {
            throw new RangeError(
                `Receiver ${input.receiverRosterPosition} ciphertext chunk ${chunk.chunkIndex} first vector does not use the frozen module rank.`,
            );
        }
        for (const polynomial of [
            ...chunk.firstCiphertextVector,
            chunk.secondCiphertextPolynomial,
        ]) {
            if (polynomial.length !== receiverEncryptionModuleDegree) {
                throw new RangeError(
                    `Receiver ${input.receiverRosterPosition} ciphertext chunk ${chunk.chunkIndex} polynomial does not use the frozen module degree.`,
                );
            }
            for (const coefficient of polynomial) {
                if (
                    !Number.isSafeInteger(coefficient) ||
                    coefficient < 0 ||
                    coefficient >= receiverEncryptionModulus
                ) {
                    throw new RangeError(
                        `Receiver ${input.receiverRosterPosition} ciphertext chunk ${chunk.chunkIndex} coefficient is outside the receiver encryption modulus.`,
                    );
                }
            }
        }
    });
};

const buildShareCommitmentEquationRows = (input: {
    readonly columnLookup: ReadonlyMap<string, number>;
    readonly shareCommitmentRows: readonly BallotPrivacyAlgebraicRelationRow[];
    readonly shareVectorWidth: number;
    readonly shareCommitmentProfileHash: ProtocolHash;
}): readonly BallotPrivacyBackendStatementExplicitRow[] => {
    const messageMatrix = deriveShareCommitmentMessageMatrix(
        input.shareCommitmentProfileHash,
    );
    const randomnessMatrix = deriveShareCommitmentRandomnessMatrix(
        input.shareCommitmentProfileHash,
    );
    const rows: BallotPrivacyBackendStatementExplicitRow[] = [];

    for (const shareCommitmentRow of input.shareCommitmentRows) {
        if (shareCommitmentRow.shareCommitmentPolynomialVector === undefined) {
            continue;
        }
        const commitmentPolynomialVector = parseShareCommitmentPolynomialVector(
            {
                commitmentPolynomialVector:
                    shareCommitmentRow.shareCommitmentPolynomialVector,
                receiverRosterPosition:
                    shareCommitmentRow.receiverRosterPosition,
            },
        );
        const shareVariableNames = Array.from(
            { length: input.shareVectorWidth },
            (_unusedValue, encodedCoordinateIndex) =>
                receiverShareVariableName(
                    shareCommitmentRow.receiverRosterPosition,
                    encodedCoordinateIndex,
                ),
        );
        const openingVariableNames = Array.from(
            { length: shareCommitmentOpeningDimension },
            (_unusedValue, openingCoordinateIndex) =>
                shareCommitmentOpeningVariableName(
                    shareCommitmentRow.receiverRosterPosition,
                    openingCoordinateIndex,
                ),
        );

        for (
            let commitmentVectorIndex = 0;
            commitmentVectorIndex < shareCommitmentModuleRank;
            commitmentVectorIndex += 1
        ) {
            const messageMatrixPolynomial =
                messageMatrix[commitmentVectorIndex] ?? [];
            const randomnessMatrixRow =
                randomnessMatrix[commitmentVectorIndex] ?? [];
            for (
                let commitmentCoefficientIndex = 0;
                commitmentCoefficientIndex < shareCommitmentModuleDegree;
                commitmentCoefficientIndex += 1
            ) {
                const shareTerms = shareVariableNames.map(
                    (variableName, shareCoordinateIndex) => ({
                        coefficient: shareCommitmentMessageCoefficient({
                            messageMatrixPolynomial,
                            outputCoefficientIndex: commitmentCoefficientIndex,
                            shareCoordinateIndex,
                        }),
                        columnIndex: requireColumnIndex(
                            input.columnLookup,
                            variableName,
                        ),
                        variableName,
                    }),
                );
                const openingTerms = openingVariableNames.map(
                    (variableName, openingCoordinateIndex) => ({
                        coefficient: shareCommitmentOpeningCoefficient({
                            outputCoefficientIndex: commitmentCoefficientIndex,
                            randomnessMatrixPolynomial:
                                randomnessMatrixRow[openingCoordinateIndex] ??
                                [],
                        }),
                        columnIndex: requireColumnIndex(
                            input.columnLookup,
                            variableName,
                        ),
                        variableName,
                    }),
                );
                rows.push({
                    modulus: shareCommitmentModulus,
                    rowIndex: rows.length,
                    rowKind: 'ShareCommitmentEquation',
                    rowName: `receiver_${shareCommitmentRow.receiverRosterPosition}_share_commitment_vector_${commitmentVectorIndex}_coefficient_${commitmentCoefficientIndex}_equation`,
                    target: canonicalShareCommitmentCoefficient(
                        commitmentPolynomialVector[commitmentVectorIndex]?.[
                            commitmentCoefficientIndex
                        ] ?? 0n,
                    ),
                    terms: [...shareTerms, ...openingTerms],
                });
            }
        }
    }

    return rows;
};

export {
    referencesByReceiver,
    deriveAlgebraicTargetHash,
    decimalString,
    deriveBackendHash,
    createVariableColumnLookup,
    requireColumnIndex,
    backendVariableColumns,
    compactReceiverEncryptionWitnessVariableColumns,
    backendTermsForLinearRow,
    buildExplicitSparseRowBatch,
    validateReceiverPublicKeyVector,
    validateReceiverPayloadCiphertextChunks,
    buildShareCommitmentEquationRows,
};
