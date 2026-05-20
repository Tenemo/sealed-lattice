import type { BallotPrivacyRelationCompilerInput } from '../relation-compiler.js';

import { receiverPayloadPlaintextBits } from './component-bundle.js';
import type {
    BallotProofComponentProjectionWitness,
    BallotProofRecordGenerationSecretState,
    BallotProofStructuredReceiverEncryptionProofStatement,
    DensePolynomial,
    DensePolynomialVector,
} from './statement-contracts.js';
import { receiverEncryptionModuleRank } from './statement-contracts.js';
import {
    receiverEncryptionChunkWitness,
    signedPolynomialCoefficient,
    zeroPolynomial,
} from './witness-accessors.js';

const signedNumberPolynomial = (input: {
    readonly coefficients: readonly number[];
    readonly sourceRingDegree: number;
}): DensePolynomial => {
    if (input.coefficients.length !== input.sourceRingDegree) {
        throw new Error(
            'Structured receiver-encryption witness polynomial has the wrong degree.',
        );
    }

    return input.coefficients.map((coefficient) => {
        if (!Number.isSafeInteger(coefficient)) {
            throw new Error(
                'Structured receiver-encryption witness coefficient must be a safe integer.',
            );
        }

        return signedPolynomialCoefficient(BigInt(coefficient));
    });
};

const plaintextChunkPolynomial = (input: {
    readonly chunkIndex: number;
    readonly plaintextBits: readonly number[];
    readonly sourceRingDegree: number;
}): DensePolynomial => {
    const polynomial = zeroPolynomial(input.sourceRingDegree);
    const chunkOffset = input.chunkIndex * input.sourceRingDegree;
    for (
        let coefficientIndex = 0;
        coefficientIndex < input.sourceRingDegree;
        coefficientIndex += 1
    ) {
        polynomial[coefficientIndex] =
            input.plaintextBits[chunkOffset + coefficientIndex] ?? 0;
    }

    return polynomial;
};

const secretStateForStructuredReceiverEncryptionStatement = (input: {
    readonly projectionWitness: BallotProofComponentProjectionWitness;
    readonly relationInput: BallotPrivacyRelationCompilerInput;
    readonly structuredStatement: BallotProofStructuredReceiverEncryptionProofStatement;
}): BallotProofRecordGenerationSecretState => {
    const sourceWitnessCoefficients: (DensePolynomial | undefined)[] =
        Array.from(
            { length: input.structuredStatement.statementColumns },
            () => undefined,
        );
    const writeWitnessPolynomial = (
        columnIndex: number,
        polynomial: DensePolynomial,
    ): void => {
        if (
            !Number.isSafeInteger(columnIndex) ||
            columnIndex < 0 ||
            columnIndex >= sourceWitnessCoefficients.length
        ) {
            throw new Error(
                'Structured receiver-encryption witness column is outside the statement shape.',
            );
        }
        if (sourceWitnessCoefficients[columnIndex] !== undefined) {
            throw new Error(
                'Structured receiver-encryption witness column is duplicated.',
            );
        }
        sourceWitnessCoefficients[columnIndex] = polynomial;
    };

    for (const receiverRow of input.structuredStatement.receiverRows) {
        const plaintextBits = receiverPayloadPlaintextBits({
            plaintextBitLength: receiverRow.plaintextBitLength,
            projectionWitness: input.projectionWitness,
            receiverRosterPosition: receiverRow.receiverRosterPosition,
            relationInput: input.relationInput,
        });
        for (const ciphertextChunk of receiverRow.ciphertextChunks) {
            const chunkWitness = receiverEncryptionChunkWitness(
                input.projectionWitness,
                receiverRow.receiverRosterPosition,
                ciphertextChunk.chunkIndex,
            );
            for (
                let vectorIndex = 0;
                vectorIndex < receiverEncryptionModuleRank;
                vectorIndex += 1
            ) {
                writeWitnessPolynomial(
                    ciphertextChunk.randomnessPolynomialColumnIndices[
                        vectorIndex
                    ] ??
                        (() => {
                            throw new Error(
                                'Structured receiver-encryption randomness column is missing.',
                            );
                        })(),
                    signedNumberPolynomial({
                        coefficients:
                            chunkWitness.encryptionRandomnessVector[
                                vectorIndex
                            ] ??
                            (() => {
                                throw new Error(
                                    'Structured receiver-encryption randomness witness is missing.',
                                );
                            })(),
                        sourceRingDegree:
                            input.structuredStatement.sourceRingDegree,
                    }),
                );
                writeWitnessPolynomial(
                    ciphertextChunk.firstNoisePolynomialColumnIndices[
                        vectorIndex
                    ] ??
                        (() => {
                            throw new Error(
                                'Structured receiver-encryption first-noise column is missing.',
                            );
                        })(),
                    signedNumberPolynomial({
                        coefficients:
                            chunkWitness.firstNoiseVector[vectorIndex] ??
                            (() => {
                                throw new Error(
                                    'Structured receiver-encryption first-noise witness is missing.',
                                );
                            })(),
                        sourceRingDegree:
                            input.structuredStatement.sourceRingDegree,
                    }),
                );
            }
            writeWitnessPolynomial(
                ciphertextChunk.secondNoiseColumnIndex,
                signedNumberPolynomial({
                    coefficients: chunkWitness.secondNoisePolynomial,
                    sourceRingDegree:
                        input.structuredStatement.sourceRingDegree,
                }),
            );
            writeWitnessPolynomial(
                ciphertextChunk.plaintextPolynomialColumnIndex,
                plaintextChunkPolynomial({
                    chunkIndex: ciphertextChunk.chunkIndex,
                    plaintextBits,
                    sourceRingDegree:
                        input.structuredStatement.sourceRingDegree,
                }),
            );
        }
    }

    if (
        sourceWitnessCoefficients.some(
            (witnessPolynomial) => witnessPolynomial === undefined,
        )
    ) {
        throw new Error(
            'Structured receiver-encryption witness did not fill every statement column.',
        );
    }

    return {
        sourceWitnessCoefficients:
            sourceWitnessCoefficients as DensePolynomialVector,
    };
};

export { secretStateForStructuredReceiverEncryptionStatement };
