import type { BallotPrivacyRelationCompilerInput } from '../relation-compiler.js';

import type {
    BallotProofComponentProjectionWitness,
    FieldVariableColumn,
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

export { witnessValueForVariable };
