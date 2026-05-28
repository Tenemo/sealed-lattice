import type { ProtocolHash } from '@sealed-lattice/types';

import {
    receiverEncryptionModuleDegree,
    receiverEncryptionModuleRank,
    receiverEncryptionModulus,
    shareCommitmentModuleDegree,
    shareCommitmentModuleRank,
    shareCommitmentModulus,
    shareCommitmentOpeningDimension,
} from '../protocol-parameters.js';

import {
    deriveUniformBigInt,
    deriveUniformNumber,
} from './primitive-randomness.js';

type ShareCommitmentMessageMatrix = readonly (readonly bigint[])[];

type ShareCommitmentRandomnessMatrix =
    readonly (readonly (readonly bigint[])[])[];

const shareCommitmentMessageMatrixCache = new Map<
    ProtocolHash,
    ShareCommitmentMessageMatrix
>();

const shareCommitmentRandomnessMatrixCache = new Map<
    ProtocolHash,
    ShareCommitmentRandomnessMatrix
>();

const deriveNumberPolynomial = (
    domain: string,
    payload: unknown,
    degree: number,
    modulus: number,
): readonly number[] =>
    Array.from({ length: degree }, (_unusedValue, coefficientIndex) =>
        deriveUniformNumber(domain, { coefficientIndex, payload }, modulus),
    );

const deriveBigIntPolynomial = (
    domain: string,
    payload: unknown,
    degree: number,
    modulus: bigint,
): readonly bigint[] =>
    Array.from({ length: degree }, (_unusedValue, coefficientIndex) =>
        deriveUniformBigInt(domain, { coefficientIndex, payload }, modulus),
    );

export const deriveReceiverPublicMatrix = (
    receiverEncryptionProfileHash: ProtocolHash,
    publicMatrixSeedHash: ProtocolHash,
): readonly (readonly (readonly number[])[])[] =>
    Array.from(
        { length: receiverEncryptionModuleRank },
        (_unusedRow, rowIndex) =>
            Array.from(
                { length: receiverEncryptionModuleRank },
                (_unusedColumn, columnIndex) =>
                    deriveNumberPolynomial(
                        'sealed.vote/internal/receiver-encryption/public-matrix-v1',
                        {
                            columnIndex,
                            publicMatrixSeedHash,
                            receiverEncryptionProfileHash,
                            rowIndex,
                        },
                        receiverEncryptionModuleDegree,
                        receiverEncryptionModulus,
                    ),
            ),
    );

export const deriveShareCommitmentMessageMatrix = (
    shareCommitmentProfileHash: ProtocolHash,
): ShareCommitmentMessageMatrix => {
    const cachedMatrix = shareCommitmentMessageMatrixCache.get(
        shareCommitmentProfileHash,
    );
    if (cachedMatrix !== undefined) {
        return cachedMatrix;
    }
    const matrix = Array.from(
        { length: shareCommitmentModuleRank },
        (_unusedRow, rowIndex) =>
            deriveBigIntPolynomial(
                'sealed.vote/internal/share-commitment/message-matrix-v1',
                { rowIndex, shareCommitmentProfileHash },
                shareCommitmentModuleDegree,
                shareCommitmentModulus,
            ),
    );
    shareCommitmentMessageMatrixCache.set(shareCommitmentProfileHash, matrix);

    return matrix;
};

export const deriveShareCommitmentRandomnessMatrix = (
    shareCommitmentProfileHash: ProtocolHash,
): ShareCommitmentRandomnessMatrix => {
    const cachedMatrix = shareCommitmentRandomnessMatrixCache.get(
        shareCommitmentProfileHash,
    );
    if (cachedMatrix !== undefined) {
        return cachedMatrix;
    }
    const matrix = Array.from(
        { length: shareCommitmentModuleRank },
        (_unusedRow, rowIndex) =>
            Array.from(
                { length: shareCommitmentOpeningDimension },
                (_unusedColumn, columnIndex) =>
                    deriveBigIntPolynomial(
                        'sealed.vote/internal/share-commitment/randomness-matrix-v1',
                        {
                            columnIndex,
                            rowIndex,
                            shareCommitmentProfileHash,
                        },
                        shareCommitmentModuleDegree,
                        shareCommitmentModulus,
                    ),
            ),
    );
    shareCommitmentRandomnessMatrixCache.set(
        shareCommitmentProfileHash,
        matrix,
    );

    return matrix;
};
