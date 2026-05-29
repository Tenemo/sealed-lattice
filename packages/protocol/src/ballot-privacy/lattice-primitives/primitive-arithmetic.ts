import type { ShareCommitmentProfile } from '@sealed-lattice/types';

import { assertCanonicalFieldElement } from '../plaintext-oracle-helpers.js';
import {
    receiverEncryptionModuleDegree,
    receiverEncryptionModuleRank,
} from '../protocol-parameters.js';

const modNumber = (value: number, modulus: number): number =>
    ((value % modulus) + modulus) % modulus;

export const modBigInt = (value: bigint, modulus: bigint): bigint =>
    ((value % modulus) + modulus) % modulus;

export const addNumberPolynomials = (
    leftPolynomial: readonly number[],
    rightPolynomial: readonly number[],
    modulus: number,
): readonly number[] =>
    leftPolynomial.map((coefficient, coefficientIndex) =>
        modNumber(
            coefficient + (rightPolynomial[coefficientIndex] ?? 0),
            modulus,
        ),
    );

export const addBigIntPolynomials = (
    leftPolynomial: readonly bigint[],
    rightPolynomial: readonly bigint[],
    modulus: bigint,
): readonly bigint[] =>
    leftPolynomial.map((coefficient, coefficientIndex) =>
        modBigInt(
            coefficient + (rightPolynomial[coefficientIndex] ?? 0n),
            modulus,
        ),
    );

const multiplyNumberPolynomials = (
    leftPolynomial: readonly number[],
    rightPolynomial: readonly number[],
    modulus: number,
): readonly number[] => {
    const degree = leftPolynomial.length;
    const output = Array.from({ length: degree }, () => 0);
    for (
        let leftCoefficientIndex = 0;
        leftCoefficientIndex < degree;
        leftCoefficientIndex += 1
    ) {
        for (
            let rightCoefficientIndex = 0;
            rightCoefficientIndex < degree;
            rightCoefficientIndex += 1
        ) {
            const rawIndex = leftCoefficientIndex + rightCoefficientIndex;
            const outputIndex = rawIndex % degree;
            const sign = rawIndex >= degree ? -1 : 1;
            output[outputIndex] = modNumber(
                output[outputIndex] +
                    sign *
                        leftPolynomial[leftCoefficientIndex] *
                        rightPolynomial[rightCoefficientIndex],
                modulus,
            );
        }
    }

    return output;
};

export const multiplyBigIntPolynomials = (
    leftPolynomial: readonly bigint[],
    rightPolynomial: readonly bigint[],
    modulus: bigint,
): readonly bigint[] => {
    const degree = leftPolynomial.length;
    const output = Array.from({ length: degree }, () => 0n);
    for (
        let leftCoefficientIndex = 0;
        leftCoefficientIndex < degree;
        leftCoefficientIndex += 1
    ) {
        for (
            let rightCoefficientIndex = 0;
            rightCoefficientIndex < degree;
            rightCoefficientIndex += 1
        ) {
            const rawIndex = leftCoefficientIndex + rightCoefficientIndex;
            const outputIndex = rawIndex % degree;
            const sign = rawIndex >= degree ? -1n : 1n;
            output[outputIndex] = modBigInt(
                output[outputIndex] +
                    sign *
                        leftPolynomial[leftCoefficientIndex] *
                        rightPolynomial[rightCoefficientIndex],
                modulus,
            );
        }
    }

    return output;
};

export const multiplyMatrixByVector = (
    matrix: readonly (readonly (readonly number[])[])[],
    vector: readonly (readonly number[])[],
    modulus: number,
): readonly (readonly number[])[] =>
    matrix.map((matrixRow) => {
        let accumulatedPolynomial = Array.from(
            { length: receiverEncryptionModuleDegree },
            () => 0,
        );
        matrixRow.forEach((matrixPolynomial, columnIndex) => {
            accumulatedPolynomial = [
                ...addNumberPolynomials(
                    accumulatedPolynomial,
                    multiplyNumberPolynomials(
                        matrixPolynomial,
                        vector[columnIndex] ?? [],
                        modulus,
                    ),
                    modulus,
                ),
            ];
        });

        return accumulatedPolynomial;
    });

export const multiplyTransposeMatrixByVector = (
    matrix: readonly (readonly (readonly number[])[])[],
    vector: readonly (readonly number[])[],
    modulus: number,
): readonly (readonly number[])[] =>
    Array.from(
        { length: receiverEncryptionModuleRank },
        (_unusedColumn, columnIndex) => {
            let accumulatedPolynomial = Array.from(
                { length: receiverEncryptionModuleDegree },
                () => 0,
            );
            for (let rowIndex = 0; rowIndex < matrix.length; rowIndex += 1) {
                accumulatedPolynomial = [
                    ...addNumberPolynomials(
                        accumulatedPolynomial,
                        multiplyNumberPolynomials(
                            matrix[rowIndex]?.[columnIndex] ?? [],
                            vector[rowIndex] ?? [],
                            modulus,
                        ),
                        modulus,
                    ),
                ];
            }

            return accumulatedPolynomial;
        },
    );

export const dotNumberPolynomialVectors = (
    leftVector: readonly (readonly number[])[],
    rightVector: readonly (readonly number[])[],
    modulus: number,
): readonly number[] => {
    let accumulatedPolynomial = Array.from(
        { length: receiverEncryptionModuleDegree },
        () => 0,
    );
    leftVector.forEach((leftPolynomial, vectorIndex) => {
        accumulatedPolynomial = [
            ...addNumberPolynomials(
                accumulatedPolynomial,
                multiplyNumberPolynomials(
                    leftPolynomial,
                    rightVector[vectorIndex] ?? [],
                    modulus,
                ),
                modulus,
            ),
        ];
    });

    return accumulatedPolynomial;
};

export function validateReceiverShareVector(
    receiverShareVector: readonly number[],
    shareCommitmentProfile: ShareCommitmentProfile,
    expectedShareVectorWidth: number = shareCommitmentProfile.shareVectorWidth,
): void {
    if (receiverShareVector.length !== expectedShareVectorWidth) {
        throw new RangeError(
            'Receiver share vectors must use the fixed width.',
        );
    }
    receiverShareVector.forEach((shareRepresentative) => {
        assertCanonicalFieldElement(
            shareRepresentative,
            'receiver share representative',
        );
    });
}
