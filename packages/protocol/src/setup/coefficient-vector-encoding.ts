import { bytesFromHex } from './common-fields.js';

export const coefficientVectorFromLittleEndianHex = (
    coefficientsLeHex: string,
    expectedCoefficientCount: number,
    fieldName: string,
): readonly number[] => {
    const coefficientBytes = bytesFromHex(coefficientsLeHex, fieldName);
    if (coefficientBytes.byteLength !== expectedCoefficientCount * 8) {
        throw new Error(
            `${fieldName} byte length must match the expected coefficient count.`,
        );
    }

    return Array.from(
        { length: expectedCoefficientCount },
        (_unused, coefficientIndex) => {
            let coefficient = 0n;
            for (let byteOffset = 7; byteOffset >= 0; byteOffset -= 1) {
                coefficient <<= 8n;
                coefficient |= BigInt(
                    coefficientBytes[coefficientIndex * 8 + byteOffset] ?? 0,
                );
            }
            if (coefficient > BigInt(Number.MAX_SAFE_INTEGER)) {
                throw new Error(
                    `${fieldName} contains a coefficient outside the JavaScript safe integer range.`,
                );
            }

            return Number(coefficient);
        },
    );
};
