import { hash512Hex } from '@sealed-lattice/crypto';

import type { CollectiveBgvSetupContext } from '../vss-share-verification-records.js';

import {
    publicKeyShareCoefficientVectorHashDomain,
    type PublicKeyShareSetInput,
} from './constants-and-types.js';

const protocolHashPattern = /^[0-9a-f]{128}$/u;
const lowercaseHexPattern = /^(?:[0-9a-f]{2})*$/u;
const contextFieldNames = [
    'ceremonyId',
    'manifestHash',
    'rosterHash',
    'setupParametersHash',
    'setupEpoch',
] as const;

export const assertProtocolHash = (value: string, fieldName: string): void => {
    if (!protocolHashPattern.test(value)) {
        throw new TypeError(`${fieldName} must be a protocol hash.`);
    }
};

export const assertLowercaseHexBytes = (
    value: string,
    fieldName: string,
): void => {
    if (!lowercaseHexPattern.test(value)) {
        throw new TypeError(`${fieldName} must be lowercase hex bytes.`);
    }
};

export const assertPositiveSafeInteger = (
    value: number,
    fieldName: string,
): void => {
    if (!Number.isSafeInteger(value) || value <= 0) {
        throw new TypeError(`${fieldName} must be a positive safe integer.`);
    }
};

export const assertNonNegativeSafeInteger = (
    value: number,
    fieldName: string,
): void => {
    if (!Number.isSafeInteger(value) || value < 0) {
        throw new TypeError(
            `${fieldName} must be a non-negative safe integer.`,
        );
    }
};

export const assertNonEmptyString = (
    value: string,
    fieldName: string,
): void => {
    if (value.length === 0) {
        throw new TypeError(`${fieldName} must be non-empty.`);
    }
};

export const bytesFromHex = (hex: string, fieldName: string): Uint8Array => {
    assertLowercaseHexBytes(hex, fieldName);
    const bytes = new Uint8Array(hex.length / 2);
    for (let byteIndex = 0; byteIndex < bytes.length; byteIndex += 1) {
        bytes[byteIndex] = Number.parseInt(
            hex.slice(byteIndex * 2, byteIndex * 2 + 2),
            16,
        );
    }

    return bytes;
};

export const coefficientVectorFromLittleEndianHex = (
    coefficientsLeHex: string,
    expectedCoefficientCount: number,
    fieldName: string,
): readonly number[] => {
    const coefficientBytes = bytesFromHex(coefficientsLeHex, fieldName);
    if (coefficientBytes.byteLength !== expectedCoefficientCount * 8) {
        throw new Error(
            `${fieldName} byte length must match the material ring degree.`,
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

const coefficientVectorBytes = (
    coefficients: readonly number[],
): Uint8Array => {
    const bytes = new Uint8Array(coefficients.length * 8);
    coefficients.forEach((coefficient, coefficientIndex) => {
        if (!Number.isSafeInteger(coefficient) || coefficient < 0) {
            throw new TypeError(
                'coefficient vector entries must be non-negative safe integers.',
            );
        }
        let value = BigInt(coefficient);
        for (let byteIndex = 0; byteIndex < 8; byteIndex += 1) {
            bytes[coefficientIndex * 8 + byteIndex] = Number(value & 0xffn);
            value >>= 8n;
        }
    });

    return bytes;
};

export const bytesToHex = (bytes: Uint8Array): string =>
    Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');

export const publicKeyShareMaterialBinaryMagic = new Uint8Array([
    0x53, 0x4c, 0x50, 0x4b, 0x53, 0x4d, 0x56, 0x31,
]);

export const appendVaruint = (outputBytes: number[], value: number): void => {
    if (!Number.isSafeInteger(value) || value < 0) {
        throw new TypeError(
            'binary varuint value must be a non-negative safe integer.',
        );
    }
    let remainingValue = value;
    do {
        let byte = remainingValue & 0x7f;
        remainingValue = Math.floor(remainingValue / 128);
        if (remainingValue !== 0) {
            byte |= 0x80;
        }
        outputBytes.push(byte);
    } while (remainingValue !== 0);
};

export const coefficientVectorHash512 = (
    coefficients: readonly number[],
): string =>
    hash512Hex(publicKeyShareCoefficientVectorHashDomain, [
        coefficientVectorBytes(coefficients),
    ]);

export const coefficientVectorToLittleEndianHex = (
    coefficients: readonly number[],
): string => bytesToHex(coefficientVectorBytes(coefficients));

export const contextFields = (
    setupContext: CollectiveBgvSetupContext,
): Pick<CollectiveBgvSetupContext, (typeof contextFieldNames)[number]> => ({
    ceremonyId: setupContext.ceremonyId,
    manifestHash: setupContext.manifestHash,
    rosterHash: setupContext.rosterHash,
    setupParametersHash: setupContext.setupParametersHash,
    setupEpoch: setupContext.setupEpoch,
});

export const assertContextMatches = (
    setupContext: CollectiveBgvSetupContext,
    value: Readonly<Record<string, unknown>>,
    valueName: string,
): void => {
    for (const fieldName of contextFieldNames) {
        if (value[fieldName] !== setupContext[fieldName]) {
            throw new Error(
                `${valueName}.${fieldName} must match setupContext.`,
            );
        }
    }
};

export const sortedByRosterPosition = <
    RecordValue extends { readonly trusteeRosterPosition: number },
>(
    records: readonly RecordValue[],
): RecordValue[] =>
    [...records].sort(
        (left, right) =>
            left.trusteeRosterPosition - right.trusteeRosterPosition,
    );

export const validateCommonInput = (
    input: Pick<
        PublicKeyShareSetInput,
        | 'participantCount'
        | 'qSharePrimes'
        | 'publicMatrixSeedHash'
        | 'publicKeyCrpRoot'
        | 'publicAPolynomialRoot'
    >,
): void => {
    assertPositiveSafeInteger(input.participantCount, 'participantCount');
    if (input.qSharePrimes.length === 0) {
        throw new Error('qSharePrimes must contain at least one RNS prime.');
    }
    input.qSharePrimes.forEach((qSharePrime, rnsLimbIndex) => {
        assertPositiveSafeInteger(
            qSharePrime,
            `qSharePrimes.${String(rnsLimbIndex)}`,
        );
    });
    assertProtocolHash(input.publicMatrixSeedHash, 'publicMatrixSeedHash');
    assertProtocolHash(input.publicKeyCrpRoot, 'publicKeyCrpRoot');
    assertProtocolHash(input.publicAPolynomialRoot, 'publicAPolynomialRoot');
};
