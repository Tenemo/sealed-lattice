import { hash512Hex } from '@sealed-lattice/crypto';

import {
    assertProtocolHash,
    assertNonNegativeSafeInteger,
    assertPositiveSafeInteger,
} from '../common-fields.js';
export { coefficientVectorFromLittleEndianHex } from '../coefficient-vector-encoding.js';

import {
    publicKeyShareCoefficientVectorHashDomain,
    type PublicKeyShareSetInput,
} from './constants-and-types.js';

export {
    assertContextMatches,
    assertProtocolHash,
    contextFields,
} from '../common-fields.js';

export { assertNonNegativeSafeInteger, assertPositiveSafeInteger };

export const assertNonEmptyString = (
    value: string,
    fieldName: string,
): void => {
    if (value.length === 0) {
        throw new TypeError(`${fieldName} must be non-empty.`);
    }
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

export const publicKeyShareMaterialBinaryMagic = new Uint8Array([
    0x53, 0x4c, 0x50, 0x4b, 0x53, 0x4d, 0x56, 0x31,
]);

export const coefficientVectorHash512 = (
    coefficients: readonly number[],
): string =>
    hash512Hex(publicKeyShareCoefficientVectorHashDomain, [
        coefficientVectorBytes(coefficients),
    ]);

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
