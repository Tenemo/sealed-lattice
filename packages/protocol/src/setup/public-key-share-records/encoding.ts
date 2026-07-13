import { hash512Hex } from '@sealed-lattice/crypto';

import { coefficientVectorToLittleEndianBytes } from '../coefficient-vector-encoding.js';
import {
    assertNonEmptyString,
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
    assertSetupContextHashMatches,
    assertProtocolHash,
    deriveCollectiveBgvSetupContextHash,
} from '../common-fields.js';

export { assertNonNegativeSafeInteger, assertPositiveSafeInteger };
export { assertNonEmptyString };

export const publicKeyShareMaterialBinaryMagic = new Uint8Array([
    0x53, 0x4c, 0x50, 0x4b, 0x53, 0x4d, 0x56, 0x31,
]);

export const coefficientVectorHash512 = (
    coefficients: readonly number[],
): string =>
    hash512Hex(publicKeyShareCoefficientVectorHashDomain, [
        coefficientVectorToLittleEndianBytes(coefficients),
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
        'participantCount' | 'qSharePrimes' | 'publicMatrixSeedHash'
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
};
