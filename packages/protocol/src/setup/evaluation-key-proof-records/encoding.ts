import { deriveCanonicalObjectHash } from '@sealed-lattice/crypto';
import type { ProtocolHash } from '@sealed-lattice/types';

import {
    assertJsonRecord,
    assertNonEmptyString,
    assertNonNegativeSafeInteger,
    assertPositiveSafeInteger,
    assertProtocolHash,
    bytesFromHex,
    bytesToHex,
} from '../common-fields.js';
export { coefficientVectorFromLittleEndianHex } from '../coefficient-vector-encoding.js';

import { type EvaluationKeyShareProofFamily } from './constants-and-types.js';

export {
    assertJsonRecord,
    assertNonEmptyString,
    assertNonNegativeSafeInteger,
    assertPositiveSafeInteger,
    assertProtocolHash,
    bytesFromHex,
};

const proofRandomnessByteLength = 64;

const defaultProofRandomBytes = (byteLength: number): Uint8Array => {
    const cryptoProvider = globalThis.crypto;
    if (cryptoProvider === undefined) {
        throw new Error(
            'Trustee evaluation-key proof generation requires Web Crypto getRandomValues.',
        );
    }
    const bytes = new Uint8Array(byteLength);
    cryptoProvider.getRandomValues(bytes);

    return bytes;
};

export const freshProofRandomnessHex = (): string => {
    const bytes = defaultProofRandomBytes(proofRandomnessByteLength);
    if (bytes.byteLength !== proofRandomnessByteLength) {
        throw new Error(
            'proof randomness byte source must return exactly 64 bytes.',
        );
    }

    return bytesToHex(bytes);
};

export const evaluationKeyShareComponentVectorRoot = (
    proofFamily: EvaluationKeyShareProofFamily,
    keySwitchDomain: string,
    keySwitchSeedHex: string,
    level: number,
    ringDegree: number,
    componentVectorsLittleEndianHexByDigitAndLimb: readonly string[],
): ProtocolHash =>
    deriveCanonicalObjectHash({
        objectType: 'EvaluationKeyShareComponentVectorSet',
        proofFamily,
        keySwitchDomain,
        keySwitchSeedHex,
        level,
        ringDegree,
        componentVectorsLittleEndianHexByDigitAndLimb,
    });

export const evaluationKeyShareComponentMaterialReferenceRoot = (
    proofFamily: EvaluationKeyShareProofFamily,
    ringDegree: number,
    keySwitchComponentVectorRoot: ProtocolHash,
    keySwitchDomain: string,
    keySwitchSeedHex: string,
    trusteeIdentity: string,
    trusteeRosterPosition: number,
    level: number,
): ProtocolHash =>
    deriveCanonicalObjectHash({
        objectType: 'EvaluationKeyShareComponentMaterialReference',
        proofFamily,
        trusteeIdentity,
        trusteeRosterPosition,
        keySwitchDomain,
        keySwitchSeedHex,
        level,
        ringDegree,
        keySwitchComponentVectorRoot,
    });
