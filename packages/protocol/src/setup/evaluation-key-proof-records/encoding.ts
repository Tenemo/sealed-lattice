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

import {
    type EvaluationKeyShareMaterial,
    type EvaluationKeyShareProofFamily,
    type JsonRecord,
} from './constants-and-types.js';

const lowercaseHexPattern = /^[0-9a-f]+$/u;

export {
    assertJsonRecord,
    assertNonEmptyString,
    assertNonNegativeSafeInteger,
    assertPositiveSafeInteger,
    assertProtocolHash,
    bytesFromHex,
};

export const assertLowercaseHex = (value: string, fieldName: string): void => {
    if (!lowercaseHexPattern.test(value)) {
        throw new TypeError(`${fieldName} must be lowercase hex.`);
    }
};

export const stringRecordField = (
    record: JsonRecord,
    fieldName: string,
    objectPath: string,
): string => {
    const value = record[fieldName];
    if (typeof value !== 'string' || value.length === 0) {
        throw new TypeError(`${objectPath}.${fieldName} must be non-empty.`);
    }

    return value;
};

export const nonNegativeIntegerRecordField = (
    record: JsonRecord,
    fieldName: string,
    objectPath: string,
): number => {
    const value = record[fieldName];
    if (
        typeof value !== 'number' ||
        !Number.isSafeInteger(value) ||
        value < 0
    ) {
        throw new TypeError(
            `${objectPath}.${fieldName} must be a non-negative safe integer.`,
        );
    }

    return value;
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
    componentVectors: readonly JsonRecord[],
): ProtocolHash =>
    deriveCanonicalObjectHash({
        objectType: 'EvaluationKeyShareComponentVectorSet',
        proofFamily,
        keySwitchDomain,
        keySwitchSeedHex,
        level,
        ringDegree,
        componentVectors,
    });

export const evaluationKeyShareComponentMaterialReferenceRoot = (
    proofFamily: EvaluationKeyShareProofFamily,
    shareMaterial: EvaluationKeyShareMaterial,
    trusteeIdentity: string,
    trusteeRosterPosition: number,
    level: number,
): ProtocolHash =>
    deriveCanonicalObjectHash({
        objectType: 'EvaluationKeyShareComponentMaterialReference',
        proofFamily,
        trusteeIdentity,
        trusteeRosterPosition,
        keySwitchDomain: shareMaterial.keySwitchDomain,
        keySwitchSeedHex: shareMaterial.keySwitchSeedHex,
        level,
        ringDegree: shareMaterial.ringDegree,
        keySwitchComponentVectorRoot:
            shareMaterial.keySwitchComponentVectorRoot,
    });
