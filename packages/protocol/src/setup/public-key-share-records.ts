import {
    deriveProtocolHash,
    hash512Hex,
    setupProofMaterialFullObjectHashHex,
} from '@sealed-lattice/crypto';
import type { ProtocolHash } from '@sealed-lattice/types';

import { BinaryChunkWriter } from './binary-chunk-writer.js';
import {
    setupProofProfileId,
    type SameSecretProofSet,
    type SameSecretConsistencyStatementRecord,
    type SameSecretConsistencyStatementSet,
} from './same-secret-consistency-records.js';
import {
    setupProofChunkManifestRoot,
    setupProofMaterialChunkHash,
    setupProofTransportChunkSizeBytes,
    type TransportedSetupProofMaterialSet,
} from './setup-proof-material-transport.js';
import {
    setupTransportChunkSizeBytes,
    setupTransportProfileId,
} from './vss-coefficient-commitments.js';
import type { CollectiveBgvSetupContext } from './vss-share-verification-records.js';

type JsonRecord = Record<string, unknown>;

const isJsonRecord = (value: unknown): value is JsonRecord =>
    typeof value === 'object' && value !== null && !Array.isArray(value);

export const publicKeyShareProofFamily = 'public-key-share';
const publicKeyShareSuccinctProofBytesHashDomain =
    'sealed-lattice/setup/public-key-share/succinct-proof-bytes-v1';
export const publicKeyShareProofVerificationStatus =
    'succinct-proof-verification-pending';
export const publicKeyShareSuccinctProofVerificationStatus =
    'succinct-public-key-share-argument-verified-with-accepted-proof-accounting';
export const publicKeyShareSuccinctProofModelStatus =
    'succinct-public-key-share-argument-accounting-accepted';
export const publicKeyShareProofBindingStatus =
    'public-key-share-proof-required';
export const publicKeyShareMaterialEncoding =
    'embedded-full-public-key-share-coefficients';
export const publicKeyShareMaterialTransportEncoding =
    'binary-chunked-full-public-key-share-coefficients';
export const publicKeyShareMaterialBinaryFormat =
    'sealed-lattice-public-key-share-material-binary-v1';
export const publicKeyShareCoefficientVectorHashDomain =
    'sealed-lattice-bgv-rns/public-key-share-coefficient-vector-v1';

export type PublicKeyShareCoefficientVectorHash = Readonly<{
    readonly rnsLimbIndex: number;
    readonly rnsPrime: number;
    readonly component: 'b_i';
    readonly coefficientVectorHash512: ProtocolHash;
}>;

export type PublicKeyShareContributionInput = Readonly<{
    readonly trusteeIdentity: string;
    readonly trusteeRosterPosition: number;
    readonly shareCoefficientVectorHash512ByLimb: readonly PublicKeyShareCoefficientVectorHash[];
}>;

export type PublicKeyShareCoefficientVectorMaterial = Readonly<
    JsonRecord & {
        readonly rnsLimbIndex: number;
        readonly rnsPrime: number;
        readonly component: 'b_i';
        readonly coefficientByteLength: number;
        readonly coefficientVectorHash512: ProtocolHash;
        readonly coefficientsLeHex: string;
    }
>;

export type PublicKeyShareMaterialContributionInput = Readonly<{
    readonly trusteeIdentity: string;
    readonly trusteeRosterPosition: number;
    readonly shareCoefficientVectorsByLimb: readonly PublicKeyShareCoefficientVectorMaterial[];
}>;

export type PublicKeyShareRecord = Readonly<
    JsonRecord & {
        readonly objectType: 'PublicKeyShare';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly setupProofProfileId: typeof setupProofProfileId;
        readonly trusteeIdentity: string;
        readonly trusteeRosterPosition: number;
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly publicKeyCrpRoot: ProtocolHash;
        readonly publicAPolynomialRoot: ProtocolHash;
        readonly sameSecretStatementRoot: ProtocolHash;
        readonly trusteeSecretCommitmentRoot: ProtocolHash;
        readonly shareComponent: 'component-zero-b_i';
        readonly rnsLimbCount: number;
        readonly shareCoefficientVectorHash512ByLimb: readonly PublicKeyShareCoefficientVectorHash[];
        readonly proofBindingStatus: typeof publicKeyShareProofBindingStatus;
        readonly publicKeyShareRoot: ProtocolHash;
    }
>;

export type PublicKeyShareSet = Readonly<
    JsonRecord & {
        readonly objectType: 'PublicKeyShareSet';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly setupProofProfileId: typeof setupProofProfileId;
        readonly proofBindingStatus: typeof publicKeyShareProofBindingStatus;
        readonly participantCount: number;
        readonly rnsLimbCount: number;
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly publicKeyCrpRoot: ProtocolHash;
        readonly publicAPolynomialRoot: ProtocolHash;
        readonly sameSecretConsistencyRoot: ProtocolHash;
        readonly publicKeyShareRoots: readonly {
            readonly trusteeIdentity: string;
            readonly trusteeRosterPosition: number;
            readonly publicKeyShareRoot: ProtocolHash;
        }[];
        readonly shareRecords: readonly PublicKeyShareRecord[];
        readonly publicKeyShareSetRoot: ProtocolHash;
    }
>;

export type PublicKeyShareProofRecord = Readonly<
    JsonRecord & {
        readonly objectType: 'PublicKeyShareProof';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly setupProofProfileId: typeof setupProofProfileId;
        readonly proofFamily: typeof publicKeyShareProofFamily;
        readonly proofVerificationStatus: typeof publicKeyShareProofVerificationStatus;
        readonly trusteeIdentity: string;
        readonly trusteeRosterPosition: number;
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly publicKeyCrpRoot: ProtocolHash;
        readonly publicAPolynomialRoot: ProtocolHash;
        readonly publicKeyShareRoot: ProtocolHash;
        readonly sameSecretStatementRoot: ProtocolHash;
        readonly trusteeSecretCommitmentRoot: ProtocolHash;
        readonly rnsLimbCount: number;
        readonly errorSupport: 'checked-by-public-key-share-succinct-proof-set';
        readonly proofBytesStatus: 'supplied-by-public-key-share-succinct-proof-set';
        readonly publicKeyShareProofRoot: ProtocolHash;
    }
>;

export type PublicKeyShareProofSet = Readonly<
    JsonRecord & {
        readonly objectType: 'PublicKeyShareProofSet';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly setupProofProfileId: typeof setupProofProfileId;
        readonly proofFamily: typeof publicKeyShareProofFamily;
        readonly proofVerificationStatus: typeof publicKeyShareProofVerificationStatus;
        readonly participantCount: number;
        readonly rnsLimbCount: number;
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly publicKeyCrpRoot: ProtocolHash;
        readonly publicAPolynomialRoot: ProtocolHash;
        readonly sameSecretConsistencyRoot: ProtocolHash;
        readonly publicKeyShareSetRoot: ProtocolHash;
        readonly publicKeyShareProofRoots: readonly {
            readonly trusteeIdentity: string;
            readonly trusteeRosterPosition: number;
            readonly publicKeyShareProofRoot: ProtocolHash;
        }[];
        readonly proofRecords: readonly PublicKeyShareProofRecord[];
        readonly publicKeyShareProofSetRoot: ProtocolHash;
    }
>;

export type PublicKeyShareMaterialRecord = Readonly<
    JsonRecord & {
        readonly objectType: 'PublicKeyShareMaterial';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly setupProofProfileId: typeof setupProofProfileId;
        readonly proofFamily: typeof publicKeyShareProofFamily;
        readonly proofModelStatus: typeof publicKeyShareSuccinctProofModelStatus;
        readonly materialEncoding: typeof publicKeyShareMaterialEncoding;
        readonly trusteeIdentity: string;
        readonly trusteeRosterPosition: number;
        readonly rnsLimbCount: number;
        readonly ringDegree: number;
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly publicKeyCrpRoot: ProtocolHash;
        readonly publicAPolynomialRoot: ProtocolHash;
        readonly publicKeyShareRoot: ProtocolHash;
        readonly shareCoefficientVectorsByLimb: readonly PublicKeyShareCoefficientVectorMaterial[];
        readonly publicKeyShareMaterialRoot: ProtocolHash;
    }
>;

export type PublicKeyShareMaterialRootReference = Readonly<{
    readonly trusteeIdentity: string;
    readonly trusteeRosterPosition: number;
    readonly publicKeyShareMaterialRoot: ProtocolHash;
}>;

export type PublicKeyShareMaterialSet = Readonly<
    JsonRecord & {
        readonly objectType: 'PublicKeyShareMaterialSet';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly setupProofProfileId: typeof setupProofProfileId;
        readonly proofFamily: typeof publicKeyShareProofFamily;
        readonly proofModelStatus: typeof publicKeyShareSuccinctProofModelStatus;
        readonly materialEncoding: typeof publicKeyShareMaterialEncoding;
        readonly participantCount: number;
        readonly rnsLimbCount: number;
        readonly ringDegree: number;
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly publicKeyCrpRoot: ProtocolHash;
        readonly publicAPolynomialRoot: ProtocolHash;
        readonly publicKeyShareSetRoot: ProtocolHash;
        readonly publicKeyShareMaterialRoots: readonly PublicKeyShareMaterialRootReference[];
        readonly shareMaterialRecords: readonly PublicKeyShareMaterialRecord[];
        readonly publicKeyShareMaterialSetRoot: ProtocolHash;
    }
>;

export type BinaryChunkedPublicKeyShareMaterialSet = Readonly<
    JsonRecord & {
        readonly objectType: 'PublicKeyShareMaterialSet';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly setupProofProfileId: typeof setupProofProfileId;
        readonly proofFamily: typeof publicKeyShareProofFamily;
        readonly proofModelStatus: typeof publicKeyShareSuccinctProofModelStatus;
        readonly materialEncoding: typeof publicKeyShareMaterialTransportEncoding;
        readonly binaryFormat: typeof publicKeyShareMaterialBinaryFormat;
        readonly participantCount: number;
        readonly rnsLimbCount: number;
        readonly ringDegree: number;
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly publicKeyCrpRoot: ProtocolHash;
        readonly publicAPolynomialRoot: ProtocolHash;
        readonly publicKeyShareSetRoot: ProtocolHash;
        readonly publicKeyShareMaterialRoots: readonly PublicKeyShareMaterialRootReference[];
        readonly transport: {
            readonly transportProfileId: typeof setupTransportProfileId;
            readonly chunkSizeBytes: typeof setupTransportChunkSizeBytes;
            readonly chunkCount: number;
            readonly totalByteLength: number;
            readonly fullObjectHash: ProtocolHash;
            readonly chunkRoot: ProtocolHash;
        };
        readonly publicKeyShareMaterialSetRoot: ProtocolHash;
    }
>;

export type SetupTransportedPublicKeyShareMaterial = Readonly<
    JsonRecord & {
        readonly objectType: 'SetupTransportedPublicKeyShareMaterial';
        readonly objectVersion: 1;
        readonly binaryFormat: typeof publicKeyShareMaterialBinaryFormat;
        readonly chunkSizeBytes: typeof setupTransportChunkSizeBytes;
        readonly chunkCount: number;
        readonly totalByteLength: number;
        readonly fullObjectHash: ProtocolHash;
        readonly chunkHashes: readonly ProtocolHash[];
        readonly chunkRoot: ProtocolHash;
        readonly chunks: readonly {
            readonly chunkIndex: number;
            readonly bytesHex: string;
        }[];
    }
>;

export type BinaryChunkedPublicKeyShareMaterialTransport = Readonly<{
    readonly materialSet: BinaryChunkedPublicKeyShareMaterialSet;
    readonly transportedPublicKeyShareMaterial: SetupTransportedPublicKeyShareMaterial;
}>;

export type BinaryChunkedPublicKeyShareMaterialBundle = Readonly<{
    readonly materialSet: BinaryChunkedPublicKeyShareMaterialSet;
    readonly transportedPublicKeyShareMaterial: SetupTransportedPublicKeyShareMaterial;
}>;

export type SetupPackagePublicKeyShareMaterialSet =
    | PublicKeyShareMaterialSet
    | BinaryChunkedPublicKeyShareMaterialSet;

export type PublicKeyShareSuccinctEmbeddedProofBytes = Readonly<{
    readonly proofBytesHex: string;
}>;

export type PublicKeyShareSuccinctTransportedProofBytes = Readonly<{
    readonly proofBytesEncoding: 'binary-chunked-proof-bytes';
    readonly proofMaterialRoot: ProtocolHash;
    readonly proofChunkSizeBytes: number;
    readonly proofChunkCount: number;
    readonly proofTotalByteLength: number;
    readonly proofFullObjectHash: ProtocolHash;
    readonly proofChunkRoot: ProtocolHash;
    readonly proofChunkHashes: readonly ProtocolHash[];
}>;

export type PublicKeyShareSuccinctProofByteMaterial =
    | PublicKeyShareSuccinctEmbeddedProofBytes
    | PublicKeyShareSuccinctTransportedProofBytes;

export type PublicKeyShareSuccinctProofMaterial = Readonly<
    PublicKeyShareSuccinctProofByteMaterial & {
        readonly setupProofProfileId: typeof setupProofProfileId;
        readonly proofFamily: typeof publicKeyShareProofFamily;
        readonly proofVerificationStatus: typeof publicKeyShareSuccinctProofVerificationStatus;
        readonly proofModelStatus: typeof publicKeyShareSuccinctProofModelStatus;
        readonly trusteeIdentity: string;
        readonly trusteeRosterPosition: number;
        readonly statementHash: ProtocolHash;
        readonly proofSizeBytes: number;
        readonly proofBytesHash: ProtocolHash;
    }
>;

export type PublicKeyShareSuccinctProofRecord = Readonly<
    JsonRecord &
        PublicKeyShareSuccinctProofByteMaterial & {
            readonly objectType: 'PublicKeyShareSuccinctProof';
            readonly objectVersion: 1;
            readonly setupProfileId: 'CollectiveBgvSetup-v1';
            readonly setupProofProfileId: typeof setupProofProfileId;
            readonly proofFamily: typeof publicKeyShareProofFamily;
            readonly proofVerificationStatus: typeof publicKeyShareSuccinctProofVerificationStatus;
            readonly proofModelStatus: typeof publicKeyShareSuccinctProofModelStatus;
            readonly trusteeIdentity: string;
            readonly trusteeRosterPosition: number;
            readonly publicKeyShareRoot: ProtocolHash;
            readonly publicKeyShareProofRoot: ProtocolHash;
            readonly publicKeyShareMaterialRoot: ProtocolHash;
            readonly sameSecretStatementRoot: ProtocolHash;
            readonly trusteeSecretCommitmentRoot: ProtocolHash;
            readonly sameSecretProofFamilyBindingRoot: ProtocolHash;
            readonly sameSecretProofRoot: ProtocolHash;
            readonly statementHash: ProtocolHash;
            readonly proofSizeBytes: number;
            readonly proofBytesHash: ProtocolHash;
            readonly publicKeyShareSuccinctProofRoot: ProtocolHash;
        }
>;

export type PublicKeyShareSuccinctProofRootReference = Readonly<{
    readonly trusteeIdentity: string;
    readonly trusteeRosterPosition: number;
    readonly publicKeyShareSuccinctProofRoot: ProtocolHash;
}>;

export type PublicKeyShareSuccinctProofSet = Readonly<
    JsonRecord & {
        readonly objectType: 'PublicKeyShareSuccinctProofSet';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly setupProofProfileId: typeof setupProofProfileId;
        readonly proofFamily: typeof publicKeyShareProofFamily;
        readonly proofVerificationStatus: typeof publicKeyShareSuccinctProofVerificationStatus;
        readonly proofModelStatus: typeof publicKeyShareSuccinctProofModelStatus;
        readonly proofAccountingHash: ProtocolHash;
        readonly participantCount: number;
        readonly rnsLimbCount: number;
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly publicKeyCrpRoot: ProtocolHash;
        readonly publicAPolynomialRoot: ProtocolHash;
        readonly sameSecretConsistencyRoot: ProtocolHash;
        readonly sameSecretProofSetRoot: ProtocolHash;
        readonly sameSecretProofFamilyBindingRoot: ProtocolHash;
        readonly publicKeyShareSetRoot: ProtocolHash;
        readonly publicKeyShareProofSetRoot: ProtocolHash;
        readonly publicKeyShareMaterialSetRoot: ProtocolHash;
        readonly publicKeyShareSuccinctProofRoots: readonly PublicKeyShareSuccinctProofRootReference[];
        readonly proofRecords: readonly PublicKeyShareSuccinctProofRecord[];
        readonly publicKeyShareSuccinctProofSetRoot: ProtocolHash;
    }
>;

export type CollectivePublicKeySourceShareMaterialRoot = Readonly<{
    readonly trusteeIdentity: string;
    readonly trusteeRosterPosition: number;
    readonly publicKeyShareRoot: ProtocolHash;
    readonly publicKeyShareMaterialRoot: ProtocolHash;
}>;

export type CollectivePublicKeyCoefficientVectorMaterial = Readonly<
    JsonRecord & {
        readonly rnsLimbIndex: number;
        readonly rnsPrime: number;
        readonly component: 'b';
        readonly coefficientByteLength: number;
        readonly coefficientVectorHash512: ProtocolHash;
        readonly coefficientsLeHex: string;
    }
>;

export type CollectivePublicKey = Readonly<
    JsonRecord & {
        readonly objectType: 'CollectivePublicKey';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly setupProofProfileId: typeof setupProofProfileId;
        readonly proofFamily: typeof publicKeyShareProofFamily;
        readonly proofVerificationStatus: typeof publicKeyShareSuccinctProofVerificationStatus;
        readonly proofModelStatus: typeof publicKeyShareSuccinctProofModelStatus;
        readonly aggregationStatus: 'succinct-proof-aggregated-with-accepted-setup-proof-accounting';
        readonly materialEncoding: 'embedded-full-collective-public-key-coefficients';
        readonly participantCount: number;
        readonly rnsLimbCount: number;
        readonly ringDegree: number;
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly publicKeyCrpRoot: ProtocolHash;
        readonly publicAPolynomialRoot: ProtocolHash;
        readonly sameSecretConsistencyRoot: ProtocolHash;
        readonly sameSecretProofSetRoot: ProtocolHash;
        readonly sameSecretProofFamilyBindingRoot: ProtocolHash;
        readonly publicKeyShareSetRoot: ProtocolHash;
        readonly publicKeyShareProofSetRoot: ProtocolHash;
        readonly publicKeyShareMaterialSetRoot: ProtocolHash;
        readonly publicKeyShareSuccinctProofSetRoot: ProtocolHash;
        readonly sourceShareMaterialRoots: readonly CollectivePublicKeySourceShareMaterialRoot[];
        readonly aggregateCoefficientVectorsByLimb: readonly CollectivePublicKeyCoefficientVectorMaterial[];
        readonly collectivePublicKeyRoot: ProtocolHash;
    }
>;

export type CollectivePublicKeyInput = Readonly<{
    readonly setupContext: CollectiveBgvSetupContext;
    readonly qSharePrimes: readonly number[];
    readonly participantCount: number;
    readonly ringDegree: number;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly publicKeyCrpRoot: ProtocolHash;
    readonly publicAPolynomialRoot: ProtocolHash;
    readonly sameSecretConsistency: SameSecretConsistencyStatementSet;
    readonly sameSecretProofs: SameSecretProofSet;
    readonly publicKeyShares: PublicKeyShareSet;
    readonly publicKeyShareProofs: PublicKeyShareProofSet;
    readonly publicKeyShareMaterial: PublicKeyShareMaterialSet;
    readonly publicKeyShareSuccinctProofs: PublicKeyShareSuccinctProofSet;
}>;

type CollectivePublicKeySourceBindingInput = Omit<
    CollectivePublicKeyInput,
    'publicKeyShareMaterial'
> & {
    readonly publicKeyShareMaterial: SetupPackagePublicKeyShareMaterialSet;
};

type TransportedCollectivePublicKeyInput = Omit<
    CollectivePublicKeyInput,
    'publicKeyShareMaterial'
> & {
    readonly publicKeyShareMaterial: BinaryChunkedPublicKeyShareMaterialSet;
    readonly transportedPublicKeyShareMaterial:
        | SetupTransportedPublicKeyShareMaterial
        | JsonRecord;
};

export type PublicKeyShareSetInput = {
    readonly setupContext: CollectiveBgvSetupContext;
    readonly qSharePrimes: readonly number[];
    readonly participantCount: number;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly publicKeyCrpRoot: ProtocolHash;
    readonly publicAPolynomialRoot: ProtocolHash;
    readonly sameSecretConsistency: SameSecretConsistencyStatementSet;
    readonly shareContributions: readonly PublicKeyShareContributionInput[];
};

export type PublicKeyShareProofSetInput = Omit<
    PublicKeyShareSetInput,
    'shareContributions'
> & {
    readonly publicKeyShares: PublicKeyShareSet;
};

export type PublicKeyShareMaterialSetInput = Omit<
    PublicKeyShareSetInput,
    'shareContributions' | 'sameSecretConsistency'
> & {
    readonly ringDegree: number;
    readonly publicKeyShares: PublicKeyShareSet;
    readonly materialContributions: readonly PublicKeyShareMaterialContributionInput[];
};

export type PublicKeyShareSuccinctProofSetInput = Omit<
    PublicKeyShareProofSetInput,
    'sameSecretConsistency'
> & {
    readonly sameSecretConsistency: SameSecretConsistencyStatementSet;
    readonly sameSecretProofs: SameSecretProofSet;
    readonly publicKeyShareProofs: PublicKeyShareProofSet;
    readonly publicKeyShareMaterial: SetupPackagePublicKeyShareMaterialSet;
    readonly proofAccountingHash: ProtocolHash;
    readonly proofMaterials: readonly PublicKeyShareSuccinctProofMaterial[];
};

export type TransportedPublicKeyShareProofMaterialSet = Readonly<
    TransportedSetupProofMaterialSet & {
        readonly objectType: 'SetupTransportedPublicKeyShareProofMaterialSet';
        readonly proofFamily: typeof publicKeyShareProofFamily;
    }
>;

export type BinaryChunkedPublicKeyShareProofMaterialTransport = Readonly<{
    readonly proofMaterials: readonly PublicKeyShareSuccinctProofMaterial[];
    readonly transportedPublicKeyShareProofMaterial: TransportedPublicKeyShareProofMaterialSet;
}>;

const protocolHashPattern = /^[0-9a-f]{128}$/u;
const lowercaseHexPattern = /^(?:[0-9a-f]{2})*$/u;
const contextFieldNames = [
    'ceremonyId',
    'manifestHash',
    'rosterHash',
    'setupProfileHash',
    'qShareHash',
    'carryAwareVssShareRelationProfileHash',
    'commitmentProfileHash',
    'setupEpoch',
] as const;

const assertProtocolHash = (value: string, fieldName: string): void => {
    if (!protocolHashPattern.test(value)) {
        throw new TypeError(`${fieldName} must be a protocol hash.`);
    }
};

const assertLowercaseHexBytes = (value: string, fieldName: string): void => {
    if (!lowercaseHexPattern.test(value)) {
        throw new TypeError(`${fieldName} must be lowercase hex bytes.`);
    }
};

const assertPositiveSafeInteger = (value: number, fieldName: string): void => {
    if (!Number.isSafeInteger(value) || value <= 0) {
        throw new TypeError(`${fieldName} must be a positive safe integer.`);
    }
};

const assertNonNegativeSafeInteger = (
    value: number,
    fieldName: string,
): void => {
    if (!Number.isSafeInteger(value) || value < 0) {
        throw new TypeError(
            `${fieldName} must be a non-negative safe integer.`,
        );
    }
};

const assertNonEmptyString = (value: string, fieldName: string): void => {
    if (value.length === 0) {
        throw new TypeError(`${fieldName} must be non-empty.`);
    }
};

const bytesFromHex = (hex: string, fieldName: string): Uint8Array => {
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

const coefficientVectorFromLittleEndianHex = (
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

const bytesToHex = (bytes: Uint8Array): string =>
    Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');

const publicKeyShareMaterialBinaryMagic = new Uint8Array([
    0x53, 0x4c, 0x50, 0x4b, 0x53, 0x4d, 0x56, 0x31,
]);

const appendVaruint = (outputBytes: number[], value: number): void => {
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

const setupTransportChunkManifestRoot = (input: {
    readonly chunkSizeBytes: number;
    readonly chunkCount: number;
    readonly totalByteLength: number;
    readonly chunkHashes: readonly ProtocolHash[];
    readonly fullObjectHash: ProtocolHash;
}): ProtocolHash =>
    deriveProtocolHash('SetupTransportChunkManifestRoot', {
        objectType: 'SetupTransportChunkManifest',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        transportProfileId: setupTransportProfileId,
        chunkSizeBytes: input.chunkSizeBytes,
        chunkCount: input.chunkCount,
        totalByteLength: input.totalByteLength,
        chunkHashes: input.chunkHashes,
        fullObjectHash: input.fullObjectHash,
    });

const publicKeyShareMaterialFullObjectHash = (
    totalByteLength: number,
    chunks: readonly Uint8Array[],
): ProtocolHash => {
    const totalLengthBytes = new Uint8Array(8);
    new DataView(totalLengthBytes.buffer).setBigUint64(
        0,
        BigInt(totalByteLength),
        true,
    );

    return hash512Hex(
        'sealed-lattice/setup/public-key-share-material/full-object-v1',
        [totalLengthBytes, ...chunks],
    );
};

const publicKeyShareMaterialChunkHash = (
    fullObjectHash: ProtocolHash,
    chunkIndex: number,
    chunk: Uint8Array,
): ProtocolHash => {
    const chunkIndexBytes = new Uint8Array(8);
    new DataView(chunkIndexBytes.buffer).setBigUint64(
        0,
        BigInt(chunkIndex),
        true,
    );

    return hash512Hex(
        'sealed-lattice/setup/public-key-share-material/chunk-v1',
        [new TextEncoder().encode(fullObjectHash), chunkIndexBytes, chunk],
    );
};

const publicKeyShareMaterialTransportHashes = (
    chunks: readonly Uint8Array[],
): Readonly<{
    readonly fullObjectHash: ProtocolHash;
    readonly chunkHashes: readonly ProtocolHash[];
    readonly chunkRoot: ProtocolHash;
    readonly totalByteLength: number;
}> => {
    if (chunks.length === 0) {
        throw new Error(
            'public-key share material transport requires at least one chunk.',
        );
    }
    const totalByteLength = chunks.reduce(
        (accumulatedLength, chunk, chunkIndex) => {
            if (chunk.byteLength === 0) {
                throw new Error(
                    'public-key share material chunks must be non-empty.',
                );
            }
            if (chunk.byteLength > setupTransportChunkSizeBytes) {
                throw new Error(
                    'public-key share material chunk exceeds the accepted chunk size.',
                );
            }
            if (
                chunkIndex + 1 < chunks.length &&
                chunk.byteLength !== setupTransportChunkSizeBytes
            ) {
                throw new Error(
                    'public-key share material contains a short non-final chunk.',
                );
            }

            return accumulatedLength + chunk.byteLength;
        },
        0,
    );
    const fullObjectHash = publicKeyShareMaterialFullObjectHash(
        totalByteLength,
        chunks,
    );
    const chunkHashes = chunks.map((chunk, chunkIndex) =>
        publicKeyShareMaterialChunkHash(fullObjectHash, chunkIndex, chunk),
    );
    const chunkRoot = setupTransportChunkManifestRoot({
        chunkSizeBytes: setupTransportChunkSizeBytes,
        chunkCount: chunks.length,
        totalByteLength,
        chunkHashes,
        fullObjectHash,
    });

    return {
        fullObjectHash,
        chunkHashes,
        chunkRoot,
        totalByteLength,
    };
};

const coefficientVectorHash512 = (coefficients: readonly number[]): string =>
    hash512Hex(publicKeyShareCoefficientVectorHashDomain, [
        coefficientVectorBytes(coefficients),
    ]);

const coefficientVectorToLittleEndianHex = (
    coefficients: readonly number[],
): string => bytesToHex(coefficientVectorBytes(coefficients));

const contextFields = (
    setupContext: CollectiveBgvSetupContext,
): Pick<CollectiveBgvSetupContext, (typeof contextFieldNames)[number]> => ({
    ceremonyId: setupContext.ceremonyId,
    manifestHash: setupContext.manifestHash,
    rosterHash: setupContext.rosterHash,
    setupProfileHash: setupContext.setupProfileHash,
    qShareHash: setupContext.qShareHash,
    carryAwareVssShareRelationProfileHash:
        setupContext.carryAwareVssShareRelationProfileHash,
    commitmentProfileHash: setupContext.commitmentProfileHash,
    setupEpoch: setupContext.setupEpoch,
});

const assertContextMatches = (
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

const sortedByRosterPosition = <
    RecordValue extends { readonly trusteeRosterPosition: number },
>(
    records: readonly RecordValue[],
): RecordValue[] =>
    [...records].sort(
        (left, right) =>
            left.trusteeRosterPosition - right.trusteeRosterPosition,
    );

const statementRecordsByRosterPosition = (
    input: Pick<
        PublicKeyShareSetInput,
        'participantCount' | 'sameSecretConsistency' | 'setupContext'
    >,
): ReadonlyMap<number, SameSecretConsistencyStatementRecord> => {
    assertContextMatches(
        input.setupContext,
        input.sameSecretConsistency,
        'sameSecretConsistency',
    );
    assertProtocolHash(
        input.sameSecretConsistency.sameSecretConsistencyRoot,
        'sameSecretConsistency.sameSecretConsistencyRoot',
    );
    const sortedStatements = sortedByRosterPosition(
        input.sameSecretConsistency.statementRecords,
    );
    if (sortedStatements.length !== input.participantCount) {
        throw new Error(
            'sameSecretConsistency.statementRecords must contain every participant.',
        );
    }
    const statementsByRosterPosition = new Map<
        number,
        SameSecretConsistencyStatementRecord
    >();
    sortedStatements.forEach((statementRecord, expectedRosterPosition) => {
        assertNonEmptyString(
            statementRecord.trusteeIdentity,
            'sameSecretStatement.trusteeIdentity',
        );
        if (statementRecord.trusteeRosterPosition !== expectedRosterPosition) {
            throw new Error(
                'sameSecretConsistency.statementRecords roster positions must be contiguous from zero.',
            );
        }
        assertProtocolHash(
            statementRecord.sameSecretStatementRoot,
            'sameSecretStatement.sameSecretStatementRoot',
        );
        assertProtocolHash(
            statementRecord.trusteeSecretCommitmentRoot,
            'sameSecretStatement.trusteeSecretCommitmentRoot',
        );
        statementsByRosterPosition.set(
            statementRecord.trusteeRosterPosition,
            statementRecord,
        );
    });

    return statementsByRosterPosition;
};

const validateCommonInput = (
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

const validateShareContribution = (
    contribution: PublicKeyShareContributionInput,
    expectedRosterPosition: number,
    qSharePrimes: readonly number[],
): void => {
    assertNonEmptyString(contribution.trusteeIdentity, 'trusteeIdentity');
    assertNonNegativeSafeInteger(
        contribution.trusteeRosterPosition,
        'trusteeRosterPosition',
    );
    if (contribution.trusteeRosterPosition !== expectedRosterPosition) {
        throw new Error(
            'shareContributions roster positions must be contiguous from zero.',
        );
    }
    if (
        contribution.shareCoefficientVectorHash512ByLimb.length !==
        qSharePrimes.length
    ) {
        throw new Error(
            'shareCoefficientVectorHash512ByLimb must contain one entry for every Q_share limb.',
        );
    }
    contribution.shareCoefficientVectorHash512ByLimb.forEach(
        (coefficientHash, rnsLimbIndex) => {
            if (
                coefficientHash.rnsLimbIndex !== rnsLimbIndex ||
                coefficientHash.rnsPrime !== qSharePrimes[rnsLimbIndex]
            ) {
                throw new Error(
                    'shareCoefficientVectorHash512ByLimb entries must follow Q_share order.',
                );
            }
            if (coefficientHash.component !== 'b_i') {
                throw new Error(
                    'shareCoefficientVectorHash512ByLimb component must be b_i.',
                );
            }
            assertProtocolHash(
                coefficientHash.coefficientVectorHash512,
                'shareCoefficientVectorHash512ByLimb.coefficientVectorHash512',
            );
        },
    );
};

export const createPublicKeyShareSet = (
    input: PublicKeyShareSetInput,
): PublicKeyShareSet => {
    validateCommonInput(input);
    const statementsByRosterPosition = statementRecordsByRosterPosition(input);
    const shareContributions = sortedByRosterPosition(input.shareContributions);
    if (shareContributions.length !== input.participantCount) {
        throw new Error(
            'shareContributions must contain one public-key share per participant.',
        );
    }
    const shareRecords = shareContributions.map(
        (contribution, expectedRosterPosition) => {
            validateShareContribution(
                contribution,
                expectedRosterPosition,
                input.qSharePrimes,
            );
            const sameSecretStatement = statementsByRosterPosition.get(
                contribution.trusteeRosterPosition,
            );
            if (sameSecretStatement === undefined) {
                throw new Error(
                    'shareContributions must reference an accepted same-secret statement.',
                );
            }
            if (
                sameSecretStatement.trusteeIdentity !==
                contribution.trusteeIdentity
            ) {
                throw new Error(
                    'shareContributions trusteeIdentity must match same-secret statements.',
                );
            }
            const shareRecordWithoutRoot = {
                objectType: 'PublicKeyShare',
                objectVersion: 1,
                setupProfileId: 'CollectiveBgvSetup-v1',
                setupProofProfileId,
                ...contextFields(input.setupContext),
                trusteeIdentity: contribution.trusteeIdentity,
                trusteeRosterPosition: contribution.trusteeRosterPosition,
                publicMatrixSeedHash: input.publicMatrixSeedHash,
                publicKeyCrpRoot: input.publicKeyCrpRoot,
                publicAPolynomialRoot: input.publicAPolynomialRoot,
                sameSecretStatementRoot:
                    sameSecretStatement.sameSecretStatementRoot,
                trusteeSecretCommitmentRoot:
                    sameSecretStatement.trusteeSecretCommitmentRoot,
                shareComponent: 'component-zero-b_i',
                rnsLimbCount: input.qSharePrimes.length,
                shareCoefficientVectorHash512ByLimb:
                    contribution.shareCoefficientVectorHash512ByLimb,
                proofBindingStatus: publicKeyShareProofBindingStatus,
            } as const satisfies Omit<
                PublicKeyShareRecord,
                'publicKeyShareRoot'
            >;

            return {
                ...shareRecordWithoutRoot,
                publicKeyShareRoot: deriveProtocolHash(
                    'PublicKeyShareRoot',
                    shareRecordWithoutRoot,
                ),
            } satisfies PublicKeyShareRecord;
        },
    );
    const shareSetWithoutRoot = {
        objectType: 'PublicKeyShareSet',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        setupProofProfileId,
        proofBindingStatus: publicKeyShareProofBindingStatus,
        ...contextFields(input.setupContext),
        participantCount: input.participantCount,
        rnsLimbCount: input.qSharePrimes.length,
        publicMatrixSeedHash: input.publicMatrixSeedHash,
        publicKeyCrpRoot: input.publicKeyCrpRoot,
        publicAPolynomialRoot: input.publicAPolynomialRoot,
        sameSecretConsistencyRoot:
            input.sameSecretConsistency.sameSecretConsistencyRoot,
        publicKeyShareRoots: shareRecords.map((shareRecord) => ({
            trusteeIdentity: shareRecord.trusteeIdentity,
            trusteeRosterPosition: shareRecord.trusteeRosterPosition,
            publicKeyShareRoot: shareRecord.publicKeyShareRoot,
        })),
        shareRecords,
    } as const satisfies Omit<PublicKeyShareSet, 'publicKeyShareSetRoot'>;

    return {
        ...shareSetWithoutRoot,
        publicKeyShareSetRoot: deriveProtocolHash(
            'PublicKeyShareRoot',
            shareSetWithoutRoot,
        ),
    } satisfies PublicKeyShareSet;
};

export const createPublicKeyShareProofSet = (
    input: PublicKeyShareProofSetInput,
): PublicKeyShareProofSet => {
    validateCommonInput(input);
    assertContextMatches(
        input.setupContext,
        input.publicKeyShares,
        'publicKeyShares',
    );
    if (
        input.publicKeyShares.publicMatrixSeedHash !==
            input.publicMatrixSeedHash ||
        input.publicKeyShares.publicKeyCrpRoot !== input.publicKeyCrpRoot ||
        input.publicKeyShares.publicAPolynomialRoot !==
            input.publicAPolynomialRoot ||
        input.publicKeyShares.sameSecretConsistencyRoot !==
            input.sameSecretConsistency.sameSecretConsistencyRoot
    ) {
        throw new Error(
            'publicKeyShares must bind the same common randomness and same-secret roots.',
        );
    }
    const statementsByRosterPosition = statementRecordsByRosterPosition(input);
    const shareRecords = sortedByRosterPosition(
        input.publicKeyShares.shareRecords,
    );
    if (shareRecords.length !== input.participantCount) {
        throw new Error(
            'publicKeyShares.shareRecords must contain one share per participant.',
        );
    }
    const proofRecords = shareRecords.map(
        (shareRecord, expectedRosterPosition) => {
            if (shareRecord.trusteeRosterPosition !== expectedRosterPosition) {
                throw new Error(
                    'publicKeyShares.shareRecords roster positions must be contiguous from zero.',
                );
            }
            const sameSecretStatement = statementsByRosterPosition.get(
                shareRecord.trusteeRosterPosition,
            );
            if (sameSecretStatement === undefined) {
                throw new Error(
                    'publicKeyShares.shareRecords must reference an accepted same-secret statement.',
                );
            }
            if (
                shareRecord.trusteeIdentity !==
                    sameSecretStatement.trusteeIdentity ||
                shareRecord.sameSecretStatementRoot !==
                    sameSecretStatement.sameSecretStatementRoot ||
                shareRecord.trusteeSecretCommitmentRoot !==
                    sameSecretStatement.trusteeSecretCommitmentRoot
            ) {
                throw new Error(
                    'publicKeyShares.shareRecords must bind the accepted same-secret statement.',
                );
            }
            const proofRecordWithoutRoot = {
                objectType: 'PublicKeyShareProof',
                objectVersion: 1,
                setupProfileId: 'CollectiveBgvSetup-v1',
                setupProofProfileId,
                proofFamily: publicKeyShareProofFamily,
                proofVerificationStatus: publicKeyShareProofVerificationStatus,
                ...contextFields(input.setupContext),
                trusteeIdentity: shareRecord.trusteeIdentity,
                trusteeRosterPosition: shareRecord.trusteeRosterPosition,
                publicMatrixSeedHash: input.publicMatrixSeedHash,
                publicKeyCrpRoot: input.publicKeyCrpRoot,
                publicAPolynomialRoot: input.publicAPolynomialRoot,
                publicKeyShareRoot: shareRecord.publicKeyShareRoot,
                sameSecretStatementRoot:
                    sameSecretStatement.sameSecretStatementRoot,
                trusteeSecretCommitmentRoot:
                    sameSecretStatement.trusteeSecretCommitmentRoot,
                rnsLimbCount: input.qSharePrimes.length,
                errorSupport: 'checked-by-public-key-share-succinct-proof-set',
                proofBytesStatus:
                    'supplied-by-public-key-share-succinct-proof-set',
            } as const satisfies Omit<
                PublicKeyShareProofRecord,
                'publicKeyShareProofRoot'
            >;

            return {
                ...proofRecordWithoutRoot,
                publicKeyShareProofRoot: deriveProtocolHash(
                    'PublicKeyShareProofRoot',
                    proofRecordWithoutRoot,
                ),
            } satisfies PublicKeyShareProofRecord;
        },
    );
    const proofSetWithoutRoot = {
        objectType: 'PublicKeyShareProofSet',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        setupProofProfileId,
        proofFamily: publicKeyShareProofFamily,
        proofVerificationStatus: publicKeyShareProofVerificationStatus,
        ...contextFields(input.setupContext),
        participantCount: input.participantCount,
        rnsLimbCount: input.qSharePrimes.length,
        publicMatrixSeedHash: input.publicMatrixSeedHash,
        publicKeyCrpRoot: input.publicKeyCrpRoot,
        publicAPolynomialRoot: input.publicAPolynomialRoot,
        sameSecretConsistencyRoot:
            input.sameSecretConsistency.sameSecretConsistencyRoot,
        publicKeyShareSetRoot: input.publicKeyShares.publicKeyShareSetRoot,
        publicKeyShareProofRoots: proofRecords.map((proofRecord) => ({
            trusteeIdentity: proofRecord.trusteeIdentity,
            trusteeRosterPosition: proofRecord.trusteeRosterPosition,
            publicKeyShareProofRoot: proofRecord.publicKeyShareProofRoot,
        })),
        proofRecords,
    } as const satisfies Omit<
        PublicKeyShareProofSet,
        'publicKeyShareProofSetRoot'
    >;

    return {
        ...proofSetWithoutRoot,
        publicKeyShareProofSetRoot: deriveProtocolHash(
            'PublicKeyShareProofRoot',
            proofSetWithoutRoot,
        ),
    } satisfies PublicKeyShareProofSet;
};

const publicKeyShareRecordsByRosterPosition = (
    input: Pick<
        PublicKeyShareMaterialSetInput,
        'setupContext' | 'participantCount' | 'publicKeyShares'
    >,
): ReadonlyMap<number, PublicKeyShareRecord> => {
    assertContextMatches(
        input.setupContext,
        input.publicKeyShares,
        'publicKeyShares',
    );
    assertProtocolHash(
        input.publicKeyShares.publicKeyShareSetRoot,
        'publicKeyShares.publicKeyShareSetRoot',
    );
    const shareRecords = sortedByRosterPosition(
        input.publicKeyShares.shareRecords,
    );
    if (shareRecords.length !== input.participantCount) {
        throw new Error(
            'publicKeyShares.shareRecords must contain one share per participant.',
        );
    }
    const recordsByRosterPosition = new Map<number, PublicKeyShareRecord>();
    shareRecords.forEach((shareRecord, expectedRosterPosition) => {
        if (shareRecord.trusteeRosterPosition !== expectedRosterPosition) {
            throw new Error(
                'publicKeyShares.shareRecords roster positions must be contiguous from zero.',
            );
        }
        assertNonEmptyString(
            shareRecord.trusteeIdentity,
            'publicKeyShares.shareRecords.trusteeIdentity',
        );
        assertProtocolHash(
            shareRecord.publicKeyShareRoot,
            'publicKeyShares.shareRecords.publicKeyShareRoot',
        );
        recordsByRosterPosition.set(
            shareRecord.trusteeRosterPosition,
            shareRecord,
        );
    });

    return recordsByRosterPosition;
};

const validatePublicKeyShareMaterialContribution = (
    contribution: PublicKeyShareMaterialContributionInput,
    expectedRosterPosition: number,
    input: PublicKeyShareMaterialSetInput,
    shareRecord: PublicKeyShareRecord,
): readonly PublicKeyShareCoefficientVectorMaterial[] => {
    assertNonEmptyString(contribution.trusteeIdentity, 'trusteeIdentity');
    assertNonNegativeSafeInteger(
        contribution.trusteeRosterPosition,
        'trusteeRosterPosition',
    );
    if (
        contribution.trusteeRosterPosition !== expectedRosterPosition ||
        contribution.trusteeIdentity !== shareRecord.trusteeIdentity
    ) {
        throw new Error(
            'publicKeyShareMaterialContributions must match accepted public-key share records.',
        );
    }
    if (
        contribution.shareCoefficientVectorsByLimb.length !==
        input.qSharePrimes.length
    ) {
        throw new Error(
            'publicKeyShareMaterialContributions must contain one coefficient vector per Q_share limb.',
        );
    }

    return contribution.shareCoefficientVectorsByLimb.map(
        (coefficientVector, rnsLimbIndex) => {
            const rnsPrime = input.qSharePrimes[rnsLimbIndex];
            if (
                rnsPrime === undefined ||
                coefficientVector.rnsLimbIndex !== rnsLimbIndex ||
                coefficientVector.rnsPrime !== rnsPrime ||
                coefficientVector.component !== 'b_i'
            ) {
                throw new Error(
                    'publicKeyShareMaterialContributions limb metadata must follow Q_share order.',
                );
            }
            if (
                coefficientVector.coefficientByteLength !==
                input.ringDegree * 8
            ) {
                throw new Error(
                    'publicKeyShareMaterialContributions coefficient byte length must match ringDegree.',
                );
            }
            assertProtocolHash(
                coefficientVector.coefficientVectorHash512,
                'publicKeyShareMaterialContributions.coefficientVectorHash512',
            );
            const coefficients = coefficientVectorFromLittleEndianHex(
                coefficientVector.coefficientsLeHex,
                input.ringDegree,
                'publicKeyShareMaterialContributions.coefficientsLeHex',
            );
            if (coefficients.some((coefficient) => coefficient >= rnsPrime)) {
                throw new Error(
                    'publicKeyShareMaterialContributions coefficients must be canonical residues.',
                );
            }
            const coefficientVectorHash =
                coefficientVectorHash512(coefficients);
            const shareCoefficientHash =
                shareRecord.shareCoefficientVectorHash512ByLimb[rnsLimbIndex];
            if (
                coefficientVector.coefficientVectorHash512 !==
                    coefficientVectorHash ||
                shareCoefficientHash?.coefficientVectorHash512 !==
                    coefficientVectorHash ||
                shareCoefficientHash.rnsLimbIndex !== rnsLimbIndex ||
                shareCoefficientHash.rnsPrime !== rnsPrime ||
                shareCoefficientHash.component !== 'b_i'
            ) {
                throw new Error(
                    'publicKeyShareMaterialContributions coefficient hash must match the accepted share record.',
                );
            }

            return {
                rnsLimbIndex,
                rnsPrime,
                component: 'b_i',
                coefficientByteLength: coefficientVector.coefficientByteLength,
                coefficientVectorHash512: coefficientVectorHash,
                coefficientsLeHex: coefficientVector.coefficientsLeHex,
            };
        },
    );
};

const publicKeyShareMaterialRecordsFromContributions = (
    input: PublicKeyShareMaterialSetInput,
): readonly PublicKeyShareMaterialRecord[] => {
    const shareRecords = publicKeyShareRecordsByRosterPosition(input);
    const materialContributions = sortedByRosterPosition(
        input.materialContributions,
    );
    if (materialContributions.length !== input.participantCount) {
        throw new Error(
            'publicKeyShareMaterialContributions must contain one contribution per participant.',
        );
    }
    const shareMaterialRecords = materialContributions.map(
        (contribution, expectedRosterPosition) => {
            const shareRecord = shareRecords.get(expectedRosterPosition);
            if (shareRecord === undefined) {
                throw new Error(
                    'publicKeyShareMaterialContributions must reference accepted public-key share records.',
                );
            }
            const shareCoefficientVectorsByLimb =
                validatePublicKeyShareMaterialContribution(
                    contribution,
                    expectedRosterPosition,
                    input,
                    shareRecord,
                );
            const materialRecordWithoutRoot = {
                objectType: 'PublicKeyShareMaterial',
                objectVersion: 1,
                setupProfileId: 'CollectiveBgvSetup-v1',
                setupProofProfileId,
                proofFamily: publicKeyShareProofFamily,
                proofModelStatus: publicKeyShareSuccinctProofModelStatus,
                materialEncoding: publicKeyShareMaterialEncoding,
                ...contextFields(input.setupContext),
                trusteeIdentity: shareRecord.trusteeIdentity,
                trusteeRosterPosition: shareRecord.trusteeRosterPosition,
                rnsLimbCount: input.qSharePrimes.length,
                ringDegree: input.ringDegree,
                publicMatrixSeedHash: input.publicMatrixSeedHash,
                publicKeyCrpRoot: input.publicKeyCrpRoot,
                publicAPolynomialRoot: input.publicAPolynomialRoot,
                publicKeyShareRoot: shareRecord.publicKeyShareRoot,
                shareCoefficientVectorsByLimb,
            } as const satisfies Omit<
                PublicKeyShareMaterialRecord,
                'publicKeyShareMaterialRoot'
            >;

            return {
                ...materialRecordWithoutRoot,
                publicKeyShareMaterialRoot: deriveProtocolHash(
                    'PublicKeyShareRoot',
                    materialRecordWithoutRoot,
                ),
            } satisfies PublicKeyShareMaterialRecord;
        },
    );

    return shareMaterialRecords;
};

const assertPublicKeyShareMaterialInput = (
    input: PublicKeyShareMaterialSetInput,
): void => {
    validateCommonInput(input);
    assertPositiveSafeInteger(input.ringDegree, 'ringDegree');
    assertContextMatches(
        input.setupContext,
        input.publicKeyShares,
        'publicKeyShares',
    );
    if (
        input.publicKeyShares.participantCount !== input.participantCount ||
        input.publicKeyShares.rnsLimbCount !== input.qSharePrimes.length ||
        input.publicKeyShares.publicMatrixSeedHash !==
            input.publicMatrixSeedHash ||
        input.publicKeyShares.publicKeyCrpRoot !== input.publicKeyCrpRoot ||
        input.publicKeyShares.publicAPolynomialRoot !==
            input.publicAPolynomialRoot
    ) {
        throw new Error(
            'publicKeyShares must bind the same public-key material input.',
        );
    }
};

const publicKeyShareMaterialRootReferences = (
    shareMaterialRecords: readonly PublicKeyShareMaterialRecord[],
): readonly PublicKeyShareMaterialRootReference[] =>
    shareMaterialRecords.map((materialRecord) => ({
        trusteeIdentity: materialRecord.trusteeIdentity,
        trusteeRosterPosition: materialRecord.trusteeRosterPosition,
        publicKeyShareMaterialRoot: materialRecord.publicKeyShareMaterialRoot,
    }));

export const createPublicKeyShareMaterialSet = (
    input: PublicKeyShareMaterialSetInput,
): PublicKeyShareMaterialSet => {
    assertPublicKeyShareMaterialInput(input);
    const shareMaterialRecords =
        publicKeyShareMaterialRecordsFromContributions(input);
    const materialSetWithoutRoot = {
        objectType: 'PublicKeyShareMaterialSet',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        setupProofProfileId,
        proofFamily: publicKeyShareProofFamily,
        proofModelStatus: publicKeyShareSuccinctProofModelStatus,
        materialEncoding: publicKeyShareMaterialEncoding,
        ...contextFields(input.setupContext),
        participantCount: input.participantCount,
        rnsLimbCount: input.qSharePrimes.length,
        ringDegree: input.ringDegree,
        publicMatrixSeedHash: input.publicMatrixSeedHash,
        publicKeyCrpRoot: input.publicKeyCrpRoot,
        publicAPolynomialRoot: input.publicAPolynomialRoot,
        publicKeyShareSetRoot: input.publicKeyShares.publicKeyShareSetRoot,
        publicKeyShareMaterialRoots:
            publicKeyShareMaterialRootReferences(shareMaterialRecords),
        shareMaterialRecords,
    } as const satisfies Omit<
        PublicKeyShareMaterialSet,
        'publicKeyShareMaterialSetRoot'
    >;

    return {
        ...materialSetWithoutRoot,
        publicKeyShareMaterialSetRoot: deriveProtocolHash(
            'PublicKeyShareRoot',
            materialSetWithoutRoot,
        ),
    } satisfies PublicKeyShareMaterialSet;
};

const sortedPublicKeyShareMaterialRecords = (input: {
    readonly participantCount: number;
    readonly shareMaterialRecords: readonly PublicKeyShareMaterialRecord[];
}): readonly PublicKeyShareMaterialRecord[] => {
    const materialRecords = sortedByRosterPosition(input.shareMaterialRecords);
    if (materialRecords.length !== input.participantCount) {
        throw new Error(
            'publicKeyShareMaterial.shareMaterialRecords must contain one record per participant.',
        );
    }
    materialRecords.forEach((materialRecord, expectedRosterPosition) => {
        if (materialRecord.trusteeRosterPosition !== expectedRosterPosition) {
            throw new Error(
                'publicKeyShareMaterial.shareMaterialRecords roster positions must be contiguous from zero.',
            );
        }
    });

    return materialRecords;
};

const encodePublicKeyShareMaterialRecords = (
    input: Readonly<{
        readonly participantCount: number;
        readonly rnsLimbCount: number;
        readonly ringDegree: number;
        readonly shareMaterialRecords: readonly PublicKeyShareMaterialRecord[];
    }>,
): readonly Uint8Array[] => {
    const writer = new BinaryChunkWriter({
        chunkSizeBytes: setupTransportChunkSizeBytes,
        emptyErrorMessage:
            'public-key share material transport requires bytes.',
    });
    writer.writeBytes(publicKeyShareMaterialBinaryMagic);
    writer.writeVaruint(1);
    writer.writeVaruint(input.participantCount);
    writer.writeVaruint(input.rnsLimbCount);
    writer.writeVaruint(input.ringDegree);
    sortedPublicKeyShareMaterialRecords(input).forEach((materialRecord) => {
        writer.writeVaruint(materialRecord.trusteeRosterPosition);
        materialRecord.shareCoefficientVectorsByLimb.forEach(
            (coefficientVector, expectedRnsLimbIndex) => {
                if (
                    coefficientVector.rnsLimbIndex !== expectedRnsLimbIndex ||
                    coefficientVector.component !== 'b_i'
                ) {
                    throw new Error(
                        'publicKeyShareMaterial coefficient vector limbs must follow Q_share order.',
                    );
                }
                writer.writeVaruint(expectedRnsLimbIndex);
                writer.writeU64LittleEndian(
                    coefficientVector.rnsPrime,
                    'publicKeyShareMaterial.rnsPrime',
                );
                const coefficients = coefficientVectorFromLittleEndianHex(
                    coefficientVector.coefficientsLeHex,
                    input.ringDegree,
                    'publicKeyShareMaterial.coefficientsLeHex',
                );
                if (
                    coefficients.some(
                        (coefficient) =>
                            coefficient >= coefficientVector.rnsPrime,
                    ) ||
                    coefficientVector.coefficientVectorHash512 !==
                        coefficientVectorHash512(coefficients)
                ) {
                    throw new Error(
                        'publicKeyShareMaterial coefficient vectors must be canonical and hash-bound before transport encoding.',
                    );
                }
                coefficients.forEach((coefficient) =>
                    writer.writeU64LittleEndian(
                        coefficient,
                        'publicKeyShareMaterial.coefficient',
                    ),
                );
            },
        );
    });

    return writer.finish();
};

const encodePublicKeyShareMaterial = (
    materialSet: PublicKeyShareMaterialSet,
): readonly Uint8Array[] => encodePublicKeyShareMaterialRecords(materialSet);

const binaryChunkedPublicKeyShareMaterialSetFromTransport = (
    input: Readonly<{
        readonly setupContext: CollectiveBgvSetupContext;
        readonly participantCount: number;
        readonly rnsLimbCount: number;
        readonly ringDegree: number;
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly publicKeyCrpRoot: ProtocolHash;
        readonly publicAPolynomialRoot: ProtocolHash;
        readonly publicKeyShareSetRoot: ProtocolHash;
        readonly publicKeyShareMaterialRoots: readonly PublicKeyShareMaterialRootReference[];
        readonly chunkCount: number;
        readonly transportHashes: Readonly<{
            readonly fullObjectHash: ProtocolHash;
            readonly chunkRoot: ProtocolHash;
            readonly totalByteLength: number;
        }>;
    }>,
): BinaryChunkedPublicKeyShareMaterialSet => {
    const materialSetWithoutRoot = {
        objectType: 'PublicKeyShareMaterialSet',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        setupProofProfileId,
        proofFamily: publicKeyShareProofFamily,
        proofModelStatus: publicKeyShareSuccinctProofModelStatus,
        materialEncoding: publicKeyShareMaterialTransportEncoding,
        binaryFormat: publicKeyShareMaterialBinaryFormat,
        ...contextFields(input.setupContext),
        participantCount: input.participantCount,
        rnsLimbCount: input.rnsLimbCount,
        ringDegree: input.ringDegree,
        publicMatrixSeedHash: input.publicMatrixSeedHash,
        publicKeyCrpRoot: input.publicKeyCrpRoot,
        publicAPolynomialRoot: input.publicAPolynomialRoot,
        publicKeyShareSetRoot: input.publicKeyShareSetRoot,
        publicKeyShareMaterialRoots: input.publicKeyShareMaterialRoots,
        transport: {
            transportProfileId: setupTransportProfileId,
            chunkSizeBytes: setupTransportChunkSizeBytes,
            chunkCount: input.chunkCount,
            totalByteLength: input.transportHashes.totalByteLength,
            fullObjectHash: input.transportHashes.fullObjectHash,
            chunkRoot: input.transportHashes.chunkRoot,
        },
    } as const satisfies Omit<
        BinaryChunkedPublicKeyShareMaterialSet,
        'publicKeyShareMaterialSetRoot'
    >;

    return {
        ...materialSetWithoutRoot,
        publicKeyShareMaterialSetRoot: deriveProtocolHash(
            'PublicKeyShareRoot',
            materialSetWithoutRoot,
        ),
    } satisfies BinaryChunkedPublicKeyShareMaterialSet;
};

const transportedPublicKeyShareMaterialFromChunks = (
    chunks: readonly Uint8Array[],
): SetupTransportedPublicKeyShareMaterial => {
    const transportHashes = publicKeyShareMaterialTransportHashes(chunks);

    return {
        objectType: 'SetupTransportedPublicKeyShareMaterial',
        objectVersion: 1,
        binaryFormat: publicKeyShareMaterialBinaryFormat,
        chunkSizeBytes: setupTransportChunkSizeBytes,
        chunkCount: chunks.length,
        totalByteLength: transportHashes.totalByteLength,
        fullObjectHash: transportHashes.fullObjectHash,
        chunkHashes: transportHashes.chunkHashes,
        chunkRoot: transportHashes.chunkRoot,
        chunks: chunks.map((chunk, chunkIndex) => ({
            chunkIndex,
            bytesHex: bytesToHex(chunk),
        })),
    };
};

export const createBinaryChunkedPublicKeyShareMaterialTransport = (
    materialSet: PublicKeyShareMaterialSet,
): BinaryChunkedPublicKeyShareMaterialTransport => {
    if (materialSet.materialEncoding !== publicKeyShareMaterialEncoding) {
        throw new Error(
            'binary public-key share material transport must be built from embedded full public values.',
        );
    }
    const chunks = encodePublicKeyShareMaterial(materialSet);
    const transportedMaterial =
        transportedPublicKeyShareMaterialFromChunks(chunks);
    const binaryMaterialSet =
        binaryChunkedPublicKeyShareMaterialSetFromTransport({
            setupContext: materialSet as unknown as CollectiveBgvSetupContext,
            participantCount: materialSet.participantCount,
            rnsLimbCount: materialSet.rnsLimbCount,
            ringDegree: materialSet.ringDegree,
            publicMatrixSeedHash: materialSet.publicMatrixSeedHash,
            publicKeyCrpRoot: materialSet.publicKeyCrpRoot,
            publicAPolynomialRoot: materialSet.publicAPolynomialRoot,
            publicKeyShareSetRoot: materialSet.publicKeyShareSetRoot,
            publicKeyShareMaterialRoots:
                materialSet.publicKeyShareMaterialRoots,
            chunkCount: transportedMaterial.chunkCount,
            transportHashes: {
                fullObjectHash: transportedMaterial.fullObjectHash,
                chunkRoot: transportedMaterial.chunkRoot,
                totalByteLength: transportedMaterial.totalByteLength,
            },
        });

    return {
        materialSet: binaryMaterialSet,
        transportedPublicKeyShareMaterial: transportedMaterial,
    };
};

export const createBinaryChunkedPublicKeyShareMaterialBundle = (
    input: PublicKeyShareMaterialSetInput,
): BinaryChunkedPublicKeyShareMaterialBundle => {
    assertPublicKeyShareMaterialInput(input);
    const shareMaterialRecords =
        publicKeyShareMaterialRecordsFromContributions(input);
    const chunks = encodePublicKeyShareMaterialRecords({
        participantCount: input.participantCount,
        rnsLimbCount: input.qSharePrimes.length,
        ringDegree: input.ringDegree,
        shareMaterialRecords,
    });
    const transportedMaterial =
        transportedPublicKeyShareMaterialFromChunks(chunks);
    const materialSet = binaryChunkedPublicKeyShareMaterialSetFromTransport({
        setupContext: input.setupContext,
        participantCount: input.participantCount,
        rnsLimbCount: input.qSharePrimes.length,
        ringDegree: input.ringDegree,
        publicMatrixSeedHash: input.publicMatrixSeedHash,
        publicKeyCrpRoot: input.publicKeyCrpRoot,
        publicAPolynomialRoot: input.publicAPolynomialRoot,
        publicKeyShareSetRoot: input.publicKeyShares.publicKeyShareSetRoot,
        publicKeyShareMaterialRoots:
            publicKeyShareMaterialRootReferences(shareMaterialRecords),
        chunkCount: transportedMaterial.chunkCount,
        transportHashes: {
            fullObjectHash: transportedMaterial.fullObjectHash,
            chunkRoot: transportedMaterial.chunkRoot,
            totalByteLength: transportedMaterial.totalByteLength,
        },
    });

    return {
        materialSet,
        transportedPublicKeyShareMaterial: transportedMaterial,
    };
};

class PublicKeyShareMaterialReader {
    private chunkIndex = 0;

    private chunkOffset = 0;

    private consumedByteLength = 0;

    private readonly totalByteLength: number;

    public constructor(chunks: readonly Uint8Array[]) {
        this.chunks = chunks;
        this.totalByteLength = chunks.reduce(
            (accumulatedLength, chunk) => accumulatedLength + chunk.byteLength,
            0,
        );
    }

    private readonly chunks: readonly Uint8Array[];

    public isFinished(): boolean {
        return this.consumedByteLength === this.totalByteLength;
    }

    public readBytes(length: number, fieldName: string): Uint8Array {
        if (
            length < 0 ||
            this.consumedByteLength + length > this.totalByteLength
        ) {
            throw new Error(
                `${fieldName} ended before the binary object was complete.`,
            );
        }
        const bytes = new Uint8Array(length);
        let outputOffset = 0;
        while (outputOffset < length) {
            const chunk = this.chunks[this.chunkIndex];
            if (chunk === undefined) {
                throw new Error(
                    `${fieldName} ended before the binary object was complete.`,
                );
            }
            const availableLength = chunk.byteLength - this.chunkOffset;
            const copyLength = Math.min(length - outputOffset, availableLength);
            bytes.set(
                chunk.subarray(this.chunkOffset, this.chunkOffset + copyLength),
                outputOffset,
            );
            outputOffset += copyLength;
            this.chunkOffset += copyLength;
            this.consumedByteLength += copyLength;
            if (this.chunkOffset === chunk.byteLength) {
                this.chunkIndex += 1;
                this.chunkOffset = 0;
            }
        }

        return bytes;
    }

    public readVaruint(fieldName: string): number {
        let shift = 0n;
        let value = 0n;
        const consumed: number[] = [];
        for (let byteIndex = 0; byteIndex < 10; byteIndex += 1) {
            const byte = this.readBytes(1, fieldName)[0];
            consumed.push(byte);
            value |= BigInt(byte & 0x7f) << shift;
            if ((byte & 0x80) === 0) {
                if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
                    throw new Error(
                        `${fieldName} does not fit a safe integer.`,
                    );
                }
                const numericValue = Number(value);
                const canonical: number[] = [];
                appendVaruint(canonical, numericValue);
                if (
                    canonical.length !== consumed.length ||
                    canonical.some(
                        (canonicalByte, index) =>
                            canonicalByte !== consumed[index],
                    )
                ) {
                    throw new Error(
                        `${fieldName} binary varuint is not minimally encoded.`,
                    );
                }

                return numericValue;
            }
            shift += 7n;
        }

        throw new Error(`${fieldName} binary varuint is too long.`);
    }

    public readU64(fieldName: string): number {
        const bytes = this.readBytes(8, fieldName);
        let value = 0n;
        for (let byteIndex = 7; byteIndex >= 0; byteIndex -= 1) {
            value <<= 8n;
            value |= BigInt(bytes[byteIndex] ?? 0);
        }
        if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
            throw new Error(`${fieldName} does not fit a safe integer.`);
        }

        return Number(value);
    }
}

const transportedPublicKeyShareMaterialChunks = (
    transportedMaterial: SetupTransportedPublicKeyShareMaterial | JsonRecord,
): readonly Uint8Array[] => {
    if (
        transportedMaterial.objectType !==
        'SetupTransportedPublicKeyShareMaterial'
    ) {
        throw new Error(
            'transportedPublicKeyShareMaterial.objectType must be SetupTransportedPublicKeyShareMaterial.',
        );
    }
    if (transportedMaterial.objectVersion !== 1) {
        throw new Error(
            'transportedPublicKeyShareMaterial.objectVersion must be 1.',
        );
    }
    if (
        transportedMaterial.binaryFormat !== publicKeyShareMaterialBinaryFormat
    ) {
        throw new Error(
            'transportedPublicKeyShareMaterial.binaryFormat must match the accepted binary format.',
        );
    }
    if (transportedMaterial.chunkSizeBytes !== setupTransportChunkSizeBytes) {
        throw new Error(
            'transportedPublicKeyShareMaterial.chunkSizeBytes must match the setup transport profile.',
        );
    }
    if (!Array.isArray(transportedMaterial.chunks)) {
        throw new TypeError(
            'transportedPublicKeyShareMaterial.chunks must be an array.',
        );
    }
    if (transportedMaterial.chunks.length !== transportedMaterial.chunkCount) {
        throw new Error(
            'transportedPublicKeyShareMaterial.chunks length must match chunkCount.',
        );
    }

    const chunkValues: readonly unknown[] = transportedMaterial.chunks;
    return chunkValues.map((chunkValue, expectedChunkIndex) => {
        if (!isJsonRecord(chunkValue)) {
            throw new TypeError(
                'transportedPublicKeyShareMaterial chunks must be objects.',
            );
        }
        if (chunkValue.chunkIndex !== expectedChunkIndex) {
            throw new Error(
                'transportedPublicKeyShareMaterial chunks must be supplied in ascending chunk-index order.',
            );
        }
        if (typeof chunkValue.bytesHex !== 'string') {
            throw new TypeError(
                'transportedPublicKeyShareMaterial chunk bytesHex must be a string.',
            );
        }

        return bytesFromHex(
            chunkValue.bytesHex,
            `transportedPublicKeyShareMaterial.chunks.${String(expectedChunkIndex)}.bytesHex`,
        );
    });
};

const verifyTransportedPublicKeyShareMaterialHashes = (
    transportedMaterial: SetupTransportedPublicKeyShareMaterial | JsonRecord,
    chunks: readonly Uint8Array[],
): void => {
    const hashes = publicKeyShareMaterialTransportHashes(chunks);
    if (
        transportedMaterial.totalByteLength !== hashes.totalByteLength ||
        transportedMaterial.fullObjectHash !== hashes.fullObjectHash ||
        transportedMaterial.chunkRoot !== hashes.chunkRoot ||
        transportedMaterial.chunkCount !== hashes.chunkHashes.length
    ) {
        throw new Error(
            'transported public-key share material hash metadata does not match supplied chunks.',
        );
    }
    const observedChunkHashes = transportedMaterial.chunkHashes;
    if (!Array.isArray(observedChunkHashes)) {
        throw new TypeError(
            'transportedPublicKeyShareMaterial.chunkHashes must be an array.',
        );
    }
    if (observedChunkHashes.length !== hashes.chunkHashes.length) {
        throw new Error(
            'transportedPublicKeyShareMaterial.chunkHashes length must match chunkCount.',
        );
    }
    hashes.chunkHashes.forEach((chunkHash, chunkIndex) => {
        if (observedChunkHashes[chunkIndex] !== chunkHash) {
            throw new Error(
                'transported public-key share material chunk hashes do not match supplied chunks.',
            );
        }
    });
};

type TransportedPublicKeyShareMaterialReaderInput = Readonly<{
    readonly setupContext: CollectiveBgvSetupContext;
    readonly publicKeyShares: PublicKeyShareSet;
    readonly materialSet: BinaryChunkedPublicKeyShareMaterialSet;
    readonly transportedPublicKeyShareMaterial:
        | SetupTransportedPublicKeyShareMaterial
        | JsonRecord;
}>;

const transportedPublicKeyShareMaterialReader = (
    input: TransportedPublicKeyShareMaterialReaderInput,
): Readonly<{
    readonly reader: PublicKeyShareMaterialReader;
    readonly shareRecords: ReadonlyMap<number, PublicKeyShareRecord>;
}> => {
    const chunks = transportedPublicKeyShareMaterialChunks(
        input.transportedPublicKeyShareMaterial,
    );
    verifyTransportedPublicKeyShareMaterialHashes(
        input.transportedPublicKeyShareMaterial,
        chunks,
    );
    const transportHashes = publicKeyShareMaterialTransportHashes(chunks);
    if (
        input.materialSet.materialEncoding !==
            publicKeyShareMaterialTransportEncoding ||
        input.materialSet.binaryFormat !== publicKeyShareMaterialBinaryFormat ||
        input.materialSet.transport.transportProfileId !==
            setupTransportProfileId ||
        input.materialSet.transport.chunkSizeBytes !==
            setupTransportChunkSizeBytes ||
        input.materialSet.transport.chunkCount !== chunks.length ||
        input.materialSet.transport.totalByteLength !==
            transportHashes.totalByteLength ||
        input.materialSet.transport.fullObjectHash !==
            transportHashes.fullObjectHash ||
        input.materialSet.transport.chunkRoot !== transportHashes.chunkRoot
    ) {
        throw new Error(
            'binary public-key share material set transport metadata must match the transported material object.',
        );
    }
    assertContextMatches(
        input.setupContext,
        input.materialSet,
        'publicKeyShareMaterial',
    );
    assertContextMatches(
        input.setupContext,
        input.publicKeyShares,
        'publicKeyShares',
    );
    if (
        input.materialSet.publicKeyShareSetRoot !==
        input.publicKeyShares.publicKeyShareSetRoot
    ) {
        throw new Error(
            'binary public-key share material set root binding must match publicKeyShares.',
        );
    }
    const materialSetWithoutRoot = { ...input.materialSet };
    delete (materialSetWithoutRoot as JsonRecord).publicKeyShareMaterialSetRoot;
    if (
        deriveProtocolHash('PublicKeyShareRoot', materialSetWithoutRoot) !==
        input.materialSet.publicKeyShareMaterialSetRoot
    ) {
        throw new Error(
            'binary public-key share material set root must match the canonical material set.',
        );
    }

    const reader = new PublicKeyShareMaterialReader(chunks);
    const magic = reader.readBytes(
        publicKeyShareMaterialBinaryMagic.byteLength,
        'public-key share material magic',
    );
    if (
        magic.byteLength !== publicKeyShareMaterialBinaryMagic.byteLength ||
        magic.some(
            (byte, index) => byte !== publicKeyShareMaterialBinaryMagic[index],
        )
    ) {
        throw new Error(
            'transported public-key share material binary magic does not match.',
        );
    }
    if (reader.readVaruint('binary version') !== 1) {
        throw new Error(
            'transported public-key share material binary version is unsupported.',
        );
    }
    if (
        reader.readVaruint('participantCount') !==
        input.materialSet.participantCount
    ) {
        throw new Error(
            'transported public-key share material participant count must match material set.',
        );
    }
    if (reader.readVaruint('rnsLimbCount') !== input.materialSet.rnsLimbCount) {
        throw new Error(
            'transported public-key share material RNS limb count must match material set.',
        );
    }
    if (reader.readVaruint('ringDegree') !== input.materialSet.ringDegree) {
        throw new Error(
            'transported public-key share material ringDegree must match material set.',
        );
    }

    const shareRecords = publicKeyShareRecordsByRosterPosition({
        setupContext: input.setupContext,
        participantCount: input.materialSet.participantCount,
        publicKeyShares: input.publicKeyShares,
    });

    return { reader, shareRecords };
};

export const materialRecordsFromTransportedPublicKeyShareMaterial = (
    input: TransportedPublicKeyShareMaterialReaderInput,
): readonly PublicKeyShareMaterialRecord[] => {
    const { reader, shareRecords } =
        transportedPublicKeyShareMaterialReader(input);
    const materialRecords: PublicKeyShareMaterialRecord[] = [];
    const materialRootReferences: PublicKeyShareMaterialRootReference[] = [];
    for (
        let expectedRosterPosition = 0;
        expectedRosterPosition < input.materialSet.participantCount;
        expectedRosterPosition += 1
    ) {
        if (
            reader.readVaruint('trusteeRosterPosition') !==
            expectedRosterPosition
        ) {
            throw new Error(
                'transported public-key share material trustee order is not canonical.',
            );
        }
        const shareRecord = shareRecords.get(expectedRosterPosition);
        if (shareRecord === undefined) {
            throw new Error(
                'transported public-key share material must reference an accepted share record.',
            );
        }
        const shareCoefficientVectorsByLimb =
            shareRecord.shareCoefficientVectorHash512ByLimb.map(
                (shareCoefficientHash, rnsLimbIndex) => {
                    if (reader.readVaruint('rnsLimbIndex') !== rnsLimbIndex) {
                        throw new Error(
                            'transported public-key share material RNS limb order is not canonical.',
                        );
                    }
                    const rnsPrime = reader.readU64('rnsPrime');
                    if (
                        shareCoefficientHash.rnsLimbIndex !== rnsLimbIndex ||
                        shareCoefficientHash.rnsPrime !== rnsPrime ||
                        shareCoefficientHash.component !== 'b_i'
                    ) {
                        throw new Error(
                            'transported public-key share material limb metadata must match publicKeyShares.',
                        );
                    }
                    const coefficients = Array.from(
                        { length: input.materialSet.ringDegree },
                        () => {
                            const coefficient = reader.readU64(
                                'public-key share coefficient',
                            );
                            if (coefficient >= rnsPrime) {
                                throw new Error(
                                    'transported public-key share coefficient is not a canonical residue.',
                                );
                            }

                            return coefficient;
                        },
                    );
                    const coefficientVectorHash =
                        coefficientVectorHash512(coefficients);
                    if (
                        shareCoefficientHash.coefficientVectorHash512 !==
                        coefficientVectorHash
                    ) {
                        throw new Error(
                            'transported public-key share coefficient hash must match publicKeyShares.',
                        );
                    }

                    return {
                        rnsLimbIndex,
                        rnsPrime,
                        component: 'b_i',
                        coefficientByteLength: input.materialSet.ringDegree * 8,
                        coefficientVectorHash512: coefficientVectorHash,
                        coefficientsLeHex:
                            coefficientVectorToLittleEndianHex(coefficients),
                    } as const satisfies PublicKeyShareCoefficientVectorMaterial;
                },
            );
        const materialRecordWithoutRoot = {
            objectType: 'PublicKeyShareMaterial',
            objectVersion: 1,
            setupProfileId: 'CollectiveBgvSetup-v1',
            setupProofProfileId,
            proofFamily: publicKeyShareProofFamily,
            proofModelStatus: publicKeyShareSuccinctProofModelStatus,
            materialEncoding: publicKeyShareMaterialEncoding,
            ...contextFields(input.setupContext),
            trusteeIdentity: shareRecord.trusteeIdentity,
            trusteeRosterPosition: shareRecord.trusteeRosterPosition,
            rnsLimbCount: input.materialSet.rnsLimbCount,
            ringDegree: input.materialSet.ringDegree,
            publicMatrixSeedHash: input.materialSet.publicMatrixSeedHash,
            publicKeyCrpRoot: input.materialSet.publicKeyCrpRoot,
            publicAPolynomialRoot: input.materialSet.publicAPolynomialRoot,
            publicKeyShareRoot: shareRecord.publicKeyShareRoot,
            shareCoefficientVectorsByLimb,
        } as const satisfies Omit<
            PublicKeyShareMaterialRecord,
            'publicKeyShareMaterialRoot'
        >;
        const materialRecord = {
            ...materialRecordWithoutRoot,
            publicKeyShareMaterialRoot: deriveProtocolHash(
                'PublicKeyShareRoot',
                materialRecordWithoutRoot,
            ),
        } satisfies PublicKeyShareMaterialRecord;
        materialRootReferences.push({
            trusteeIdentity: materialRecord.trusteeIdentity,
            trusteeRosterPosition: materialRecord.trusteeRosterPosition,
            publicKeyShareMaterialRoot:
                materialRecord.publicKeyShareMaterialRoot,
        });
        materialRecords.push(materialRecord);
    }
    if (!reader.isFinished()) {
        throw new Error(
            'transported public-key share material has trailing bytes.',
        );
    }
    if (
        JSON.stringify(materialRootReferences) !==
        JSON.stringify(input.materialSet.publicKeyShareMaterialRoots)
    ) {
        throw new Error(
            'transported public-key share material roots must match material set references.',
        );
    }

    return materialRecords;
};

const assertCollectivePublicKeySourceBindings = (
    input: CollectivePublicKeySourceBindingInput,
): void => {
    validateCommonInput(input);
    assertPositiveSafeInteger(input.ringDegree, 'ringDegree');
    assertContextMatches(
        input.setupContext,
        input.sameSecretConsistency,
        'sameSecretConsistency',
    );
    assertContextMatches(
        input.setupContext,
        input.sameSecretProofs,
        'sameSecretProofs',
    );
    assertContextMatches(
        input.setupContext,
        input.publicKeyShares,
        'publicKeyShares',
    );
    assertContextMatches(
        input.setupContext,
        input.publicKeyShareProofs,
        'publicKeyShareProofs',
    );
    assertContextMatches(
        input.setupContext,
        input.publicKeyShareMaterial,
        'publicKeyShareMaterial',
    );
    assertContextMatches(
        input.setupContext,
        input.publicKeyShareSuccinctProofs,
        'publicKeyShareSuccinctProofs',
    );
    if (
        input.sameSecretProofs.sameSecretConsistencyRoot !==
            input.sameSecretConsistency.sameSecretConsistencyRoot ||
        input.sameSecretProofs.sameSecretProofFamilyBindingRoot !==
            input.sameSecretConsistency.sameSecretProofFamilyBindingRoot ||
        input.publicKeyShares.sameSecretConsistencyRoot !==
            input.sameSecretConsistency.sameSecretConsistencyRoot ||
        input.publicKeyShareProofs.publicKeyShareSetRoot !==
            input.publicKeyShares.publicKeyShareSetRoot ||
        input.publicKeyShareMaterial.publicKeyShareSetRoot !==
            input.publicKeyShares.publicKeyShareSetRoot ||
        input.publicKeyShareSuccinctProofs.sameSecretProofSetRoot !==
            input.sameSecretProofs.sameSecretProofSetRoot ||
        input.publicKeyShareSuccinctProofs.publicKeyShareSetRoot !==
            input.publicKeyShares.publicKeyShareSetRoot ||
        input.publicKeyShareSuccinctProofs.publicKeyShareProofSetRoot !==
            input.publicKeyShareProofs.publicKeyShareProofSetRoot ||
        input.publicKeyShareSuccinctProofs.publicKeyShareMaterialSetRoot !==
            input.publicKeyShareMaterial.publicKeyShareMaterialSetRoot
    ) {
        throw new Error(
            'collective public key sources must bind the accepted public-key proof chain.',
        );
    }
    if (
        input.publicKeyShareMaterial.participantCount !==
            input.participantCount ||
        input.publicKeyShareMaterial.rnsLimbCount !==
            input.qSharePrimes.length ||
        input.publicKeyShareMaterial.ringDegree !== input.ringDegree ||
        input.publicKeyShareMaterial.publicMatrixSeedHash !==
            input.publicMatrixSeedHash ||
        input.publicKeyShareMaterial.publicKeyCrpRoot !==
            input.publicKeyCrpRoot ||
        input.publicKeyShareMaterial.publicAPolynomialRoot !==
            input.publicAPolynomialRoot
    ) {
        throw new Error(
            'publicKeyShareMaterial must bind the collective public-key profile and common randomness.',
        );
    }
};

const createCollectivePublicKeyFromAggregateCoefficients = (
    input: CollectivePublicKeySourceBindingInput & {
        readonly sourceShareMaterialRoots: readonly CollectivePublicKeySourceShareMaterialRoot[];
        readonly aggregateCoefficientsByLimb: readonly (readonly number[])[];
    },
): CollectivePublicKey => {
    const aggregateCoefficientVectorsByLimb =
        input.aggregateCoefficientsByLimb.map((coefficients, rnsLimbIndex) => {
            const rnsPrime = input.qSharePrimes[rnsLimbIndex];
            if (rnsPrime === undefined) {
                throw new Error('Q_share prime is missing for aggregate limb.');
            }

            return {
                rnsLimbIndex,
                rnsPrime,
                component: 'b',
                coefficientByteLength: input.ringDegree * 8,
                coefficientVectorHash512:
                    coefficientVectorHash512(coefficients),
                coefficientsLeHex:
                    coefficientVectorToLittleEndianHex(coefficients),
            } as const satisfies CollectivePublicKeyCoefficientVectorMaterial;
        });
    const collectivePublicKeyWithoutRoot = {
        objectType: 'CollectivePublicKey',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        setupProofProfileId,
        proofFamily: publicKeyShareProofFamily,
        proofVerificationStatus: publicKeyShareSuccinctProofVerificationStatus,
        proofModelStatus: publicKeyShareSuccinctProofModelStatus,
        aggregationStatus:
            'succinct-proof-aggregated-with-accepted-setup-proof-accounting',
        materialEncoding: 'embedded-full-collective-public-key-coefficients',
        ...contextFields(input.setupContext),
        participantCount: input.participantCount,
        rnsLimbCount: input.qSharePrimes.length,
        ringDegree: input.ringDegree,
        publicMatrixSeedHash: input.publicMatrixSeedHash,
        publicKeyCrpRoot: input.publicKeyCrpRoot,
        publicAPolynomialRoot: input.publicAPolynomialRoot,
        sameSecretConsistencyRoot:
            input.sameSecretConsistency.sameSecretConsistencyRoot,
        sameSecretProofSetRoot: input.sameSecretProofs.sameSecretProofSetRoot,
        sameSecretProofFamilyBindingRoot:
            input.sameSecretConsistency.sameSecretProofFamilyBindingRoot,
        publicKeyShareSetRoot: input.publicKeyShares.publicKeyShareSetRoot,
        publicKeyShareProofSetRoot:
            input.publicKeyShareProofs.publicKeyShareProofSetRoot,
        publicKeyShareMaterialSetRoot:
            input.publicKeyShareMaterial.publicKeyShareMaterialSetRoot,
        publicKeyShareSuccinctProofSetRoot:
            input.publicKeyShareSuccinctProofs
                .publicKeyShareSuccinctProofSetRoot,
        sourceShareMaterialRoots: input.sourceShareMaterialRoots,
        aggregateCoefficientVectorsByLimb,
    } as const satisfies Omit<CollectivePublicKey, 'collectivePublicKeyRoot'>;

    return {
        ...collectivePublicKeyWithoutRoot,
        collectivePublicKeyRoot: deriveProtocolHash(
            'CollectivePublicKeyRoot',
            collectivePublicKeyWithoutRoot,
        ),
    } satisfies CollectivePublicKey;
};

export const createCollectivePublicKey = (
    input: CollectivePublicKeyInput,
): CollectivePublicKey => {
    assertCollectivePublicKeySourceBindings(input);
    const materialRecords = sortedByRosterPosition(
        input.publicKeyShareMaterial.shareMaterialRecords,
    );
    if (materialRecords.length !== input.participantCount) {
        throw new Error(
            'publicKeyShareMaterial must contain one material record per participant.',
        );
    }
    const aggregateCoefficientsByLimb = input.qSharePrimes.map(() =>
        Array.from({ length: input.ringDegree }, () => 0),
    );
    const sourceShareMaterialRoots = materialRecords.map(
        (materialRecord, expectedRosterPosition) => {
            if (
                materialRecord.trusteeRosterPosition !==
                    expectedRosterPosition ||
                materialRecord.rnsLimbCount !== input.qSharePrimes.length ||
                materialRecord.ringDegree !== input.ringDegree ||
                materialRecord.shareCoefficientVectorsByLimb.length !==
                    input.qSharePrimes.length
            ) {
                throw new Error(
                    'publicKeyShareMaterial records must match the collective public-key profile.',
                );
            }
            materialRecord.shareCoefficientVectorsByLimb.forEach(
                (coefficientVector, rnsLimbIndex) => {
                    const rnsPrime = input.qSharePrimes[rnsLimbIndex];
                    const aggregateCoefficients =
                        aggregateCoefficientsByLimb[rnsLimbIndex];
                    if (
                        rnsPrime === undefined ||
                        aggregateCoefficients === undefined ||
                        coefficientVector.rnsLimbIndex !== rnsLimbIndex ||
                        coefficientVector.rnsPrime !== rnsPrime ||
                        coefficientVector.component !== 'b_i' ||
                        coefficientVector.coefficientByteLength !==
                            input.ringDegree * 8
                    ) {
                        throw new Error(
                            'publicKeyShareMaterial coefficient vector metadata must match Q_share order.',
                        );
                    }
                    const coefficients = coefficientVectorFromLittleEndianHex(
                        coefficientVector.coefficientsLeHex,
                        input.ringDegree,
                        'publicKeyShareMaterial.shareCoefficientVectorsByLimb.coefficientsLeHex',
                    );
                    if (
                        coefficients.some(
                            (coefficient) => coefficient >= rnsPrime,
                        ) ||
                        coefficientVector.coefficientVectorHash512 !==
                            coefficientVectorHash512(coefficients)
                    ) {
                        throw new Error(
                            'publicKeyShareMaterial coefficient vectors must be canonical and hash-bound.',
                        );
                    }
                    coefficients.forEach((coefficient, coefficientIndex) => {
                        aggregateCoefficients[coefficientIndex] =
                            (aggregateCoefficients[coefficientIndex] +
                                coefficient) %
                            rnsPrime;
                    });
                },
            );

            return {
                trusteeIdentity: materialRecord.trusteeIdentity,
                trusteeRosterPosition: materialRecord.trusteeRosterPosition,
                publicKeyShareRoot: materialRecord.publicKeyShareRoot,
                publicKeyShareMaterialRoot:
                    materialRecord.publicKeyShareMaterialRoot,
            };
        },
    );
    return createCollectivePublicKeyFromAggregateCoefficients({
        ...input,
        sourceShareMaterialRoots,
        aggregateCoefficientsByLimb,
    });
};

export const createCollectivePublicKeyFromTransportedPublicKeyShareMaterial = (
    input: TransportedCollectivePublicKeyInput,
): CollectivePublicKey => {
    assertCollectivePublicKeySourceBindings(input);
    const { reader, shareRecords } = transportedPublicKeyShareMaterialReader({
        setupContext: input.setupContext,
        publicKeyShares: input.publicKeyShares,
        materialSet: input.publicKeyShareMaterial,
        transportedPublicKeyShareMaterial:
            input.transportedPublicKeyShareMaterial,
    });
    const aggregateCoefficientsByLimb = input.qSharePrimes.map(() =>
        Array.from({ length: input.ringDegree }, () => 0),
    );
    const materialRootReferences: PublicKeyShareMaterialRootReference[] = [];
    const sourceShareMaterialRoots: CollectivePublicKeySourceShareMaterialRoot[] =
        [];
    for (
        let expectedRosterPosition = 0;
        expectedRosterPosition < input.publicKeyShareMaterial.participantCount;
        expectedRosterPosition += 1
    ) {
        if (
            reader.readVaruint('trusteeRosterPosition') !==
            expectedRosterPosition
        ) {
            throw new Error(
                'transported public-key share material trustee order is not canonical.',
            );
        }
        const shareRecord = shareRecords.get(expectedRosterPosition);
        if (shareRecord === undefined) {
            throw new Error(
                'transported public-key share material must reference an accepted share record.',
            );
        }
        const shareCoefficientVectorsByLimb =
            shareRecord.shareCoefficientVectorHash512ByLimb.map(
                (shareCoefficientHash, rnsLimbIndex) => {
                    if (reader.readVaruint('rnsLimbIndex') !== rnsLimbIndex) {
                        throw new Error(
                            'transported public-key share material RNS limb order is not canonical.',
                        );
                    }
                    const rnsPrime = reader.readU64('rnsPrime');
                    const aggregateCoefficients =
                        aggregateCoefficientsByLimb[rnsLimbIndex];
                    if (
                        aggregateCoefficients === undefined ||
                        shareCoefficientHash.rnsLimbIndex !== rnsLimbIndex ||
                        shareCoefficientHash.rnsPrime !== rnsPrime ||
                        shareCoefficientHash.component !== 'b_i'
                    ) {
                        throw new Error(
                            'transported public-key share material limb metadata must match publicKeyShares.',
                        );
                    }
                    const coefficients = Array.from(
                        { length: input.publicKeyShareMaterial.ringDegree },
                        () => {
                            const coefficient = reader.readU64(
                                'public-key share coefficient',
                            );
                            if (coefficient >= rnsPrime) {
                                throw new Error(
                                    'transported public-key share coefficient is not a canonical residue.',
                                );
                            }

                            return coefficient;
                        },
                    );
                    const coefficientVectorHash =
                        coefficientVectorHash512(coefficients);
                    if (
                        shareCoefficientHash.coefficientVectorHash512 !==
                        coefficientVectorHash
                    ) {
                        throw new Error(
                            'transported public-key share coefficient hash must match publicKeyShares.',
                        );
                    }
                    coefficients.forEach((coefficient, coefficientIndex) => {
                        aggregateCoefficients[coefficientIndex] =
                            (aggregateCoefficients[coefficientIndex] +
                                coefficient) %
                            rnsPrime;
                    });

                    return {
                        rnsLimbIndex,
                        rnsPrime,
                        component: 'b_i',
                        coefficientByteLength:
                            input.publicKeyShareMaterial.ringDegree * 8,
                        coefficientVectorHash512: coefficientVectorHash,
                        coefficientsLeHex:
                            coefficientVectorToLittleEndianHex(coefficients),
                    } as const satisfies PublicKeyShareCoefficientVectorMaterial;
                },
            );
        const materialRecordWithoutRoot = {
            objectType: 'PublicKeyShareMaterial',
            objectVersion: 1,
            setupProfileId: 'CollectiveBgvSetup-v1',
            setupProofProfileId,
            proofFamily: publicKeyShareProofFamily,
            proofModelStatus: publicKeyShareSuccinctProofModelStatus,
            materialEncoding: publicKeyShareMaterialEncoding,
            ...contextFields(input.setupContext),
            trusteeIdentity: shareRecord.trusteeIdentity,
            trusteeRosterPosition: shareRecord.trusteeRosterPosition,
            rnsLimbCount: input.publicKeyShareMaterial.rnsLimbCount,
            ringDegree: input.publicKeyShareMaterial.ringDegree,
            publicMatrixSeedHash:
                input.publicKeyShareMaterial.publicMatrixSeedHash,
            publicKeyCrpRoot: input.publicKeyShareMaterial.publicKeyCrpRoot,
            publicAPolynomialRoot:
                input.publicKeyShareMaterial.publicAPolynomialRoot,
            publicKeyShareRoot: shareRecord.publicKeyShareRoot,
            shareCoefficientVectorsByLimb,
        } as const satisfies Omit<
            PublicKeyShareMaterialRecord,
            'publicKeyShareMaterialRoot'
        >;
        const publicKeyShareMaterialRoot = deriveProtocolHash(
            'PublicKeyShareRoot',
            materialRecordWithoutRoot,
        );
        materialRootReferences.push({
            trusteeIdentity: shareRecord.trusteeIdentity,
            trusteeRosterPosition: shareRecord.trusteeRosterPosition,
            publicKeyShareMaterialRoot,
        });
        sourceShareMaterialRoots.push({
            trusteeIdentity: shareRecord.trusteeIdentity,
            trusteeRosterPosition: shareRecord.trusteeRosterPosition,
            publicKeyShareRoot: shareRecord.publicKeyShareRoot,
            publicKeyShareMaterialRoot,
        });
    }
    if (!reader.isFinished()) {
        throw new Error(
            'transported public-key share material has trailing bytes.',
        );
    }
    if (
        JSON.stringify(materialRootReferences) !==
        JSON.stringify(input.publicKeyShareMaterial.publicKeyShareMaterialRoots)
    ) {
        throw new Error(
            'transported public-key share material roots must match material set references.',
        );
    }

    return createCollectivePublicKeyFromAggregateCoefficients({
        ...input,
        sourceShareMaterialRoots,
        aggregateCoefficientsByLimb,
    });
};

const publicKeyShareProofRecordsByRosterPosition = (
    input: Pick<
        PublicKeyShareSuccinctProofSetInput,
        'setupContext' | 'participantCount' | 'publicKeyShareProofs'
    >,
): ReadonlyMap<number, PublicKeyShareProofRecord> => {
    assertContextMatches(
        input.setupContext,
        input.publicKeyShareProofs,
        'publicKeyShareProofs',
    );
    assertProtocolHash(
        input.publicKeyShareProofs.publicKeyShareProofSetRoot,
        'publicKeyShareProofs.publicKeyShareProofSetRoot',
    );
    const proofRecords = sortedByRosterPosition(
        input.publicKeyShareProofs.proofRecords,
    );
    if (proofRecords.length !== input.participantCount) {
        throw new Error(
            'publicKeyShareProofs.proofRecords must contain one proof statement per participant.',
        );
    }
    const recordsByRosterPosition = new Map<
        number,
        PublicKeyShareProofRecord
    >();
    proofRecords.forEach((proofRecord, expectedRosterPosition) => {
        if (proofRecord.trusteeRosterPosition !== expectedRosterPosition) {
            throw new Error(
                'publicKeyShareProofs.proofRecords roster positions must be contiguous from zero.',
            );
        }
        assertProtocolHash(
            proofRecord.publicKeyShareProofRoot,
            'publicKeyShareProofs.proofRecords.publicKeyShareProofRoot',
        );
        recordsByRosterPosition.set(
            proofRecord.trusteeRosterPosition,
            proofRecord,
        );
    });

    return recordsByRosterPosition;
};

const sameSecretProofRecordsByRosterPosition = (
    input: Pick<
        PublicKeyShareSuccinctProofSetInput,
        | 'setupContext'
        | 'participantCount'
        | 'sameSecretConsistency'
        | 'sameSecretProofs'
    >,
): ReadonlyMap<number, SameSecretProofSet['proofRecords'][number]> => {
    assertContextMatches(
        input.setupContext,
        input.sameSecretProofs,
        'sameSecretProofs',
    );
    if (
        input.sameSecretProofs.sameSecretConsistencyRoot !==
            input.sameSecretConsistency.sameSecretConsistencyRoot ||
        input.sameSecretProofs.sameSecretProofFamilyBindingRoot !==
            input.sameSecretConsistency.sameSecretProofFamilyBindingRoot
    ) {
        throw new Error(
            'sameSecretProofs must bind the accepted same-secret statement set.',
        );
    }
    assertProtocolHash(
        input.sameSecretProofs.sameSecretProofSetRoot,
        'sameSecretProofs.sameSecretProofSetRoot',
    );
    const proofRecords = sortedByRosterPosition(
        input.sameSecretProofs.proofRecords,
    );
    if (proofRecords.length !== input.participantCount) {
        throw new Error(
            'sameSecretProofs.proofRecords must contain one proof per participant.',
        );
    }
    const recordsByRosterPosition = new Map<
        number,
        SameSecretProofSet['proofRecords'][number]
    >();
    proofRecords.forEach((proofRecord, expectedRosterPosition) => {
        if (proofRecord.trusteeRosterPosition !== expectedRosterPosition) {
            throw new Error(
                'sameSecretProofs.proofRecords roster positions must be contiguous from zero.',
            );
        }
        assertProtocolHash(
            proofRecord.sameSecretProofRoot,
            'sameSecretProofs.proofRecords.sameSecretProofRoot',
        );
        recordsByRosterPosition.set(
            proofRecord.trusteeRosterPosition,
            proofRecord,
        );
    });

    return recordsByRosterPosition;
};

type PublicKeyShareMaterialProofReference =
    PublicKeyShareMaterialRootReference &
        Readonly<{
            readonly publicKeyShareRoot?: ProtocolHash;
        }>;

const publicKeyShareMaterialReferencesByRosterPosition = (
    input: Pick<
        PublicKeyShareSuccinctProofSetInput,
        'setupContext' | 'participantCount' | 'publicKeyShareMaterial'
    >,
): ReadonlyMap<number, PublicKeyShareMaterialProofReference> => {
    assertContextMatches(
        input.setupContext,
        input.publicKeyShareMaterial,
        'publicKeyShareMaterial',
    );
    assertProtocolHash(
        input.publicKeyShareMaterial.publicKeyShareMaterialSetRoot,
        'publicKeyShareMaterial.publicKeyShareMaterialSetRoot',
    );
    const recordsByRosterPosition = new Map<
        number,
        PublicKeyShareMaterialProofReference
    >();
    const shareMaterialRecords = (
        input.publicKeyShareMaterial as Partial<PublicKeyShareMaterialSet>
    ).shareMaterialRecords;
    const materialReferences: readonly PublicKeyShareMaterialProofReference[] =
        shareMaterialRecords === undefined
            ? sortedByRosterPosition(
                  input.publicKeyShareMaterial.publicKeyShareMaterialRoots,
              )
            : sortedByRosterPosition(shareMaterialRecords).map(
                  (materialRecord) => ({
                      trusteeIdentity: materialRecord.trusteeIdentity,
                      trusteeRosterPosition:
                          materialRecord.trusteeRosterPosition,
                      publicKeyShareRoot: materialRecord.publicKeyShareRoot,
                      publicKeyShareMaterialRoot:
                          materialRecord.publicKeyShareMaterialRoot,
                  }),
              );
    if (materialReferences.length !== input.participantCount) {
        throw new Error(
            'publicKeyShareMaterial.publicKeyShareMaterialRoots must contain one material root per participant.',
        );
    }
    materialReferences.forEach((materialReference, expectedRosterPosition) => {
        if (
            materialReference.trusteeRosterPosition !== expectedRosterPosition
        ) {
            throw new Error(
                'publicKeyShareMaterial.publicKeyShareMaterialRoots roster positions must be contiguous from zero.',
            );
        }
        assertNonEmptyString(
            materialReference.trusteeIdentity,
            'publicKeyShareMaterial.publicKeyShareMaterialRoots.trusteeIdentity',
        );
        assertProtocolHash(
            materialReference.publicKeyShareMaterialRoot,
            'publicKeyShareMaterial.publicKeyShareMaterialRoots.publicKeyShareMaterialRoot',
        );
        const publicKeyShareRoot = materialReference.publicKeyShareRoot;
        if (publicKeyShareRoot !== undefined) {
            if (typeof publicKeyShareRoot !== 'string') {
                throw new TypeError(
                    'publicKeyShareMaterial.shareMaterialRecords.publicKeyShareRoot must be a string.',
                );
            }
            assertProtocolHash(
                publicKeyShareRoot,
                'publicKeyShareMaterial.shareMaterialRecords.publicKeyShareRoot',
            );
        }
        recordsByRosterPosition.set(
            materialReference.trusteeRosterPosition,
            materialReference,
        );
    });

    return recordsByRosterPosition;
};

const validatePublicKeyShareSuccinctProofMaterial = (
    material: PublicKeyShareSuccinctProofMaterial,
    fieldName: string,
): void => {
    if (material.setupProofProfileId !== setupProofProfileId) {
        throw new Error(
            `${fieldName}.setupProofProfileId must match setup proof profile.`,
        );
    }
    if (material.proofFamily !== publicKeyShareProofFamily) {
        throw new Error(`${fieldName}.proofFamily must be public-key share.`);
    }
    if (
        material.proofVerificationStatus !==
        publicKeyShareSuccinctProofVerificationStatus
    ) {
        throw new Error(
            `${fieldName}.proofVerificationStatus must be the public-key share succinct verification status.`,
        );
    }
    if (material.proofModelStatus !== publicKeyShareSuccinctProofModelStatus) {
        throw new Error(
            `${fieldName}.proofModelStatus must match public-key share succinct proof model.`,
        );
    }
    assertNonEmptyString(
        material.trusteeIdentity,
        `${fieldName}.trusteeIdentity`,
    );
    assertNonNegativeSafeInteger(
        material.trusteeRosterPosition,
        `${fieldName}.trusteeRosterPosition`,
    );
    assertProtocolHash(material.statementHash, `${fieldName}.statementHash`);
    assertPositiveSafeInteger(
        material.proofSizeBytes,
        `${fieldName}.proofSizeBytes`,
    );
    assertProtocolHash(material.proofBytesHash, `${fieldName}.proofBytesHash`);
    const proofBytesHex = (material as JsonRecord).proofBytesHex;
    if (proofBytesHex !== undefined) {
        if (typeof proofBytesHex !== 'string') {
            throw new TypeError(`${fieldName}.proofBytesHex must be a string.`);
        }
        assertLowercaseHexBytes(proofBytesHex, `${fieldName}.proofBytesHex`);
        if (proofBytesHex.length / 2 !== material.proofSizeBytes) {
            throw new Error(
                `${fieldName}.proofBytesHex must match proofSizeBytes.`,
            );
        }

        return;
    }

    const transportedMaterial =
        material as PublicKeyShareSuccinctTransportedProofBytes;
    if (
        transportedMaterial.proofBytesEncoding !== 'binary-chunked-proof-bytes'
    ) {
        throw new TypeError(
            `${fieldName}.proofBytesEncoding must be binary-chunked-proof-bytes.`,
        );
    }
    assertProtocolHash(
        transportedMaterial.proofMaterialRoot,
        `${fieldName}.proofMaterialRoot`,
    );
    assertPositiveSafeInteger(
        transportedMaterial.proofChunkSizeBytes,
        `${fieldName}.proofChunkSizeBytes`,
    );
    assertPositiveSafeInteger(
        transportedMaterial.proofChunkCount,
        `${fieldName}.proofChunkCount`,
    );
    assertPositiveSafeInteger(
        transportedMaterial.proofTotalByteLength,
        `${fieldName}.proofTotalByteLength`,
    );
    if (transportedMaterial.proofTotalByteLength !== material.proofSizeBytes) {
        throw new Error(
            `${fieldName}.proofTotalByteLength must match proofSizeBytes.`,
        );
    }
    assertProtocolHash(
        transportedMaterial.proofFullObjectHash,
        `${fieldName}.proofFullObjectHash`,
    );
    assertProtocolHash(
        transportedMaterial.proofChunkRoot,
        `${fieldName}.proofChunkRoot`,
    );
    transportedMaterial.proofChunkHashes.forEach((proofChunkHash, chunkIndex) =>
        assertProtocolHash(
            proofChunkHash,
            `${fieldName}.proofChunkHashes.${String(chunkIndex)}`,
        ),
    );
    if (
        transportedMaterial.proofChunkHashes.length !==
        transportedMaterial.proofChunkCount
    ) {
        throw new Error(
            `${fieldName}.proofChunkHashes must match proofChunkCount.`,
        );
    }
};

const publicKeyShareSuccinctProofByteMaterial = (
    material: PublicKeyShareSuccinctProofMaterial,
): PublicKeyShareSuccinctProofByteMaterial => {
    const proofBytesHex = (material as JsonRecord).proofBytesHex;
    if (proofBytesHex !== undefined) {
        if (typeof proofBytesHex !== 'string') {
            throw new TypeError(
                'publicKeyShareSuccinctProofMaterial.proofBytesHex must be a string.',
            );
        }
        return {
            proofBytesHex,
        };
    }

    const transportedMaterial =
        material as PublicKeyShareSuccinctTransportedProofBytes;

    return {
        proofBytesEncoding: transportedMaterial.proofBytesEncoding,
        proofMaterialRoot: transportedMaterial.proofMaterialRoot,
        proofChunkSizeBytes: transportedMaterial.proofChunkSizeBytes,
        proofChunkCount: transportedMaterial.proofChunkCount,
        proofTotalByteLength: transportedMaterial.proofTotalByteLength,
        proofFullObjectHash: transportedMaterial.proofFullObjectHash,
        proofChunkRoot: transportedMaterial.proofChunkRoot,
        proofChunkHashes: transportedMaterial.proofChunkHashes,
    };
};

const sortedPublicKeyShareSuccinctProofMaterials = (
    input: Pick<
        PublicKeyShareSuccinctProofSetInput,
        'participantCount' | 'proofMaterials'
    >,
): PublicKeyShareSuccinctProofMaterial[] => {
    const proofMaterials = [...input.proofMaterials].sort(
        (left, right) =>
            left.trusteeRosterPosition - right.trusteeRosterPosition,
    );
    if (proofMaterials.length !== input.participantCount) {
        throw new Error(
            'publicKeyShareSuccinctProofMaterials must contain one proof per participant.',
        );
    }
    proofMaterials.forEach((proofMaterial, expectedRosterPosition) => {
        validatePublicKeyShareSuccinctProofMaterial(
            proofMaterial,
            `publicKeyShareSuccinctProofMaterials.${String(expectedRosterPosition)}`,
        );
        if (proofMaterial.trusteeRosterPosition !== expectedRosterPosition) {
            throw new Error(
                'publicKeyShareSuccinctProofMaterials roster positions must be contiguous from zero.',
            );
        }
    });

    return proofMaterials;
};

export const createPublicKeyShareSuccinctProofSet = (
    input: PublicKeyShareSuccinctProofSetInput,
): PublicKeyShareSuccinctProofSet => {
    validateCommonInput(input);
    assertProtocolHash(input.proofAccountingHash, 'proofAccountingHash');
    assertContextMatches(
        input.setupContext,
        input.sameSecretConsistency,
        'sameSecretConsistency',
    );
    assertContextMatches(
        input.setupContext,
        input.sameSecretProofs,
        'sameSecretProofs',
    );
    assertContextMatches(
        input.setupContext,
        input.publicKeyShareProofs,
        'publicKeyShareProofs',
    );
    assertContextMatches(
        input.setupContext,
        input.publicKeyShareMaterial,
        'publicKeyShareMaterial',
    );
    if (
        input.sameSecretProofs.sameSecretConsistencyRoot !==
            input.sameSecretConsistency.sameSecretConsistencyRoot ||
        input.sameSecretProofs.sameSecretProofFamilyBindingRoot !==
            input.sameSecretConsistency.sameSecretProofFamilyBindingRoot ||
        input.publicKeyShareProofs.publicKeyShareSetRoot !==
            input.publicKeyShares.publicKeyShareSetRoot ||
        input.publicKeyShareProofs.sameSecretConsistencyRoot !==
            input.sameSecretConsistency.sameSecretConsistencyRoot ||
        input.publicKeyShareMaterial.publicKeyShareSetRoot !==
            input.publicKeyShares.publicKeyShareSetRoot
    ) {
        throw new Error(
            'public-key succinct proofs must bind the accepted public-key share, same-secret, statement, and material roots.',
        );
    }

    const statementsByRosterPosition = statementRecordsByRosterPosition(input);
    const shareRecords = publicKeyShareRecordsByRosterPosition(input);
    const proofStatementRecords =
        publicKeyShareProofRecordsByRosterPosition(input);
    const sameSecretProofRecords =
        sameSecretProofRecordsByRosterPosition(input);
    const materialReferences =
        publicKeyShareMaterialReferencesByRosterPosition(input);
    const proofMaterials = sortedPublicKeyShareSuccinctProofMaterials(input);
    const proofRecords = proofMaterials.map(
        (proofMaterial, expectedRosterPosition) => {
            const statementRecord = statementsByRosterPosition.get(
                expectedRosterPosition,
            );
            const shareRecord = shareRecords.get(expectedRosterPosition);
            const proofStatementRecord = proofStatementRecords.get(
                expectedRosterPosition,
            );
            const sameSecretProofRecord = sameSecretProofRecords.get(
                expectedRosterPosition,
            );
            const materialReference = materialReferences.get(
                expectedRosterPosition,
            );
            if (
                statementRecord === undefined ||
                shareRecord === undefined ||
                proofStatementRecord === undefined ||
                sameSecretProofRecord === undefined ||
                materialReference === undefined
            ) {
                throw new Error(
                    'publicKeyShareSuccinctProofMaterials must match accepted setup records.',
                );
            }
            if (
                proofMaterial.trusteeIdentity !== shareRecord.trusteeIdentity ||
                proofStatementRecord.publicKeyShareRoot !==
                    shareRecord.publicKeyShareRoot ||
                (materialReference.publicKeyShareRoot !== undefined &&
                    materialReference.publicKeyShareRoot !==
                        shareRecord.publicKeyShareRoot) ||
                shareRecord.sameSecretStatementRoot !==
                    statementRecord.sameSecretStatementRoot ||
                proofStatementRecord.sameSecretStatementRoot !==
                    statementRecord.sameSecretStatementRoot ||
                sameSecretProofRecord.sameSecretStatementRoot !==
                    statementRecord.sameSecretStatementRoot ||
                sameSecretProofRecord.trusteeSecretCommitmentRoot !==
                    statementRecord.trusteeSecretCommitmentRoot
            ) {
                throw new Error(
                    'publicKeyShareSuccinctProofMaterials must bind accepted public-key and same-secret records.',
                );
            }
            const proofRecordWithoutRoot = {
                objectType: 'PublicKeyShareSuccinctProof',
                objectVersion: 1,
                setupProfileId: 'CollectiveBgvSetup-v1',
                setupProofProfileId,
                proofFamily: publicKeyShareProofFamily,
                proofVerificationStatus:
                    publicKeyShareSuccinctProofVerificationStatus,
                proofModelStatus: publicKeyShareSuccinctProofModelStatus,
                ...contextFields(input.setupContext),
                trusteeIdentity: shareRecord.trusteeIdentity,
                trusteeRosterPosition: shareRecord.trusteeRosterPosition,
                publicKeyShareRoot: shareRecord.publicKeyShareRoot,
                publicKeyShareProofRoot:
                    proofStatementRecord.publicKeyShareProofRoot,
                publicKeyShareMaterialRoot:
                    materialReference.publicKeyShareMaterialRoot,
                sameSecretStatementRoot:
                    statementRecord.sameSecretStatementRoot,
                trusteeSecretCommitmentRoot:
                    statementRecord.trusteeSecretCommitmentRoot,
                sameSecretProofFamilyBindingRoot:
                    sameSecretProofRecord.sameSecretProofFamilyBindingRoot,
                sameSecretProofRoot: sameSecretProofRecord.sameSecretProofRoot,
                statementHash: proofMaterial.statementHash,
                proofSizeBytes: proofMaterial.proofSizeBytes,
                proofBytesHash: proofMaterial.proofBytesHash,
                ...publicKeyShareSuccinctProofByteMaterial(proofMaterial),
            } as const satisfies Omit<
                PublicKeyShareSuccinctProofRecord,
                'publicKeyShareSuccinctProofRoot'
            >;

            return {
                ...proofRecordWithoutRoot,
                publicKeyShareSuccinctProofRoot: deriveProtocolHash(
                    'PublicKeyShareProofRoot',
                    proofRecordWithoutRoot,
                ),
            } satisfies PublicKeyShareSuccinctProofRecord;
        },
    );
    const proofSetWithoutRoot = {
        objectType: 'PublicKeyShareSuccinctProofSet',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        setupProofProfileId,
        proofFamily: publicKeyShareProofFamily,
        proofVerificationStatus: publicKeyShareSuccinctProofVerificationStatus,
        proofModelStatus: publicKeyShareSuccinctProofModelStatus,
        proofAccountingHash: input.proofAccountingHash,
        ...contextFields(input.setupContext),
        participantCount: input.participantCount,
        rnsLimbCount: input.qSharePrimes.length,
        publicMatrixSeedHash: input.publicMatrixSeedHash,
        publicKeyCrpRoot: input.publicKeyCrpRoot,
        publicAPolynomialRoot: input.publicAPolynomialRoot,
        sameSecretConsistencyRoot:
            input.sameSecretConsistency.sameSecretConsistencyRoot,
        sameSecretProofSetRoot: input.sameSecretProofs.sameSecretProofSetRoot,
        sameSecretProofFamilyBindingRoot:
            input.sameSecretConsistency.sameSecretProofFamilyBindingRoot,
        publicKeyShareSetRoot: input.publicKeyShares.publicKeyShareSetRoot,
        publicKeyShareProofSetRoot:
            input.publicKeyShareProofs.publicKeyShareProofSetRoot,
        publicKeyShareMaterialSetRoot:
            input.publicKeyShareMaterial.publicKeyShareMaterialSetRoot,
        publicKeyShareSuccinctProofRoots: proofRecords.map((proofRecord) => ({
            trusteeIdentity: proofRecord.trusteeIdentity,
            trusteeRosterPosition: proofRecord.trusteeRosterPosition,
            publicKeyShareSuccinctProofRoot:
                proofRecord.publicKeyShareSuccinctProofRoot,
        })),
        proofRecords,
    } as const satisfies Omit<
        PublicKeyShareSuccinctProofSet,
        'publicKeyShareSuccinctProofSetRoot'
    >;

    return {
        ...proofSetWithoutRoot,
        publicKeyShareSuccinctProofSetRoot: deriveProtocolHash(
            'PublicKeyShareProofRoot',
            proofSetWithoutRoot,
        ),
    } satisfies PublicKeyShareSuccinctProofSet;
};

export const createBinaryChunkedPublicKeyShareProofMaterialTransport = (
    proofMaterials: readonly PublicKeyShareSuccinctProofMaterial[],
): BinaryChunkedPublicKeyShareProofMaterialTransport => {
    const transportedProofMaterials: JsonRecord[] = [];
    const transportedRecords = proofMaterials.map(
        (proofMaterial, proofIndex) => {
            validatePublicKeyShareSuccinctProofMaterial(
                proofMaterial,
                `proofMaterials.${String(proofIndex)}`,
            );
            const materialRecord = proofMaterial as JsonRecord;
            const proofBytesHex = materialRecord.proofBytesHex;
            if (
                typeof proofBytesHex !== 'string' ||
                proofBytesHex.length === 0
            ) {
                throw new TypeError(
                    `proofMaterials.${String(proofIndex)}.proofBytesHex must be non-empty.`,
                );
            }
            const proofBytes = bytesFromHex(
                proofBytesHex,
                `proofMaterials.${String(proofIndex)}.proofBytesHex`,
            );
            if (proofMaterial.proofSizeBytes !== proofBytes.byteLength) {
                throw new Error(
                    `proofMaterials.${String(proofIndex)}.proofSizeBytes must match proofBytesHex.`,
                );
            }
            const expectedProofBytesHash = hash512Hex(
                publicKeyShareSuccinctProofBytesHashDomain,
                [proofBytes],
            );
            if (proofMaterial.proofBytesHash !== expectedProofBytesHash) {
                throw new Error(
                    `proofMaterials.${String(proofIndex)}.proofBytesHash must match proofBytesHex before transport.`,
                );
            }
            const chunks: Uint8Array[] = [];
            for (
                let chunkStart = 0;
                chunkStart < proofBytes.byteLength;
                chunkStart += setupProofTransportChunkSizeBytes
            ) {
                chunks.push(
                    proofBytes.slice(
                        chunkStart,
                        Math.min(
                            chunkStart + setupProofTransportChunkSizeBytes,
                            proofBytes.byteLength,
                        ),
                    ),
                );
            }
            if (chunks.length === 0) {
                throw new Error(
                    `proofMaterials.${String(proofIndex)}.proofBytesHex must produce at least one transported chunk.`,
                );
            }
            const totalByteLength = proofBytes.byteLength;
            const fullObjectHash = setupProofMaterialFullObjectHashHex(
                publicKeyShareProofFamily,
                totalByteLength,
                chunks,
            );
            const chunkHashes = chunks.map((chunk, chunkIndex) =>
                setupProofMaterialChunkHash(
                    publicKeyShareProofFamily,
                    fullObjectHash,
                    chunkIndex,
                    chunk,
                ),
            );
            const chunkRoot = setupProofChunkManifestRoot(
                publicKeyShareProofFamily,
                chunkHashes,
                fullObjectHash,
                totalByteLength,
            );
            const proofMaterialRoot = deriveProtocolHash(
                'PublicKeyShareProofMaterialRoot',
                {
                    objectType: 'PublicKeyShareSuccinctProofMaterialReference',
                    objectVersion: 1,
                    setupProfileId: 'CollectiveBgvSetup-v1',
                    setupProofProfileId,
                    proofFamily: publicKeyShareProofFamily,
                    trusteeIdentity: proofMaterial.trusteeIdentity,
                    trusteeRosterPosition: proofMaterial.trusteeRosterPosition,
                    statementHash: proofMaterial.statementHash,
                    proofSizeBytes: proofMaterial.proofSizeBytes,
                    proofBytesHash: proofMaterial.proofBytesHash,
                    chunkSizeBytes: setupProofTransportChunkSizeBytes,
                    chunkCount: chunkHashes.length,
                    totalByteLength,
                    fullObjectHash,
                    chunkRoot,
                    chunkHashes,
                },
            );
            transportedProofMaterials.push({
                objectType: 'SetupTransportedPublicKeyShareProofMaterial',
                objectVersion: 1,
                setupProfileId: 'CollectiveBgvSetup-v1',
                setupProofProfileId,
                proofFamily: publicKeyShareProofFamily,
                proofMaterialRoot,
                chunkSizeBytes: setupProofTransportChunkSizeBytes,
                chunkCount: chunkHashes.length,
                totalByteLength,
                fullObjectHash,
                chunkHashes,
                chunkRoot,
                chunks: chunks.map((chunk, chunkIndex) => ({
                    chunkIndex,
                    bytesHex: bytesToHex(chunk),
                })),
            });
            const transportedMaterial = {
                ...materialRecord,
                proofBytesEncoding: 'binary-chunked-proof-bytes',
                proofMaterialRoot,
                proofChunkSizeBytes: setupProofTransportChunkSizeBytes,
                proofChunkCount: chunkHashes.length,
                proofTotalByteLength: totalByteLength,
                proofFullObjectHash: fullObjectHash,
                proofChunkRoot: chunkRoot,
                proofChunkHashes: chunkHashes,
            } as JsonRecord;
            delete transportedMaterial.proofBytesHex;

            return transportedMaterial as unknown as PublicKeyShareSuccinctProofMaterial;
        },
    );

    return {
        proofMaterials: transportedRecords,
        transportedPublicKeyShareProofMaterial: {
            objectType: 'SetupTransportedPublicKeyShareProofMaterialSet',
            objectVersion: 1,
            setupProfileId: 'CollectiveBgvSetup-v1',
            setupProofProfileId,
            proofFamily: publicKeyShareProofFamily,
            proofMaterials: transportedProofMaterials,
        },
    };
};
