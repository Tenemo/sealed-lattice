import {
    deriveProtocolHash,
    hash512Hex,
    setupVssMaterialFullObjectHashHex,
} from '@sealed-lattice/crypto';
import type { ProtocolHash } from '@sealed-lattice/types';

import type { CollectiveBgvSetupContext } from './vss-share-verification-records.js';

type JsonRecord = Record<string, unknown>;

export const setupCommitmentProfileId = 'SealedLattice-BDLOP-LNP-Commitment-v1';
export const setupCommitmentModuleRank = 2;
export const setupCommitmentRandomnessWidth = 2 * setupCommitmentModuleRank + 1;
export const setupCommitmentRowCount = setupCommitmentModuleRank + 1;
export const setupCommitmentModulusLimbIndices = [0, 1, 2] as const;
export const acceptedBgvProfileRingDegree = 32_768;
export const setupTransportProfileId =
    'sealed-lattice-setup-binary-chunked-transport-v1';
export const setupTransportChunkSizeBytes = 1_048_576;
export const vssCoefficientCommitmentMaterialBinaryFormat =
    'sealed-lattice-vss-coefficient-commitment-material-binary-v1';

export type SetupCommitmentLimbValue = {
    readonly commitmentModulusIndex: number;
    readonly modulus: number;
    readonly rows: readonly (readonly number[])[];
};

export type SetupCommitmentValue = {
    readonly sourceRnsLimbIndex: number;
    readonly sourceMessageModulus: number;
    readonly shamirCoefficientIndex: number;
    readonly ringDegree: number;
    readonly commitmentLimbs: readonly SetupCommitmentLimbValue[];
};

export type VssCoefficientOpeningInput = {
    readonly rnsLimbIndex: number;
    readonly rnsPrime: number;
    readonly shamirCoefficientIndex: number;
    readonly coefficientMessage: readonly number[];
    readonly randomnessByColumn: readonly (readonly number[])[];
};

export type VssCoefficientOpeningMaterial = Readonly<
    VssCoefficientOpeningInput & {
        readonly commitmentRoot: ProtocolHash;
    }
>;

export type VssSourceTrusteeCoefficientOpeningState = {
    readonly sourceTrusteeIdentity: string;
    readonly sourceTrusteeRosterPosition: number;
    readonly coefficientOpenings: readonly VssCoefficientOpeningInput[];
};

export type VssOpeningRandomByteSource = (byteLength: number) => Uint8Array;

export type VssSourceTrusteeCoefficientOpeningStateGenerationInput = {
    readonly sourceTrusteeIdentity: string;
    readonly sourceTrusteeRosterPosition: number;
    readonly participantCount: number;
    readonly qSharePrimes: readonly number[];
    readonly ringDegree: number;
    readonly thresholdDegree: number;
    readonly randomBytes?: VssOpeningRandomByteSource;
};

export type VssCoefficientCommitmentRecord = Readonly<
    JsonRecord & {
        readonly objectType: 'VssCoefficientCommitment';
        readonly objectVersion: 1;
        readonly sourceTrusteeIdentity: string;
        readonly sourceTrusteeRosterPosition: number;
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly rnsLimbIndex: number;
        readonly rnsPrime: number;
        readonly shamirCoefficientIndex: number;
        readonly commitmentRoot: ProtocolHash;
        readonly commitmentChunkRoot: ProtocolHash;
        readonly coefficientVectorHash512: string;
        readonly openingVerificationStatus: 'pending-private-envelope-opening';
    }
>;

export type VssSourceTrusteeCoefficientCommitmentRecord = Readonly<
    JsonRecord & {
        readonly objectType: 'VssSourceTrusteeCoefficientCommitments';
        readonly objectVersion: 1;
        readonly sourceTrusteeIdentity: string;
        readonly sourceTrusteeRosterPosition: number;
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly coefficientCommitments: readonly VssCoefficientCommitmentRecord[];
        readonly sourceTrusteeCommitmentRoot: ProtocolHash;
    }
>;

export type VssCoefficientCommitmentMaterialRecord = Readonly<
    JsonRecord & {
        readonly objectType: 'VssCoefficientCommitmentMaterial';
        readonly objectVersion: 1;
        readonly sourceTrusteeIdentity: string;
        readonly sourceTrusteeRosterPosition: number;
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly rnsLimbIndex: number;
        readonly rnsPrime: number;
        readonly shamirCoefficientIndex: number;
        readonly commitmentRoot: ProtocolHash;
        readonly commitment: JsonRecord;
    }
>;

export type VssCoefficientCommitmentSet = Readonly<
    JsonRecord & {
        readonly objectType: 'VssCoefficientCommitmentSet';
        readonly objectVersion: 1;
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly sourceTrusteeRecords: readonly VssSourceTrusteeCoefficientCommitmentRecord[];
        readonly vssCoefficientCommitmentRoot: ProtocolHash;
    }
>;

export type VssCoefficientCommitmentMaterialSet = Readonly<
    JsonRecord & {
        readonly objectType: 'VssCoefficientCommitmentMaterialSet';
        readonly objectVersion: 1;
        readonly commitmentProfileId: typeof setupCommitmentProfileId;
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly vssCoefficientCommitmentRoot: ProtocolHash;
        readonly materialEncoding: 'full-public-setup-commitment-values';
        readonly participantCount: number;
        readonly thresholdDegree: number;
        readonly rnsLimbCount: number;
        readonly ringDegree: number;
        readonly ringDegreeStatus: 'profile-ring' | 'development-reduced-ring';
        readonly materialRecordCount: number;
        readonly coefficientCommitments: readonly VssCoefficientCommitmentMaterialRecord[];
        readonly vssCoefficientCommitmentMaterialRoot: ProtocolHash;
    }
>;

export type SetupTransportChunk = Readonly<
    JsonRecord & {
        readonly chunkIndex: number;
        readonly bytesHex: string;
    }
>;

export type SetupTransportedVssCoefficientCommitmentMaterial = Readonly<
    JsonRecord & {
        readonly objectType: 'SetupTransportedVssCoefficientCommitmentMaterial';
        readonly objectVersion: 1;
        readonly binaryFormat: typeof vssCoefficientCommitmentMaterialBinaryFormat;
        readonly chunkSizeBytes: typeof setupTransportChunkSizeBytes;
        readonly chunkCount: number;
        readonly totalByteLength: number;
        readonly fullObjectHash: ProtocolHash;
        readonly chunkHashes: readonly ProtocolHash[];
        readonly chunkRoot: ProtocolHash;
        readonly chunks: readonly SetupTransportChunk[];
    }
>;

export type BinaryChunkedVssCoefficientCommitmentMaterialSet = Readonly<
    JsonRecord & {
        readonly objectType: 'VssCoefficientCommitmentMaterialSet';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly commitmentProfileId: typeof setupCommitmentProfileId;
        readonly commitmentProfileHash: ProtocolHash;
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly vssCoefficientCommitmentRoot: ProtocolHash;
        readonly materialEncoding: 'binary-chunked-full-public-setup-commitment-values';
        readonly binaryFormat: typeof vssCoefficientCommitmentMaterialBinaryFormat;
        readonly participantCount: number;
        readonly thresholdDegree: number;
        readonly rnsLimbCount: number;
        readonly ringDegree: number;
        readonly ringDegreeStatus: 'profile-ring' | 'development-reduced-ring';
        readonly materialRecordCount: number;
        readonly transport: Readonly<
            JsonRecord & {
                readonly transportProfileId: typeof setupTransportProfileId;
                readonly chunkSizeBytes: typeof setupTransportChunkSizeBytes;
                readonly chunkCount: number;
                readonly totalByteLength: number;
                readonly fullObjectHash: ProtocolHash;
                readonly chunkRoot: ProtocolHash;
            }
        >;
        readonly vssCoefficientCommitmentMaterialRoot: ProtocolHash;
    }
>;

export type SetupPackageVssCoefficientCommitmentMaterialSet =
    | VssCoefficientCommitmentMaterialSet
    | BinaryChunkedVssCoefficientCommitmentMaterialSet;

export type BinaryChunkedVssCoefficientCommitmentMaterialTransport = Readonly<{
    readonly materialSet: BinaryChunkedVssCoefficientCommitmentMaterialSet;
    readonly transportedVssCoefficientCommitmentMaterial: SetupTransportedVssCoefficientCommitmentMaterial;
}>;

export type VssSourceTrusteeOpeningMaterial = Readonly<{
    readonly sourceTrusteeIdentity: string;
    readonly sourceTrusteeRosterPosition: number;
    readonly sourceTrusteeCommitmentRoot: ProtocolHash;
    readonly sourceTrusteeCoefficientCommitmentRecord: VssSourceTrusteeCoefficientCommitmentRecord;
    readonly sourceTrusteeCoefficientCommitmentMaterialRecords: readonly VssCoefficientCommitmentMaterialRecord[];
    readonly coefficientOpenings: readonly VssCoefficientOpeningMaterial[];
}>;

export type VssSourceTrusteeCoefficientCommitmentContribution = Readonly<{
    readonly sourceTrusteeRecord: VssSourceTrusteeCoefficientCommitmentRecord;
    readonly materialRecords: readonly VssCoefficientCommitmentMaterialRecord[];
    readonly privateOpeningMaterial: VssSourceTrusteeOpeningMaterial;
}>;

export type VssCoefficientCommitmentBundle = Readonly<{
    readonly commitmentSet: VssCoefficientCommitmentSet;
    readonly materialSet: VssCoefficientCommitmentMaterialSet;
    readonly privateOpeningMaterialBySourceTrustee: readonly VssSourceTrusteeOpeningMaterial[];
}>;

export type VssCoefficientCommitmentBundleInput = {
    readonly setupContext: CollectiveBgvSetupContext;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly qSharePrimes: readonly number[];
    readonly ringDegree: number;
    readonly participantCount: number;
    readonly thresholdDegree: number;
    readonly sourceTrusteeOpeningStates: readonly VssSourceTrusteeCoefficientOpeningState[];
};

export type VssSourceTrusteeCoefficientCommitmentContributionInput = Omit<
    VssCoefficientCommitmentBundleInput,
    'sourceTrusteeOpeningStates'
> & {
    readonly sourceTrusteeOpeningState: VssSourceTrusteeCoefficientOpeningState;
};

const textEncoder = new TextEncoder();
const twoToTheSixtyFourth = 1n << 64n;
const setupContextFieldNames = [
    'ceremonyId',
    'manifestHash',
    'rosterHash',
    'setupProfileHash',
    'qShareHash',
    'carryAwareVssShareRelationProfileHash',
    'commitmentProfileHash',
    'setupEpoch',
] as const;

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

const defaultRandomBytes: VssOpeningRandomByteSource = (byteLength) => {
    const cryptoProvider = globalThis.crypto;
    if (cryptoProvider === undefined) {
        throw new Error(
            'VSS coefficient opening generation requires Web Crypto getRandomValues.',
        );
    }
    const bytes = new Uint8Array(byteLength);
    cryptoProvider.getRandomValues(bytes);

    return bytes;
};

class RandomByteSampler {
    private buffer = new Uint8Array(0);

    private offset = 0;

    public constructor(
        private readonly randomBytes: VssOpeningRandomByteSource,
    ) {}

    public take(byteLength: number): Uint8Array {
        if (this.buffer.byteLength - this.offset < byteLength) {
            const requestedByteLength = Math.max(byteLength, 4096);
            const nextBuffer = this.randomBytes(requestedByteLength);
            if (nextBuffer.byteLength !== requestedByteLength) {
                throw new Error(
                    'randomBytes must return exactly the requested byte length.',
                );
            }
            this.buffer = Uint8Array.from(nextBuffer);
            this.offset = 0;
        }
        const bytes = this.buffer.subarray(
            this.offset,
            this.offset + byteLength,
        );
        this.offset += byteLength;

        return bytes;
    }
}

const assertHashLike = (value: string, fieldName: string): void => {
    if (!/^[0-9a-f]{128}$/u.test(value)) {
        throw new TypeError(
            `${fieldName} must be a 512-bit lowercase hex hash.`,
        );
    }
};

const assertResidueVector = (
    coefficients: readonly number[],
    modulus: number,
    ringDegree: number,
    fieldName: string,
): void => {
    if (coefficients.length !== ringDegree) {
        throw new Error(`${fieldName} length must match ringDegree.`);
    }
    coefficients.forEach((coefficient, coefficientIndex) => {
        if (
            !Number.isSafeInteger(coefficient) ||
            coefficient < 0 ||
            coefficient >= modulus
        ) {
            throw new TypeError(
                `${fieldName}.${String(coefficientIndex)} must be a residue below the declared modulus.`,
            );
        }
    });
};

const assertRandomness = (
    randomnessByColumn: readonly (readonly number[])[],
    ringDegree: number,
    fieldName: string,
): void => {
    if (randomnessByColumn.length !== setupCommitmentRandomnessWidth) {
        throw new Error(
            `${fieldName} must contain the selected randomness width.`,
        );
    }
    randomnessByColumn.forEach((randomnessColumn, randomnessColumnIndex) => {
        if (randomnessColumn.length !== ringDegree) {
            throw new Error(
                `${fieldName}.${String(randomnessColumnIndex)} length must match ringDegree.`,
            );
        }
        randomnessColumn.forEach((coefficient, coefficientIndex) => {
            if (
                !Number.isSafeInteger(coefficient) ||
                coefficient < -1 ||
                coefficient > 1
            ) {
                throw new TypeError(
                    `${fieldName}.${String(randomnessColumnIndex)}.${String(coefficientIndex)} must be centered ternary.`,
                );
            }
        });
    });
};

const sortedByRosterPosition = (
    sourceTrusteeOpeningStates: readonly VssSourceTrusteeCoefficientOpeningState[],
): VssSourceTrusteeCoefficientOpeningState[] =>
    [...sourceTrusteeOpeningStates].sort(
        (left, right) =>
            left.sourceTrusteeRosterPosition -
            right.sourceTrusteeRosterPosition,
    );

const assertFullRosterCoverage = (
    sourceTrusteeOpeningStates: readonly VssSourceTrusteeCoefficientOpeningState[],
    participantCount: number,
): void => {
    if (sourceTrusteeOpeningStates.length !== participantCount) {
        throw new Error(
            'sourceTrusteeOpeningStates must contain every accepted participant.',
        );
    }
    sourceTrusteeOpeningStates.forEach(
        (sourceTrusteeState, expectedRosterPosition) => {
            if (
                sourceTrusteeState.sourceTrusteeRosterPosition !==
                expectedRosterPosition
            ) {
                throw new Error(
                    'sourceTrusteeOpeningStates roster positions must be contiguous from zero.',
                );
            }
        },
    );
};

const openingCoordinateKey = (
    rnsLimbIndex: number,
    shamirCoefficientIndex: number,
): string => `${String(rnsLimbIndex)}:${String(shamirCoefficientIndex)}`;

const openingStateByCoordinate = (
    sourceTrusteeState: VssSourceTrusteeCoefficientOpeningState,
    qSharePrimes: readonly number[],
    ringDegree: number,
    thresholdDegree: number,
): ReadonlyMap<string, VssCoefficientOpeningInput> => {
    const expectedOpeningCount = qSharePrimes.length * thresholdDegree;
    if (
        sourceTrusteeState.coefficientOpenings.length !== expectedOpeningCount
    ) {
        throw new Error(
            'source trustee coefficientOpenings must cover every Q_share limb and Shamir coefficient.',
        );
    }
    const openingsByCoordinate = new Map<string, VssCoefficientOpeningInput>();
    sourceTrusteeState.coefficientOpenings.forEach(
        (openingState, openingIndex) => {
            assertNonNegativeSafeInteger(
                openingState.rnsLimbIndex,
                `coefficientOpenings.${String(openingIndex)}.rnsLimbIndex`,
            );
            assertNonNegativeSafeInteger(
                openingState.shamirCoefficientIndex,
                `coefficientOpenings.${String(openingIndex)}.shamirCoefficientIndex`,
            );
            const expectedPrime = qSharePrimes[openingState.rnsLimbIndex];
            if (expectedPrime === undefined) {
                throw new Error(
                    'coefficient opening rnsLimbIndex is outside Q_share.',
                );
            }
            if (openingState.rnsPrime !== expectedPrime) {
                throw new Error(
                    'coefficient opening rnsPrime must match Q_share at rnsLimbIndex.',
                );
            }
            if (openingState.shamirCoefficientIndex >= thresholdDegree) {
                throw new Error(
                    'coefficient opening shamirCoefficientIndex is outside thresholdDegree.',
                );
            }
            assertResidueVector(
                openingState.coefficientMessage,
                openingState.rnsPrime,
                ringDegree,
                `coefficientOpenings.${String(openingIndex)}.coefficientMessage`,
            );
            assertRandomness(
                openingState.randomnessByColumn,
                ringDegree,
                `coefficientOpenings.${String(openingIndex)}.randomnessByColumn`,
            );
            const coordinateKey = openingCoordinateKey(
                openingState.rnsLimbIndex,
                openingState.shamirCoefficientIndex,
            );
            if (openingsByCoordinate.has(coordinateKey)) {
                throw new Error(
                    'source trustee coefficientOpenings must have distinct limb/coefficient coordinates.',
                );
            }
            openingsByCoordinate.set(coordinateKey, openingState);
        },
    );

    return openingsByCoordinate;
};

const contextFields = (
    setupContext: CollectiveBgvSetupContext,
): Pick<
    CollectiveBgvSetupContext,
    (typeof setupContextFieldNames)[number]
> => ({
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

const centeredIntegerToResidue = (value: number, modulus: number): number => {
    const modulusWide = BigInt(modulus);
    const residue = BigInt(value) % modulusWide;

    return Number(residue < 0n ? residue + modulusWide : residue);
};

const addMod = (left: number, right: number, modulus: number): number =>
    Number((BigInt(left) + BigInt(right)) % BigInt(modulus));

const coefficientVectorBytes = (
    coefficients: readonly number[],
): Uint8Array => {
    const bytes = new Uint8Array(coefficients.length * 8);
    coefficients.forEach((coefficient, coefficientIndex) => {
        let value = BigInt(coefficient);
        for (let byteIndex = 0; byteIndex < 8; byteIndex += 1) {
            bytes[coefficientIndex * 8 + byteIndex] = Number(value & 0xffn);
            value >>= 8n;
        }
    });

    return bytes;
};

const coefficientVectorHash512 = (
    coefficients: readonly number[],
    domain: string,
): string => hash512Hex(domain, [coefficientVectorBytes(coefficients)]);

const hexToBytes = (hex: string): Uint8Array => {
    const bytes = new Uint8Array(hex.length / 2);
    for (let index = 0; index < bytes.length; index += 1) {
        bytes[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
    }

    return bytes;
};

const littleEndianU64 = (bytes: Uint8Array): bigint => {
    let value = 0n;
    for (let byteIndex = bytes.length - 1; byteIndex >= 0; byteIndex -= 1) {
        value = (value << 8n) | BigInt(bytes[byteIndex] ?? 0);
    }

    return value;
};

const reduceUnbiasedU64 = (
    value: bigint,
    modulus: number,
): number | undefined => {
    const modulusWide = BigInt(modulus);
    const limit = twoToTheSixtyFourth - (twoToTheSixtyFourth % modulusWide);
    if (value >= limit) {
        return undefined;
    }

    return Number(value % modulusWide);
};

const randomLittleEndianU64 = (sampler: RandomByteSampler): bigint =>
    littleEndianU64(sampler.take(8));

const sampleUniformResidue = (
    sampler: RandomByteSampler,
    modulus: number,
): number => {
    while (true) {
        const residue = reduceUnbiasedU64(
            randomLittleEndianU64(sampler),
            modulus,
        );
        if (residue !== undefined) {
            return residue;
        }
    }
};

const sampleCenteredTernary = (sampler: RandomByteSampler): -1 | 0 | 1 => {
    while (true) {
        const candidateByte = sampler.take(1)[0];
        if (candidateByte === undefined) {
            throw new Error('random byte sampler returned an empty byte.');
        }
        if (candidateByte < 255) {
            const residue = candidateByte % 3;

            return residue === 0 ? -1 : residue === 1 ? 0 : 1;
        }
    }
};

const sampleCenteredTernaryVector = (
    sampler: RandomByteSampler,
    ringDegree: number,
): (-1 | 0 | 1)[] =>
    Array.from({ length: ringDegree }, () => sampleCenteredTernary(sampler));

const sampleUniformResidueVector = (
    sampler: RandomByteSampler,
    modulus: number,
    ringDegree: number,
): number[] =>
    Array.from({ length: ringDegree }, () =>
        sampleUniformResidue(sampler, modulus),
    );

const sampleCommitmentOpeningRandomness = (
    sampler: RandomByteSampler,
    ringDegree: number,
): readonly (readonly number[])[] =>
    Array.from({ length: setupCommitmentRandomnessWidth }, () =>
        sampleCenteredTernaryVector(sampler, ringDegree),
    );

export const createVssSourceTrusteeCoefficientOpeningState = (
    input: VssSourceTrusteeCoefficientOpeningStateGenerationInput,
): VssSourceTrusteeCoefficientOpeningState => {
    assertNonEmptyString(input.sourceTrusteeIdentity, 'sourceTrusteeIdentity');
    assertNonNegativeSafeInteger(
        input.sourceTrusteeRosterPosition,
        'sourceTrusteeRosterPosition',
    );
    assertPositiveSafeInteger(input.participantCount, 'participantCount');
    assertPositiveSafeInteger(input.ringDegree, 'ringDegree');
    assertPositiveSafeInteger(input.thresholdDegree, 'thresholdDegree');
    if (input.sourceTrusteeRosterPosition >= input.participantCount) {
        throw new Error(
            'sourceTrusteeRosterPosition must be inside the accepted participant count.',
        );
    }
    if (input.qSharePrimes.length === 0) {
        throw new Error('qSharePrimes must contain at least one RNS prime.');
    }
    input.qSharePrimes.forEach((qSharePrime, rnsLimbIndex) => {
        assertPositiveSafeInteger(
            qSharePrime,
            `qSharePrimes.${String(rnsLimbIndex)}`,
        );
    });

    const sampler = new RandomByteSampler(
        input.randomBytes ?? defaultRandomBytes,
    );
    const shortSecretCoefficients = sampleCenteredTernaryVector(
        sampler,
        input.ringDegree,
    );
    const coefficientOpenings = input.qSharePrimes.flatMap(
        (rnsPrime, rnsLimbIndex) =>
            Array.from(
                { length: input.thresholdDegree },
                (_unused, shamirCoefficientIndex) => ({
                    rnsLimbIndex,
                    rnsPrime,
                    shamirCoefficientIndex,
                    coefficientMessage:
                        shamirCoefficientIndex === 0
                            ? shortSecretCoefficients.map((coefficient) =>
                                  centeredIntegerToResidue(
                                      coefficient,
                                      rnsPrime,
                                  ),
                              )
                            : sampleUniformResidueVector(
                                  sampler,
                                  rnsPrime,
                                  input.ringDegree,
                              ),
                    randomnessByColumn: sampleCommitmentOpeningRandomness(
                        sampler,
                        input.ringDegree,
                    ),
                }),
            ),
    );

    return {
        sourceTrusteeIdentity: input.sourceTrusteeIdentity,
        sourceTrusteeRosterPosition: input.sourceTrusteeRosterPosition,
        coefficientOpenings,
    };
};

const structuralMatrixCoefficient = (
    matrixRowIndex: number,
    randomnessColumnIndex: number,
    ringCoefficientPosition: number,
): number | undefined => {
    if (
        matrixRowIndex < setupCommitmentModuleRank &&
        randomnessColumnIndex > setupCommitmentModuleRank
    ) {
        const identityColumnIndex =
            randomnessColumnIndex - setupCommitmentModuleRank - 1;
        return Number(
            identityColumnIndex === matrixRowIndex &&
                ringCoefficientPosition === 0,
        );
    }
    if (
        matrixRowIndex === setupCommitmentModuleRank &&
        randomnessColumnIndex >= setupCommitmentModuleRank
    ) {
        return Number(
            randomnessColumnIndex === setupCommitmentModuleRank &&
                ringCoefficientPosition === 0,
        );
    }

    return undefined;
};

const sampleCommitmentMatrixResidue = (
    publicMatrixSeedHash: ProtocolHash,
    sourceRnsLimbIndex: number,
    commitmentModulusIndex: number,
    matrixRowIndex: number,
    randomnessColumnIndex: number,
    ringCoefficientPosition: number,
    modulus: number,
): number => {
    let blockIndex = 0;
    while (true) {
        const output = hexToBytes(
            hash512Hex(
                'sealed-lattice-bdlop-lnp-commitment/matrix-coefficient-v1',
                [
                    textEncoder.encode(publicMatrixSeedHash),
                    textEncoder.encode(String(sourceRnsLimbIndex)),
                    textEncoder.encode(String(commitmentModulusIndex)),
                    textEncoder.encode(String(matrixRowIndex)),
                    textEncoder.encode(String(randomnessColumnIndex)),
                    textEncoder.encode(String(ringCoefficientPosition)),
                    textEncoder.encode(String(modulus)),
                    textEncoder.encode(String(blockIndex)),
                ],
            ),
        );
        for (let offset = 0; offset < output.length; offset += 8) {
            const word = littleEndianU64(output.subarray(offset, offset + 8));
            const reducedValue = reduceUnbiasedU64(word, modulus);
            if (reducedValue !== undefined) {
                return reducedValue;
            }
        }
        blockIndex += 1;
    }
};

const setupCommitmentMatrixCoefficient = (
    publicMatrixSeedHash: ProtocolHash,
    sourceRnsLimbIndex: number,
    commitmentModulusIndex: number,
    matrixRowIndex: number,
    randomnessColumnIndex: number,
    ringCoefficientPosition: number,
    modulus: number,
): number => {
    const structuralCoefficient = structuralMatrixCoefficient(
        matrixRowIndex,
        randomnessColumnIndex,
        ringCoefficientPosition,
    );
    if (structuralCoefficient !== undefined) {
        return structuralCoefficient % modulus;
    }

    return sampleCommitmentMatrixResidue(
        publicMatrixSeedHash,
        sourceRnsLimbIndex,
        commitmentModulusIndex,
        matrixRowIndex,
        randomnessColumnIndex,
        ringCoefficientPosition,
        modulus,
    );
};

const setupCommitmentMatrixPolynomial = (
    publicMatrixSeedHash: ProtocolHash,
    sourceRnsLimbIndex: number,
    commitmentModulusIndex: number,
    matrixRowIndex: number,
    randomnessColumnIndex: number,
    ringDegree: number,
    modulus: number,
): number[] =>
    Array.from({ length: ringDegree }, (_unused, ringCoefficientPosition) =>
        setupCommitmentMatrixCoefficient(
            publicMatrixSeedHash,
            sourceRnsLimbIndex,
            commitmentModulusIndex,
            matrixRowIndex,
            randomnessColumnIndex,
            ringCoefficientPosition,
            modulus,
        ),
    );

const negacyclicProduct = (
    left: readonly number[],
    right: readonly number[],
    modulus: number,
): number[] => {
    if (left.length !== right.length) {
        throw new Error('negacyclic product inputs must have the same length.');
    }
    const modulusWide = BigInt(modulus);
    const product = Array.from({ length: left.length }, () => 0n);
    left.forEach((leftValue, leftIndex) => {
        right.forEach((rightValue, rightIndex) => {
            const term = (BigInt(leftValue) * BigInt(rightValue)) % modulusWide;
            const rawTargetIndex = leftIndex + rightIndex;
            const targetIndex =
                rawTargetIndex >= left.length
                    ? rawTargetIndex - left.length
                    : rawTargetIndex;
            product[targetIndex] =
                rawTargetIndex >= left.length
                    ? product[targetIndex] - term
                    : product[targetIndex] + term;
        });
    });

    return product.map((coefficient) =>
        Number(
            coefficient % modulusWide < 0n
                ? (coefficient % modulusWide) + modulusWide
                : coefficient % modulusWide,
        ),
    );
};

export const computeSetupCommitmentFromOpening = (input: {
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly qSharePrimes: readonly number[];
    readonly sourceRnsLimbIndex: number;
    readonly sourceMessageModulus: number;
    readonly shamirCoefficientIndex: number;
    readonly messageCoefficients: readonly number[];
    readonly randomnessByColumn: readonly (readonly number[])[];
    readonly ringDegree: number;
}): SetupCommitmentValue => {
    assertHashLike(input.publicMatrixSeedHash, 'publicMatrixSeedHash');
    assertNonNegativeSafeInteger(
        input.sourceRnsLimbIndex,
        'sourceRnsLimbIndex',
    );
    assertNonNegativeSafeInteger(
        input.shamirCoefficientIndex,
        'shamirCoefficientIndex',
    );
    assertPositiveSafeInteger(input.ringDegree, 'ringDegree');
    const expectedSourcePrime = input.qSharePrimes[input.sourceRnsLimbIndex];
    if (expectedSourcePrime === undefined) {
        throw new Error('sourceRnsLimbIndex is outside Q_share.');
    }
    if (input.sourceMessageModulus !== expectedSourcePrime) {
        throw new Error('sourceMessageModulus must match Q_share.');
    }
    assertResidueVector(
        input.messageCoefficients,
        input.sourceMessageModulus,
        input.ringDegree,
        'messageCoefficients',
    );
    assertRandomness(
        input.randomnessByColumn,
        input.ringDegree,
        'randomnessByColumn',
    );

    const commitmentLimbs = setupCommitmentModulusLimbIndices.map(
        (commitmentModulusIndex) => {
            const modulus = input.qSharePrimes[commitmentModulusIndex];
            if (modulus === undefined) {
                throw new Error('Commitment modulus limb is missing.');
            }
            const messageResidues = input.messageCoefficients.map(
                (coefficient) => coefficient % modulus,
            );
            const randomnessResidues = input.randomnessByColumn.map((column) =>
                column.map((coefficient) =>
                    centeredIntegerToResidue(coefficient, modulus),
                ),
            );
            const rows = Array.from(
                { length: setupCommitmentRowCount },
                (_unused, matrixRowIndex) => {
                    const rowAccumulator = Array.from(
                        { length: input.ringDegree },
                        () => 0,
                    );
                    randomnessResidues.forEach(
                        (randomnessColumn, randomnessColumnIndex) => {
                            const matrixPolynomial =
                                setupCommitmentMatrixPolynomial(
                                    input.publicMatrixSeedHash,
                                    input.sourceRnsLimbIndex,
                                    commitmentModulusIndex,
                                    matrixRowIndex,
                                    randomnessColumnIndex,
                                    input.ringDegree,
                                    modulus,
                                );
                            const product = negacyclicProduct(
                                matrixPolynomial,
                                randomnessColumn,
                                modulus,
                            );
                            product.forEach(
                                (productValue, coefficientIndex) => {
                                    rowAccumulator[coefficientIndex] = addMod(
                                        rowAccumulator[coefficientIndex] ?? 0,
                                        productValue,
                                        modulus,
                                    );
                                },
                            );
                        },
                    );
                    if (matrixRowIndex === setupCommitmentModuleRank) {
                        messageResidues.forEach(
                            (messageValue, coefficientIndex) => {
                                rowAccumulator[coefficientIndex] = addMod(
                                    rowAccumulator[coefficientIndex] ?? 0,
                                    messageValue,
                                    modulus,
                                );
                            },
                        );
                    }

                    return rowAccumulator;
                },
            );

            return {
                commitmentModulusIndex,
                modulus,
                rows,
            };
        },
    );

    return {
        sourceRnsLimbIndex: input.sourceRnsLimbIndex,
        sourceMessageModulus: input.sourceMessageModulus,
        shamirCoefficientIndex: input.shamirCoefficientIndex,
        ringDegree: input.ringDegree,
        commitmentLimbs,
    };
};

export const setupCommitmentFullValue = (
    commitment: SetupCommitmentValue,
): JsonRecord => ({
    objectType: 'SetupCommitment',
    objectVersion: 1,
    profileId: setupCommitmentProfileId,
    sourceRnsLimbIndex: commitment.sourceRnsLimbIndex,
    sourceMessageModulus: commitment.sourceMessageModulus,
    shamirCoefficientIndex: commitment.shamirCoefficientIndex,
    ringDegree: commitment.ringDegree,
    commitmentLimbs: commitment.commitmentLimbs.map((limb) => ({
        commitmentModulusIndex: limb.commitmentModulusIndex,
        modulus: limb.modulus,
        rows: limb.rows,
    })),
});

export const setupCommitmentRootPayload = (
    commitment: SetupCommitmentValue,
): JsonRecord => ({
    objectType: 'SetupCommitment',
    objectVersion: 1,
    profileId: setupCommitmentProfileId,
    sourceRnsLimbIndex: commitment.sourceRnsLimbIndex,
    sourceMessageModulus: commitment.sourceMessageModulus,
    shamirCoefficientIndex: commitment.shamirCoefficientIndex,
    ringDegree: commitment.ringDegree,
    commitmentLimbs: commitment.commitmentLimbs.map((limb) => ({
        commitmentModulusIndex: limb.commitmentModulusIndex,
        modulus: limb.modulus,
        rowCoefficientHash512: limb.rows.map((row) =>
            coefficientVectorHash512(
                row,
                'sealed-lattice-bdlop-lnp-commitment/row-coefficients-v1',
            ),
        ),
    })),
});

const publicCommitmentCoefficientVectorHash512 = (
    commitment: SetupCommitmentValue,
): string =>
    coefficientVectorHash512(
        commitment.commitmentLimbs.flatMap((limb) => limb.rows.flat()),
        'sealed-lattice-bdlop-lnp-commitment/public-commitment-coefficients-v1',
    );

const commitmentChunkRoot = (
    commitment: SetupCommitmentValue,
    commitmentRoot: ProtocolHash,
): ProtocolHash =>
    deriveProtocolHash('VssCoefficientCommitmentRoot', {
        objectType: 'VssCoefficientCommitmentChunkRoot',
        objectVersion: 1,
        commitmentProfileId: setupCommitmentProfileId,
        commitmentRoot,
        commitmentLimbs: commitment.commitmentLimbs.map((limb) => ({
            commitmentModulusIndex: limb.commitmentModulusIndex,
            modulus: limb.modulus,
            rowCoefficientHash512: limb.rows.map((row) =>
                coefficientVectorHash512(
                    row,
                    'sealed-lattice-bdlop-lnp-commitment/row-coefficients-v1',
                ),
            ),
        })),
    });

const bytesToHex = (bytes: Uint8Array): string =>
    Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');

const hexToBytesStrict = (hex: string, fieldName: string): Uint8Array => {
    if (!/^(?:[0-9a-f]{2})*$/u.test(hex)) {
        throw new TypeError(`${fieldName} must be lowercase hex bytes.`);
    }

    return hexToBytes(hex);
};

const assertJsonRecord = (value: unknown, fieldName: string): JsonRecord => {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
        throw new TypeError(`${fieldName} must be an object.`);
    }

    return value as JsonRecord;
};

const assertJsonRecordArray = (
    value: unknown,
    fieldName: string,
): readonly JsonRecord[] => {
    if (!Array.isArray(value)) {
        throw new TypeError(`${fieldName} must be an array.`);
    }

    return value.map((entry, entryIndex) =>
        assertJsonRecord(entry, `${fieldName}.${String(entryIndex)}`),
    );
};

const appendVaruint = (outputBytes: number[], value: number): void => {
    if (!Number.isSafeInteger(value) || value < 0) {
        throw new TypeError(
            'varuint values must be non-negative safe integers.',
        );
    }
    let remainingValue = value;
    for (;;) {
        let byte = remainingValue & 0x7f;
        remainingValue = Math.floor(remainingValue / 128);
        if (remainingValue !== 0) {
            byte |= 0x80;
        }
        outputBytes.push(byte);
        if (remainingValue === 0) {
            break;
        }
    }
};

const varuintBytes = (value: number): Uint8Array => {
    const outputBytes: number[] = [];
    appendVaruint(outputBytes, value);

    return Uint8Array.from(outputBytes);
};

const assertSafeU64 = (value: number, fieldName: string): void => {
    if (!Number.isSafeInteger(value) || value < 0) {
        throw new TypeError(
            `${fieldName} must be a non-negative safe integer.`,
        );
    }
};

const positiveSafeIntegerField = (
    value: unknown,
    fieldName: string,
): number => {
    if (
        typeof value !== 'number' ||
        !Number.isSafeInteger(value) ||
        value <= 0
    ) {
        throw new TypeError(`${fieldName} must be a positive safe integer.`);
    }

    return value;
};

const nonNegativeSafeIntegerField = (
    value: unknown,
    fieldName: string,
): number => {
    if (
        typeof value !== 'number' ||
        !Number.isSafeInteger(value) ||
        value < 0
    ) {
        throw new TypeError(
            `${fieldName} must be a non-negative safe integer.`,
        );
    }

    return value;
};

class BinaryChunkWriter {
    private readonly chunks: Uint8Array[] = [];

    private currentChunk = new Uint8Array(setupTransportChunkSizeBytes);

    private currentChunkOffset = 0;

    public writeByte(value: number): void {
        if (this.currentChunkOffset === this.currentChunk.byteLength) {
            this.flushCurrentChunk();
        }
        this.currentChunk[this.currentChunkOffset] = value;
        this.currentChunkOffset += 1;
    }

    public writeBytes(bytes: Uint8Array): void {
        let sourceOffset = 0;
        while (sourceOffset < bytes.byteLength) {
            if (this.currentChunkOffset === this.currentChunk.byteLength) {
                this.flushCurrentChunk();
            }
            const writableLength = Math.min(
                bytes.byteLength - sourceOffset,
                this.currentChunk.byteLength - this.currentChunkOffset,
            );
            this.currentChunk.set(
                bytes.subarray(sourceOffset, sourceOffset + writableLength),
                this.currentChunkOffset,
            );
            sourceOffset += writableLength;
            this.currentChunkOffset += writableLength;
        }
    }

    public writeVaruint(value: number): void {
        this.writeBytes(varuintBytes(value));
    }

    public writeU64(value: number, fieldName: string): void {
        assertSafeU64(value, fieldName);
        let remainingValue = BigInt(value);
        for (let byteIndex = 0; byteIndex < 8; byteIndex += 1) {
            this.writeByte(Number(remainingValue & 0xffn));
            remainingValue >>= 8n;
        }
    }

    public finish(): readonly Uint8Array[] {
        if (this.currentChunkOffset > 0) {
            this.flushCurrentChunk();
        }
        if (this.chunks.length === 0) {
            throw new Error(
                'binary VSS material transport requires at least one chunk.',
            );
        }

        return this.chunks;
    }

    private flushCurrentChunk(): void {
        this.chunks.push(this.currentChunk.slice(0, this.currentChunkOffset));
        this.currentChunk = new Uint8Array(setupTransportChunkSizeBytes);
        this.currentChunkOffset = 0;
    }
}

class BinaryChunkReader {
    private chunkIndex = 0;

    private chunkOffset = 0;

    private bytesRead = 0;

    private readonly totalByteLength: number;

    public constructor(private readonly chunks: readonly Uint8Array[]) {
        if (chunks.length === 0) {
            throw new Error(
                'transported VSS material requires at least one chunk.',
            );
        }
        this.totalByteLength = chunks.reduce(
            (accumulatedLength, chunk) => accumulatedLength + chunk.byteLength,
            0,
        );
    }

    public isFinished(): boolean {
        return this.bytesRead === this.totalByteLength;
    }

    public readBytes(byteLength: number, fieldName: string): Uint8Array {
        const outputBytes = new Uint8Array(byteLength);
        let outputOffset = 0;
        while (outputOffset < byteLength) {
            const chunk = this.chunks[this.chunkIndex];
            if (chunk === undefined) {
                throw new Error(
                    `${fieldName} ended before the binary object was complete.`,
                );
            }
            const availableLength = chunk.byteLength - this.chunkOffset;
            if (availableLength === 0) {
                this.chunkIndex += 1;
                this.chunkOffset = 0;
                continue;
            }
            const copyLength = Math.min(
                byteLength - outputOffset,
                availableLength,
            );
            outputBytes.set(
                chunk.subarray(this.chunkOffset, this.chunkOffset + copyLength),
                outputOffset,
            );
            this.chunkOffset += copyLength;
            this.bytesRead += copyLength;
            outputOffset += copyLength;
        }

        return outputBytes;
    }

    public readVaruint(fieldName: string): number {
        let shift = 0;
        let value = 0n;
        const consumedBytes: number[] = [];
        for (let byteIndex = 0; byteIndex < 10; byteIndex += 1) {
            const byte = this.readBytes(1, fieldName)[0];
            if (byte === undefined) {
                throw new Error(`${fieldName} varuint is malformed.`);
            }
            consumedBytes.push(byte);
            const payload = BigInt(byte & 0x7f);
            if (byteIndex === 9 && payload > 1n) {
                throw new Error(`${fieldName} varuint exceeds u64.`);
            }
            value |= payload << BigInt(shift);
            if ((byte & 0x80) === 0) {
                if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
                    throw new Error(
                        `${fieldName} varuint exceeds safe integer.`,
                    );
                }
                const numberValue = Number(value);
                const canonicalBytes = Array.from(varuintBytes(numberValue));
                if (
                    canonicalBytes.length !== consumedBytes.length ||
                    canonicalBytes.some(
                        (canonicalByte, index) =>
                            canonicalByte !== consumedBytes[index],
                    )
                ) {
                    throw new Error(
                        `${fieldName} varuint is not minimally encoded.`,
                    );
                }

                return numberValue;
            }
            shift += 7;
        }

        throw new Error(`${fieldName} varuint is too long.`);
    }

    public readU64(fieldName: string): number {
        const bytes = this.readBytes(8, fieldName);
        let value = 0n;
        for (let byteIndex = 7; byteIndex >= 0; byteIndex -= 1) {
            value = (value << 8n) | BigInt(bytes[byteIndex] ?? 0);
        }
        if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
            throw new Error(`${fieldName} exceeds safe integer.`);
        }

        return Number(value);
    }
}

const setupVssMaterialChunkHash = (
    fullObjectHash: ProtocolHash,
    chunkIndex: number,
    chunk: Uint8Array,
): ProtocolHash =>
    hash512Hex(
        'sealed-lattice/setup/vss-coefficient-commitment-material/chunk-v1',
        [textEncoder.encode(fullObjectHash), varuintBytes(chunkIndex), chunk],
    );

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

const transportHashesForChunks = (
    chunks: readonly Uint8Array[],
): Readonly<{
    readonly fullObjectHash: ProtocolHash;
    readonly chunkHashes: readonly ProtocolHash[];
    readonly chunkRoot: ProtocolHash;
    readonly totalByteLength: number;
}> => {
    if (chunks.length === 0) {
        throw new Error(
            'setup transport requires at least one material chunk.',
        );
    }
    const totalByteLength = chunks.reduce(
        (accumulatedLength, chunk, chunkIndex) => {
            if (chunk.byteLength === 0) {
                throw new Error('setup transport chunks must be non-empty.');
            }
            if (chunk.byteLength > setupTransportChunkSizeBytes) {
                throw new Error(
                    'setup transport chunk exceeds the accepted chunk size.',
                );
            }
            if (
                chunkIndex + 1 < chunks.length &&
                chunk.byteLength !== setupTransportChunkSizeBytes
            ) {
                throw new Error(
                    'setup transport contains a short non-final chunk.',
                );
            }

            return accumulatedLength + chunk.byteLength;
        },
        0,
    );
    const fullObjectHash = setupVssMaterialFullObjectHashHex(
        totalByteLength,
        chunks,
    );
    const chunkHashes = chunks.map((chunk, chunkIndex) =>
        setupVssMaterialChunkHash(fullObjectHash, chunkIndex, chunk),
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

const parseSetupCommitmentValue = (
    value: unknown,
    objectPath: string,
): SetupCommitmentValue => {
    const commitment = assertJsonRecord(value, objectPath);
    if (commitment.objectType !== 'SetupCommitment') {
        throw new Error(`${objectPath}.objectType must be SetupCommitment.`);
    }
    if (commitment.objectVersion !== 1) {
        throw new Error(`${objectPath}.objectVersion must be 1.`);
    }
    if (commitment.profileId !== setupCommitmentProfileId) {
        throw new Error(
            `${objectPath}.profileId must be ${setupCommitmentProfileId}.`,
        );
    }
    const sourceRnsLimbIndex = nonNegativeSafeIntegerField(
        commitment.sourceRnsLimbIndex,
        `${objectPath}.sourceRnsLimbIndex`,
    );
    const sourceMessageModulus = positiveSafeIntegerField(
        commitment.sourceMessageModulus,
        `${objectPath}.sourceMessageModulus`,
    );
    const shamirCoefficientIndex = nonNegativeSafeIntegerField(
        commitment.shamirCoefficientIndex,
        `${objectPath}.shamirCoefficientIndex`,
    );
    const ringDegree = positiveSafeIntegerField(
        commitment.ringDegree,
        `${objectPath}.ringDegree`,
    );
    const commitmentLimbs = assertJsonRecordArray(
        commitment.commitmentLimbs,
        `${objectPath}.commitmentLimbs`,
    ).map((commitmentLimb, commitmentLimbIndex) => {
        const limbPath = `${objectPath}.commitmentLimbs.${String(commitmentLimbIndex)}`;
        const commitmentModulusIndex = nonNegativeSafeIntegerField(
            commitmentLimb.commitmentModulusIndex,
            `${limbPath}.commitmentModulusIndex`,
        );
        const modulus = positiveSafeIntegerField(
            commitmentLimb.modulus,
            `${limbPath}.modulus`,
        );
        if (!Array.isArray(commitmentLimb.rows)) {
            throw new TypeError(`${limbPath}.rows must be an array.`);
        }
        const rows = commitmentLimb.rows.map((rowValue, rowIndex) => {
            if (!Array.isArray(rowValue)) {
                throw new TypeError(
                    `${limbPath}.rows.${String(rowIndex)} must be an array.`,
                );
            }
            const row = rowValue.map((coefficient, coefficientIndex) => {
                if (typeof coefficient !== 'number') {
                    throw new TypeError(
                        `${limbPath}.rows.${String(rowIndex)}.${String(coefficientIndex)} must be a number.`,
                    );
                }

                return coefficient;
            });
            assertResidueVector(
                row,
                modulus,
                ringDegree,
                `${limbPath}.rows.${String(rowIndex)}`,
            );

            return row;
        });

        return {
            commitmentModulusIndex,
            modulus,
            rows,
        };
    });

    return {
        sourceRnsLimbIndex,
        sourceMessageModulus,
        shamirCoefficientIndex,
        ringDegree,
        commitmentLimbs,
    };
};

const sortedCoefficientCommitmentMaterialRecords = (
    materialSet: VssCoefficientCommitmentMaterialSet,
): readonly VssCoefficientCommitmentMaterialRecord[] => {
    const recordsByCoordinate = new Map<
        string,
        VssCoefficientCommitmentMaterialRecord
    >();
    materialSet.coefficientCommitments.forEach((materialRecord) => {
        const coordinateKey = [
            materialRecord.sourceTrusteeRosterPosition,
            materialRecord.rnsLimbIndex,
            materialRecord.shamirCoefficientIndex,
        ].join(':');
        if (recordsByCoordinate.has(coordinateKey)) {
            throw new Error(
                'vssCoefficientCommitmentMaterial must not contain duplicate coordinate records.',
            );
        }
        recordsByCoordinate.set(coordinateKey, materialRecord);
    });

    const sortedRecords: VssCoefficientCommitmentMaterialRecord[] = [];
    for (
        let sourceTrusteeRosterPosition = 0;
        sourceTrusteeRosterPosition < materialSet.participantCount;
        sourceTrusteeRosterPosition += 1
    ) {
        for (
            let rnsLimbIndex = 0;
            rnsLimbIndex < materialSet.rnsLimbCount;
            rnsLimbIndex += 1
        ) {
            for (
                let shamirCoefficientIndex = 0;
                shamirCoefficientIndex < materialSet.thresholdDegree;
                shamirCoefficientIndex += 1
            ) {
                const materialRecord = recordsByCoordinate.get(
                    [
                        sourceTrusteeRosterPosition,
                        rnsLimbIndex,
                        shamirCoefficientIndex,
                    ].join(':'),
                );
                if (materialRecord === undefined) {
                    throw new Error(
                        'vssCoefficientCommitmentMaterial must cover every source trustee, RNS limb, and Shamir coefficient.',
                    );
                }
                sortedRecords.push(materialRecord);
            }
        }
    }
    if (sortedRecords.length !== materialSet.materialRecordCount) {
        throw new Error(
            'vssCoefficientCommitmentMaterial.materialRecordCount must match the encoded records.',
        );
    }

    return sortedRecords;
};

const writeSetupCommitment = (
    writer: BinaryChunkWriter,
    materialRecord: VssCoefficientCommitmentMaterialRecord,
): void => {
    const commitment = parseSetupCommitmentValue(
        materialRecord.commitment,
        'vssCoefficientCommitmentMaterial.coefficientCommitments.commitment',
    );
    const commitmentRoot = deriveProtocolHash(
        'SetupCommitmentRoot',
        setupCommitmentRootPayload(commitment),
    );
    if (commitmentRoot !== materialRecord.commitmentRoot) {
        throw new Error(
            'VSS coefficient commitment material record root must match the encoded setup commitment.',
        );
    }
    if (
        commitment.sourceRnsLimbIndex !== materialRecord.rnsLimbIndex ||
        commitment.sourceMessageModulus !== materialRecord.rnsPrime ||
        commitment.shamirCoefficientIndex !==
            materialRecord.shamirCoefficientIndex
    ) {
        throw new Error(
            'VSS coefficient commitment material coordinate must match the encoded setup commitment.',
        );
    }
    writer.writeVaruint(materialRecord.sourceTrusteeRosterPosition);
    writer.writeVaruint(materialRecord.rnsLimbIndex);
    writer.writeVaruint(materialRecord.shamirCoefficientIndex);
    for (const commitmentModulusIndex of setupCommitmentModulusLimbIndices) {
        const commitmentLimb = commitment.commitmentLimbs.find(
            (candidateLimb) =>
                candidateLimb.commitmentModulusIndex === commitmentModulusIndex,
        );
        if (commitmentLimb === undefined) {
            throw new Error(
                'setup commitment must include every commitment modulus limb.',
            );
        }
        writer.writeVaruint(commitmentModulusIndex);
        writer.writeU64(
            commitmentLimb.modulus,
            'setup commitment modulus limb',
        );
        if (commitmentLimb.rows.length !== setupCommitmentRowCount) {
            throw new Error(
                'setup commitment must include the accepted row count.',
            );
        }
        commitmentLimb.rows.forEach((row, rowIndex) => {
            if (row.length !== commitment.ringDegree) {
                throw new Error(
                    `setup commitment row ${String(rowIndex)} length must match ringDegree.`,
                );
            }
            row.forEach((coefficient) =>
                writer.writeU64(coefficient, 'setup commitment coefficient'),
            );
        });
    }
};

const encodeVssCoefficientCommitmentMaterial = (
    materialSet: VssCoefficientCommitmentMaterialSet,
): readonly Uint8Array[] => {
    const writer = new BinaryChunkWriter();
    writer.writeBytes(textEncoder.encode('SLVSSMAT'));
    writer.writeVaruint(1);
    writer.writeVaruint(materialSet.participantCount);
    writer.writeVaruint(materialSet.thresholdDegree);
    writer.writeVaruint(materialSet.rnsLimbCount);
    writer.writeVaruint(materialSet.ringDegree);
    writer.writeVaruint(setupCommitmentModulusLimbIndices.length);
    writer.writeVaruint(setupCommitmentRowCount);
    sortedCoefficientCommitmentMaterialRecords(materialSet).forEach(
        (materialRecord) => writeSetupCommitment(writer, materialRecord),
    );

    return writer.finish();
};

export const createBinaryChunkedVssCoefficientCommitmentMaterialTransport = (
    materialSet: VssCoefficientCommitmentMaterialSet,
): BinaryChunkedVssCoefficientCommitmentMaterialTransport => {
    if (
        materialSet.materialEncoding !== 'full-public-setup-commitment-values'
    ) {
        throw new Error(
            'binary VSS material transport must be built from embedded full public values.',
        );
    }
    const chunks = encodeVssCoefficientCommitmentMaterial(materialSet);
    const transportHashes = transportHashesForChunks(chunks);
    const commitmentProfileHash = materialSet.commitmentProfileHash;
    if (typeof commitmentProfileHash !== 'string') {
        throw new TypeError(
            'vssCoefficientCommitmentMaterial.commitmentProfileHash must be a string.',
        );
    }
    assertHashLike(
        commitmentProfileHash,
        'vssCoefficientCommitmentMaterial.commitmentProfileHash',
    );
    const materialSetWithoutRoot = {
        objectType: 'VssCoefficientCommitmentMaterialSet',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        ...contextFields(materialSet as unknown as CollectiveBgvSetupContext),
        commitmentProfileId: setupCommitmentProfileId,
        commitmentProfileHash,
        materialEncoding: 'binary-chunked-full-public-setup-commitment-values',
        binaryFormat: vssCoefficientCommitmentMaterialBinaryFormat,
        publicMatrixSeedHash: materialSet.publicMatrixSeedHash,
        vssCoefficientCommitmentRoot: materialSet.vssCoefficientCommitmentRoot,
        participantCount: materialSet.participantCount,
        thresholdDegree: materialSet.thresholdDegree,
        rnsLimbCount: materialSet.rnsLimbCount,
        ringDegree: materialSet.ringDegree,
        ringDegreeStatus: materialSet.ringDegreeStatus,
        materialRecordCount: materialSet.materialRecordCount,
        transport: {
            transportProfileId: setupTransportProfileId,
            chunkSizeBytes: setupTransportChunkSizeBytes,
            chunkCount: chunks.length,
            totalByteLength: transportHashes.totalByteLength,
            fullObjectHash: transportHashes.fullObjectHash,
            chunkRoot: transportHashes.chunkRoot,
        },
    } as const satisfies Omit<
        BinaryChunkedVssCoefficientCommitmentMaterialSet,
        'vssCoefficientCommitmentMaterialRoot'
    >;
    const binaryMaterialSet = {
        ...materialSetWithoutRoot,
        vssCoefficientCommitmentMaterialRoot: deriveProtocolHash(
            'VssCoefficientCommitmentMaterialRoot',
            materialSetWithoutRoot,
        ),
    } satisfies BinaryChunkedVssCoefficientCommitmentMaterialSet;

    return {
        materialSet: binaryMaterialSet,
        transportedVssCoefficientCommitmentMaterial: {
            objectType: 'SetupTransportedVssCoefficientCommitmentMaterial',
            objectVersion: 1,
            binaryFormat: vssCoefficientCommitmentMaterialBinaryFormat,
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
        },
    };
};

const transportChunksFromObject = (
    transportedMaterial:
        | SetupTransportedVssCoefficientCommitmentMaterial
        | JsonRecord,
): readonly Uint8Array[] => {
    const materialObject = assertJsonRecord(
        transportedMaterial,
        'transportedVssCoefficientCommitmentMaterial',
    );
    if (
        materialObject.objectType !==
        'SetupTransportedVssCoefficientCommitmentMaterial'
    ) {
        throw new Error(
            'transportedVssCoefficientCommitmentMaterial.objectType must be SetupTransportedVssCoefficientCommitmentMaterial.',
        );
    }
    if (materialObject.objectVersion !== 1) {
        throw new Error(
            'transportedVssCoefficientCommitmentMaterial.objectVersion must be 1.',
        );
    }
    if (
        materialObject.binaryFormat !==
        vssCoefficientCommitmentMaterialBinaryFormat
    ) {
        throw new Error(
            'transported VSS coefficient material must use the accepted binary format.',
        );
    }
    if (materialObject.chunkSizeBytes !== setupTransportChunkSizeBytes) {
        throw new Error(
            'transported VSS coefficient material must use the accepted 1 MiB setup chunk size.',
        );
    }
    const chunkCount = positiveSafeIntegerField(
        materialObject.chunkCount,
        'transportedVssCoefficientCommitmentMaterial.chunkCount',
    );
    const chunkHashes = assertJsonRecordArray(
        (materialObject as SetupTransportedVssCoefficientCommitmentMaterial)
            .chunks,
        'transportedVssCoefficientCommitmentMaterial.chunks',
    );
    if (chunkHashes.length !== chunkCount) {
        throw new Error('transport chunks length must match chunkCount.');
    }

    return chunkHashes.map((chunk, expectedChunkIndex) => {
        if (chunk.chunkIndex !== expectedChunkIndex) {
            throw new Error(
                'transport chunks must be supplied in ascending chunk-index order.',
            );
        }

        return hexToBytesStrict(
            String(chunk.bytesHex),
            `transportedVssCoefficientCommitmentMaterial.chunks.${String(expectedChunkIndex)}.bytesHex`,
        );
    });
};

const verifyTransportObjectHashes = (
    transportedMaterial:
        | SetupTransportedVssCoefficientCommitmentMaterial
        | JsonRecord,
    chunks: readonly Uint8Array[],
): void => {
    const materialObject = assertJsonRecord(
        transportedMaterial,
        'transportedVssCoefficientCommitmentMaterial',
    );
    const hashes = transportHashesForChunks(chunks);
    if (materialObject.totalByteLength !== hashes.totalByteLength) {
        throw new Error(
            'transport totalByteLength must match supplied chunk bytes.',
        );
    }
    if (materialObject.fullObjectHash !== hashes.fullObjectHash) {
        throw new Error(
            'transport fullObjectHash does not match supplied chunk bytes.',
        );
    }
    if (materialObject.chunkRoot !== hashes.chunkRoot) {
        throw new Error(
            'transport chunkRoot does not match the canonical chunk manifest.',
        );
    }
    const observedChunkHashes = materialObject.chunkHashes;
    if (!Array.isArray(observedChunkHashes)) {
        throw new TypeError('transport chunkHashes must be an array.');
    }
    if (observedChunkHashes.length !== hashes.chunkHashes.length) {
        throw new Error('transport chunkHashes length must match chunkCount.');
    }
    hashes.chunkHashes.forEach((chunkHash, chunkIndex) => {
        if (observedChunkHashes[chunkIndex] !== chunkHash) {
            throw new Error(
                'transport chunkHashes do not match supplied chunk bytes.',
            );
        }
    });
};

const readTransportedSetupCommitment = (
    reader: BinaryChunkReader,
    expectedSourceTrusteeRosterPosition: number,
    expectedRnsLimbIndex: number,
    expectedRnsPrime: number,
    expectedShamirCoefficientIndex: number,
    expectedRingDegree: number,
    expectedCommitmentModuli: readonly number[],
): SetupCommitmentValue => {
    if (
        reader.readVaruint('sourceTrusteeRosterPosition') !==
        expectedSourceTrusteeRosterPosition
    ) {
        throw new Error(
            'transported VSS material source trustee order is not canonical.',
        );
    }
    if (reader.readVaruint('rnsLimbIndex') !== expectedRnsLimbIndex) {
        throw new Error(
            'transported VSS material RNS limb order is not canonical.',
        );
    }
    if (
        reader.readVaruint('shamirCoefficientIndex') !==
        expectedShamirCoefficientIndex
    ) {
        throw new Error(
            'transported VSS material Shamir coefficient order is not canonical.',
        );
    }
    const commitmentLimbs = setupCommitmentModulusLimbIndices.map(
        (expectedCommitmentModulusIndex) => {
            if (
                reader.readVaruint('commitmentModulusIndex') !==
                expectedCommitmentModulusIndex
            ) {
                throw new Error(
                    'transported commitment modulus limb order is not canonical.',
                );
            }
            const modulus = reader.readU64('commitment modulus');
            if (
                expectedCommitmentModuli[expectedCommitmentModulusIndex] !==
                modulus
            ) {
                throw new Error(
                    'transported commitment modulus does not match the commitment profile.',
                );
            }
            const rows = Array.from({ length: setupCommitmentRowCount }, () =>
                Array.from({ length: expectedRingDegree }, () => {
                    const coefficient = reader.readU64(
                        'commitment coefficient',
                    );
                    if (coefficient >= modulus) {
                        throw new Error(
                            'transported commitment coefficient is not canonical modulo its limb.',
                        );
                    }

                    return coefficient;
                }),
            );

            return {
                commitmentModulusIndex: expectedCommitmentModulusIndex,
                modulus,
                rows,
            };
        },
    );

    return {
        sourceRnsLimbIndex: expectedRnsLimbIndex,
        sourceMessageModulus: expectedRnsPrime,
        shamirCoefficientIndex: expectedShamirCoefficientIndex,
        ringDegree: expectedRingDegree,
        commitmentLimbs,
    };
};

const sortedSourceTrusteeCommitmentRecords = (
    vssCoefficientCommitments: VssCoefficientCommitmentSet,
): readonly VssSourceTrusteeCoefficientCommitmentRecord[] => {
    const sourceTrusteeRecords = [
        ...vssCoefficientCommitments.sourceTrusteeRecords,
    ].sort(
        (left, right) =>
            left.sourceTrusteeRosterPosition -
            right.sourceTrusteeRosterPosition,
    );
    sourceTrusteeRecords.forEach((sourceTrusteeRecord, expectedPosition) => {
        if (
            sourceTrusteeRecord.sourceTrusteeRosterPosition !== expectedPosition
        ) {
            throw new Error(
                'vssCoefficientCommitments source trustee records must be in contiguous roster order.',
            );
        }
    });

    return sourceTrusteeRecords;
};

export const materialRecordsFromTransportedVssCoefficientCommitmentMaterial = (
    input: Readonly<{
        readonly setupContext: CollectiveBgvSetupContext;
        readonly vssCoefficientCommitments: VssCoefficientCommitmentSet;
        readonly materialSet: BinaryChunkedVssCoefficientCommitmentMaterialSet;
        readonly transportedVssCoefficientCommitmentMaterial:
            | SetupTransportedVssCoefficientCommitmentMaterial
            | JsonRecord;
    }>,
): readonly VssCoefficientCommitmentMaterialRecord[] => {
    const chunks = transportChunksFromObject(
        input.transportedVssCoefficientCommitmentMaterial,
    );
    verifyTransportObjectHashes(
        input.transportedVssCoefficientCommitmentMaterial,
        chunks,
    );
    const materialTransport = input.materialSet.transport;
    const transportedMaterial = assertJsonRecord(
        input.transportedVssCoefficientCommitmentMaterial,
        'transportedVssCoefficientCommitmentMaterial',
    );
    if (
        materialTransport.fullObjectHash !==
            transportedMaterial.fullObjectHash ||
        materialTransport.chunkRoot !== transportedMaterial.chunkRoot ||
        materialTransport.chunkCount !== transportedMaterial.chunkCount ||
        materialTransport.totalByteLength !==
            transportedMaterial.totalByteLength
    ) {
        throw new Error(
            'binary VSS material set transport metadata must match the transported material object.',
        );
    }
    if (
        input.materialSet.vssCoefficientCommitmentRoot !==
        input.vssCoefficientCommitments.vssCoefficientCommitmentRoot
    ) {
        throw new Error(
            'binary VSS material set root binding must match VSS coefficient commitments.',
        );
    }
    const materialRootWithoutRoot = { ...input.materialSet };
    delete (materialRootWithoutRoot as JsonRecord)
        .vssCoefficientCommitmentMaterialRoot;
    if (
        deriveProtocolHash(
            'VssCoefficientCommitmentMaterialRoot',
            materialRootWithoutRoot,
        ) !== input.materialSet.vssCoefficientCommitmentMaterialRoot
    ) {
        throw new Error(
            'binary VSS material set root must match the canonical material set.',
        );
    }

    const sourceTrusteeRecords = sortedSourceTrusteeCommitmentRecords(
        input.vssCoefficientCommitments,
    );
    if (sourceTrusteeRecords.length !== input.materialSet.participantCount) {
        throw new Error(
            'binary VSS material participant count must match VSS coefficient commitments.',
        );
    }
    const reader = new BinaryChunkReader(chunks);
    const expectedCommitmentModuli = setupCommitmentModulusLimbIndices.map(
        (commitmentModulusIndex) => {
            const firstSourceTrusteeRecord = sourceTrusteeRecords[0];
            const coefficientRecord =
                firstSourceTrusteeRecord?.coefficientCommitments.find(
                    (candidateRecord) =>
                        candidateRecord.rnsLimbIndex === commitmentModulusIndex,
                );
            if (coefficientRecord === undefined) {
                throw new Error(
                    'VSS coefficient commitments must expose every commitment modulus limb.',
                );
            }

            return coefficientRecord.rnsPrime;
        },
    );
    const magic = reader.readBytes(8, 'transported VSS material magic');
    if (new TextDecoder().decode(magic) !== 'SLVSSMAT') {
        throw new Error(
            'transported VSS material binary magic does not match.',
        );
    }
    if (reader.readVaruint('binary version') !== 1) {
        throw new Error(
            'transported VSS material binary version is unsupported.',
        );
    }
    if (
        reader.readVaruint('participantCount') !==
        input.materialSet.participantCount
    ) {
        throw new Error(
            'transported VSS material participant count does not match the material set.',
        );
    }
    if (
        reader.readVaruint('thresholdDegree') !==
        input.materialSet.thresholdDegree
    ) {
        throw new Error(
            'transported VSS material threshold degree does not match the material set.',
        );
    }
    if (reader.readVaruint('rnsLimbCount') !== input.materialSet.rnsLimbCount) {
        throw new Error(
            'transported VSS material RNS limb count does not match the material set.',
        );
    }
    if (reader.readVaruint('ringDegree') !== input.materialSet.ringDegree) {
        throw new Error(
            'transported VSS material ring degree does not match the material set.',
        );
    }
    if (
        reader.readVaruint('commitmentLimbCount') !==
        setupCommitmentModulusLimbIndices.length
    ) {
        throw new Error(
            'transported VSS material commitment limb count does not match the commitment profile.',
        );
    }
    if (reader.readVaruint('rowCount') !== setupCommitmentRowCount) {
        throw new Error(
            'transported VSS material row count does not match the commitment profile.',
        );
    }

    const materialRecords: VssCoefficientCommitmentMaterialRecord[] = [];
    for (
        let sourceTrusteeRosterPosition = 0;
        sourceTrusteeRosterPosition < input.materialSet.participantCount;
        sourceTrusteeRosterPosition += 1
    ) {
        const sourceTrusteeRecord =
            sourceTrusteeRecords[sourceTrusteeRosterPosition];
        if (sourceTrusteeRecord === undefined) {
            throw new Error(
                'transport material is missing a source trustee binding.',
            );
        }
        for (
            let rnsLimbIndex = 0;
            rnsLimbIndex < input.materialSet.rnsLimbCount;
            rnsLimbIndex += 1
        ) {
            const coefficientRecordForLimb =
                sourceTrusteeRecord.coefficientCommitments.find(
                    (candidateRecord) =>
                        candidateRecord.rnsLimbIndex === rnsLimbIndex,
                );
            if (coefficientRecordForLimb === undefined) {
                throw new Error(
                    'source trustee record is missing an RNS limb commitment.',
                );
            }
            for (
                let shamirCoefficientIndex = 0;
                shamirCoefficientIndex < input.materialSet.thresholdDegree;
                shamirCoefficientIndex += 1
            ) {
                const commitment = readTransportedSetupCommitment(
                    reader,
                    sourceTrusteeRosterPosition,
                    rnsLimbIndex,
                    coefficientRecordForLimb.rnsPrime,
                    shamirCoefficientIndex,
                    input.materialSet.ringDegree,
                    expectedCommitmentModuli,
                );
                const commitmentRoot = deriveProtocolHash(
                    'SetupCommitmentRoot',
                    setupCommitmentRootPayload(commitment),
                );
                const expectedCommitmentRecord =
                    sourceTrusteeRecord.coefficientCommitments.find(
                        (candidateRecord) =>
                            candidateRecord.rnsLimbIndex === rnsLimbIndex &&
                            candidateRecord.shamirCoefficientIndex ===
                                shamirCoefficientIndex,
                    );
                if (expectedCommitmentRecord === undefined) {
                    throw new Error(
                        'transport material coordinate is absent from the source trustee record.',
                    );
                }
                if (
                    expectedCommitmentRecord.commitmentRoot !== commitmentRoot
                ) {
                    throw new Error(
                        'transported setup commitment material does not match the source trustee commitment root.',
                    );
                }
                materialRecords.push({
                    objectType: 'VssCoefficientCommitmentMaterial',
                    objectVersion: 1,
                    ...contextFields(input.setupContext),
                    sourceTrusteeIdentity:
                        sourceTrusteeRecord.sourceTrusteeIdentity,
                    sourceTrusteeRosterPosition,
                    publicMatrixSeedHash:
                        input.materialSet.publicMatrixSeedHash,
                    rnsLimbIndex,
                    rnsPrime: expectedCommitmentRecord.rnsPrime,
                    shamirCoefficientIndex,
                    commitmentRoot,
                    commitment: setupCommitmentFullValue(commitment),
                });
            }
        }
    }
    if (!reader.isFinished()) {
        throw new Error(
            'transported VSS material has trailing bytes after the final commitment record.',
        );
    }
    if (materialRecords.length !== input.materialSet.materialRecordCount) {
        throw new Error(
            'transported VSS material record count must match the material set.',
        );
    }

    return materialRecords;
};

const validateCommitmentCommonInput = (
    input: Omit<
        VssCoefficientCommitmentBundleInput,
        'sourceTrusteeOpeningStates'
    >,
): void => {
    assertHashLike(input.publicMatrixSeedHash, 'publicMatrixSeedHash');
    assertPositiveSafeInteger(input.ringDegree, 'ringDegree');
    assertPositiveSafeInteger(input.participantCount, 'participantCount');
    assertPositiveSafeInteger(input.thresholdDegree, 'thresholdDegree');
    input.qSharePrimes.forEach((qSharePrime, rnsLimbIndex) => {
        assertPositiveSafeInteger(
            qSharePrime,
            `qSharePrimes.${String(rnsLimbIndex)}`,
        );
    });
    for (const fieldName of setupContextFieldNames) {
        const value = input.setupContext[fieldName];
        if (typeof value !== 'string' || value.length === 0) {
            throw new TypeError(`setupContext.${fieldName} must be non-empty.`);
        }
    }
};

export const createVssSourceTrusteeCoefficientCommitmentContribution = (
    input: VssSourceTrusteeCoefficientCommitmentContributionInput,
): VssSourceTrusteeCoefficientCommitmentContribution => {
    validateCommitmentCommonInput(input);
    const context = contextFields(input.setupContext);
    const sourceTrusteeState = input.sourceTrusteeOpeningState;
    assertNonEmptyString(
        sourceTrusteeState.sourceTrusteeIdentity,
        'sourceTrusteeIdentity',
    );
    assertNonNegativeSafeInteger(
        sourceTrusteeState.sourceTrusteeRosterPosition,
        'sourceTrusteeRosterPosition',
    );
    if (
        sourceTrusteeState.sourceTrusteeRosterPosition >= input.participantCount
    ) {
        throw new Error(
            'sourceTrusteeRosterPosition must be inside the accepted participant count.',
        );
    }
    const openingsByCoordinate = openingStateByCoordinate(
        sourceTrusteeState,
        input.qSharePrimes,
        input.ringDegree,
        input.thresholdDegree,
    );
    const materialRecords: VssCoefficientCommitmentMaterialRecord[] = [];
    const coefficientCommitments: VssCoefficientCommitmentRecord[] = [];
    const sourceTrusteePrivateOpenings: VssCoefficientOpeningMaterial[] = [];
    input.qSharePrimes.forEach((rnsPrime, rnsLimbIndex) => {
        for (
            let shamirCoefficientIndex = 0;
            shamirCoefficientIndex < input.thresholdDegree;
            shamirCoefficientIndex += 1
        ) {
            const openingState = openingsByCoordinate.get(
                openingCoordinateKey(rnsLimbIndex, shamirCoefficientIndex),
            );
            if (openingState === undefined) {
                throw new Error(
                    'source trustee coefficientOpenings must cover every declared coordinate.',
                );
            }
            const commitment = computeSetupCommitmentFromOpening({
                publicMatrixSeedHash: input.publicMatrixSeedHash,
                qSharePrimes: input.qSharePrimes,
                sourceRnsLimbIndex: rnsLimbIndex,
                sourceMessageModulus: rnsPrime,
                shamirCoefficientIndex,
                messageCoefficients: openingState.coefficientMessage,
                randomnessByColumn: openingState.randomnessByColumn,
                ringDegree: input.ringDegree,
            });
            const commitmentRoot = deriveProtocolHash(
                'SetupCommitmentRoot',
                setupCommitmentRootPayload(commitment),
            );
            sourceTrusteePrivateOpenings.push({
                ...openingState,
                commitmentRoot,
            });
            coefficientCommitments.push({
                objectType: 'VssCoefficientCommitment',
                objectVersion: 1,
                ...context,
                sourceTrusteeIdentity: sourceTrusteeState.sourceTrusteeIdentity,
                sourceTrusteeRosterPosition:
                    sourceTrusteeState.sourceTrusteeRosterPosition,
                publicMatrixSeedHash: input.publicMatrixSeedHash,
                rnsLimbIndex,
                rnsPrime,
                shamirCoefficientIndex,
                commitmentRoot,
                commitmentChunkRoot: commitmentChunkRoot(
                    commitment,
                    commitmentRoot,
                ),
                coefficientVectorHash512:
                    publicCommitmentCoefficientVectorHash512(commitment),
                openingVerificationStatus: 'pending-private-envelope-opening',
            });
            materialRecords.push({
                objectType: 'VssCoefficientCommitmentMaterial',
                objectVersion: 1,
                ...context,
                sourceTrusteeIdentity: sourceTrusteeState.sourceTrusteeIdentity,
                sourceTrusteeRosterPosition:
                    sourceTrusteeState.sourceTrusteeRosterPosition,
                publicMatrixSeedHash: input.publicMatrixSeedHash,
                rnsLimbIndex,
                rnsPrime,
                shamirCoefficientIndex,
                commitmentRoot,
                commitment: setupCommitmentFullValue(commitment),
            });
        }
    });
    const sourceTrusteeRecordWithoutRoot = {
        objectType: 'VssSourceTrusteeCoefficientCommitments',
        objectVersion: 1,
        ...context,
        sourceTrusteeIdentity: sourceTrusteeState.sourceTrusteeIdentity,
        sourceTrusteeRosterPosition:
            sourceTrusteeState.sourceTrusteeRosterPosition,
        publicMatrixSeedHash: input.publicMatrixSeedHash,
        coefficientCommitments,
    } as const satisfies Omit<
        VssSourceTrusteeCoefficientCommitmentRecord,
        'sourceTrusteeCommitmentRoot'
    >;
    const sourceTrusteeRecord = {
        ...sourceTrusteeRecordWithoutRoot,
        sourceTrusteeCommitmentRoot: deriveProtocolHash(
            'VssCoefficientCommitmentRoot',
            sourceTrusteeRecordWithoutRoot,
        ),
    } satisfies VssSourceTrusteeCoefficientCommitmentRecord;

    return {
        sourceTrusteeRecord,
        materialRecords,
        privateOpeningMaterial: {
            sourceTrusteeIdentity: sourceTrusteeState.sourceTrusteeIdentity,
            sourceTrusteeRosterPosition:
                sourceTrusteeState.sourceTrusteeRosterPosition,
            sourceTrusteeCommitmentRoot:
                sourceTrusteeRecord.sourceTrusteeCommitmentRoot,
            sourceTrusteeCoefficientCommitmentRecord: sourceTrusteeRecord,
            sourceTrusteeCoefficientCommitmentMaterialRecords: materialRecords,
            coefficientOpenings: sourceTrusteePrivateOpenings,
        },
    };
};

export const createVssCoefficientCommitmentBundle = (
    input: VssCoefficientCommitmentBundleInput,
): VssCoefficientCommitmentBundle => {
    validateCommitmentCommonInput(input);
    const context = contextFields(input.setupContext);
    const sortedSourceTrusteeStates = sortedByRosterPosition(
        input.sourceTrusteeOpeningStates,
    );
    assertFullRosterCoverage(sortedSourceTrusteeStates, input.participantCount);

    const sourceTrusteeContributions = sortedSourceTrusteeStates.map(
        (sourceTrusteeOpeningState) =>
            createVssSourceTrusteeCoefficientCommitmentContribution({
                setupContext: input.setupContext,
                publicMatrixSeedHash: input.publicMatrixSeedHash,
                qSharePrimes: input.qSharePrimes,
                ringDegree: input.ringDegree,
                participantCount: input.participantCount,
                thresholdDegree: input.thresholdDegree,
                sourceTrusteeOpeningState,
            }),
    );
    const sourceTrusteeRecords = sourceTrusteeContributions.map(
        (contribution) => contribution.sourceTrusteeRecord,
    );
    const coefficientCommitmentMaterial = sourceTrusteeContributions.flatMap(
        (contribution) => contribution.materialRecords,
    );
    const privateOpeningMaterialBySourceTrustee =
        sourceTrusteeContributions.map(
            (contribution) => contribution.privateOpeningMaterial,
        );

    const commitmentSetWithoutRoot = {
        objectType: 'VssCoefficientCommitmentSet',
        objectVersion: 1,
        ...context,
        publicMatrixSeedHash: input.publicMatrixSeedHash,
        sourceTrusteeRecords,
    } as const satisfies Omit<
        VssCoefficientCommitmentSet,
        'vssCoefficientCommitmentRoot'
    >;
    const commitmentSet = {
        ...commitmentSetWithoutRoot,
        vssCoefficientCommitmentRoot: deriveProtocolHash(
            'VssCoefficientCommitmentRoot',
            commitmentSetWithoutRoot,
        ),
    } satisfies VssCoefficientCommitmentSet;
    const materialSetWithoutRoot = {
        objectType: 'VssCoefficientCommitmentMaterialSet',
        objectVersion: 1,
        ...context,
        commitmentProfileId: setupCommitmentProfileId,
        publicMatrixSeedHash: input.publicMatrixSeedHash,
        vssCoefficientCommitmentRoot:
            commitmentSet.vssCoefficientCommitmentRoot,
        materialEncoding: 'full-public-setup-commitment-values',
        participantCount: input.participantCount,
        thresholdDegree: input.thresholdDegree,
        rnsLimbCount: input.qSharePrimes.length,
        ringDegree: input.ringDegree,
        ringDegreeStatus:
            input.ringDegree === acceptedBgvProfileRingDegree
                ? 'profile-ring'
                : 'development-reduced-ring',
        materialRecordCount: coefficientCommitmentMaterial.length,
        coefficientCommitments: coefficientCommitmentMaterial,
    } as const satisfies Omit<
        VssCoefficientCommitmentMaterialSet,
        'vssCoefficientCommitmentMaterialRoot'
    >;
    const materialSet = {
        ...materialSetWithoutRoot,
        vssCoefficientCommitmentMaterialRoot: deriveProtocolHash(
            'VssCoefficientCommitmentMaterialRoot',
            materialSetWithoutRoot,
        ),
    } satisfies VssCoefficientCommitmentMaterialSet;

    return {
        commitmentSet,
        materialSet,
        privateOpeningMaterialBySourceTrustee,
    };
};
