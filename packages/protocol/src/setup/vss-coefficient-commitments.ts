import { deriveProtocolHash, hash512Hex } from '@sealed-lattice/crypto';
import type { ProtocolHash } from '@sealed-lattice/types';

import type { CollectiveBgvSetupContext } from './vss-share-verification-records.js';

type JsonRecord = Record<string, unknown>;

export const setupCommitmentProfileId = 'SealedLattice-BDLOP-LNP-Commitment-v1';
export const setupCommitmentModuleRank = 2;
export const setupCommitmentRandomnessWidth = 2 * setupCommitmentModuleRank + 1;
export const setupCommitmentRowCount = setupCommitmentModuleRank + 1;
export const setupCommitmentModulusLimbIndices = [0, 1, 2] as const;
export const acceptedBgvProfileRingDegree = 32_768;

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
