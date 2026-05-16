import {
    canonicalJson,
    deriveProtocolDigest,
    hash512,
} from '@sealed-lattice/crypto';
import type {
    ProtocolDigest,
    ReceiverEncryptionProfile,
    ReceiverEncryptionPublicKey,
    ReceiverPayload,
    RefusalRecord,
    ShareCommitment,
    ShareCommitmentProfile,
} from '@sealed-lattice/types';

import { createRefusal } from '../common/verification-helpers.js';
import { assertCanonicalFieldElement } from '../plaintext-oracle/field.js';
import { pvssBallotShareVectorWidth } from '../pvss-ballot/common.js';

import {
    createReceiverEncryptionPublicKeyShell,
    createReceiverPayloadShell,
    createShareCommitmentShell,
} from './objects.js';

const textEncoder = new TextEncoder();
const receiverEncryptionModulus = 12_289;
const receiverEncryptionModuleRank = 4;
const receiverEncryptionModuleDegree = 256;
const receiverEncryptionMessageScale = Math.floor(
    receiverEncryptionModulus / 2,
);
const receiverEncryptionCenteredBinomialEta = 2;
const receiverOpeningRandomnessBitLength = 12;
const shareCommitmentModuleRank = 4;
const shareCommitmentModuleDegree = 256;
const shareCommitmentOpeningDimension = 64;
const shareCommitmentModulus = 18_446_744_069_414_584_321n;
const unsignedWordModulus = 1n << 64n;

type DeterministicFixtureRandomness = {
    readonly kind: 'fixture';
    readonly fixtureSeed: string;
    readonly allowFixtureMode: true;
};

type ProductionRandomness = {
    readonly kind: 'production';
};

type BallotPrivacyRandomnessSource =
    | DeterministicFixtureRandomness
    | ProductionRandomness;

export type ShareCommitmentOpeningWitness = {
    readonly openingRandomness: readonly number[];
};

export type ReceiverPayloadPlaintextWitness = {
    readonly receiverShareVector: readonly number[];
    readonly shareCommitmentOpening: ShareCommitmentOpeningWitness;
    readonly ceremonyId: string;
    readonly manifestDigest: ProtocolDigest;
    readonly rosterDigest: ProtocolDigest;
    readonly pollSpecDigest: ProtocolDigest;
    readonly voterIdentityDigest: ProtocolDigest;
    readonly receiverIdentity: string;
    readonly receiverRosterPosition: number;
    readonly ballotPackageContextDigest: ProtocolDigest;
};

type ReceiverEncryptionSecretState = {
    readonly secretVector: readonly (readonly number[])[];
    readonly errorVector: readonly (readonly number[])[];
};

type ReceiverEncryptionPublicKeyMaterial = {
    readonly publicMatrixSeedDigest: ProtocolDigest;
    readonly publicKeyVector: readonly (readonly number[])[];
};

type ReceiverEncryptionState = {
    readonly receiverPublicKey: ReceiverEncryptionPublicKey;
    readonly publicKeyMaterial: ReceiverEncryptionPublicKeyMaterial;
    readonly secretState: ReceiverEncryptionSecretState;
};

type ReceiverEncryptionChunkWitness = {
    readonly chunkIndex: number;
    readonly encryptionRandomnessVector: readonly (readonly number[])[];
    readonly firstNoiseVector: readonly (readonly number[])[];
    readonly secondNoisePolynomial: readonly number[];
};

type ReceiverEncryptionWitness = {
    readonly chunkWitnesses: readonly ReceiverEncryptionChunkWitness[];
};

type ReceiverPayloadCiphertextChunk = {
    readonly chunkIndex: number;
    readonly firstCiphertextVector: readonly (readonly number[])[];
    readonly secondCiphertextPolynomial: readonly number[];
};

type ReceiverPayloadEncryptionResult = {
    readonly receiverPayload: ReceiverPayload;
    readonly ciphertextChunks: readonly ReceiverPayloadCiphertextChunk[];
    readonly plaintextBitLength: number;
    readonly witness: ReceiverEncryptionWitness;
};

type ShareCommitmentMaterial = {
    readonly shareCommitment: ShareCommitment;
    readonly commitmentPolynomialVector: readonly (readonly string[])[];
    readonly opening: ShareCommitmentOpeningWitness;
};

const bytesToHex = (bytes: Uint8Array): string =>
    Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');

const canonicalBytes = (value: unknown): Uint8Array =>
    textEncoder.encode(canonicalJson(value));

const canonicalEqual = (leftValue: unknown, rightValue: unknown): boolean =>
    canonicalJson(leftValue) === canonicalJson(rightValue);

const deriveBytes = (
    domain: string,
    payload: unknown,
    byteLength: number,
): Uint8Array => {
    const output = new Uint8Array(byteLength);
    let outputOffset = 0;
    let blockCounter = 0;
    while (outputOffset < byteLength) {
        const block = hash512(domain, [
            canonicalBytes({
                blockCounter,
                payload,
            }),
        ]);
        const bytesToCopy = Math.min(block.length, byteLength - outputOffset);
        output.set(block.subarray(0, bytesToCopy), outputOffset);
        outputOffset += bytesToCopy;
        blockCounter += 1;
    }

    return output;
};

const readLittleEndianWord = (
    bytes: Uint8Array,
    byteOffset: number,
): bigint => {
    let value = 0n;
    for (let wordByteIndex = 0; wordByteIndex < 8; wordByteIndex += 1) {
        value |=
            BigInt(bytes[byteOffset + wordByteIndex] ?? 0) <<
            BigInt(8 * wordByteIndex);
    }

    return value;
};

const deriveUniformBigInt = (
    domain: string,
    payload: unknown,
    modulus: bigint,
): bigint => {
    const rejectionLimit =
        unsignedWordModulus - (unsignedWordModulus % modulus);
    let blockCounter = 0;
    for (;;) {
        const block = deriveBytes(domain, { blockCounter, payload }, 64);
        for (
            let byteOffset = 0;
            byteOffset + 8 <= block.length;
            byteOffset += 8
        ) {
            const candidate = readLittleEndianWord(block, byteOffset);
            if (candidate < rejectionLimit) {
                return candidate % modulus;
            }
        }
        blockCounter += 1;
    }
};

const deriveUniformNumber = (
    domain: string,
    payload: unknown,
    modulus: number,
): number => Number(deriveUniformBigInt(domain, payload, BigInt(modulus)));

const resolveRandomBytes = (
    randomnessSource: BallotPrivacyRandomnessSource,
    domain: string,
    payload: unknown,
    byteLength: number,
): Uint8Array => {
    if (randomnessSource.kind === 'fixture') {
        if (
            !randomnessSource.allowFixtureMode ||
            randomnessSource.fixtureSeed.length === 0
        ) {
            throw new RangeError(
                'Deterministic fixture randomness requires an explicit non-empty fixture seed and fixture-mode acknowledgement.',
            );
        }

        return deriveBytes(
            domain,
            { fixtureSeed: randomnessSource.fixtureSeed, payload },
            byteLength,
        );
    }

    const cryptoProvider = globalThis.crypto;
    if (
        cryptoProvider === undefined ||
        typeof cryptoProvider.getRandomValues !== 'function'
    ) {
        throw new Error(
            'Production ballot privacy randomness requires Web Crypto getRandomValues.',
        );
    }
    const bytes = new Uint8Array(byteLength);
    cryptoProvider.getRandomValues(bytes);

    return bytes;
};

const sampleCenteredBinomialCoefficient = (
    byteValue: number,
    nibbleOffset: number,
): number => {
    const nibble = (byteValue >> nibbleOffset) & 0x0f;
    const positiveWeight = (nibble & 0x01) + ((nibble >> 1) & 0x01);
    const negativeWeight = ((nibble >> 2) & 0x01) + ((nibble >> 3) & 0x01);

    return positiveWeight - negativeWeight;
};

const sampleCenteredBinomialVector = (
    randomnessSource: BallotPrivacyRandomnessSource,
    domain: string,
    payload: unknown,
    vectorLength: number,
    polynomialDegree: number,
): readonly (readonly number[])[] => {
    if (receiverEncryptionCenteredBinomialEta !== 2) {
        throw new RangeError(
            'Only centered-binomial eta=2 is supported by this profile.',
        );
    }
    const coefficientCount = vectorLength * polynomialDegree;
    const bytes = resolveRandomBytes(
        randomnessSource,
        domain,
        payload,
        Math.ceil(coefficientCount / 2),
    );
    const polynomials: number[][] = [];
    let coefficientIndex = 0;
    for (let vectorIndex = 0; vectorIndex < vectorLength; vectorIndex += 1) {
        const polynomial: number[] = [];
        for (
            let coefficientOffset = 0;
            coefficientOffset < polynomialDegree;
            coefficientOffset += 1
        ) {
            const byteValue = bytes[Math.floor(coefficientIndex / 2)] ?? 0;
            polynomial.push(
                sampleCenteredBinomialCoefficient(
                    byteValue,
                    coefficientIndex % 2 === 0 ? 0 : 4,
                ),
            );
            coefficientIndex += 1;
        }
        polynomials.push(polynomial);
    }

    return polynomials;
};

const modNumber = (value: number, modulus: number): number =>
    ((value % modulus) + modulus) % modulus;

const modBigInt = (value: bigint, modulus: bigint): bigint =>
    ((value % modulus) + modulus) % modulus;

const addNumberPolynomials = (
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

const addBigIntPolynomials = (
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

const multiplyBigIntPolynomials = (
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

const deriveNumberPolynomial = (
    domain: string,
    payload: unknown,
    degree: number,
    modulus: number,
): readonly number[] =>
    Array.from({ length: degree }, (_unusedValue, coefficientIndex) =>
        deriveUniformNumber(domain, { coefficientIndex, payload }, modulus),
    );

const deriveBigIntPolynomial = (
    domain: string,
    payload: unknown,
    degree: number,
    modulus: bigint,
): readonly bigint[] =>
    Array.from({ length: degree }, (_unusedValue, coefficientIndex) =>
        deriveUniformBigInt(domain, { coefficientIndex, payload }, modulus),
    );

const deriveReceiverPublicMatrix = (
    receiverEncryptionProfileDigest: ProtocolDigest,
    publicMatrixSeedDigest: ProtocolDigest,
): readonly (readonly (readonly number[])[])[] =>
    Array.from(
        { length: receiverEncryptionModuleRank },
        (_unusedRow, rowIndex) =>
            Array.from(
                { length: receiverEncryptionModuleRank },
                (_unusedColumn, columnIndex) =>
                    deriveNumberPolynomial(
                        'sealed.vote/internal/receiver-encryption/public-matrix-v1',
                        {
                            columnIndex,
                            publicMatrixSeedDigest,
                            receiverEncryptionProfileDigest,
                            rowIndex,
                        },
                        receiverEncryptionModuleDegree,
                        receiverEncryptionModulus,
                    ),
            ),
    );

const deriveShareCommitmentMessageMatrix = (
    shareCommitmentProfileDigest: ProtocolDigest,
): readonly (readonly bigint[])[] =>
    Array.from({ length: shareCommitmentModuleRank }, (_unusedRow, rowIndex) =>
        deriveBigIntPolynomial(
            'sealed.vote/internal/share-commitment/message-matrix-v1',
            { rowIndex, shareCommitmentProfileDigest },
            shareCommitmentModuleDegree,
            shareCommitmentModulus,
        ),
    );

const deriveShareCommitmentRandomnessMatrix = (
    shareCommitmentProfileDigest: ProtocolDigest,
): readonly (readonly (readonly bigint[])[])[] =>
    Array.from({ length: shareCommitmentModuleRank }, (_unusedRow, rowIndex) =>
        Array.from(
            { length: shareCommitmentOpeningDimension },
            (_unusedColumn, columnIndex) =>
                deriveBigIntPolynomial(
                    'sealed.vote/internal/share-commitment/randomness-matrix-v1',
                    {
                        columnIndex,
                        rowIndex,
                        shareCommitmentProfileDigest,
                    },
                    shareCommitmentModuleDegree,
                    shareCommitmentModulus,
                ),
        ),
    );

const multiplyMatrixByVector = (
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

const multiplyTransposeMatrixByVector = (
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

const dotNumberPolynomialVectors = (
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

function validateReceiverShareVector(
    receiverShareVector: readonly number[],
): void {
    if (receiverShareVector.length !== pvssBallotShareVectorWidth) {
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

function validateShareCommitmentOpening(
    opening: ShareCommitmentOpeningWitness,
    shareCommitmentProfile: ShareCommitmentProfile,
): void {
    if (opening.openingRandomness.length !== shareCommitmentOpeningDimension) {
        throw new RangeError(
            'Share commitment openings must use the frozen dimension.',
        );
    }
    for (const openingCoordinate of opening.openingRandomness) {
        if (
            !Number.isSafeInteger(openingCoordinate) ||
            Math.abs(openingCoordinate) >
                shareCommitmentProfile.openingRandomnessInfinityNormBound
        ) {
            throw new RangeError(
                'Share commitment opening coordinates must satisfy the frozen infinity-norm bound.',
            );
        }
    }
}

const encodeShareVectorAsMessagePolynomial = (
    receiverShareVector: readonly number[],
): readonly bigint[] => {
    validateReceiverShareVector(receiverShareVector);
    const coefficients = Array.from(
        { length: shareCommitmentModuleDegree },
        () => 0n,
    );
    receiverShareVector.forEach((shareRepresentative, coefficientIndex) => {
        coefficients[coefficientIndex] = BigInt(shareRepresentative);
    });

    return coefficients;
};

const sampleShareCommitmentOpening = (
    randomnessSource: BallotPrivacyRandomnessSource,
    shareCommitmentProfile: ShareCommitmentProfile,
    payload: unknown,
): ShareCommitmentOpeningWitness => {
    const bytes = resolveRandomBytes(
        randomnessSource,
        'sealed.vote/internal/share-commitment/opening-randomness-v1',
        payload,
        shareCommitmentOpeningDimension * 2,
    );
    const openingRandomness = Array.from(
        { length: shareCommitmentOpeningDimension },
        (_unusedValue, coordinateIndex) => {
            const firstByte = bytes[coordinateIndex * 2] ?? 0;
            const secondByte = bytes[coordinateIndex * 2 + 1] ?? 0;
            const unsignedValue = firstByte | (secondByte << 8);
            const rangeWidth =
                shareCommitmentProfile.openingRandomnessInfinityNormBound * 2 +
                1;

            return (
                (unsignedValue % rangeWidth) -
                shareCommitmentProfile.openingRandomnessInfinityNormBound
            );
        },
    );

    return { openingRandomness };
};

const computeShareCommitmentVector = (
    shareVector: readonly number[],
    opening: ShareCommitmentOpeningWitness,
    shareCommitmentProfile: ShareCommitmentProfile,
): readonly (readonly bigint[])[] => {
    validateReceiverShareVector(shareVector);
    validateShareCommitmentOpening(opening, shareCommitmentProfile);
    const messagePolynomial = encodeShareVectorAsMessagePolynomial(shareVector);
    const messageMatrix = deriveShareCommitmentMessageMatrix(
        shareCommitmentProfile.shareCommitmentProfileDigest,
    );
    const randomnessMatrix = deriveShareCommitmentRandomnessMatrix(
        shareCommitmentProfile.shareCommitmentProfileDigest,
    );

    return messageMatrix.map((messageMatrixPolynomial, rowIndex) => {
        let accumulatedPolynomial = [
            ...multiplyBigIntPolynomials(
                messageMatrixPolynomial,
                messagePolynomial,
                shareCommitmentModulus,
            ),
        ];
        opening.openingRandomness.forEach((openingCoordinate, columnIndex) => {
            const randomnessPolynomial =
                randomnessMatrix[rowIndex]?.[columnIndex] ?? [];
            const openingPolynomial = Array.from(
                { length: shareCommitmentModuleDegree },
                (_unusedValue, coefficientIndex) =>
                    coefficientIndex === 0 ? BigInt(openingCoordinate) : 0n,
            );
            accumulatedPolynomial = [
                ...addBigIntPolynomials(
                    accumulatedPolynomial,
                    multiplyBigIntPolynomials(
                        randomnessPolynomial,
                        openingPolynomial,
                        shareCommitmentModulus,
                    ),
                    shareCommitmentModulus,
                ),
            ];
        });

        return accumulatedPolynomial;
    });
};

const stringifyBigIntPolynomialVector = (
    polynomialVector: readonly (readonly bigint[])[],
): readonly (readonly string[])[] =>
    polynomialVector.map((polynomial) =>
        polynomial.map((coefficient) => coefficient.toString()),
    );

export const addShareCommitmentPolynomialVectors = (
    leftPolynomialVector: readonly (readonly string[])[],
    rightPolynomialVector: readonly (readonly string[])[],
): readonly (readonly string[])[] => {
    if (leftPolynomialVector.length !== rightPolynomialVector.length) {
        throw new RangeError(
            'Share commitment vectors must have the same rank.',
        );
    }

    return leftPolynomialVector.map((leftPolynomial, vectorIndex) => {
        const rightPolynomial = rightPolynomialVector[vectorIndex];
        if (leftPolynomial.length !== rightPolynomial?.length) {
            throw new RangeError(
                'Share commitment polynomials must have the same degree.',
            );
        }

        return leftPolynomial.map((leftCoefficient, coefficientIndex) =>
            modBigInt(
                BigInt(leftCoefficient) +
                    BigInt(rightPolynomial[coefficientIndex] ?? '0'),
                shareCommitmentModulus,
            ).toString(),
        );
    });
};

export const addShareCommitmentOpenings = (
    leftOpening: ShareCommitmentOpeningWitness,
    rightOpening: ShareCommitmentOpeningWitness,
): ShareCommitmentOpeningWitness => {
    if (
        leftOpening.openingRandomness.length !==
        rightOpening.openingRandomness.length
    ) {
        throw new RangeError(
            'Share commitment openings must have the same dimension.',
        );
    }

    return {
        openingRandomness: leftOpening.openingRandomness.map(
            (leftCoordinate, coordinateIndex) =>
                leftCoordinate +
                (rightOpening.openingRandomness[coordinateIndex] ?? 0),
        ),
    };
};

export const createShareCommitment = (input: {
    readonly ceremonyId: string;
    readonly manifestDigest: ProtocolDigest;
    readonly rosterDigest: ProtocolDigest;
    readonly receiverIdentity: string;
    readonly receiverRosterPosition: number;
    readonly receiverShareVector: readonly number[];
    readonly shareCommitmentProfile: ShareCommitmentProfile;
    readonly opening?: ShareCommitmentOpeningWitness;
    readonly randomnessSource?: BallotPrivacyRandomnessSource;
}): ShareCommitmentMaterial => {
    const opening =
        input.opening ??
        sampleShareCommitmentOpening(
            input.randomnessSource ?? { kind: 'production' },
            input.shareCommitmentProfile,
            {
                ceremonyId: input.ceremonyId,
                manifestDigest: input.manifestDigest,
                receiverIdentity: input.receiverIdentity,
                receiverRosterPosition: input.receiverRosterPosition,
                rosterDigest: input.rosterDigest,
            },
        );
    const commitmentVector = computeShareCommitmentVector(
        input.receiverShareVector,
        opening,
        input.shareCommitmentProfile,
    );
    const commitmentPolynomialVector =
        stringifyBigIntPolynomialVector(commitmentVector);
    const commitmentBodyDigest = deriveProtocolDigest('ShareCommitmentDigest', {
        commitmentPolynomialVector,
        profileDigest:
            input.shareCommitmentProfile.shareCommitmentProfileDigest,
    });
    const shareCommitment = createShareCommitmentShell({
        ceremonyId: input.ceremonyId,
        manifestDigest: input.manifestDigest,
        rosterDigest: input.rosterDigest,
        receiverIdentity: input.receiverIdentity,
        receiverRosterPosition: input.receiverRosterPosition,
        shareCommitmentProfileDigest:
            input.shareCommitmentProfile.shareCommitmentProfileDigest,
        commitmentBodyDigest,
    });

    return {
        commitmentPolynomialVector,
        opening,
        shareCommitment,
    };
};

export const verifyShareCommitmentWitness = (input: {
    readonly ceremonyId: string;
    readonly manifestDigest: ProtocolDigest;
    readonly rosterDigest: ProtocolDigest;
    readonly receiverIdentity: string;
    readonly receiverRosterPosition: number;
    readonly receiverShareVector: readonly number[];
    readonly shareCommitmentProfile: ShareCommitmentProfile;
    readonly opening: ShareCommitmentOpeningWitness;
    readonly expectedShareCommitment: ShareCommitment;
    readonly expectedCommitmentPolynomialVector?: readonly (readonly string[])[];
}): readonly RefusalRecord[] => {
    const recomputedCommitment = createShareCommitment({
        ceremonyId: input.ceremonyId,
        manifestDigest: input.manifestDigest,
        opening: input.opening,
        receiverIdentity: input.receiverIdentity,
        receiverRosterPosition: input.receiverRosterPosition,
        receiverShareVector: input.receiverShareVector,
        rosterDigest: input.rosterDigest,
        shareCommitmentProfile: input.shareCommitmentProfile,
    });
    const refusedObjects: RefusalRecord[] = [];

    if (
        recomputedCommitment.shareCommitment.shareCommitmentDigest !==
        input.expectedShareCommitment.shareCommitmentDigest
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Share commitment witness does not open the expected commitment digest.',
                input.expectedShareCommitment.shareCommitmentDigest,
            ),
        );
    }
    if (
        input.expectedCommitmentPolynomialVector !== undefined &&
        !canonicalEqual(
            recomputedCommitment.commitmentPolynomialVector,
            input.expectedCommitmentPolynomialVector,
        )
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Share commitment witness does not reproduce the expected commitment polynomial vector.',
                input.expectedShareCommitment.shareCommitmentDigest,
            ),
        );
    }

    return refusedObjects;
};

const encodePayloadPlaintextBits = (
    plaintext: ReceiverPayloadPlaintextWitness,
    shareCommitmentProfile: ShareCommitmentProfile,
): readonly number[] => {
    validateReceiverShareVector(plaintext.receiverShareVector);
    validateShareCommitmentOpening(
        plaintext.shareCommitmentOpening,
        shareCommitmentProfile,
    );
    const bits: number[] = [];
    const pushUnsignedBits = (value: number, bitLength: number): void => {
        if (
            !Number.isSafeInteger(value) ||
            value < 0 ||
            value >= 2 ** bitLength
        ) {
            throw new RangeError(
                'Payload plaintext integer does not fit its bit width.',
            );
        }
        for (let bitIndex = 0; bitIndex < bitLength; bitIndex += 1) {
            bits.push((value >> bitIndex) & 1);
        }
    };

    for (const shareRepresentative of plaintext.receiverShareVector) {
        pushUnsignedBits(shareRepresentative, 17);
    }
    for (const openingCoordinate of plaintext.shareCommitmentOpening
        .openingRandomness) {
        pushUnsignedBits(
            openingCoordinate +
                shareCommitmentProfile.openingRandomnessInfinityNormBound,
            receiverOpeningRandomnessBitLength,
        );
    }

    return bits;
};

const encodePlaintextChunkPolynomial = (
    plaintextBits: readonly number[],
    chunkIndex: number,
): readonly number[] =>
    Array.from(
        { length: receiverEncryptionModuleDegree },
        (_unusedValue, coefficientIndex) => {
            const plaintextBit =
                plaintextBits[
                    chunkIndex * receiverEncryptionModuleDegree +
                        coefficientIndex
                ] ?? 0;

            return plaintextBit === 0 ? 0 : receiverEncryptionMessageScale;
        },
    );

const deriveReceiverMatrixSeedDigest = (input: {
    readonly ceremonyId: string;
    readonly manifestDigest: ProtocolDigest;
    readonly receiverEncryptionProfileDigest: ProtocolDigest;
    readonly receiverIdentity: string;
    readonly receiverRosterPosition: number;
    readonly recoveryEpoch: number;
    readonly rosterDigest: ProtocolDigest;
}): ProtocolDigest =>
    deriveProtocolDigest('ReceiverEncryptionProfileDigest', {
        purpose: 'receiver-public-matrix-seed',
        ...input,
    });

const deriveReceiverKeyMaterialDigest = (input: {
    readonly publicKeyVector: readonly (readonly number[])[];
    readonly publicMatrixSeedDigest: ProtocolDigest;
    readonly receiverEncryptionProfileDigest: ProtocolDigest;
}): ProtocolDigest => deriveProtocolDigest('PublicKeyDigest', input);

export const generateReceiverState = (input: {
    readonly ceremonyId: string;
    readonly manifestDigest: ProtocolDigest;
    readonly rosterDigest: ProtocolDigest;
    readonly receiverIdentity: string;
    readonly receiverRosterPosition: number;
    readonly recoveryEpoch: number;
    readonly receiverEncryptionProfile: ReceiverEncryptionProfile;
    readonly randomnessSource?: BallotPrivacyRandomnessSource;
}): ReceiverEncryptionState => {
    const randomnessSource = input.randomnessSource ?? { kind: 'production' };
    const publicMatrixSeedDigest = deriveReceiverMatrixSeedDigest({
        ceremonyId: input.ceremonyId,
        manifestDigest: input.manifestDigest,
        receiverEncryptionProfileDigest:
            input.receiverEncryptionProfile.receiverEncryptionProfileDigest,
        receiverIdentity: input.receiverIdentity,
        receiverRosterPosition: input.receiverRosterPosition,
        recoveryEpoch: input.recoveryEpoch,
        rosterDigest: input.rosterDigest,
    });
    const secretVector = sampleCenteredBinomialVector(
        randomnessSource,
        'sealed.vote/internal/receiver-encryption/secret-vector-v1',
        {
            publicMatrixSeedDigest,
            receiverIdentity: input.receiverIdentity,
            receiverRosterPosition: input.receiverRosterPosition,
        },
        receiverEncryptionModuleRank,
        receiverEncryptionModuleDegree,
    );
    const errorVector = sampleCenteredBinomialVector(
        randomnessSource,
        'sealed.vote/internal/receiver-encryption/key-error-vector-v1',
        {
            publicMatrixSeedDigest,
            receiverIdentity: input.receiverIdentity,
            receiverRosterPosition: input.receiverRosterPosition,
        },
        receiverEncryptionModuleRank,
        receiverEncryptionModuleDegree,
    );
    const publicMatrix = deriveReceiverPublicMatrix(
        input.receiverEncryptionProfile.receiverEncryptionProfileDigest,
        publicMatrixSeedDigest,
    );
    const publicKeyVector = multiplyMatrixByVector(
        publicMatrix,
        secretVector,
        receiverEncryptionModulus,
    ).map((polynomial, vectorIndex) =>
        addNumberPolynomials(
            polynomial,
            errorVector[vectorIndex] ?? [],
            receiverEncryptionModulus,
        ),
    );
    const keyMaterialDigest = deriveReceiverKeyMaterialDigest({
        publicKeyVector,
        publicMatrixSeedDigest,
        receiverEncryptionProfileDigest:
            input.receiverEncryptionProfile.receiverEncryptionProfileDigest,
    });
    const receiverPublicKey = createReceiverEncryptionPublicKeyShell({
        ceremonyId: input.ceremonyId,
        manifestDigest: input.manifestDigest,
        rosterDigest: input.rosterDigest,
        receiverIdentity: input.receiverIdentity,
        receiverRosterPosition: input.receiverRosterPosition,
        recoveryEpoch: input.recoveryEpoch,
        receiverEncryptionProfileDigest:
            input.receiverEncryptionProfile.receiverEncryptionProfileDigest,
        keyMaterialDigest,
    });

    return {
        publicKeyMaterial: {
            publicKeyVector,
            publicMatrixSeedDigest,
        },
        receiverPublicKey,
        secretState: {
            errorVector,
            secretVector,
        },
    };
};

const validateReceiverPublicKeyMaterial = (
    publicKeyMaterial: ReceiverEncryptionPublicKeyMaterial,
): void => {
    if (
        publicKeyMaterial.publicKeyVector.length !==
        receiverEncryptionModuleRank
    ) {
        throw new RangeError(
            'Receiver public-key material must use the frozen module rank.',
        );
    }
    for (const polynomial of publicKeyMaterial.publicKeyVector) {
        if (polynomial.length !== receiverEncryptionModuleDegree) {
            throw new RangeError(
                'Receiver public-key polynomials must use the frozen degree.',
            );
        }
        for (const coefficient of polynomial) {
            if (
                !Number.isSafeInteger(coefficient) ||
                coefficient < 0 ||
                coefficient >= receiverEncryptionModulus
            ) {
                throw new RangeError(
                    'Receiver public-key coefficients must be canonical representatives.',
                );
            }
        }
    }
};

const sampleReceiverEncryptionChunkWitness = (
    randomnessSource: BallotPrivacyRandomnessSource,
    payload: unknown,
    chunkIndex: number,
): ReceiverEncryptionChunkWitness => ({
    chunkIndex,
    encryptionRandomnessVector: sampleCenteredBinomialVector(
        randomnessSource,
        'sealed.vote/internal/receiver-encryption/randomness-vector-v1',
        { chunkIndex, payload },
        receiverEncryptionModuleRank,
        receiverEncryptionModuleDegree,
    ),
    firstNoiseVector: sampleCenteredBinomialVector(
        randomnessSource,
        'sealed.vote/internal/receiver-encryption/first-noise-vector-v1',
        { chunkIndex, payload },
        receiverEncryptionModuleRank,
        receiverEncryptionModuleDegree,
    ),
    secondNoisePolynomial:
        sampleCenteredBinomialVector(
            randomnessSource,
            'sealed.vote/internal/receiver-encryption/second-noise-polynomial-v1',
            { chunkIndex, payload },
            1,
            receiverEncryptionModuleDegree,
        )[0] ?? [],
});

const sampleReceiverEncryptionWitness = (
    randomnessSource: BallotPrivacyRandomnessSource,
    payload: unknown,
    chunkCount: number,
): ReceiverEncryptionWitness => ({
    chunkWitnesses: Array.from(
        { length: chunkCount },
        (_unusedValue, chunkIndex) =>
            sampleReceiverEncryptionChunkWitness(
                randomnessSource,
                payload,
                chunkIndex,
            ),
    ),
});

export const encryptReceiverPayload = (input: {
    readonly receiverEncryptionProfile: ReceiverEncryptionProfile;
    readonly shareCommitmentProfile: ShareCommitmentProfile;
    readonly receiverPublicKey: ReceiverEncryptionPublicKey;
    readonly publicKeyMaterial: ReceiverEncryptionPublicKeyMaterial;
    readonly plaintext: ReceiverPayloadPlaintextWitness;
    readonly randomnessSource?: BallotPrivacyRandomnessSource;
    readonly witness?: ReceiverEncryptionWitness;
}): ReceiverPayloadEncryptionResult => {
    validateReceiverPublicKeyMaterial(input.publicKeyMaterial);
    const expectedKeyMaterialDigest = deriveReceiverKeyMaterialDigest({
        publicKeyVector: input.publicKeyMaterial.publicKeyVector,
        publicMatrixSeedDigest: input.publicKeyMaterial.publicMatrixSeedDigest,
        receiverEncryptionProfileDigest:
            input.receiverEncryptionProfile.receiverEncryptionProfileDigest,
    });
    if (
        input.receiverPublicKey.keyMaterialDigest !== expectedKeyMaterialDigest
    ) {
        throw new RangeError(
            'Receiver public-key material does not match the public key digest.',
        );
    }
    if (
        input.plaintext.receiverIdentity !==
            input.receiverPublicKey.receiverIdentity ||
        input.plaintext.receiverRosterPosition !==
            input.receiverPublicKey.receiverRosterPosition
    ) {
        throw new RangeError(
            'Receiver payload plaintext must target the frozen receiver key.',
        );
    }

    const plaintextBits = encodePayloadPlaintextBits(
        input.plaintext,
        input.shareCommitmentProfile,
    );
    const chunkCount = Math.ceil(
        plaintextBits.length / receiverEncryptionModuleDegree,
    );
    const randomnessSource = input.randomnessSource ?? { kind: 'production' };
    const witness =
        input.witness ??
        sampleReceiverEncryptionWitness(
            randomnessSource,
            {
                ballotPackageContextDigest:
                    input.plaintext.ballotPackageContextDigest,
                receiverIdentity: input.plaintext.receiverIdentity,
                receiverRosterPosition: input.plaintext.receiverRosterPosition,
                receiverPublicKeyDigest:
                    input.receiverPublicKey.receiverPublicKeyDigest,
            },
            chunkCount,
        );
    if (witness.chunkWitnesses.length !== chunkCount) {
        throw new RangeError(
            'Receiver encryption witness must contain one chunk witness per plaintext chunk.',
        );
    }
    const publicMatrix = deriveReceiverPublicMatrix(
        input.receiverEncryptionProfile.receiverEncryptionProfileDigest,
        input.publicKeyMaterial.publicMatrixSeedDigest,
    );
    const ciphertextChunks = Array.from(
        { length: chunkCount },
        (_unusedValue, chunkIndex) => {
            const chunkWitness = witness.chunkWitnesses[chunkIndex];
            if (chunkWitness?.chunkIndex !== chunkIndex) {
                throw new RangeError(
                    'Receiver encryption chunk witnesses must be in canonical chunk order.',
                );
            }
            const firstCiphertextBaseVector = multiplyTransposeMatrixByVector(
                publicMatrix,
                chunkWitness.encryptionRandomnessVector,
                receiverEncryptionModulus,
            ).map((polynomial, vectorIndex) =>
                addNumberPolynomials(
                    polynomial,
                    chunkWitness.firstNoiseVector[vectorIndex] ?? [],
                    receiverEncryptionModulus,
                ),
            );
            const secondCiphertextBasePolynomial = dotNumberPolynomialVectors(
                input.publicKeyMaterial.publicKeyVector,
                chunkWitness.encryptionRandomnessVector,
                receiverEncryptionModulus,
            );
            const encodedPlaintextPolynomial = encodePlaintextChunkPolynomial(
                plaintextBits,
                chunkIndex,
            );
            const secondCiphertextPolynomial = addNumberPolynomials(
                addNumberPolynomials(
                    secondCiphertextBasePolynomial,
                    chunkWitness.secondNoisePolynomial,
                    receiverEncryptionModulus,
                ),
                encodedPlaintextPolynomial,
                receiverEncryptionModulus,
            );

            return {
                chunkIndex,
                firstCiphertextVector: firstCiphertextBaseVector,
                secondCiphertextPolynomial,
            };
        },
    );
    const ciphertextBodyDigest = deriveProtocolDigest(
        'ReceiverPayloadCiphertextRoot',
        {
            ciphertextChunks,
            plaintextBitLength: plaintextBits.length,
            receiverEncryptionProfileDigest:
                input.receiverEncryptionProfile.receiverEncryptionProfileDigest,
        },
    );
    const payloadContextDigest = deriveProtocolDigest('ReceiverPayloadDigest', {
        ballotPackageContextDigest: input.plaintext.ballotPackageContextDigest,
        ceremonyId: input.plaintext.ceremonyId,
        manifestDigest: input.plaintext.manifestDigest,
        pollSpecDigest: input.plaintext.pollSpecDigest,
        receiverIdentity: input.plaintext.receiverIdentity,
        receiverRosterPosition: input.plaintext.receiverRosterPosition,
        rosterDigest: input.plaintext.rosterDigest,
        voterIdentityDigest: input.plaintext.voterIdentityDigest,
    });
    const receiverPayload = createReceiverPayloadShell({
        ceremonyId: input.plaintext.ceremonyId,
        manifestDigest: input.plaintext.manifestDigest,
        rosterDigest: input.plaintext.rosterDigest,
        pollSpecDigest: input.plaintext.pollSpecDigest,
        voterIdentityDigest: input.plaintext.voterIdentityDigest,
        receiverIdentity: input.plaintext.receiverIdentity,
        receiverRosterPosition: input.plaintext.receiverRosterPosition,
        receiverPublicKeyDigest:
            input.receiverPublicKey.receiverPublicKeyDigest,
        receiverEncryptionProfileDigest:
            input.receiverEncryptionProfile.receiverEncryptionProfileDigest,
        payloadContextDigest,
        ciphertextBodyDigest,
    });

    return {
        ciphertextChunks,
        plaintextBitLength: plaintextBits.length,
        receiverPayload,
        witness,
    };
};

export const verifyReceiverPayloadWitness = (input: {
    readonly receiverEncryptionProfile: ReceiverEncryptionProfile;
    readonly shareCommitmentProfile: ShareCommitmentProfile;
    readonly receiverPublicKey: ReceiverEncryptionPublicKey;
    readonly publicKeyMaterial: ReceiverEncryptionPublicKeyMaterial;
    readonly plaintext: ReceiverPayloadPlaintextWitness;
    readonly witness: ReceiverEncryptionWitness;
    readonly expectedReceiverPayload: ReceiverPayload;
    readonly expectedCiphertextChunks?: readonly ReceiverPayloadCiphertextChunk[];
}): readonly RefusalRecord[] => {
    const recomputedPayload = encryptReceiverPayload({
        plaintext: input.plaintext,
        publicKeyMaterial: input.publicKeyMaterial,
        receiverEncryptionProfile: input.receiverEncryptionProfile,
        receiverPublicKey: input.receiverPublicKey,
        shareCommitmentProfile: input.shareCommitmentProfile,
        witness: input.witness,
    });
    const refusedObjects: RefusalRecord[] = [];

    if (
        recomputedPayload.receiverPayload.receiverPayloadDigest !==
        input.expectedReceiverPayload.receiverPayloadDigest
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Receiver payload witness does not reproduce the expected encrypted payload digest.',
                input.expectedReceiverPayload.receiverPayloadDigest,
            ),
        );
    }
    if (
        input.expectedCiphertextChunks !== undefined &&
        !canonicalEqual(
            recomputedPayload.ciphertextChunks,
            input.expectedCiphertextChunks,
        )
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Receiver payload witness does not reproduce the expected ciphertext chunks.',
                input.expectedReceiverPayload.receiverPayloadDigest,
            ),
        );
    }

    return refusedObjects;
};

export const createFixtureRandomnessSource = (
    fixtureSeed: string,
): BallotPrivacyRandomnessSource => ({
    allowFixtureMode: true,
    fixtureSeed,
    kind: 'fixture',
});

export const assertNoFixtureRandomnessInProduction = (
    randomnessSource: BallotPrivacyRandomnessSource,
): void => {
    if (randomnessSource.kind === 'fixture') {
        throw new RangeError(
            'Deterministic fixture randomness is not accepted outside explicit test construction.',
        );
    }
};

export const encodeReceiverPayloadPlaintextForTests = (input: {
    readonly plaintext: ReceiverPayloadPlaintextWitness;
    readonly shareCommitmentProfile: ShareCommitmentProfile;
}): string =>
    bytesToHex(
        Uint8Array.from(
            encodePayloadPlaintextBits(
                input.plaintext,
                input.shareCommitmentProfile,
            ),
        ),
    );
