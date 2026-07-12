import { deriveCanonicalObjectHash } from '@sealed-lattice/crypto';

import type { CanonicalProofMaterialChunkPull } from '../setup-proof-material-transport.js';
import { setupProofTransportChunkSizeBytes } from '../setup-proof-material-transport.js';
import { appendVaruint } from '../varuint-encoding.js';

import {
    publicKeyShareMaterialEncoding,
    publicKeyShareProofFamily,
    type PublicKeyShareCoefficientVectorMaterial,
    type PublicKeyShareMaterialContributionInput,
    type PublicKeyShareMaterialRecord,
    type PublicKeyShareMaterialRootReference,
    type PublicKeyShareMaterialSet,
    type PublicKeyShareMaterialSetInput,
    type PublicKeyShareRecord,
} from './constants-and-types.js';
import {
    assertContextMatches,
    assertNonEmptyString,
    assertNonNegativeSafeInteger,
    assertPositiveSafeInteger,
    assertProtocolHash,
    coefficientVectorFromLittleEndianHex,
    coefficientVectorHash512,
    contextFields,
    publicKeyShareMaterialBinaryMagic,
    sortedByRosterPosition,
    validateCommonInput,
} from './encoding.js';
import { publicKeyShareRecordsByRosterPosition } from './share-statement-records.js';

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

export const publicKeyShareMaterialRecordsFromContributions = (
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
                proofFamily: publicKeyShareProofFamily,
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
                publicKeyShareMaterialRoot: deriveCanonicalObjectHash(
                    materialRecordWithoutRoot,
                ),
            } satisfies PublicKeyShareMaterialRecord;
        },
    );

    return shareMaterialRecords;
};

export const assertPublicKeyShareMaterialInput = (
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

export const publicKeyShareMaterialRootReferences = (
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
        proofFamily: publicKeyShareProofFamily,
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
        publicKeyShareMaterialSetRoot: deriveCanonicalObjectHash(
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

type PublicKeyShareMaterialBinarySegment = Readonly<
    | {
          readonly byteLength: number;
          readonly byteOffset: number;
          readonly bytes: Uint8Array;
      }
    | {
          readonly byteLength: number;
          readonly byteOffset: number;
          readonly bytesHex: string;
      }
>;

export type PublicKeyShareMaterialEncodingSource = Readonly<{
    readonly pullChunk: CanonicalProofMaterialChunkPull;
    readonly totalByteLength: number;
}>;

const encodedVaruint = (value: number): Uint8Array => {
    const bytes: number[] = [];
    appendVaruint(bytes, value);
    return Uint8Array.from(bytes);
};

const encodedUnsigned64 = (value: number, fieldName: string): Uint8Array => {
    if (!Number.isSafeInteger(value) || value < 0) {
        throw new TypeError(
            `${fieldName} must be a non-negative safe integer.`,
        );
    }
    const bytes = new Uint8Array(8);
    new DataView(bytes.buffer).setBigUint64(0, BigInt(value), true);
    return bytes;
};

const publicKeyShareMaterialBinarySegments = (
    input: Readonly<{
        readonly participantCount: number;
        readonly rnsLimbCount: number;
        readonly ringDegree: number;
        readonly shareMaterialRecords: readonly PublicKeyShareMaterialRecord[];
    }>,
): readonly PublicKeyShareMaterialBinarySegment[] => {
    const segments: PublicKeyShareMaterialBinarySegment[] = [];
    let byteOffset = 0;
    const appendBytes = (bytes: Uint8Array): void => {
        segments.push({ byteLength: bytes.byteLength, byteOffset, bytes });
        byteOffset += bytes.byteLength;
    };
    const appendHex = (bytesHex: string): void => {
        const byteLength = bytesHex.length / 2;
        segments.push({ byteLength, byteOffset, bytesHex });
        byteOffset += byteLength;
    };

    appendBytes(publicKeyShareMaterialBinaryMagic.slice());
    for (const headerValue of [
        1,
        input.participantCount,
        input.rnsLimbCount,
        input.ringDegree,
    ]) {
        appendBytes(encodedVaruint(headerValue));
    }
    for (const materialRecord of sortedPublicKeyShareMaterialRecords(input)) {
        appendBytes(encodedVaruint(materialRecord.trusteeRosterPosition));
        for (const [
            expectedRnsLimbIndex,
            coefficientVector,
        ] of materialRecord.shareCoefficientVectorsByLimb.entries()) {
            if (
                coefficientVector.rnsLimbIndex !== expectedRnsLimbIndex ||
                coefficientVector.component !== 'b_i'
            ) {
                throw new Error(
                    'publicKeyShareMaterial coefficient vector limbs must follow Q_share order.',
                );
            }
            appendBytes(encodedVaruint(expectedRnsLimbIndex));
            appendBytes(
                encodedUnsigned64(
                    coefficientVector.rnsPrime,
                    'publicKeyShareMaterial.rnsPrime',
                ),
            );
            const coefficients = coefficientVectorFromLittleEndianHex(
                coefficientVector.coefficientsLeHex,
                input.ringDegree,
                'publicKeyShareMaterial.coefficientsLeHex',
            );
            if (
                coefficients.some(
                    (coefficient) => coefficient >= coefficientVector.rnsPrime,
                ) ||
                coefficientVector.coefficientVectorHash512 !==
                    coefficientVectorHash512(coefficients)
            ) {
                throw new Error(
                    'publicKeyShareMaterial coefficient vectors must be canonical and hash-bound before transport encoding.',
                );
            }
            appendHex(coefficientVector.coefficientsLeHex);
        }
    }

    return segments;
};

const copyHexBytes = (
    bytesHex: string,
    sourceByteOffset: number,
    destination: Uint8Array,
    destinationByteOffset: number,
    byteLength: number,
): void => {
    for (let byteIndex = 0; byteIndex < byteLength; byteIndex += 1) {
        const hexByteOffset = (sourceByteOffset + byteIndex) * 2;
        const byte = Number.parseInt(
            bytesHex.slice(hexByteOffset, hexByteOffset + 2),
            16,
        );
        if (!Number.isInteger(byte)) {
            throw new Error(
                'public-key share material contains malformed coefficient hex.',
            );
        }
        destination[destinationByteOffset + byteIndex] = byte;
    }
};

export const createPublicKeyShareMaterialEncodingSource = (
    input: Readonly<{
        readonly participantCount: number;
        readonly rnsLimbCount: number;
        readonly ringDegree: number;
        readonly shareMaterialRecords: readonly PublicKeyShareMaterialRecord[];
    }>,
): PublicKeyShareMaterialEncodingSource => {
    const segments = publicKeyShareMaterialBinarySegments(input);
    const finalSegment = segments[segments.length - 1];
    if (finalSegment === undefined) {
        throw new Error('public-key share material transport requires bytes.');
    }
    const totalByteLength = finalSegment.byteOffset + finalSegment.byteLength;
    if (!Number.isSafeInteger(totalByteLength) || totalByteLength <= 0) {
        throw new Error(
            'public-key share material byte length is outside the JavaScript safe integer range.',
        );
    }

    const pullChunk: CanonicalProofMaterialChunkPull = ({
        chunkIndex,
        expectedByteLength,
    }) => {
        if (!Number.isSafeInteger(chunkIndex) || chunkIndex < 0) {
            throw new TypeError(
                'public-key share material chunk index must be a non-negative safe integer.',
            );
        }
        const chunkByteOffset = chunkIndex * setupProofTransportChunkSizeBytes;
        if (chunkByteOffset >= totalByteLength) {
            if (expectedByteLength !== 0) {
                throw new Error(
                    'public-key share material source was pulled past its canonical end.',
                );
            }
            return Promise.resolve(undefined);
        }
        const canonicalByteLength = Math.min(
            setupProofTransportChunkSizeBytes,
            totalByteLength - chunkByteOffset,
        );
        if (expectedByteLength !== canonicalByteLength) {
            throw new Error(
                'public-key share material pull length must match the canonical chunk boundary.',
            );
        }
        const chunk = new Uint8Array(canonicalByteLength);
        const chunkEndOffset = chunkByteOffset + canonicalByteLength;
        for (const segment of segments) {
            const segmentEndOffset = segment.byteOffset + segment.byteLength;
            const overlapStart = Math.max(chunkByteOffset, segment.byteOffset);
            const overlapEnd = Math.min(chunkEndOffset, segmentEndOffset);
            if (overlapStart >= overlapEnd) {
                continue;
            }
            const sourceByteOffset = overlapStart - segment.byteOffset;
            const destinationByteOffset = overlapStart - chunkByteOffset;
            const overlapByteLength = overlapEnd - overlapStart;
            if ('bytes' in segment) {
                chunk.set(
                    segment.bytes.subarray(
                        sourceByteOffset,
                        sourceByteOffset + overlapByteLength,
                    ),
                    destinationByteOffset,
                );
            } else {
                copyHexBytes(
                    segment.bytesHex,
                    sourceByteOffset,
                    chunk,
                    destinationByteOffset,
                    overlapByteLength,
                );
            }
        }

        return Promise.resolve(chunk.buffer);
    };

    return { pullChunk, totalByteLength };
};

export const createPublicKeyShareMaterialSetEncodingSource = (
    materialSet: PublicKeyShareMaterialSet,
): PublicKeyShareMaterialEncodingSource =>
    createPublicKeyShareMaterialEncodingSource(materialSet);
