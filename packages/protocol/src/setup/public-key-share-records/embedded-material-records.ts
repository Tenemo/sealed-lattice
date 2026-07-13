import { deriveCanonicalObjectHash } from '@sealed-lattice/crypto';
import { foundationProfile } from '@sealed-lattice/types';

import type { CanonicalProofMaterialChunkPull } from '../setup-proof-material-transport.js';
import { appendVaruint } from '../varuint-encoding.js';

import {
    type PublicKeyShareCoefficientVectorMaterial,
    type PublicKeyShareMaterialContributionInput,
    type PublicKeyShareMaterialRecord,
    type PublicKeyShareMaterialSetInput,
    type PublicKeyShareRecord,
} from './constants-and-types.js';
import {
    assertNonEmptyString,
    assertNonNegativeSafeInteger,
    assertPositiveSafeInteger,
    coefficientVectorFromLittleEndianHex,
    coefficientVectorHash512,
    deriveCollectiveBgvSetupContextHash,
    publicKeyShareMaterialBinaryMagic,
    sortedByRosterPosition,
    validateCommonInput,
} from './encoding.js';
import { publicKeyShareRecordsByRosterPosition } from './share-statement-records.js';

type PublicKeyShareMaterialRootFields = Pick<
    PublicKeyShareMaterialRecord,
    | 'trusteeIdentity'
    | 'trusteeRosterPosition'
    | 'publicKeyShareRoot'
    | 'shareCoefficientVectorsByLimb'
>;

const publicKeyShareMaterialRootInput = (
    input: Pick<
        PublicKeyShareMaterialSetInput,
        'setupContext' | 'publicMatrixSeedHash'
    >,
    materialRecord: PublicKeyShareMaterialRootFields,
) => ({
    objectType: 'PublicKeyShareMaterial',
    setupContextHash: deriveCollectiveBgvSetupContextHash(input.setupContext),
    trusteeIdentity: materialRecord.trusteeIdentity,
    trusteeRosterPosition: materialRecord.trusteeRosterPosition,
    publicMatrixSeedHash: input.publicMatrixSeedHash,
    publicKeyShareRoot: materialRecord.publicKeyShareRoot,
    shareCoefficientVectorsByLimb: materialRecord.shareCoefficientVectorsByLimb,
});

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
            if (rnsPrime === undefined) {
                throw new Error(
                    'publicKeyShareMaterialContributions must follow Q_share order.',
                );
            }
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
                shareCoefficientHash?.coefficientVectorHash512 !==
                coefficientVectorHash
            ) {
                throw new Error(
                    'publicKeyShareMaterialContributions coefficient hash must match the accepted share record.',
                );
            }

            return {
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
                trusteeIdentity: shareRecord.trusteeIdentity,
                trusteeRosterPosition: shareRecord.trusteeRosterPosition,
                publicKeyShareRoot: shareRecord.publicKeyShareRoot,
                shareCoefficientVectorsByLimb,
            } as const satisfies Omit<
                PublicKeyShareMaterialRecord,
                'publicKeyShareMaterialRoot'
            >;

            return {
                ...materialRecordWithoutRoot,
                publicKeyShareMaterialRoot: deriveCanonicalObjectHash(
                    publicKeyShareMaterialRootInput(
                        input,
                        materialRecordWithoutRoot,
                    ),
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
};

const sortedPublicKeyShareMaterialRecords = (
    shareMaterialRecords: readonly PublicKeyShareMaterialRecord[],
): readonly PublicKeyShareMaterialRecord[] => {
    const materialRecords = sortedByRosterPosition(shareMaterialRecords);
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

type PublicKeyShareMaterialEncodingSource = Readonly<{
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
        readonly qSharePrimes: readonly number[];
        readonly ringDegree: number;
        readonly shareMaterialRecords: readonly PublicKeyShareMaterialRecord[];
    }>,
): readonly PublicKeyShareMaterialBinarySegment[] => {
    assertPositiveSafeInteger(input.ringDegree, 'ringDegree');
    if (input.shareMaterialRecords.length === 0) {
        throw new Error(
            'publicKeyShareMaterial.shareMaterialRecords must contain at least one record.',
        );
    }
    if (input.qSharePrimes.length === 0) {
        throw new Error('qSharePrimes must contain at least one RNS prime.');
    }
    input.qSharePrimes.forEach((rnsPrime, rnsLimbIndex) => {
        assertPositiveSafeInteger(
            rnsPrime,
            `qSharePrimes.${String(rnsLimbIndex)}`,
        );
    });
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
        input.shareMaterialRecords.length,
        input.qSharePrimes.length,
        input.ringDegree,
    ]) {
        appendBytes(encodedVaruint(headerValue));
    }
    for (const materialRecord of sortedPublicKeyShareMaterialRecords(
        input.shareMaterialRecords,
    )) {
        appendBytes(encodedVaruint(materialRecord.trusteeRosterPosition));
        if (
            materialRecord.shareCoefficientVectorsByLimb.length !==
            input.qSharePrimes.length
        ) {
            throw new Error(
                'publicKeyShareMaterial must contain one coefficient vector per Q_share limb.',
            );
        }
        for (const [
            expectedRnsLimbIndex,
            coefficientVector,
        ] of materialRecord.shareCoefficientVectorsByLimb.entries()) {
            const rnsPrime = input.qSharePrimes[expectedRnsLimbIndex];
            if (rnsPrime === undefined) {
                throw new Error(
                    'publicKeyShareMaterial coefficient vector limbs must follow Q_share order.',
                );
            }
            appendBytes(encodedVaruint(expectedRnsLimbIndex));
            appendBytes(
                encodedUnsigned64(rnsPrime, 'publicKeyShareMaterial.rnsPrime'),
            );
            const coefficients = coefficientVectorFromLittleEndianHex(
                coefficientVector.coefficientsLeHex,
                input.ringDegree,
                'publicKeyShareMaterial.coefficientsLeHex',
            );
            if (coefficients.some((coefficient) => coefficient >= rnsPrime)) {
                throw new Error(
                    'publicKeyShareMaterial coefficient vectors must contain canonical residues before transport encoding.',
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
        readonly qSharePrimes: readonly number[];
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
        const chunkByteOffset =
            chunkIndex * foundationProfile.streamChunkByteLength;
        if (chunkByteOffset >= totalByteLength) {
            if (expectedByteLength !== 0) {
                throw new Error(
                    'public-key share material source was pulled past its canonical end.',
                );
            }
            return Promise.resolve(undefined);
        }
        const canonicalByteLength = Math.min(
            foundationProfile.streamChunkByteLength,
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
