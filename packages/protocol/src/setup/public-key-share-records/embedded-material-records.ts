import { deriveCanonicalObjectHash } from '@sealed-lattice/crypto';
import { foundationProfile } from '@sealed-lattice/types';

import type { CanonicalProofMaterialChunkPull } from '../setup-proof-material-transport.js';

import {
    type PublicKeyShareMaterialContributionInput,
    type PublicKeyShareMaterialRecord,
    type PublicKeyShareMaterialSetInput,
    type PublicKeyShareRecord,
} from './constants-and-types.js';
import {
    assertNonNegativeSafeInteger,
    assertPositiveSafeInteger,
    coefficientVectorFromLittleEndianHex,
    coefficientVectorHash512,
    deriveCollectiveBgvSetupContextHash,
    publicKeyShareMaterialBinaryMagic,
    sortedByRosterPosition,
    validateCommonInput,
} from './encoding.js';
import {
    derivePublicKeyShareRoot,
    publicKeyShareRecordsByRosterPosition,
} from './share-statement-records.js';

export const derivePublicKeyShareMaterialRoot = (
    input: Pick<
        PublicKeyShareMaterialSetInput,
        'setupContext' | 'publicMatrixSeedHash'
    >,
    trusteeRosterPosition: number,
    shareRecord: PublicKeyShareRecord,
    materialRecord: PublicKeyShareMaterialRecord,
) =>
    deriveCanonicalObjectHash({
        objectType: 'PublicKeyShareMaterial',
        setupContextHash: deriveCollectiveBgvSetupContextHash(
            input.setupContext,
        ),
        trusteeRosterPosition,
        publicMatrixSeedHash: input.publicMatrixSeedHash,
        publicKeyShareRoot: derivePublicKeyShareRoot(
            input.setupContext,
            input.publicMatrixSeedHash,
            trusteeRosterPosition,
            shareRecord,
        ),
        shareCoefficientVectorsLittleEndianHexByLimb:
            materialRecord.shareCoefficientVectorsLittleEndianHexByLimb,
    });

const validatePublicKeyShareMaterialContribution = (
    contribution: PublicKeyShareMaterialContributionInput,
    expectedRosterPosition: number,
    input: PublicKeyShareMaterialSetInput,
    shareRecord: PublicKeyShareRecord,
): readonly string[] => {
    assertNonNegativeSafeInteger(
        contribution.trusteeRosterPosition,
        'trusteeRosterPosition',
    );
    if (contribution.trusteeRosterPosition !== expectedRosterPosition) {
        throw new Error(
            'publicKeyShareMaterialContributions must match accepted public-key share records.',
        );
    }
    if (
        contribution.shareCoefficientVectorsLittleEndianHexByLimb.length !==
        input.qSharePrimes.length
    ) {
        throw new Error(
            'publicKeyShareMaterialContributions must contain one coefficient vector per Q_share limb.',
        );
    }

    return contribution.shareCoefficientVectorsLittleEndianHexByLimb.map(
        (coefficientVectorLittleEndianHex, rnsLimbIndex) => {
            const rnsPrime = input.qSharePrimes[rnsLimbIndex];
            if (rnsPrime === undefined) {
                throw new Error(
                    'publicKeyShareMaterialContributions must follow Q_share order.',
                );
            }
            const coefficients = coefficientVectorFromLittleEndianHex(
                coefficientVectorLittleEndianHex,
                input.ringDegree,
                'publicKeyShareMaterialContributions.shareCoefficientVectorsLittleEndianHexByLimb',
            );
            if (coefficients.some((coefficient) => coefficient >= rnsPrime)) {
                throw new Error(
                    'publicKeyShareMaterialContributions coefficients must be canonical residues.',
                );
            }
            const coefficientVectorHash =
                coefficientVectorHash512(coefficients);
            const shareCoefficientHash =
                shareRecord.shareCoefficientVectorHashesByLimb[rnsLimbIndex];
            if (shareCoefficientHash !== coefficientVectorHash) {
                throw new Error(
                    'publicKeyShareMaterialContributions coefficient hash must match the accepted share record.',
                );
            }

            return coefficientVectorLittleEndianHex;
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
    if (materialContributions.length !== input.setupContext.participantCount) {
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
            const shareCoefficientVectorsLittleEndianHexByLimb =
                validatePublicKeyShareMaterialContribution(
                    contribution,
                    expectedRosterPosition,
                    input,
                    shareRecord,
                );
            return {
                objectType: 'PublicKeyShareMaterial',
                shareCoefficientVectorsLittleEndianHexByLimb,
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
    for (const materialRecord of input.shareMaterialRecords) {
        if (
            materialRecord.shareCoefficientVectorsLittleEndianHexByLimb
                .length !== input.qSharePrimes.length
        ) {
            throw new Error(
                'publicKeyShareMaterial must contain one coefficient vector per Q_share limb.',
            );
        }
        for (const [
            expectedRnsLimbIndex,
            coefficientVectorLittleEndianHex,
        ] of materialRecord.shareCoefficientVectorsLittleEndianHexByLimb.entries()) {
            const rnsPrime = input.qSharePrimes[expectedRnsLimbIndex];
            if (rnsPrime === undefined) {
                throw new Error(
                    'publicKeyShareMaterial coefficient vector limbs must follow Q_share order.',
                );
            }
            const coefficients = coefficientVectorFromLittleEndianHex(
                coefficientVectorLittleEndianHex,
                input.ringDegree,
                'publicKeyShareMaterial.shareCoefficientVectorsLittleEndianHexByLimb',
            );
            if (coefficients.some((coefficient) => coefficient >= rnsPrime)) {
                throw new Error(
                    'publicKeyShareMaterial coefficient vectors must contain canonical residues before transport encoding.',
                );
            }
            appendHex(coefficientVectorLittleEndianHex);
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
