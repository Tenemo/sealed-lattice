import { deriveCanonicalObjectHash } from '@sealed-lattice/crypto';

import { BinaryChunkWriter } from '../binary-chunk-writer.js';
import { setupTransportChunkSizeBytes } from '../vss-coefficient-commitments.js';

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

export const encodePublicKeyShareMaterialRecords = (
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

export const encodePublicKeyShareMaterial = (
    materialSet: PublicKeyShareMaterialSet,
): readonly Uint8Array[] => encodePublicKeyShareMaterialRecords(materialSet);
