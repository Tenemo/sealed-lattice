import { deriveCanonicalObjectHash } from '@sealed-lattice/crypto';

import {
    type PublicKeyShareContributionInput,
    type PublicKeyShareMaterialSetInput,
    type PublicKeyShareProofRecord,
    type PublicKeyShareProofSet,
    type PublicKeyShareProofSetInput,
    type PublicKeyShareRecord,
    type PublicKeyShareSet,
    type PublicKeyShareSetInput,
} from './constants-and-types.js';
import {
    assertNonEmptyString,
    assertNonNegativeSafeInteger,
    assertProtocolHash,
    assertContextMatches,
    contextFields,
    sortedByRosterPosition,
    validateCommonInput,
} from './encoding.js';

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
            const shareRecordWithoutRoot = {
                objectType: 'PublicKeyShare',
                ...contextFields(input.setupContext),
                trusteeIdentity: contribution.trusteeIdentity,
                trusteeRosterPosition: contribution.trusteeRosterPosition,
                publicMatrixSeedHash: input.publicMatrixSeedHash,
                publicKeyCrpRoot: input.publicKeyCrpRoot,
                publicAPolynomialRoot: input.publicAPolynomialRoot,
                rnsLimbCount: input.qSharePrimes.length,
                shareCoefficientVectorHash512ByLimb:
                    contribution.shareCoefficientVectorHash512ByLimb,
            } as const satisfies Omit<
                PublicKeyShareRecord,
                'publicKeyShareRoot'
            >;

            return {
                ...shareRecordWithoutRoot,
                publicKeyShareRoot: deriveCanonicalObjectHash(
                    shareRecordWithoutRoot,
                ),
            } satisfies PublicKeyShareRecord;
        },
    );
    const shareSetWithoutRoot = {
        objectType: 'PublicKeyShareSet',
        ...contextFields(input.setupContext),
        participantCount: input.participantCount,
        rnsLimbCount: input.qSharePrimes.length,
        publicMatrixSeedHash: input.publicMatrixSeedHash,
        publicKeyCrpRoot: input.publicKeyCrpRoot,
        publicAPolynomialRoot: input.publicAPolynomialRoot,
        shareRecords,
    } as const satisfies Omit<PublicKeyShareSet, 'publicKeyShareSetRoot'>;

    return {
        ...shareSetWithoutRoot,
        publicKeyShareSetRoot: deriveCanonicalObjectHash(shareSetWithoutRoot),
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
            input.publicAPolynomialRoot
    ) {
        throw new Error(
            'publicKeyShares must bind the same common randomness.',
        );
    }
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
            const proofRecordWithoutRoot = {
                objectType: 'PublicKeyShareProof',
                ...contextFields(input.setupContext),
                trusteeIdentity: shareRecord.trusteeIdentity,
                trusteeRosterPosition: shareRecord.trusteeRosterPosition,
                publicMatrixSeedHash: input.publicMatrixSeedHash,
                publicKeyCrpRoot: input.publicKeyCrpRoot,
                publicAPolynomialRoot: input.publicAPolynomialRoot,
                publicKeyShareRoot: shareRecord.publicKeyShareRoot,
                rnsLimbCount: input.qSharePrimes.length,
            } as const satisfies Omit<
                PublicKeyShareProofRecord,
                'publicKeyShareProofRoot'
            >;

            return {
                ...proofRecordWithoutRoot,
                publicKeyShareProofRoot: deriveCanonicalObjectHash(
                    proofRecordWithoutRoot,
                ),
            } satisfies PublicKeyShareProofRecord;
        },
    );
    const proofSetWithoutRoot = {
        objectType: 'PublicKeyShareProofSet',
        ...contextFields(input.setupContext),
        participantCount: input.participantCount,
        rnsLimbCount: input.qSharePrimes.length,
        publicMatrixSeedHash: input.publicMatrixSeedHash,
        publicKeyCrpRoot: input.publicKeyCrpRoot,
        publicAPolynomialRoot: input.publicAPolynomialRoot,
        publicKeyShareSetRoot: input.publicKeyShares.publicKeyShareSetRoot,
        proofRecords,
    } as const satisfies Omit<
        PublicKeyShareProofSet,
        'publicKeyShareProofSetRoot'
    >;

    return {
        ...proofSetWithoutRoot,
        publicKeyShareProofSetRoot:
            deriveCanonicalObjectHash(proofSetWithoutRoot),
    } satisfies PublicKeyShareProofSet;
};

export const publicKeyShareRecordsByRosterPosition = (
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
