import { deriveCanonicalObjectHash } from '@sealed-lattice/crypto';

import {
    type PublicKeyShareContributionInput,
    type PublicKeyShareMaterialSetInput,
    type PublicKeyShareRecord,
    type PublicKeyShareSet,
    type PublicKeyShareSetInput,
} from './constants-and-types.js';
import {
    assertNonEmptyString,
    assertNonNegativeSafeInteger,
    assertProtocolHash,
    deriveCollectiveBgvSetupContextHash,
    sortedByRosterPosition,
    validateCommonInput,
} from './encoding.js';

export const derivePublicKeyShareRoot = (
    setupContext: PublicKeyShareSetInput['setupContext'],
    publicMatrixSeedHash: PublicKeyShareSetInput['publicMatrixSeedHash'],
    shareRecord: PublicKeyShareRecord,
) =>
    deriveCanonicalObjectHash({
        objectType: 'PublicKeyShare',
        setupContextHash: deriveCollectiveBgvSetupContextHash(setupContext),
        trusteeIdentity: shareRecord.trusteeIdentity,
        trusteeRosterPosition: shareRecord.trusteeRosterPosition,
        publicMatrixSeedHash,
        shareCoefficientVectorHash512ByLimb:
            shareRecord.shareCoefficientVectorHash512ByLimb,
    });

export const derivePublicKeyShareSetRoot = (
    setupContext: PublicKeyShareSetInput['setupContext'],
    publicMatrixSeedHash: PublicKeyShareSetInput['publicMatrixSeedHash'],
    publicKeyShares: PublicKeyShareSet,
) =>
    deriveCanonicalObjectHash({
        objectType: 'PublicKeyShareSet',
        setupContextHash: deriveCollectiveBgvSetupContextHash(setupContext),
        publicMatrixSeedHash,
        shareRecords: publicKeyShares.shareRecords,
    });

const validatePublicKeyShare = (
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
            'public-key shares must follow contiguous roster order from zero.',
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
        (coefficientHash) => {
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
    if (shareContributions.length !== input.setupContext.participantCount) {
        throw new Error(
            'shareContributions must contain one public-key share per participant.',
        );
    }
    const shareRecords = shareContributions.map(
        (contribution, expectedRosterPosition) => {
            validatePublicKeyShare(
                contribution,
                expectedRosterPosition,
                input.qSharePrimes,
            );
            return {
                objectType: 'PublicKeyShare',
                trusteeIdentity: contribution.trusteeIdentity,
                trusteeRosterPosition: contribution.trusteeRosterPosition,
                shareCoefficientVectorHash512ByLimb:
                    contribution.shareCoefficientVectorHash512ByLimb,
            } satisfies PublicKeyShareRecord;
        },
    );

    return {
        objectType: 'PublicKeyShareSet',
        shareRecords,
    } satisfies PublicKeyShareSet;
};

export const publicKeyShareRecordsByRosterPosition = (
    input: Pick<
        PublicKeyShareMaterialSetInput,
        | 'setupContext'
        | 'qSharePrimes'
        | 'publicMatrixSeedHash'
        | 'publicKeyShares'
    >,
): ReadonlyMap<number, PublicKeyShareRecord> => {
    const shareRecords = input.publicKeyShares.shareRecords;
    if (shareRecords.length !== input.setupContext.participantCount) {
        throw new Error(
            'publicKeyShares.shareRecords must contain one share per participant.',
        );
    }
    const recordsByRosterPosition = new Map<number, PublicKeyShareRecord>();
    shareRecords.forEach((shareRecord, expectedRosterPosition) => {
        validatePublicKeyShare(
            shareRecord,
            expectedRosterPosition,
            input.qSharePrimes,
        );
        recordsByRosterPosition.set(
            shareRecord.trusteeRosterPosition,
            shareRecord,
        );
    });

    return recordsByRosterPosition;
};
