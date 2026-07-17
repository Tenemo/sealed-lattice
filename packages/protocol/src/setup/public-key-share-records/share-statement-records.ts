import { deriveCanonicalObjectHash } from '@sealed-lattice/crypto';

import { requireFoundationRosterParameters } from '../common-fields.js';

import {
    type PublicKeyShareContributionInput,
    type PublicKeyShareMaterialSetInput,
    type PublicKeyShareRecord,
    type PublicKeyShareSet,
    type PublicKeyShareSetInput,
} from './constants-and-types.js';
import {
    assertNonNegativeSafeInteger,
    assertProtocolHash,
    deriveCollectiveBgvSetupContextHash,
    sortedByRosterPosition,
    validateCommonInput,
} from './encoding.js';

export const derivePublicKeyShareRoot = (
    setupContext: PublicKeyShareSetInput['setupContext'],
    publicMatrixSeedHash: PublicKeyShareSetInput['publicMatrixSeedHash'],
    trusteeRosterPosition: number,
    shareRecord: PublicKeyShareRecord,
) =>
    deriveCanonicalObjectHash({
        objectType: 'PublicKeyShare',
        setupContextHash: deriveCollectiveBgvSetupContextHash(setupContext),
        trusteeRosterPosition,
        publicMatrixSeedHash,
        shareCoefficientVectorHashesByLimb:
            shareRecord.shareCoefficientVectorHashesByLimb,
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
        contribution.shareCoefficientVectorHashesByLimb.length !==
        qSharePrimes.length
    ) {
        throw new Error(
            'shareCoefficientVectorHashesByLimb must contain one entry for every Q_share limb.',
        );
    }
    contribution.shareCoefficientVectorHashesByLimb.forEach(
        (coefficientVectorHash) => {
            assertProtocolHash(
                coefficientVectorHash,
                'shareCoefficientVectorHashesByLimb',
            );
        },
    );
};

const validatePublicKeyShareRecord = (
    shareRecord: PublicKeyShareRecord,
    qSharePrimes: readonly number[],
): void => {
    if (
        shareRecord.shareCoefficientVectorHashesByLimb.length !==
        qSharePrimes.length
    ) {
        throw new Error(
            'shareCoefficientVectorHashesByLimb must contain one entry for every Q_share limb.',
        );
    }
    shareRecord.shareCoefficientVectorHashesByLimb.forEach(
        (coefficientVectorHash) => {
            assertProtocolHash(
                coefficientVectorHash,
                'shareCoefficientVectorHashesByLimb',
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
                shareCoefficientVectorHashesByLimb:
                    contribution.shareCoefficientVectorHashesByLimb,
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
    requireFoundationRosterParameters(
        input.setupContext.participantCount,
        'setupContext.participantCount',
    );
    const shareRecords = input.publicKeyShares.shareRecords;
    if (shareRecords.length !== input.setupContext.participantCount) {
        throw new Error(
            'publicKeyShares.shareRecords must contain one share per participant.',
        );
    }
    const recordsByRosterPosition = new Map<number, PublicKeyShareRecord>();
    shareRecords.forEach((shareRecord, expectedRosterPosition) => {
        validatePublicKeyShareRecord(shareRecord, input.qSharePrimes);
        recordsByRosterPosition.set(expectedRosterPosition, shareRecord);
    });

    return recordsByRosterPosition;
};
