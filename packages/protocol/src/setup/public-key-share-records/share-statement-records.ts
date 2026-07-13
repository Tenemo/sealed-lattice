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

type PublicKeyShareRootFields = Pick<
    PublicKeyShareRecord,
    | 'trusteeIdentity'
    | 'trusteeRosterPosition'
    | 'shareCoefficientVectorHash512ByLimb'
>;

const publicKeyShareRootInput = (
    setupContext: PublicKeyShareSetInput['setupContext'],
    publicMatrixSeedHash: PublicKeyShareSetInput['publicMatrixSeedHash'],
    shareRecord: PublicKeyShareRootFields,
) => ({
    objectType: 'PublicKeyShare',
    setupContextHash: deriveCollectiveBgvSetupContextHash(setupContext),
    trusteeIdentity: shareRecord.trusteeIdentity,
    trusteeRosterPosition: shareRecord.trusteeRosterPosition,
    publicMatrixSeedHash,
    shareCoefficientVectorHash512ByLimb:
        shareRecord.shareCoefficientVectorHash512ByLimb,
});

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
                trusteeIdentity: contribution.trusteeIdentity,
                trusteeRosterPosition: contribution.trusteeRosterPosition,
                shareCoefficientVectorHash512ByLimb:
                    contribution.shareCoefficientVectorHash512ByLimb,
            } as const satisfies Omit<
                PublicKeyShareRecord,
                'publicKeyShareRoot'
            >;

            return {
                ...shareRecordWithoutRoot,
                publicKeyShareRoot: deriveCanonicalObjectHash(
                    publicKeyShareRootInput(
                        input.setupContext,
                        input.publicMatrixSeedHash,
                        shareRecordWithoutRoot,
                    ),
                ),
            } satisfies PublicKeyShareRecord;
        },
    );
    const shareSetWithoutRoot = {
        objectType: 'PublicKeyShareSet',
        shareRecords,
    } as const satisfies Omit<PublicKeyShareSet, 'publicKeyShareSetRoot'>;

    return {
        ...shareSetWithoutRoot,
        publicKeyShareSetRoot: deriveCanonicalObjectHash({
            objectType: shareSetWithoutRoot.objectType,
            setupContextHash: deriveCollectiveBgvSetupContextHash(
                input.setupContext,
            ),
            publicMatrixSeedHash: input.publicMatrixSeedHash,
            shareRecords,
        }),
    } satisfies PublicKeyShareSet;
};

export const publicKeyShareRecordsByRosterPosition = (
    input: Pick<
        PublicKeyShareMaterialSetInput,
        | 'setupContext'
        | 'qSharePrimes'
        | 'participantCount'
        | 'publicMatrixSeedHash'
        | 'publicKeyShares'
    >,
): ReadonlyMap<number, PublicKeyShareRecord> => {
    assertProtocolHash(
        input.publicKeyShares.publicKeyShareSetRoot,
        'publicKeyShares.publicKeyShareSetRoot',
    );
    if (
        input.publicKeyShares.publicKeyShareSetRoot !==
        deriveCanonicalObjectHash({
            objectType: input.publicKeyShares.objectType,
            setupContextHash: deriveCollectiveBgvSetupContextHash(
                input.setupContext,
            ),
            publicMatrixSeedHash: input.publicMatrixSeedHash,
            shareRecords: input.publicKeyShares.shareRecords,
        })
    ) {
        throw new Error(
            'publicKeyShares.publicKeyShareSetRoot must bind the authoritative setup context, publicMatrixSeedHash, and share records.',
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
    const recordsByRosterPosition = new Map<number, PublicKeyShareRecord>();
    shareRecords.forEach((shareRecord, expectedRosterPosition) => {
        validateShareContribution(
            shareRecord,
            expectedRosterPosition,
            input.qSharePrimes,
        );
        assertProtocolHash(
            shareRecord.publicKeyShareRoot,
            'publicKeyShares.shareRecords.publicKeyShareRoot',
        );
        if (
            shareRecord.publicKeyShareRoot !==
            deriveCanonicalObjectHash(
                publicKeyShareRootInput(
                    input.setupContext,
                    input.publicMatrixSeedHash,
                    shareRecord,
                ),
            )
        ) {
            throw new Error(
                'publicKeyShares.shareRecords.publicKeyShareRoot must bind the parent setup context and publicMatrixSeedHash.',
            );
        }
        recordsByRosterPosition.set(
            shareRecord.trusteeRosterPosition,
            shareRecord,
        );
    });

    return recordsByRosterPosition;
};
