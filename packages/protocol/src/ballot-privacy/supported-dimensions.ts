import type { ProtocolDigest, RefusalRecord } from '@sealed-lattice/types';

import { createRefusal } from '../common/verification-helpers.js';

import {
    ballotPrivacyMaximumOptionCount,
    ballotPrivacyMaximumParticipantCount,
    ballotPrivacyMinimumOptionCount,
    ballotPrivacyMinimumSafeParticipantCount,
    ballotPrivacyMinimumUnsafeParticipantCount,
    getBallotPrivacyEncodedShareVectorWidth,
} from './protocol-parameters.js';

const isPositiveSafeInteger = (value: number): boolean =>
    Number.isSafeInteger(value) && value > 0 && !Object.is(value, -0);

const participantCountIsInSupportedRange = (
    participantCount: number,
): boolean =>
    isPositiveSafeInteger(participantCount) &&
    participantCount >= ballotPrivacyMinimumUnsafeParticipantCount &&
    participantCount <= ballotPrivacyMaximumParticipantCount;

const optionCountIsInSupportedRange = (optionCount: number): boolean =>
    isPositiveSafeInteger(optionCount) &&
    optionCount >= ballotPrivacyMinimumOptionCount &&
    optionCount <= ballotPrivacyMaximumOptionCount;

export const collectBallotPrivacyDimensionRefusals = (input: {
    readonly objectDigest?: ProtocolDigest;
    readonly optionCount: number;
    readonly participantCount: number;
    readonly shareVectorWidth: number;
    readonly unsafeSmallRosterAcknowledged?: boolean;
}): readonly RefusalRecord[] => {
    const refusedObjects: RefusalRecord[] = [];

    if (!optionCountIsInSupportedRange(input.optionCount)) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                `Ballot privacy statements support ${ballotPrivacyMinimumOptionCount} to ${ballotPrivacyMaximumOptionCount} options.`,
                input.objectDigest,
            ),
        );
    }
    if (
        optionCountIsInSupportedRange(input.optionCount) &&
        input.shareVectorWidth !==
            getBallotPrivacyEncodedShareVectorWidth(input.optionCount)
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Ballot privacy statement shareVectorWidth must equal 11 * optionCount.',
                input.objectDigest,
            ),
        );
    }
    if (!participantCountIsInSupportedRange(input.participantCount)) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                `Ballot privacy statements support ${ballotPrivacyMinimumUnsafeParticipantCount} to ${ballotPrivacyMaximumParticipantCount} participants.`,
                input.objectDigest,
            ),
        );
    } else if (
        input.participantCount < ballotPrivacyMinimumSafeParticipantCount &&
        input.unsafeSmallRosterAcknowledged !== true
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                `Ballot privacy verification for ${ballotPrivacyMinimumUnsafeParticipantCount} to ${
                    ballotPrivacyMinimumSafeParticipantCount - 1
                } participants requires explicit unsafe small-roster acknowledgement.`,
                input.objectDigest,
            ),
        );
    }

    return refusedObjects;
};

export {
    ballotPrivacyMaximumOptionCount,
    ballotPrivacyMaximumParticipantCount,
    ballotPrivacyMinimumOptionCount,
    ballotPrivacyMinimumUnsafeParticipantCount,
};
