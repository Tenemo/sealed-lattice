import type {
    PollSpec,
    PvssBallotRosterEntry,
    RefusalRecord,
    SignedBoardOrder,
    ThresholdProfile,
} from '@sealed-lattice/types';

import { createRefusal } from '../common/verification-helpers.js';

// Equals the maximum option count. All share/commitment/opening vectors are
// fixed at this width with zero padding, so summing across ballots aligns
// slot-by-slot (additive aggregation lines up the same option in every ballot).
export const pvssBallotShareVectorWidth = 20 as const;

export const compareSignedBoardOrder = (
    left: SignedBoardOrder,
    right: SignedBoardOrder,
): number =>
    left.boardSequence - right.boardSequence ||
    left.boardPosition - right.boardPosition;

export const isBeforeSignedBoardOrder = (
    left: SignedBoardOrder,
    right: SignedBoardOrder,
): boolean => compareSignedBoardOrder(left, right) < 0;

const isPositiveSafeInteger = (value: number): boolean =>
    Number.isSafeInteger(value) && value > 0 && !Object.is(value, -0);

export const validatePollAndThreshold = (
    pollSpec: PollSpec,
    thresholdProfile: ThresholdProfile,
): readonly RefusalRecord[] => {
    const refusedObjects: RefusalRecord[] = [];

    if (
        pollSpec.scoreDomain.min !== 1 ||
        pollSpec.scoreDomain.max !== 10 ||
        pollSpec.scoreDomain.skippedOptionScore !== 1 ||
        pollSpec.tiePolicy !== 'HigherScoreThenLowerOptionIndex' ||
        pollSpec.duplicateBallotPolicy !== 'FirstValidBeforeVotingClosedCounts'
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Ballot algebra requires the frozen score, tie, and duplicate policies.',
            ),
        );
    }
    if (
        pollSpec.options.length < 1 ||
        pollSpec.options.length > pvssBallotShareVectorWidth ||
        pollSpec.topOptionCount < 1 ||
        pollSpec.topOptionCount > pollSpec.options.length
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Ballot algebra requires a valid option count and top-option count.',
            ),
        );
    }
    if (
        !isPositiveSafeInteger(thresholdProfile.rosterSize) ||
        !isPositiveSafeInteger(thresholdProfile.pvssThreshold) ||
        thresholdProfile.pvssThreshold > thresholdProfile.rosterSize
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Ballot algebra requires a valid roster size and PVSS threshold.',
            ),
        );
    }

    return refusedObjects;
};

export const sortRosterEntries = (
    rosterEntries: readonly PvssBallotRosterEntry[],
): readonly PvssBallotRosterEntry[] =>
    [...rosterEntries].sort(
        (left, right) => left.rosterPosition - right.rosterPosition,
    );

export const validateRosterEntries = (
    rosterEntries: readonly PvssBallotRosterEntry[],
    thresholdProfile: ThresholdProfile,
): readonly RefusalRecord[] => {
    const refusedObjects: RefusalRecord[] = [];
    const identities = new Set<string>();
    const positions = new Set<number>();

    if (rosterEntries.length !== thresholdProfile.rosterSize) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Ballot roster entry count must match the threshold profile roster size.',
            ),
        );
    }

    for (const entry of rosterEntries) {
        if (entry.participantIdentity.length === 0) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    'Ballot roster identities must be non-empty.',
                ),
            );
        }
        if (identities.has(entry.participantIdentity)) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    'Ballot roster identities must be unique.',
                ),
            );
        }
        identities.add(entry.participantIdentity);

        if (
            !isPositiveSafeInteger(entry.rosterPosition) ||
            entry.rosterPosition > thresholdProfile.rosterSize
        ) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    'Ballot roster positions must be one-based and within the roster.',
                ),
            );
        }
        if (positions.has(entry.rosterPosition)) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    'Ballot roster positions must be unique.',
                ),
            );
        }
        positions.add(entry.rosterPosition);
    }

    for (
        let expectedRosterPosition = 1;
        expectedRosterPosition <= thresholdProfile.rosterSize;
        expectedRosterPosition += 1
    ) {
        if (!positions.has(expectedRosterPosition)) {
            refusedObjects.push(
                createRefusal(
                    'BallotPackageInvalid',
                    'Ballot roster positions must cover every one-based position.',
                ),
            );
            break;
        }
    }

    return refusedObjects;
};

export const requireNoRefusals = (
    refusedObjects: readonly RefusalRecord[],
): void => {
    if (refusedObjects.length > 0) {
        throw new RangeError(refusedObjects[0]?.message ?? 'Invalid input.');
    }
};

export const getRosterEntryByIdentity = (
    rosterEntries: readonly PvssBallotRosterEntry[],
    participantIdentity: string,
): PvssBallotRosterEntry | undefined =>
    rosterEntries.find(
        (entry) => entry.participantIdentity === participantIdentity,
    );
