import type {
    DuplicateBallotPolicy,
    HeBackendCorruptionModel,
    ScoreDomain,
    TiePolicy,
} from '@sealed-lattice/types';
export {
    cpadProfileId,
    targetBoundShareSelectionProfileId,
} from '@sealed-lattice/types';

export const strictLessThanOneThirdModel = {
    kind: 'StrictLessThanOneThird',
} as const satisfies HeBackendCorruptionModel;

export const defaultScoreDomain = {
    min: 1,
    max: 10,
    skippedOptionScore: 1,
} as const satisfies ScoreDomain;

export const defaultDuplicateBallotPolicy =
    'LastValidBeforeVotingClosedCounts' as const satisfies DuplicateBallotPolicy;

export const defaultTiePolicy =
    'HigherScoreThenLowerOptionIndex' as const satisfies TiePolicy;

export const minimumUnsafeRosterSize = 3;
export const minimumSafeRosterSize = 20;
export const maximumSafeRosterSize = 50;
