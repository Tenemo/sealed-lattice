import type {
    HeBackendCorruptionModel,
    ScoreDomain,
    SmallRosterPolicy,
} from '@sealed-lattice/types';
export {
    targetDecryptionId,
    targetBoundShareSelectionId,
} from '@sealed-lattice/types';

export const structuralOneThirdModel = {
    kind: 'StructuralOneThird',
} as const satisfies HeBackendCorruptionModel;

export const defaultScoreDomain = {
    min: 1,
    max: 10,
    skippedOptionScore: 1,
} as const satisfies ScoreDomain;

export const defaultSmallRosterPolicy =
    'ForbidMicroRoster' as const satisfies SmallRosterPolicy;

// Roster-size landmarks:
//  3  - absolute minimum supported roster.
//  10 - the first (and only) end-to-end closure roster size.
//  20 - hard maximum supported roster; the parameterized upper bound for which
//       code paths exist but no end-to-end/runtime evidence is claimed yet.
export const minimumSupportedRosterSize = 3;
export const minimumDynamicRosterSize = 10;
export const firstClosureRosterSize = 10;
export const maximumSupportedRosterSize = 20;
