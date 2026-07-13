import type { SmallRosterPolicy } from '@sealed-lattice/types';

export const defaultSmallRosterPolicy =
    'ForbidMicroRoster' as const satisfies SmallRosterPolicy;

// Roster-size landmarks:
//  3  - absolute minimum supported roster.
//  10 - boundary below which the poll's micro-roster policy applies.
//  20 - hard maximum accepted by this structural calculator.
export const minimumSupportedRosterSize = 3;
export const minimumNonMicroRosterSize = 10;
export const maximumSupportedRosterSize = 20;
