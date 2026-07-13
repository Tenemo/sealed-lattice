import type { SmallRosterPolicy } from '@sealed-lattice/types';

export const defaultSmallRosterPolicy =
    'ForbidMicroRoster' as const satisfies SmallRosterPolicy;

export const minimumSupportedRosterSize = 3;
export const minimumNonMicroRosterSize = 10;
export const maximumSupportedRosterSize = 20;
