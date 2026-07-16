import { foundationProfile } from '@sealed-lattice/types';

import { actionRandomnessCommandIdentifiers } from './action-randomness-command-identifiers.js';
import { structuredCommitmentWorkerResponseProductionByteLength } from './structured-commitment-worker-response.js';

export const maximumClosedWorkerCommandByteLength =
    foundationProfile.maximumCopiedBufferByteLength;

// The fixed commitment response carries the maximum copied residue payload plus
// 44 bytes of closed-worker framing. No other command may exceed the ordinary
// command ceiling, and command inputs never receive this output-only allowance.
export const actionRandomnessCommandOutputByteLimit = (
    command: number,
): number =>
    command === actionRandomnessCommandIdentifiers.computeStructuredCommitment
        ? structuredCommitmentWorkerResponseProductionByteLength
        : maximumClosedWorkerCommandByteLength;
