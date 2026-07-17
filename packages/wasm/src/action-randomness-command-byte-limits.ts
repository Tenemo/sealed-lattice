import { foundationProfile } from '@sealed-lattice/types';

import { actionRandomnessCommandIdentifiers } from './action-randomness-command-identifiers.js';
import { structuredCommitmentWorkerResponseProductionByteLength } from './structured-commitment-worker-response.js';

export const maximumClosedWorkerCommandByteLength =
    foundationProfile.maximumCopiedBufferByteLength;

// The structured-commitment command has one fixed production response shape.
// Bind that output to its exact byte length; all other commands retain the
// ordinary copied-buffer ceiling.
export const actionRandomnessCommandOutputByteLimit = (
    command: number,
): number =>
    command === actionRandomnessCommandIdentifiers.computeStructuredCommitment
        ? structuredCommitmentWorkerResponseProductionByteLength
        : maximumClosedWorkerCommandByteLength;
