import { foundationProfile } from '@sealed-lattice/types';

export const maximumClosedWorkerCommandByteLength =
    foundationProfile.maximumCopiedBufferByteLength;

export const actionRandomnessCommandOutputByteLimit = (
    _commandIdentifier: number,
): number => maximumClosedWorkerCommandByteLength;
