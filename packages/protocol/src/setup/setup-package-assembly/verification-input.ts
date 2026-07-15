import { assertProtocolHash } from '../common-fields.js';

import type { SetupPackageVerificationInput } from './types.js';

export const createSetupPackageVerificationInput = (
    input: SetupPackageVerificationInput,
): SetupPackageVerificationInput => {
    assertProtocolHash(input.expectedManifestHash, 'expectedManifestHash');
    assertProtocolHash(input.expectedRosterHash, 'expectedRosterHash');

    return {
        setupPackage: input.setupPackage,
        expectedManifestHash: input.expectedManifestHash,
        expectedRosterHash: input.expectedRosterHash,
    };
};
