import { assertProtocolHash } from '../common-fields.js';

import type {
    SetupPackageVerificationInput,
    SetupPackageVerificationInputSource,
} from './types.js';

export const createSetupPackageVerificationInput = (
    input: SetupPackageVerificationInputSource,
): SetupPackageVerificationInput => {
    assertProtocolHash(input.expectedManifestHash, 'expectedManifestHash');
    assertProtocolHash(input.expectedRosterHash, 'expectedRosterHash');

    return {
        setupPackage: input.setupPackage,
        expectedManifestHash: input.expectedManifestHash,
        expectedRosterHash: input.expectedRosterHash,
    };
};
