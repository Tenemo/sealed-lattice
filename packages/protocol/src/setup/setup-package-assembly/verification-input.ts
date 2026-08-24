import { assertProtocolHash } from '../common-fields.js';

import type { SetupPackageVerificationInput } from './types.js';

export const createSetupPackageVerificationInput = (
    input: SetupPackageVerificationInput,
): SetupPackageVerificationInput => {
    if (
        !ArrayBuffer.isView(input.canonicalSetupPackageBytes) ||
        Object.prototype.toString.call(input.canonicalSetupPackageBytes) !==
            '[object Uint8Array]'
    ) {
        throw new TypeError('canonicalSetupPackageBytes must be a Uint8Array.');
    }
    assertProtocolHash(input.expectedManifestHash, 'expectedManifestHash');
    assertProtocolHash(input.expectedRosterHash, 'expectedRosterHash');
    if (input.expectedSetupPackageHash !== undefined) {
        assertProtocolHash(
            input.expectedSetupPackageHash,
            'expectedSetupPackageHash',
        );
    }

    return {
        canonicalSetupPackageBytes: input.canonicalSetupPackageBytes.slice(),
        ...(input.expectedSetupPackageHash === undefined
            ? {}
            : { expectedSetupPackageHash: input.expectedSetupPackageHash }),
        expectedManifestHash: input.expectedManifestHash,
        expectedRosterHash: input.expectedRosterHash,
    };
};
