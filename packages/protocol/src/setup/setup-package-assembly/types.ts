import type { ProtocolHash } from '@sealed-lattice/types';

export type SetupPackageVerificationInput = Readonly<{
    readonly canonicalSetupPackageBytes: Uint8Array;
    readonly expectedSetupPackageHash?: ProtocolHash;
    readonly expectedManifestHash: ProtocolHash;
    readonly expectedRosterHash: ProtocolHash;
}>;
