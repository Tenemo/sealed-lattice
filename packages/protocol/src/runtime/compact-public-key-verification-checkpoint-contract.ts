export const compactPublicKeyVerificationCheckpointStateStreamDomains =
    Object.freeze({
        acceptedSetup:
            'sealed-lattice/bgv/accepted-setup-compact-public-key-verification-checkpoint/v1',
        algebraic:
            'sealed-lattice/bgv/compact-public-key-algebraic-verification-checkpoint/v1',
    });

export const createEmptyCompactPublicKeyVerificationPrivateRandomnessCursorManifestBytes =
    (): Uint8Array<ArrayBuffer> =>
        Uint8Array.of(
            0x53,
            0x4c,
            0x43,
            0x50,
            0x43,
            0x4d,
            0x30,
            0x33,
            0x03,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
        );
