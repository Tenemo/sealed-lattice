import { deriveCanonicalObjectHash } from '@sealed-lattice/crypto';
import { describe, expect, it } from 'vitest';

import {
    createBgvTargetDecryptionShareCanonicalProofMaterialTransport,
    type BgvTargetDecryptionShareProofMaterial,
} from '#packages/protocol/src/target-decryption/proof-material-transport';

const proofBytesHash = '11'.repeat(64);

const proofMaterial = (): BgvTargetDecryptionShareProofMaterial => {
    const preimage = {
        objectType: 'BgvTargetDecryptionShareProofMaterial' as const,
        proofRecords: [
            {
                objectType: 'BgvTargetDecryptionShareProofRecord',
                proofBytesEncoding: 'binary-chunked-proof-bytes',
                proofBytesHash,
            },
        ],
    };

    return {
        ...preimage,
        proofMaterialRoot: deriveCanonicalObjectHash(preimage),
    };
};

describe('target-decryption canonical proof material transport', () => {
    it('copies the canonical descriptor and binds the semantic root', () => {
        const descriptorBytes = Uint8Array.of(1, 2, 3, 4);
        const transport =
            createBgvTargetDecryptionShareCanonicalProofMaterialTransport(
                proofMaterial(),
                {
                    descriptorBytes,
                },
            );

        expect(transport.objectType).toBe(
            'BgvTargetDecryptionShareCanonicalProofMaterialTransport',
        );
        expect(transport.descriptorBytes).not.toBe(descriptorBytes);
        expect([...transport.descriptorBytes]).toEqual([1, 2, 3, 4]);
    });

    it('refuses a wrong semantic root and malformed descriptor', () => {
        const wrongRootMaterial = {
            ...proofMaterial(),
            proofMaterialRoot: '22'.repeat(64),
        };
        expect(() =>
            createBgvTargetDecryptionShareCanonicalProofMaterialTransport(
                wrongRootMaterial,
                {
                    descriptorBytes: Uint8Array.of(1),
                },
            ),
        ).toThrow(/root does not match/u);

        expect(() =>
            createBgvTargetDecryptionShareCanonicalProofMaterialTransport(
                proofMaterial(),
                {
                    descriptorBytes: new Uint8Array(),
                },
            ),
        ).toThrow(/non-empty Uint8Array/u);
    });
});
