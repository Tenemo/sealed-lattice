import type {
    BgvTargetDecryptionShareProofMaterial,
    ProtocolHash,
} from '@sealed-lattice/types';

import { protocolHashPattern } from '../common/verification-helpers.js';
import { copyCanonicalStreamDescriptor } from '../setup/canonical-stream-descriptor.js';

export type { BgvTargetDecryptionShareProofMaterial };

export type BgvTargetDecryptionShareCanonicalProofMaterialTransport = Readonly<{
    readonly objectType: 'BgvTargetDecryptionShareCanonicalProofMaterialTransport';
    readonly proofBytesHash: ProtocolHash;
    readonly descriptorBytes: Uint8Array;
}>;

export type BgvTargetDecryptionShareCanonicalMaterialExport = Readonly<{
    readonly descriptorBytes: Uint8Array;
}>;

const assertProtocolHash = (
    value: unknown,
    fieldName: string,
): ProtocolHash => {
    if (typeof value !== 'string' || !protocolHashPattern.test(value)) {
        throw new TypeError(`${fieldName} must be a protocol hash.`);
    }

    return value;
};

const validatedTargetProofBytesHash = (
    proofMaterial: BgvTargetDecryptionShareProofMaterial,
): ProtocolHash => {
    if (proofMaterial.objectType !== 'BgvTargetDecryptionShareProofMaterial') {
        throw new TypeError(
            'target-decryption proof material objectType must be BgvTargetDecryptionShareProofMaterial.',
        );
    }
    return assertProtocolHash(
        proofMaterial.proofBytesHash,
        'target-decryption proof material proofBytesHash',
    );
};

export const createBgvTargetDecryptionShareCanonicalProofMaterialTransport = (
    proofMaterial: BgvTargetDecryptionShareProofMaterial,
    materialExport: BgvTargetDecryptionShareCanonicalMaterialExport,
): BgvTargetDecryptionShareCanonicalProofMaterialTransport => {
    const proofBytesHash = validatedTargetProofBytesHash(proofMaterial);

    return {
        objectType: 'BgvTargetDecryptionShareCanonicalProofMaterialTransport',
        proofBytesHash,
        descriptorBytes: copyCanonicalStreamDescriptor(
            materialExport.descriptorBytes,
            'target-decryption canonical material descriptorBytes',
        ),
    };
};
