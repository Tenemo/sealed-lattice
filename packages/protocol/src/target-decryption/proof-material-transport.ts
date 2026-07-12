import { deriveCanonicalObjectHash } from '@sealed-lattice/crypto';
import type { ProtocolHash } from '@sealed-lattice/types';

import { protocolHashPattern } from '../common/verification-helpers.js';

type JsonRecord = Record<string, unknown>;

export const targetDecryptionShareProofFamily = 'target-decryption-share';
export const targetDecryptionShareProofBytesEncoding =
    'binary-chunked-proof-bytes';

export type BgvTargetDecryptionShareProofMaterial = Readonly<
    JsonRecord & {
        readonly objectType: 'BgvTargetDecryptionShareProofMaterial';
        readonly proofRecords: readonly unknown[];
        readonly proofMaterialRoot: ProtocolHash;
    }
>;

export type BgvTargetDecryptionShareCanonicalProofMaterialTransport = Readonly<{
    readonly objectType: 'BgvTargetDecryptionShareCanonicalProofMaterialTransport';
    readonly proofFamily: typeof targetDecryptionShareProofFamily;
    readonly proofMaterialRoot: ProtocolHash;
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

const assertObject = (value: unknown, fieldName: string): JsonRecord => {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
        throw new TypeError(`${fieldName} must be an object.`);
    }

    return value as JsonRecord;
};

const validatedTargetProofMaterialRoot = (
    proofMaterial: BgvTargetDecryptionShareProofMaterial,
): ProtocolHash => {
    if (proofMaterial.objectType !== 'BgvTargetDecryptionShareProofMaterial') {
        throw new TypeError(
            'target-decryption proof material objectType must be BgvTargetDecryptionShareProofMaterial.',
        );
    }
    if (proofMaterial.proofRecords.length !== 1) {
        throw new TypeError(
            'target-decryption proof material must contain one all-active-limb proof record.',
        );
    }
    const proofRecord = assertObject(
        proofMaterial.proofRecords[0],
        'target-decryption proof material proofRecords.0',
    );
    if (proofRecord.objectType !== 'BgvTargetDecryptionShareProofRecord') {
        throw new TypeError(
            'target-decryption proof record objectType must be BgvTargetDecryptionShareProofRecord.',
        );
    }
    if (
        proofRecord.proofBytesEncoding !==
        targetDecryptionShareProofBytesEncoding
    ) {
        throw new TypeError(
            'target-decryption proof record proofBytesEncoding must be binary-chunked-proof-bytes.',
        );
    }
    assertProtocolHash(
        proofRecord.proofBytesHash,
        'target-decryption proof record proofBytesHash',
    );
    const proofMaterialRoot = assertProtocolHash(
        proofMaterial.proofMaterialRoot,
        'target-decryption proof material proofMaterialRoot',
    );
    const {
        proofMaterialRoot: omittedProofMaterialRoot,
        ...proofMaterialRootPreimage
    } = proofMaterial;
    void omittedProofMaterialRoot;
    if (
        proofMaterialRoot !==
        deriveCanonicalObjectHash(proofMaterialRootPreimage)
    ) {
        throw new Error(
            'target-decryption proof material root does not match its proof records.',
        );
    }

    return proofMaterialRoot;
};

export const createBgvTargetDecryptionShareCanonicalProofMaterialTransport = (
    proofMaterial: BgvTargetDecryptionShareProofMaterial,
    materialExport: BgvTargetDecryptionShareCanonicalMaterialExport,
): BgvTargetDecryptionShareCanonicalProofMaterialTransport => {
    const proofMaterialRoot = validatedTargetProofMaterialRoot(proofMaterial);
    if (
        !ArrayBuffer.isView(materialExport.descriptorBytes) ||
        Object.prototype.toString.call(materialExport.descriptorBytes) !==
            '[object Uint8Array]' ||
        materialExport.descriptorBytes.byteLength === 0
    ) {
        throw new TypeError(
            'target-decryption canonical material descriptorBytes must be a non-empty Uint8Array.',
        );
    }

    return {
        objectType: 'BgvTargetDecryptionShareCanonicalProofMaterialTransport',
        proofFamily: targetDecryptionShareProofFamily,
        proofMaterialRoot,
        descriptorBytes: materialExport.descriptorBytes.slice(),
    };
};

// Preserve the existing internal helper name while routing it through the sole
// canonical stream representation. There is no target-specific binary framing.
export const encodeBgvTargetDecryptionShareProofMaterialBinary =
    createBgvTargetDecryptionShareCanonicalProofMaterialTransport;
