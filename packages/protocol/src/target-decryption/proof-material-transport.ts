import {
    deriveCanonicalObjectHash,
    setupProofMaterialFullObjectHashHex,
} from '@sealed-lattice/crypto';
import type { ProtocolHash } from '@sealed-lattice/types';

import { protocolHashPattern } from '../common/verification-helpers.js';
import { BinaryChunkWriter } from '../setup/binary-chunk-writer.js';
import { bytesFromStandardBase64 } from '../setup/proof-byte-encoding.js';
import {
    setupProofChunkManifestRoot,
    setupProofMaterialChunkHash,
    setupProofTransportChunkSizeBytes,
} from '../setup/setup-proof-material-transport.js';

type JsonRecord = Record<string, unknown>;

export const targetDecryptionShareProofFamily = 'target-decryption-share';
export const targetDecryptionShareProofMaterialBinaryFormat =
    'sealed-lattice-target-decryption-share-proof-material-binary-v1';

const targetDecryptionShareProofMaterialBinaryMagic = new TextEncoder().encode(
    'SEALED-LATTICE-TARGET-DECRYPTION-SHARE-PROOF-MATERIAL-BINARY-V1',
);

export type BgvTargetDecryptionShareProofMaterial = Readonly<
    JsonRecord & {
        readonly objectType: 'BgvTargetDecryptionShareProofMaterial';
        readonly objectVersion: 8;
        readonly proofRecords: readonly unknown[];
        readonly proofMaterialRoot: ProtocolHash;
    }
>;

type BgvTargetDecryptionShareBinaryProofMaterialTransport = Readonly<
    JsonRecord & {
        readonly objectType: 'BgvTargetDecryptionShareBinaryProofMaterialTransport';
        readonly objectVersion: 1;
        readonly proofFamily: typeof targetDecryptionShareProofFamily;
        readonly binaryFormat: typeof targetDecryptionShareProofMaterialBinaryFormat;
        readonly proofMaterialRoot: ProtocolHash;
        readonly chunkSizeBytes: typeof setupProofTransportChunkSizeBytes;
        readonly chunkCount: number;
        readonly totalByteLength: number;
        readonly fullObjectHash: ProtocolHash;
        readonly chunkRoot: ProtocolHash;
        readonly chunkHashes: readonly ProtocolHash[];
        readonly chunks: readonly Uint8Array[];
    }
>;

const assertProtocolHash = (
    value: unknown,
    fieldName: string,
): ProtocolHash => {
    if (typeof value !== 'string' || !protocolHashPattern.test(value)) {
        throw new TypeError(`${fieldName} must be a protocol hash.`);
    }

    return value;
};

const assertExactStringField = (
    value: unknown,
    fieldName: string,
    expectedValue: string,
): void => {
    if (value !== expectedValue) {
        throw new TypeError(`${fieldName} must be ${expectedValue}.`);
    }
};

const assertObject = (value: unknown, fieldName: string): JsonRecord => {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
        throw new TypeError(`${fieldName} must be an object.`);
    }

    return value as JsonRecord;
};

const assertObjectVersion = (
    value: unknown,
    fieldName: string,
    expectedValue: number,
): void => {
    if (value !== expectedValue) {
        throw new TypeError(`${fieldName} objectVersion is not supported.`);
    }
};

const hexToBytes = (hex: ProtocolHash): Uint8Array => {
    const bytes = new Uint8Array(hex.length / 2);
    for (let byteIndex = 0; byteIndex < bytes.length; byteIndex += 1) {
        bytes[byteIndex] = Number.parseInt(
            hex.slice(byteIndex * 2, byteIndex * 2 + 2),
            16,
        );
    }

    return bytes;
};

const validatedTargetProofMaterialRoot = (
    proofMaterial: BgvTargetDecryptionShareProofMaterial,
): ProtocolHash => {
    assertExactStringField(
        proofMaterial.objectType,
        'target-decryption proof material objectType',
        'BgvTargetDecryptionShareProofMaterial',
    );
    assertObjectVersion(
        proofMaterial.objectVersion,
        'target-decryption proof material',
        8,
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
    const expectedProofMaterialRoot = deriveCanonicalObjectHash(
        proofMaterialRootPreimage,
    );
    if (proofMaterialRoot !== expectedProofMaterialRoot) {
        throw new Error(
            'target-decryption proof material root does not match its proof records.',
        );
    }

    return proofMaterialRoot;
};

export const encodeBgvTargetDecryptionShareProofMaterialBinary = (
    proofMaterial: BgvTargetDecryptionShareProofMaterial,
): BgvTargetDecryptionShareBinaryProofMaterialTransport => {
    const proofMaterialRoot = validatedTargetProofMaterialRoot(proofMaterial);
    if (proofMaterial.proofRecords.length !== 1) {
        throw new TypeError(
            'target-decryption proof material must contain one all-active-limb proof record.',
        );
    }

    const writer = new BinaryChunkWriter({
        chunkSizeBytes: setupProofTransportChunkSizeBytes,
        emptyErrorMessage:
            'target-decryption proof material binary transport requires bytes.',
    });

    writer.writeBytes(targetDecryptionShareProofMaterialBinaryMagic);
    writer.writeVaruint(1);
    writer.writeBytes(hexToBytes(proofMaterialRoot));
    writer.writeVaruint(proofMaterial.proofRecords.length);
    proofMaterial.proofRecords.forEach((proofRecordValue, proofRecordIndex) => {
        const proofRecord = assertObject(
            proofRecordValue,
            `target-decryption proof material proofRecords.${String(proofRecordIndex)}`,
        );
        assertExactStringField(
            proofRecord.objectType,
            `target-decryption proof material proofRecords.${String(proofRecordIndex)} objectType`,
            'BgvTargetDecryptionShareProofRecord',
        );
        assertObjectVersion(
            proofRecord.objectVersion,
            `target-decryption proof material proofRecords.${String(proofRecordIndex)}`,
            7,
        );
        const proofBytesBase64 = proofRecord.proofBytesBase64;
        if (typeof proofBytesBase64 !== 'string') {
            throw new TypeError(
                `target-decryption proof material proofRecords.${String(proofRecordIndex)} proofBytesBase64 must be a string.`,
            );
        }
        const proofBytes = bytesFromStandardBase64(
            proofBytesBase64,
            `target-decryption proof material proofRecords.${String(proofRecordIndex)} proofBytesBase64`,
        );
        writer.writeVaruint(proofBytes.byteLength);
        writer.writeBytes(proofBytes);
    });

    const { chunks, chunkCount, totalByteLength } = writer.finishWithSummary();
    const fullObjectHash = setupProofMaterialFullObjectHashHex(
        targetDecryptionShareProofFamily,
        totalByteLength,
        chunks,
    );
    const chunkHashes = chunks.map((chunk, chunkIndex) =>
        setupProofMaterialChunkHash(
            targetDecryptionShareProofFamily,
            fullObjectHash,
            chunkIndex,
            chunk,
        ),
    );
    const chunkRoot = setupProofChunkManifestRoot(
        targetDecryptionShareProofFamily,
        chunkHashes,
        fullObjectHash,
        totalByteLength,
    );

    return {
        objectType: 'BgvTargetDecryptionShareBinaryProofMaterialTransport',
        objectVersion: 1,
        proofFamily: targetDecryptionShareProofFamily,
        binaryFormat: targetDecryptionShareProofMaterialBinaryFormat,
        proofMaterialRoot,
        chunkSizeBytes: setupProofTransportChunkSizeBytes,
        chunkCount,
        totalByteLength,
        fullObjectHash,
        chunkRoot,
        chunkHashes,
        chunks,
    };
};
