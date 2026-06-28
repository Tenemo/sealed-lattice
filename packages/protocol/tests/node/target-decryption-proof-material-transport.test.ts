import { deriveProtocolHash } from '@sealed-lattice/crypto';
import { describe, expect, it } from 'vitest';

import {
    encodeBgvTargetDecryptionShareProofMaterialBinary,
    targetDecryptionShareProofFamily,
    targetDecryptionShareProofMaterialBinaryFormat,
    type BgvTargetDecryptionShareProofMaterial,
} from '#packages/protocol/src/target-decryption/proof-material-transport';

const proofMaterialWithBytes = (
    proofBytesBase64: string,
): BgvTargetDecryptionShareProofMaterial => {
    const proofMaterialWithoutRoot = {
        objectType: 'BgvTargetDecryptionShareProofMaterial',
        objectVersion: 8,
        proofRecords: [
            {
                objectType: 'BgvTargetDecryptionShareProofRecord',
                objectVersion: 7,
                proofBytesBase64,
            },
        ],
    } as const;

    return {
        ...proofMaterialWithoutRoot,
        proofMaterialRoot: deriveProtocolHash(
            'TargetDecryptionShareProofMaterialRoot',
            proofMaterialWithoutRoot,
        ),
    };
};

describe('target-decryption proof material transport', () => {
    it('encodes compact binary proof material with bound chunk metadata', () => {
        const proofMaterial = proofMaterialWithBytes('AQIDBAU=');
        const transport =
            encodeBgvTargetDecryptionShareProofMaterialBinary(proofMaterial);

        expect(transport).toMatchObject({
            objectType: 'BgvTargetDecryptionShareBinaryProofMaterialTransport',
            objectVersion: 1,
            setupProfileId: 'CollectiveBgvSetup-v1',
            targetDecryptionProfileId: 'BGV-RNS-AsyncTargetDecryption-v1',
            proofFamily: targetDecryptionShareProofFamily,
            binaryFormat: targetDecryptionShareProofMaterialBinaryFormat,
            proofMaterialRoot: proofMaterial.proofMaterialRoot,
            chunkCount: 1,
        });
        expect(transport.chunks).toHaveLength(transport.chunkCount);
        expect(transport.chunkHashes).toHaveLength(transport.chunkCount);
        expect(
            transport.chunks.reduce(
                (totalBytes, chunk) => totalBytes + chunk.byteLength,
                0,
            ),
        ).toBe(transport.totalByteLength);
        expect(transport.totalByteLength).toBeLessThan(
            JSON.stringify(proofMaterial).length,
        );
        expect(transport.fullObjectHash).toMatch(/^[0-9a-f]{128}$/u);
        expect(transport.chunkRoot).toMatch(/^[0-9a-f]{128}$/u);
    });

    it('rejects proof material whose root no longer binds the proof bytes', () => {
        const proofMaterial = proofMaterialWithBytes('AQIDBAU=');
        const tamperedProofMaterial = {
            ...proofMaterial,
            proofRecords: [
                {
                    objectType: 'BgvTargetDecryptionShareProofRecord',
                    objectVersion: 7,
                    proofBytesBase64: 'BQIDBAE=',
                },
            ],
        } as BgvTargetDecryptionShareProofMaterial;

        expect(() =>
            encodeBgvTargetDecryptionShareProofMaterialBinary(
                tamperedProofMaterial,
            ),
        ).toThrow(/root does not match/u);
    });

    it('rejects malformed proof-byte base64 before framing bytes', () => {
        const proofMaterial = proofMaterialWithBytes('AQIDBAU=');
        const malformedProofMaterial = {
            ...proofMaterial,
            proofRecords: [
                {
                    objectType: 'BgvTargetDecryptionShareProofRecord',
                    objectVersion: 7,
                    proofBytesBase64: 'AQI=BAU=',
                },
            ],
            proofMaterialRoot: deriveProtocolHash(
                'TargetDecryptionShareProofMaterialRoot',
                {
                    objectType: 'BgvTargetDecryptionShareProofMaterial',
                    objectVersion: 8,
                    proofRecords: [
                        {
                            objectType: 'BgvTargetDecryptionShareProofRecord',
                            objectVersion: 7,
                            proofBytesBase64: 'AQI=BAU=',
                        },
                    ],
                },
            ),
        } as BgvTargetDecryptionShareProofMaterial;

        expect(() =>
            encodeBgvTargetDecryptionShareProofMaterialBinary(
                malformedProofMaterial,
            ),
        ).toThrow(/multiple of four|standard base64|padding/u);
    });
});
