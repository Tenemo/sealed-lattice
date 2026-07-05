import { describe, expect, it } from 'vitest';

import { loadPublicTranscriptCoreKernel } from './accepted-setup-public-api/support.js';

import { hash512Hex } from '#packages/crypto/src/index';
import {
    createBinaryChunkedSameSecretBridgeProofMaterialTransport,
    createBinaryChunkedVssShareLinkageProofMaterialTransport,
} from '#packages/protocol/src/index';

type JsonRecord = Record<string, unknown>;

// The two compact public-VSS proof material families the kernel streams through
// the shared setup proof-material transport instead of embedding as base64 in the
// package JSON. Each carries a distinct proof-family string, transported object
// types, and proof-bytes hash domain; the streamed proofRecordRoot canonical form
// otherwise differs only in the embedded identity fields.
type ProofMaterialCase = Readonly<{
    readonly proofFamily:
        | 'vss-share-linkage'
        | 'same-secret-bridge';
    readonly proofRecordObjectType:
        | 'VssShareLinkageProofRecord'
        | 'VssSameSecretBridgeProofRecord';
    readonly proofMaterialSetObjectType:
        | 'VssShareLinkageProofMaterialSet'
        | 'VssSameSecretBridgeProofMaterialSet';
    readonly transportSetObjectType:
        | 'SetupTransportedVssShareLinkageProofMaterialSet'
        | 'SetupTransportedSameSecretBridgeProofMaterialSet';
    readonly transportMaterialObjectType:
        | 'SetupTransportedVssShareLinkageProofMaterial'
        | 'SetupTransportedSameSecretBridgeProofMaterial';
    readonly proofBytesHashDomain: string;
    readonly moveEmbeddedToTransport: (proofMaterialSet: JsonRecord) => {
        readonly proofMaterialSet: JsonRecord;
        readonly transportedProofMaterialSet: JsonRecord;
    };
    readonly identityFields: (recordIndex: number) => JsonRecord;
}>;

const shareLinkageIdentityFields = (recordIndex: number): JsonRecord => ({
    linkageItems: [
        {
            sourceTrusteeRosterPosition: 0,
            recipientRosterPosition: recordIndex,
            sourceRnsLimbIndex: 0,
            itemIndex: 0,
        },
    ],
    vssShareLinkage: {
        sourceTrusteeRosterPosition: 0,
        recipientRosterPosition: recordIndex,
        sourceRnsLimbIndex: 0,
        shareLinkageStatementRoot: 'a'.repeat(128),
        publicMatrixSeedHash: 'b'.repeat(128),
        additionalLinkageItems: [],
    },
});

const sameSecretBridgeIdentityFields = (recordIndex: number): JsonRecord => ({
    sameSecretBridgeStatementRoot: `${String(recordIndex)}`.padStart(
        128,
        'c',
    ),
});

const proofMaterialCases = [
    {
        proofFamily: 'vss-share-linkage',
        proofRecordObjectType: 'VssShareLinkageProofRecord',
        proofMaterialSetObjectType: 'VssShareLinkageProofMaterialSet',
        transportSetObjectType:
            'SetupTransportedVssShareLinkageProofMaterialSet',
        transportMaterialObjectType:
            'SetupTransportedVssShareLinkageProofMaterial',
        proofBytesHashDomain:
            'sealed-lattice/setup/vss-share-linkage/proof-bytes-v1',
        moveEmbeddedToTransport: (proofMaterialSet: JsonRecord) => {
            const moved =
                createBinaryChunkedVssShareLinkageProofMaterialTransport(
                    proofMaterialSet,
                );

            return {
                proofMaterialSet: moved.proofMaterialSet,
                transportedProofMaterialSet:
                    moved.transportedVssShareLinkageProofMaterial,
            };
        },
        identityFields: shareLinkageIdentityFields,
    },
    {
        proofFamily: 'same-secret-bridge',
        proofRecordObjectType: 'VssSameSecretBridgeProofRecord',
        proofMaterialSetObjectType:
            'VssSameSecretBridgeProofMaterialSet',
        transportSetObjectType:
            'SetupTransportedSameSecretBridgeProofMaterialSet',
        transportMaterialObjectType:
            'SetupTransportedSameSecretBridgeProofMaterial',
        proofBytesHashDomain:
            'sealed-lattice/setup/same-secret-bridge/proof-bytes-v1',
        moveEmbeddedToTransport: (proofMaterialSet: JsonRecord) => {
            const moved =
                createBinaryChunkedSameSecretBridgeProofMaterialTransport(
                    proofMaterialSet,
                );

            return {
                proofMaterialSet: moved.proofMaterialSet,
                transportedProofMaterialSet:
                    moved.transportedSameSecretBridgeProofMaterial,
            };
        },
        identityFields: sameSecretBridgeIdentityFields,
    },
] as const satisfies readonly ProofMaterialCase[];

const encodeStandardBase64Alphabet =
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

const encodeStandardBase64 = (bytes: Uint8Array): string => {
    let encoded = '';
    for (let chunkStart = 0; chunkStart < bytes.length; chunkStart += 3) {
        const remaining = bytes.length - chunkStart;
        const first = bytes[chunkStart];
        const second = remaining >= 2 ? bytes[chunkStart + 1] : 0;
        const third = remaining >= 3 ? bytes[chunkStart + 2] : 0;
        encoded += encodeStandardBase64Alphabet[first >> 2];
        encoded +=
            encodeStandardBase64Alphabet[((first & 0x03) << 4) | (second >> 4)];
        encoded +=
            remaining >= 2
                ? encodeStandardBase64Alphabet[
                      ((second & 0x0f) << 2) | (third >> 6)
                  ]
                : '=';
        encoded +=
            remaining >= 3 ? encodeStandardBase64Alphabet[third & 0x3f] : '=';
    }

    return encoded;
};

// A tiny embedded compact proof material set for one source trustee. The proof
// bytes are short synthetic bytes, not a certified proof: the streaming transport
// path binds and recomputes the transport hashes over whatever bytes it is given,
// so this exercises the move-to-transport rewrite and the kernel chunk-hash
// binding at the smallest possible scale.
const embeddedProofMaterialSet = (
    compactCase: ProofMaterialCase,
    recordCount: number,
): JsonRecord => {
    const proofRecords = Array.from(
        { length: recordCount },
        (_unused, recordIndex) => {
            const proofBytes = Uint8Array.from([
                recordIndex,
                0x11,
                0x22,
                0x33,
                0x44,
            ]);

            return {
                objectType: compactCase.proofRecordObjectType,
                objectVersion: 1,
                proofFamily: compactCase.proofFamily,
                ...compactCase.identityFields(recordIndex),
                proofBytesHash: hash512Hex(compactCase.proofBytesHashDomain, [
                    proofBytes,
                ]),
                proofBytesBase64: encodeStandardBase64(proofBytes),
                proofRecordRoot: `stale-record-root-${String(recordIndex)}`,
            };
        },
    );

    return {
        objectType: compactCase.proofMaterialSetObjectType,
        objectVersion: 1,
        proofFamily: compactCase.proofFamily,
        proofRecords,
        proofMaterialSetRoot: 'stale-proof-material-set-root',
    };
};

describe('compact VSS proof material move to transport', () => {
    it.each(proofMaterialCases)(
        'moves $proofFamily embedded proof bytes onto the streamable transport',
        (compactCase) => {
            const embedded = embeddedProofMaterialSet(compactCase, 2);
            const moved = compactCase.moveEmbeddedToTransport(embedded);

            const transportedProofMaterials = moved.transportedProofMaterialSet
                .proofMaterials as readonly JsonRecord[];
            expect(moved.transportedProofMaterialSet.objectType).toBe(
                compactCase.transportSetObjectType,
            );
            expect(moved.transportedProofMaterialSet.proofFamily).toBe(
                compactCase.proofFamily,
            );
            expect(transportedProofMaterials).toHaveLength(2);

            const rewrittenProofRecords = moved.proofMaterialSet
                .proofRecords as readonly JsonRecord[];
            rewrittenProofRecords.forEach((proofRecord, recordIndex) => {
                const transportMaterial =
                    transportedProofMaterials[recordIndex];
                expect(proofRecord).not.toHaveProperty('proofBytesBase64');
                expect(proofRecord.proofBytesEncoding).toBe(
                    'binary-chunked-proof-bytes',
                );
                expect(proofRecord.proofMaterialRoot).toBe(
                    transportMaterial.proofMaterialRoot,
                );
                expect(proofRecord.proofChunkSizeBytes).toBe(1_048_576);
                expect(proofRecord.proofChunkCount).toBe(1);
                expect(proofRecord.proofChunkRoot).toBe(
                    transportMaterial.chunkRoot,
                );
                expect(proofRecord.proofChunkHashes).toStrictEqual(
                    transportMaterial.chunkHashes,
                );
                // The record must rebind its root over the transport reference,
                // not keep the stale embedded root.
                expect(proofRecord.proofRecordRoot).not.toBe(
                    `stale-record-root-${String(recordIndex)}`,
                );
                expect(proofRecord.proofRecordRoot).toMatch(/^[0-9a-f]{128}$/u);

                const transportChunks =
                    transportMaterial.chunks as readonly JsonRecord[];
                expect(transportChunks[0]).toMatchObject({
                    chunkIndex: 0,
                    bytesHex: `0${String(recordIndex)}11223344`,
                });
            });

            expect(moved.proofMaterialSet.proofMaterialSetRoot).not.toBe(
                'stale-proof-material-set-root',
            );
            expect(moved.proofMaterialSet.proofMaterialSetRoot).toMatch(
                /^[0-9a-f]{128}$/u,
            );
        },
    );

    it.each(proofMaterialCases)(
        'rejects a $proofFamily proof material set with no proof records',
        (compactCase) => {
            expect(() =>
                compactCase.moveEmbeddedToTransport({
                    objectType: compactCase.proofMaterialSetObjectType,
                    objectVersion: 1,
                    proofFamily: compactCase.proofFamily,
                }),
            ).toThrow(/proofRecords must be an array/u);
        },
    );

    it.each(proofMaterialCases)(
        'rejects a $proofFamily record whose proofBytesHash does not match its bytes',
        (compactCase) => {
            const embedded = embeddedProofMaterialSet(compactCase, 1);
            const tamperedRecords = (
                embedded.proofRecords as readonly JsonRecord[]
            ).map((proofRecord) => ({
                ...proofRecord,
                proofBytesHash: 'd'.repeat(128),
            }));

            expect(() =>
                compactCase.moveEmbeddedToTransport({
                    ...embedded,
                    proofRecords: tamperedRecords,
                }),
            ).toThrow(/proofBytesHash must match proofBytesBase64/u);
        },
    );
});

describe('compact VSS proof material streaming through the kernel', () => {
    it.each(proofMaterialCases)(
        'accepts a streamed $proofFamily transported material set and rejects a tampered chunk hash',
        async (compactCase) => {
            const kernel = await loadPublicTranscriptCoreKernel();

            const embedded = embeddedProofMaterialSet(compactCase, 1);
            const moved = compactCase.moveEmbeddedToTransport(embedded);
            const transportMaterial = (
                moved.transportedProofMaterialSet
                    .proofMaterials as readonly JsonRecord[]
            )[0];

            const { chunks: transportChunks, ...transportReference } =
                transportMaterial;
            const verificationId = `compact-stream-${compactCase.proofFamily}`;
            kernel.beginSetupProofMaterialTransportStream({
                verificationId,
                transportedSetupProofMaterial: transportReference,
            });
            for (const chunk of transportChunks as readonly JsonRecord[]) {
                kernel.absorbSetupProofMaterialTransportStreamChunk({
                    verificationId,
                    chunkIndex: chunk.chunkIndex as number,
                    bytesHex: chunk.bytesHex as string,
                });
            }
            const verification = kernel.finishSetupProofMaterialTransportStream(
                {
                    verificationId,
                },
            ) as unknown as JsonRecord;

            expect(verification.proofFamily).toBe(compactCase.proofFamily);
            expect(verification.proofBytesEncoding).toBe(
                'binary-chunked-proof-bytes',
            );
            expect(verification.proofMaterialRoot).toBe(
                transportMaterial.proofMaterialRoot,
            );
            const verifiedHandle =
                verification.verifiedSetupProofMaterial as JsonRecord;
            expect(verifiedHandle.proofFamily).toBe(compactCase.proofFamily);
            expect(verifiedHandle.proofMaterialRoot).toBe(
                transportMaterial.proofMaterialRoot,
            );

            // Tampering a declared chunk hash must be rejected: the declared
            // chunkHashes no longer reproduce the declared chunkRoot, and the
            // absorbed chunk bytes no longer reproduce the declared chunk hash,
            // so the kernel refuses the transported material somewhere in the
            // begin/absorb/finish sequence.
            const tamperedReference = {
                ...transportReference,
                chunkHashes: ['0'.repeat(128)],
            };
            const tamperedVerificationId = `compact-stream-tampered-${compactCase.proofFamily}`;
            const streamTamperedMaterial = (): void => {
                kernel.beginSetupProofMaterialTransportStream({
                    verificationId: tamperedVerificationId,
                    transportedSetupProofMaterial: tamperedReference,
                });
                for (const chunk of transportChunks as readonly JsonRecord[]) {
                    kernel.absorbSetupProofMaterialTransportStreamChunk({
                        verificationId: tamperedVerificationId,
                        chunkIndex: chunk.chunkIndex as number,
                        bytesHex: chunk.bytesHex as string,
                    });
                }
                kernel.finishSetupProofMaterialTransportStream({
                    verificationId: tamperedVerificationId,
                });
            };
            expect(streamTamperedMaterial).toThrow();
        },
    );
});
