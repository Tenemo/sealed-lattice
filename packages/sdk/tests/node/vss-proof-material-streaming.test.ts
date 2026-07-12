import { describe, expect, it } from 'vitest';

import { loadPublicTranscriptCoreKernel } from './accepted-setup-public-api/support.js';

import {
    deriveCanonicalObjectHash,
    hash512Hex,
} from '#packages/crypto/src/index';
import {
    createBinaryChunkedSameSecretBridgeProofMaterialTransport,
    createBinaryChunkedVssShareLinkageProofMaterialTransport,
} from '#packages/protocol/src/index';
import {
    canonicalStreamDomains,
    openCanonicalStreamWorkerRuntime,
    type CanonicalStreamDomain,
} from '#packages/wasm/src/canonical-stream-runtime';
import {
    bgvCanonicalStreamFamilies,
    openBgvCanonicalStreamRuntime,
} from '#packages/wasm/src/index';

type JsonRecord = Record<string, unknown>;

type CanonicalProofMaterialBuild = Readonly<{
    readonly proofMaterialSet: JsonRecord;
    readonly canonicalProofMaterials: readonly Readonly<{
        readonly proofMaterialRoot: string;
        readonly descriptorBytes: Uint8Array;
        readonly chunks: readonly Readonly<{
            readonly chunkIndex: number;
            readonly bytes: ArrayBuffer;
        }>[];
    }>[];
}>;

type ProofMaterialCase = Readonly<{
    readonly proofFamily: 'vss-share-linkage' | 'same-secret-bridge';
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
    readonly proofRecordRootField:
        | 'proofRecordRoot'
        | 'sameSecretBridgeProofRecordRoot';
    readonly runtimeFamily: number;
    readonly streamDomain: CanonicalStreamDomain;
    readonly identityFields: (recordIndex: number) => JsonRecord;
    readonly createTransport: (build: CanonicalProofMaterialBuild) => Readonly<{
        readonly proofMaterialSet: JsonRecord;
        readonly transportedProofMaterialSet: JsonRecord;
    }>;
}>;

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
            'sealed-lattice/setup/vss-share-linkage/proof-bytes',
        proofRecordRootField: 'proofRecordRoot',
        runtimeFamily: bgvCanonicalStreamFamilies.vssShareLinkage,
        streamDomain: canonicalStreamDomains.dealerVssShareLinkageProof,
        identityFields: (recordIndex: number): JsonRecord => ({
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
        }),
        createTransport: (build) => {
            const transport =
                createBinaryChunkedVssShareLinkageProofMaterialTransport(build);

            return {
                proofMaterialSet: transport.proofMaterialSet,
                transportedProofMaterialSet:
                    transport.transportedVssShareLinkageProofMaterial,
            };
        },
    },
    {
        proofFamily: 'same-secret-bridge',
        proofRecordObjectType: 'VssSameSecretBridgeProofRecord',
        proofMaterialSetObjectType: 'VssSameSecretBridgeProofMaterialSet',
        transportSetObjectType:
            'SetupTransportedSameSecretBridgeProofMaterialSet',
        transportMaterialObjectType:
            'SetupTransportedSameSecretBridgeProofMaterial',
        proofBytesHashDomain:
            'sealed-lattice/setup/same-secret-bridge/proof-bytes',
        proofRecordRootField: 'sameSecretBridgeProofRecordRoot',
        runtimeFamily: bgvCanonicalStreamFamilies.sameSecretBridge,
        streamDomain: canonicalStreamDomains.sameSecretProof,
        identityFields: (recordIndex: number): JsonRecord => ({
            sameSecretBridgeStatementRoot: `${String(recordIndex)}`.padStart(
                128,
                'c',
            ),
        }),
        createTransport: (build) => {
            const transport =
                createBinaryChunkedSameSecretBridgeProofMaterialTransport(
                    build as unknown as Parameters<
                        typeof createBinaryChunkedSameSecretBridgeProofMaterialTransport
                    >[0],
                );

            return {
                proofMaterialSet: transport.proofMaterialSet,
                transportedProofMaterialSet:
                    transport.transportedSameSecretBridgeProofMaterial,
            };
        },
    },
] as const satisfies readonly ProofMaterialCase[];

const canonicalProofMaterialBuild = (
    proofMaterialCase: ProofMaterialCase,
    descriptors: readonly Uint8Array[],
): CanonicalProofMaterialBuild => {
    const canonicalProofMaterials: CanonicalProofMaterialBuild['canonicalProofMaterials'][number][] =
        [];
    const proofRecords = descriptors.map((descriptorBytes, recordIndex) => {
        const proofBytes = Uint8Array.of(recordIndex, 0x11, 0x22, 0x33, 0x44);
        const proofBytesHash = hash512Hex(
            proofMaterialCase.proofBytesHashDomain,
            [proofBytes],
        );
        const proofMaterialRoot = deriveCanonicalObjectHash({
            objectType: 'SetupProofMaterialReference',
            proofFamily: proofMaterialCase.proofFamily,
            proofBytesHash,
        });
        const recordWithoutRoot = {
            objectType: proofMaterialCase.proofRecordObjectType,
            proofFamily: proofMaterialCase.proofFamily,
            ...proofMaterialCase.identityFields(recordIndex),
            proofBytesHash,
            proofBytesEncoding: 'binary-chunked-proof-bytes',
            proofMaterialRoot,
        };
        canonicalProofMaterials.push({
            proofMaterialRoot,
            descriptorBytes,
            chunks: [{ chunkIndex: 0, bytes: proofBytes.buffer }],
        });

        return {
            ...recordWithoutRoot,
            [proofMaterialCase.proofRecordRootField]:
                deriveCanonicalObjectHash(recordWithoutRoot),
        };
    });
    const proofMaterialSetWithoutRoot = {
        objectType: proofMaterialCase.proofMaterialSetObjectType,
        proofFamily: proofMaterialCase.proofFamily,
        proofRecords,
    };

    return {
        proofMaterialSet: {
            ...proofMaterialSetWithoutRoot,
            proofMaterialSetRoot: deriveCanonicalObjectHash(
                proofMaterialSetWithoutRoot,
            ),
        },
        canonicalProofMaterials,
    };
};

describe('VSS canonical proof material transport', () => {
    it.each(proofMaterialCases)(
        'maps $proofFamily semantic references to descriptor and binary-chunk sidecars',
        (proofMaterialCase) => {
            const build = canonicalProofMaterialBuild(proofMaterialCase, [
                Uint8Array.of(1, 2, 3),
                Uint8Array.of(4, 5, 6),
            ]);
            const transported = proofMaterialCase.createTransport(build);

            expect(transported.proofMaterialSet).toBe(build.proofMaterialSet);
            expect(transported.transportedProofMaterialSet.objectType).toBe(
                proofMaterialCase.transportSetObjectType,
            );
            const transportedProofMaterials = transported
                .transportedProofMaterialSet
                .proofMaterials as readonly JsonRecord[];
            expect(transportedProofMaterials).toHaveLength(2);
            transportedProofMaterials.forEach((material, materialIndex) => {
                const expectedMaterial =
                    build.canonicalProofMaterials[materialIndex];
                expect(material.objectType).toBe(
                    proofMaterialCase.transportMaterialObjectType,
                );
                expect(material.proofMaterialRoot).toBe(
                    expectedMaterial?.proofMaterialRoot,
                );
                expect(material.descriptorBytes).toEqual(
                    expectedMaterial?.descriptorBytes,
                );
                const chunks = material.chunks as readonly Readonly<{
                    readonly chunkIndex: number;
                    readonly bytes: ArrayBuffer;
                }>[];
                expect(chunks[0]?.chunkIndex).toBe(0);
                expect([...new Uint8Array(chunks[0].bytes)]).toEqual([
                    materialIndex,
                    0x11,
                    0x22,
                    0x33,
                    0x44,
                ]);
            });
        },
    );

    it.each(proofMaterialCases)(
        'rejects $proofFamily canonical material whose root does not match a proof record',
        (proofMaterialCase) => {
            const build = canonicalProofMaterialBuild(proofMaterialCase, [
                Uint8Array.of(1),
            ]);

            expect(() =>
                proofMaterialCase.createTransport({
                    ...build,
                    canonicalProofMaterials: [
                        {
                            ...build.canonicalProofMaterials[0],
                            proofMaterialRoot: 'd'.repeat(128),
                        },
                    ],
                }),
            ).toThrow(/must match exactly one proof record/u);
        },
    );
});

describe('VSS canonical proof material streaming through the kernel', () => {
    it.each(proofMaterialCases)(
        'authenticates the supplied $proofFamily descriptor and chunks',
        async (proofMaterialCase) => {
            const kernel = await loadPublicTranscriptCoreKernel();
            const chunk = Uint8Array.of(0, 0x11, 0x22, 0x33, 0x44).buffer;
            const writer = openCanonicalStreamWorkerRuntime({
                kernel,
            }).openWriter({
                streamDomain: proofMaterialCase.streamDomain,
                totalByteLength: chunk.byteLength,
            });
            writer.absorbChunk(0, chunk);
            const descriptorBytes = writer.finish();
            const build = canonicalProofMaterialBuild(proofMaterialCase, [
                descriptorBytes,
            ]);
            const transported = proofMaterialCase.createTransport(build);
            const material = (
                transported.transportedProofMaterialSet
                    .proofMaterials as readonly JsonRecord[]
            )[0];
            const chunks = material.chunks as readonly Readonly<{
                readonly chunkIndex: number;
                readonly bytes: ArrayBuffer;
            }>[];
            const verifier = openBgvCanonicalStreamRuntime({
                kernel,
            }).openVerifier({
                descriptorBytes: material.descriptorBytes as Uint8Array,
                family: proofMaterialCase.runtimeFamily,
                materialRoot: material.proofMaterialRoot as string,
            });
            chunks.forEach((transportChunk) => {
                verifier.absorbChunk(
                    transportChunk.chunkIndex,
                    transportChunk.bytes,
                );
            });
            verifier.finish();

            expect(verifier.state()).toBe('completed');
        },
    );
});
