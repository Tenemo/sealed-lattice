import { hash512Hex } from '@sealed-lattice/crypto';
import { describe, expect, it } from 'vitest';

import {
    createBinaryChunkedSameSecretBridgeProofMaterialTransport,
    createBinaryChunkedVssShareLinkageProofMaterialTransport,
} from '#packages/protocol/src/index';
import { canonicalStreamDescriptorFixture } from '#tests/support/canonical-stream-descriptor-fixture';

type JsonRecord = Record<string, unknown>;

type CanonicalProofMaterialBuild = Readonly<{
    readonly proofMaterialSet: JsonRecord;
    readonly proofMaterialStreams: readonly Readonly<{
        readonly descriptorBytes: Uint8Array;
        readonly pullChunk: (input: {
            readonly chunkIndex: number;
            readonly expectedByteLength: number;
        }) => Promise<ArrayBuffer | undefined>;
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
    readonly proofBytesHashDomain: string;
    readonly usesProofHashArray: boolean;
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
        proofBytesHashDomain:
            'sealed-lattice/setup/vss-share-linkage/proof-bytes',
        usesProofHashArray: false,
        identityFields: (recordIndex: number): JsonRecord => ({
            coverage: [
                {
                    sourceTrusteeRosterPosition: 0,
                    recipientRosterPosition: recordIndex,
                    sourceRnsLimbIndex: 0,
                },
            ],
        }),
        createTransport: (build) => {
            const transport =
                createBinaryChunkedVssShareLinkageProofMaterialTransport(
                    build as unknown as Parameters<
                        typeof createBinaryChunkedVssShareLinkageProofMaterialTransport
                    >[0],
                );

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
        proofBytesHashDomain:
            'sealed-lattice/setup/same-secret-bridge/proof-bytes',
        usesProofHashArray: true,
        identityFields: (): JsonRecord => ({}),
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
    const proofMaterialStreams: CanonicalProofMaterialBuild['proofMaterialStreams'][number][] =
        [];
    const proofRecords = descriptors.map((descriptorBytes, recordIndex) => {
        const proofBytes = Uint8Array.of(recordIndex, 0x11, 0x22, 0x33, 0x44);
        const proofBytesHash = hash512Hex(
            proofMaterialCase.proofBytesHashDomain,
            [proofBytes],
        );
        const proofRecord = {
            objectType: proofMaterialCase.proofRecordObjectType,
            ...proofMaterialCase.identityFields(recordIndex),
            proofBytesHash,
        };
        proofMaterialStreams.push({
            descriptorBytes,
            pullChunk: ({ chunkIndex, expectedByteLength }) =>
                Promise.resolve(
                    chunkIndex === 0 &&
                        expectedByteLength === proofBytes.byteLength
                        ? Uint8Array.from(proofBytes).buffer
                        : undefined,
                ),
        });

        return proofRecord;
    });
    const proofMaterialSet: JsonRecord = {
        objectType: proofMaterialCase.proofMaterialSetObjectType,
    };
    if (proofMaterialCase.usesProofHashArray) {
        proofMaterialSet.proofBytesHashes = proofRecords.map(
            (proofRecord) => proofRecord.proofBytesHash,
        );
    } else {
        proofMaterialSet.proofRecords = proofRecords;
    }
    return {
        proofMaterialSet,
        proofMaterialStreams,
    };
};

describe('VSS canonical proof material transport', () => {
    it.each(proofMaterialCases)(
        'pairs $proofFamily references with canonical proof streams',
        (proofMaterialCase) => {
            const build = canonicalProofMaterialBuild(proofMaterialCase, [
                canonicalStreamDescriptorFixture(3, 1),
                canonicalStreamDescriptorFixture(3, 4),
            ]);
            const transported = proofMaterialCase.createTransport(build);

            expect(transported.proofMaterialSet).toBe(build.proofMaterialSet);
            const transportedProofMaterialStreams = transported
                .transportedProofMaterialSet
                .proofMaterialStreams as readonly JsonRecord[];
            expect(transportedProofMaterialStreams).toHaveLength(2);
            transportedProofMaterialStreams.forEach((stream, streamIndex) => {
                const expectedStream = build.proofMaterialStreams[streamIndex];
                expect(stream.descriptorBytes).toEqual(
                    expectedStream?.descriptorBytes,
                );
                expect(stream.descriptorBytes).not.toBe(
                    expectedStream?.descriptorBytes,
                );
                expect(stream.pullChunk).toBe(expectedStream?.pullChunk);
            });
        },
    );

    it.each(proofMaterialCases)(
        'rejects $proofFamily streams that do not cover every proof reference',
        (proofMaterialCase) => {
            const build = canonicalProofMaterialBuild(proofMaterialCase, [
                Uint8Array.of(1),
            ]);

            expect(() =>
                proofMaterialCase.createTransport({
                    ...build,
                    proofMaterialStreams: [],
                }),
            ).toThrow(/exactly once in canonical order/u);
        },
    );
});
