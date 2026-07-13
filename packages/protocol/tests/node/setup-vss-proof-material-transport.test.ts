import { deriveCanonicalObjectHash, hash512Hex } from '@sealed-lattice/crypto';
import { describe, expect, it } from 'vitest';

import {
    createBinaryChunkedSameSecretBridgeProofMaterialTransport,
    createBinaryChunkedVssShareLinkageProofMaterialTransport,
} from '#packages/protocol/src/index';
import { canonicalStreamDescriptorFixture } from '#tests/support/canonical-stream-descriptor-fixture';

type JsonRecord = Record<string, unknown>;

type CanonicalProofMaterialBuild = Readonly<{
    readonly proofMaterialSet: JsonRecord;
    readonly canonicalProofMaterials: readonly Readonly<{
        readonly proofMaterialRoot: string;
        readonly descriptorBytes: Uint8Array;
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
        identityFields: (recordIndex: number): JsonRecord => ({
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
            ...proofMaterialCase.identityFields(recordIndex),
            proofBytesHash,
            proofMaterialRoot,
        };
        canonicalProofMaterials.push({
            proofMaterialRoot,
            descriptorBytes,
        });

        return {
            ...recordWithoutRoot,
            [proofMaterialCase.proofRecordRootField]:
                deriveCanonicalObjectHash(recordWithoutRoot),
        };
    });
    const proofMaterialSetWithoutRoot = {
        objectType: proofMaterialCase.proofMaterialSetObjectType,
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
        'maps $proofFamily semantic references to descriptor sidecars',
        (proofMaterialCase) => {
            const build = canonicalProofMaterialBuild(proofMaterialCase, [
                canonicalStreamDescriptorFixture(3, 1, 2),
                canonicalStreamDescriptorFixture(3, 4, 5),
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
