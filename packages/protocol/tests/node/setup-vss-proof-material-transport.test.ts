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
    readonly canonicalProofMaterials: readonly Readonly<{
        readonly proofBytesHash: string;
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
    readonly proofBytesHashDomain: string;
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
        identityFields: (recordIndex: number): JsonRecord => ({
            coverage: [{
                sourceTrusteeRosterPosition: 0,
                recipientRosterPosition: recordIndex,
                sourceRnsLimbIndex: 0,
            }],
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
    const canonicalProofMaterials: CanonicalProofMaterialBuild['canonicalProofMaterials'][number][] =
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
        canonicalProofMaterials.push({
            proofBytesHash,
            descriptorBytes,
        });

        return proofRecord;
    });
    return {
        proofMaterialSet: {
            objectType: proofMaterialCase.proofMaterialSetObjectType,
            proofRecords,
        },
        canonicalProofMaterials,
    };
};

describe('VSS canonical proof material transport', () => {
    it.each(proofMaterialCases)(
        'maps $proofFamily semantic references to descriptor sidecars',
        (proofMaterialCase) => {
            const build = canonicalProofMaterialBuild(proofMaterialCase, [
                canonicalStreamDescriptorFixture(3, 1),
                canonicalStreamDescriptorFixture(3, 4),
            ]);
            const transported = proofMaterialCase.createTransport(build);

            expect(transported.proofMaterialSet).toBe(build.proofMaterialSet);
            const transportedProofMaterials = transported
                .transportedProofMaterialSet
                .proofMaterials as readonly JsonRecord[];
            expect(transportedProofMaterials).toHaveLength(2);
            transportedProofMaterials.forEach((material, materialIndex) => {
                const expectedMaterial =
                    build.canonicalProofMaterials[materialIndex];
                expect(material.proofBytesHash).toBe(
                    expectedMaterial?.proofBytesHash,
                );
                expect(material.descriptorBytes).toEqual(
                    expectedMaterial?.descriptorBytes,
                );
            });
        },
    );

    it.each(proofMaterialCases)(
        'rejects $proofFamily canonical material whose hash does not match a proof record',
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
                            proofBytesHash: 'd'.repeat(128),
                        },
                    ],
                }),
            ).toThrow(/must match exactly one proof record/u);
        },
    );
});
