import { copyCanonicalStreamDescriptor } from '../canonical-stream-descriptor.js';
import type { TransportedSetupProofMaterialSet } from '../setup-proof-material-transport.js';

import type { VssAggregateThresholdProofMaterial } from './commitment-sets.js';
import {
    sameSecretBridgeProofFamily,
    vssShareLinkageProofFamily,
    type GeneratedVssCanonicalProofMaterial,
    type VssSameSecretBridgeProofMaterialBuild,
    type VssShareLinkageProofMaterialBuild,
} from './linkage-and-bridge.js';

type JsonRecord = Record<string, unknown>;

export type TransportedVssShareLinkageProofMaterialSet = Readonly<
    TransportedSetupProofMaterialSet & {
        readonly objectType: 'SetupTransportedVssShareLinkageProofMaterialSet';
        readonly proofFamily: typeof vssShareLinkageProofFamily;
    }
>;

export type TransportedSameSecretBridgeProofMaterialSet = Readonly<
    TransportedSetupProofMaterialSet & {
        readonly objectType: 'SetupTransportedSameSecretBridgeProofMaterialSet';
        readonly proofFamily: typeof sameSecretBridgeProofFamily;
    }
>;

type ProofMaterialTransportParameters = Readonly<{
    readonly proofFamily: string;
    readonly transportSetObjectType: string;
    readonly transportMaterialObjectType: string;
}>;

const canonicalProofMaterialsToTransport = (
    proofMaterialSet: JsonRecord,
    canonicalProofMaterials: readonly GeneratedVssCanonicalProofMaterial[],
    parameters: ProofMaterialTransportParameters,
): Readonly<{
    readonly proofMaterialSet: JsonRecord;
    readonly transportedProofMaterialSet: TransportedSetupProofMaterialSet;
}> => {
    const proofRecords = proofMaterialSet.proofRecords;
    if (!Array.isArray(proofRecords)) {
        throw new TypeError(
            `${parameters.proofFamily} proof material set proofRecords must be an array.`,
        );
    }
    const referencedRoots = proofRecords.map((proofRecordValue, proofIndex) => {
        if (proofRecordValue === null || typeof proofRecordValue !== 'object') {
            throw new TypeError(
                `${parameters.proofFamily} proofRecords.${String(proofIndex)} must be an object.`,
            );
        }
        const proofRecord = proofRecordValue as JsonRecord;
        if (typeof proofRecord.proofMaterialRoot !== 'string') {
            throw new TypeError(
                `${parameters.proofFamily} proofRecords.${String(proofIndex)} must carry a canonical proof-material reference.`,
            );
        }

        return proofRecord.proofMaterialRoot;
    });
    if (
        new Set(referencedRoots).size !== referencedRoots.length ||
        canonicalProofMaterials.length !== referencedRoots.length
    ) {
        throw new Error(
            `${parameters.proofFamily} canonical proof material must cover every distinct proof record exactly once.`,
        );
    }
    const referencedRootSet = new Set(referencedRoots);
    const transportedProofMaterials = canonicalProofMaterials.map(
        (proofMaterial): JsonRecord => {
            if (!referencedRootSet.delete(proofMaterial.proofMaterialRoot)) {
                throw new Error(
                    `${parameters.proofFamily} canonical proof material root must match exactly one proof record.`,
                );
            }

            return {
                objectType: parameters.transportMaterialObjectType,
                proofFamily: parameters.proofFamily,
                proofMaterialRoot: proofMaterial.proofMaterialRoot,
                descriptorBytes: copyCanonicalStreamDescriptor(
                    proofMaterial.descriptorBytes,
                    `${parameters.proofFamily} canonical proof material descriptorBytes`,
                ),
            };
        },
    );
    if (referencedRootSet.size !== 0) {
        throw new Error(
            `${parameters.proofFamily} canonical proof material is missing a proof record root.`,
        );
    }

    return {
        proofMaterialSet,
        transportedProofMaterialSet: {
            objectType: parameters.transportSetObjectType,
            proofFamily: parameters.proofFamily,
            proofMaterials: transportedProofMaterials,
        },
    };
};

export type BinaryChunkedVssShareLinkageProofMaterialTransport = Readonly<{
    readonly proofMaterialSet: JsonRecord;
    readonly transportedVssShareLinkageProofMaterial: TransportedVssShareLinkageProofMaterialSet;
}>;

// Aggregate-threshold proofs use the same share-linkage proof family and
// canonical transport set as the ordinary linkage proofs. Their local builder
// already receives the external descriptor from the WASM material writer, so
// merge those references without decoding or rebuilding the proof.
export const appendVssAggregateThresholdProofMaterials = (
    transportedProofMaterialSet: TransportedVssShareLinkageProofMaterialSet,
    aggregateThresholdProofMaterials: readonly VssAggregateThresholdProofMaterial[],
): TransportedVssShareLinkageProofMaterialSet => {
    if (
        transportedProofMaterialSet.objectType !==
            'SetupTransportedVssShareLinkageProofMaterialSet' ||
        transportedProofMaterialSet.proofFamily !== vssShareLinkageProofFamily
    ) {
        throw new TypeError(
            'Aggregate threshold proof materials require the VSS share-linkage transport set.',
        );
    }

    const materialRoots = new Set<string>();
    transportedProofMaterialSet.proofMaterials.forEach((material) => {
        if (typeof material.proofMaterialRoot !== 'string') {
            throw new TypeError(
                'A VSS share-linkage transported material must carry proofMaterialRoot.',
            );
        }
        if (materialRoots.has(material.proofMaterialRoot)) {
            throw new Error(
                'VSS share-linkage transported material roots must be unique.',
            );
        }
        materialRoots.add(material.proofMaterialRoot);
    });

    const appendedMaterials = aggregateThresholdProofMaterials.map(
        (material): JsonRecord => {
            if (
                material.objectType !==
                    'SetupTransportedVssShareLinkageProofMaterial' ||
                material.proofFamily !== vssShareLinkageProofFamily ||
                materialRoots.has(material.proofMaterialRoot)
            ) {
                throw new Error(
                    'Aggregate threshold proof material must be a unique VSS share-linkage transport entry.',
                );
            }
            materialRoots.add(material.proofMaterialRoot);

            return {
                objectType: material.objectType,
                proofFamily: material.proofFamily,
                proofMaterialRoot: material.proofMaterialRoot,
                descriptorBytes: copyCanonicalStreamDescriptor(
                    material.descriptorBytes,
                    'VSS aggregate threshold proof material descriptorBytes',
                ),
            };
        },
    );

    return {
        ...transportedProofMaterialSet,
        proofMaterials: [
            ...transportedProofMaterialSet.proofMaterials,
            ...appendedMaterials,
        ],
    };
};

export const createBinaryChunkedVssShareLinkageProofMaterialTransport = (
    build: VssShareLinkageProofMaterialBuild,
): BinaryChunkedVssShareLinkageProofMaterialTransport => {
    const moved = canonicalProofMaterialsToTransport(
        build.proofMaterialSet,
        build.canonicalProofMaterials,
        {
            proofFamily: vssShareLinkageProofFamily,
            transportSetObjectType:
                'SetupTransportedVssShareLinkageProofMaterialSet',
            transportMaterialObjectType:
                'SetupTransportedVssShareLinkageProofMaterial',
        },
    );

    return {
        proofMaterialSet: moved.proofMaterialSet,
        transportedVssShareLinkageProofMaterial:
            moved.transportedProofMaterialSet as TransportedVssShareLinkageProofMaterialSet,
    };
};

export type BinaryChunkedSameSecretBridgeProofMaterialTransport = Readonly<{
    readonly proofMaterialSet: JsonRecord;
    readonly transportedSameSecretBridgeProofMaterial: TransportedSameSecretBridgeProofMaterialSet;
}>;

export const createBinaryChunkedSameSecretBridgeProofMaterialTransport = (
    build: VssSameSecretBridgeProofMaterialBuild,
): BinaryChunkedSameSecretBridgeProofMaterialTransport => {
    const moved = canonicalProofMaterialsToTransport(
        build.proofMaterialSet,
        build.canonicalProofMaterials,
        {
            proofFamily: sameSecretBridgeProofFamily,
            transportSetObjectType:
                'SetupTransportedSameSecretBridgeProofMaterialSet',
            transportMaterialObjectType:
                'SetupTransportedSameSecretBridgeProofMaterial',
        },
    );

    return {
        proofMaterialSet: moved.proofMaterialSet,
        transportedSameSecretBridgeProofMaterial:
            moved.transportedProofMaterialSet as TransportedSameSecretBridgeProofMaterialSet,
    };
};
