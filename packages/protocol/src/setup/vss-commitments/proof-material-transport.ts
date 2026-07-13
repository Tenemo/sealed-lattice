import { copyCanonicalStreamDescriptor } from '../canonical-stream-descriptor.js';
import type { TransportedSetupProofMaterialSet } from '../setup-proof-material-transport.js';

import {
    type GeneratedVssCanonicalProofMaterial,
    type VssSameSecretBridgeProofMaterialBuild,
    type VssShareLinkageProofMaterialBuild,
} from './linkage-and-bridge.js';

type JsonRecord = Record<string, unknown>;

export type TransportedVssShareLinkageProofMaterialSet = Readonly<
    TransportedSetupProofMaterialSet & {
        readonly objectType: 'SetupTransportedVssShareLinkageProofMaterialSet';
    }
>;

export type TransportedSameSecretBridgeProofMaterialSet = Readonly<
    TransportedSetupProofMaterialSet & {
        readonly objectType: 'SetupTransportedSameSecretBridgeProofMaterialSet';
    }
>;

type ProofMaterialTransportParameters = Readonly<{
    readonly proofDescription: string;
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
            `${parameters.proofDescription} proof material set proofRecords must be an array.`,
        );
    }
    const referencedRoots = proofRecords.map((proofRecordValue, proofIndex) => {
        if (proofRecordValue === null || typeof proofRecordValue !== 'object') {
            throw new TypeError(
                `${parameters.proofDescription} proofRecords.${String(proofIndex)} must be an object.`,
            );
        }
        const proofRecord = proofRecordValue as JsonRecord;
        if (typeof proofRecord.proofMaterialRoot !== 'string') {
            throw new TypeError(
                `${parameters.proofDescription} proofRecords.${String(proofIndex)} must carry a canonical proof-material reference.`,
            );
        }

        return proofRecord.proofMaterialRoot;
    });
    if (
        new Set(referencedRoots).size !== referencedRoots.length ||
        canonicalProofMaterials.length !== referencedRoots.length
    ) {
        throw new Error(
            `${parameters.proofDescription} canonical proof material must cover every distinct proof record exactly once.`,
        );
    }
    const referencedRootSet = new Set(referencedRoots);
    const transportedProofMaterials = canonicalProofMaterials.map(
        (proofMaterial): JsonRecord => {
            if (!referencedRootSet.delete(proofMaterial.proofMaterialRoot)) {
                throw new Error(
                    `${parameters.proofDescription} canonical proof material root must match exactly one proof record.`,
                );
            }

            return {
                objectType: parameters.transportMaterialObjectType,
                proofMaterialRoot: proofMaterial.proofMaterialRoot,
                descriptorBytes: copyCanonicalStreamDescriptor(
                    proofMaterial.descriptorBytes,
                    `${parameters.proofDescription} canonical proof material descriptorBytes`,
                ),
            };
        },
    );
    if (referencedRootSet.size !== 0) {
        throw new Error(
            `${parameters.proofDescription} canonical proof material is missing a proof record root.`,
        );
    }

    return {
        proofMaterialSet,
        transportedProofMaterialSet: {
            objectType: parameters.transportSetObjectType,
            proofMaterials: transportedProofMaterials,
        },
    };
};

type BinaryChunkedVssShareLinkageProofMaterialTransport = Readonly<{
    readonly proofMaterialSet: JsonRecord;
    readonly transportedVssShareLinkageProofMaterial: TransportedVssShareLinkageProofMaterialSet;
}>;

export const createBinaryChunkedVssShareLinkageProofMaterialTransport = (
    build: VssShareLinkageProofMaterialBuild,
): BinaryChunkedVssShareLinkageProofMaterialTransport => {
    const moved = canonicalProofMaterialsToTransport(
        build.proofMaterialSet,
        build.canonicalProofMaterials,
        {
            proofDescription: 'vss-share-linkage',
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

type BinaryChunkedSameSecretBridgeProofMaterialTransport = Readonly<{
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
            proofDescription: 'same-secret-bridge',
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
