import { copyCanonicalStreamDescriptor } from '../canonical-stream-descriptor.js';
import type {
    TransportedSetupProofMaterial,
    TransportedSetupProofMaterialSet,
} from '../setup-proof-material-transport.js';

import {
    type GeneratedVssCanonicalProofMaterial,
    type VssSameSecretBridgeProofMaterialBuild,
    type VssShareLinkageProofMaterialBuild,
} from './linkage-and-bridge.js';

type JsonRecord = Record<string, unknown>;

export type TransportedVssShareLinkageProofMaterialSet =
    TransportedSetupProofMaterialSet;

export type TransportedSameSecretBridgeProofMaterialSet =
    TransportedSetupProofMaterialSet;

type ProofMaterialTransportParameters = Readonly<{
    readonly proofDescription: string;
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
    const referencedProofBytesHashes = proofRecords.map(
        (proofRecordValue, proofIndex) => {
            if (
                proofRecordValue === null ||
                typeof proofRecordValue !== 'object'
            ) {
                throw new TypeError(
                    `${parameters.proofDescription} proofRecords.${String(proofIndex)} must be an object.`,
                );
            }
            const proofRecord = proofRecordValue as JsonRecord;
            if (typeof proofRecord.proofBytesHash !== 'string') {
                throw new TypeError(
                    `${parameters.proofDescription} proofRecords.${String(proofIndex)} must carry a proof-bytes hash.`,
                );
            }

            return proofRecord.proofBytesHash;
        },
    );
    if (
        new Set(referencedProofBytesHashes).size !==
            referencedProofBytesHashes.length ||
        canonicalProofMaterials.length !== referencedProofBytesHashes.length
    ) {
        throw new Error(
            `${parameters.proofDescription} canonical proof material must cover every distinct proof record exactly once.`,
        );
    }
    const referencedProofBytesHashSet = new Set(referencedProofBytesHashes);
    const transportedProofMaterials = canonicalProofMaterials.map(
        (proofMaterial): TransportedSetupProofMaterial => {
            if (
                !referencedProofBytesHashSet.delete(
                    proofMaterial.proofBytesHash,
                )
            ) {
                throw new Error(
                    `${parameters.proofDescription} canonical proof material hash must match exactly one proof record.`,
                );
            }

            return {
                proofBytesHash: proofMaterial.proofBytesHash,
                descriptorBytes: copyCanonicalStreamDescriptor(
                    proofMaterial.descriptorBytes,
                    `${parameters.proofDescription} canonical proof material descriptorBytes`,
                ),
            };
        },
    );
    if (referencedProofBytesHashSet.size !== 0) {
        throw new Error(
            `${parameters.proofDescription} canonical proof material is missing a proof record hash.`,
        );
    }

    return {
        proofMaterialSet,
        transportedProofMaterialSet: {
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
        },
    );

    return {
        proofMaterialSet: moved.proofMaterialSet,
        transportedVssShareLinkageProofMaterial:
            moved.transportedProofMaterialSet,
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
        },
    );

    return {
        proofMaterialSet: moved.proofMaterialSet,
        transportedSameSecretBridgeProofMaterial:
            moved.transportedProofMaterialSet,
    };
};
