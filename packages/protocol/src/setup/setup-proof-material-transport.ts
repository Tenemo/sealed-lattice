import type { ProtocolHash } from '@sealed-lattice/types';

import type { JsonRecord } from './common-fields.js';

export const setupProofTransportChunkSizeBytes = 1_048_576;

export type CanonicalProofMaterialChunkPull = (input: {
    readonly abortSignal?: AbortSignal;
    readonly chunkIndex: number;
    readonly expectedByteLength: number;
}) => Promise<ArrayBuffer | undefined>;

export type CanonicalProofMaterialChunkSink = (input: {
    readonly abortSignal?: AbortSignal;
    readonly bytes: ArrayBuffer;
    readonly chunkIndex: number;
}) => Promise<void>;

export type CanonicalGeneratedSetupProofMaterial = Readonly<{
    readonly descriptorBytes: Uint8Array;
}>;

export type SetupProofMaterialChunkSource = Readonly<{
    readonly proofMaterialRoot: ProtocolHash;
    readonly pullChunk: CanonicalProofMaterialChunkPull;
}>;

export const setupProofMaterialRecordTransportFields = <
    ProofBytesEncoding extends string,
>(
    proofMaterialRoot: ProtocolHash,
    proofBytesEncoding: ProofBytesEncoding,
): Readonly<
    JsonRecord & {
        readonly proofBytesEncoding: ProofBytesEncoding;
        readonly proofMaterialRoot: ProtocolHash;
    }
> => ({
    proofBytesEncoding,
    proofMaterialRoot,
});

export const setupTransportedProofMaterialFields = (
    proofMaterialRoot: ProtocolHash,
): Readonly<
    JsonRecord & {
        readonly proofMaterialRoot: ProtocolHash;
    }
> => ({
    proofMaterialRoot,
});

export const canonicalGeneratedSetupProofMaterialDescriptor = (
    material: CanonicalGeneratedSetupProofMaterial,
): Uint8Array => {
    if (
        !ArrayBuffer.isView(material.descriptorBytes) ||
        Object.prototype.toString.call(material.descriptorBytes) !==
            '[object Uint8Array]' ||
        material.descriptorBytes.byteLength === 0
    ) {
        throw new TypeError(
            'canonical generated proof material must contain a descriptor.',
        );
    }
    return material.descriptorBytes.slice();
};

export type TransportedSetupProofMaterialSet<
    ObjectType extends string = string,
> = Readonly<
    JsonRecord & {
        readonly objectType: ObjectType;
        readonly proofFamily: string;
        readonly proofMaterials: readonly JsonRecord[];
    }
>;

export const setupProofMaterialReferenceSetForVerificationInput = <
    TransportedSet extends TransportedSetupProofMaterialSet | undefined,
>(
    transportedMaterialSet: TransportedSet,
): TransportedSet => {
    if (transportedMaterialSet === undefined) {
        return transportedMaterialSet;
    }
    let strippedAnyDescriptor = false;
    const proofMaterials = transportedMaterialSet.proofMaterials.map(
        (proofMaterial) => {
            if (
                !Object.prototype.hasOwnProperty.call(
                    proofMaterial,
                    'descriptorBytes',
                ) ||
                typeof proofMaterial.proofMaterialRoot !== 'string'
            ) {
                return proofMaterial;
            }
            const {
                descriptorBytes: omittedDescriptorBytes,
                ...proofMaterialReference
            } = proofMaterial;
            void omittedDescriptorBytes;
            strippedAnyDescriptor = true;

            return proofMaterialReference;
        },
    );

    if (!strippedAnyDescriptor) {
        return transportedMaterialSet;
    }

    return {
        ...transportedMaterialSet,
        proofMaterials,
    };
};
