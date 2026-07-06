import { deriveCanonicalObjectHash, hash512Hex } from '@sealed-lattice/crypto';

import { bytesFromStandardBase64 } from '../proof-byte-encoding.js';
import {
    setupProofMaterialRecordTransportMetadataFields,
    setupProofMaterialReferenceFields,
    setupProofMaterialTransportChunks,
    setupProofMaterialTransportMetadata,
    setupTransportedProofMaterialFields,
    type TransportedSetupProofMaterialSet,
} from '../setup-proof-material-transport.js';

import {
    sameSecretBridgeProofBytesHashDomain,
    sameSecretBridgeProofFamily,
    vssShareLinkageProofBytesHashDomain,
    vssShareLinkageProofFamily,
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
    readonly proofBytesHashDomain: string;
    readonly transportSetObjectType: string;
    readonly transportMaterialObjectType: string;
}>;

// Move every proof record's embedded base64 proof bytes onto the shared
// setup proof-material transport. Each record keeps its identity fields but drops
// proofBytesBase64 for the transport reference fields and a recomputed
// proofRecordRoot, exactly as the kernel verifier rebuilds it, and its proof
// bytes travel as streamable chunks in the returned transported material set.
// The proof material set root is rebound over the rewritten records because it
// canonically binds the per-record proof-bytes encoding. This mirrors the kernel
// fixture move helpers so a transported set verifies identically to the embedded
// set it replaces, while staying small enough for the canonical string encoder
// at production roster sizes.
const moveProofBytesToTransport = (
    proofMaterialSet: JsonRecord,
    parameters: ProofMaterialTransportParameters,
): Readonly<{
    readonly proofMaterialSet: JsonRecord;
    readonly transportedProofMaterialSet: TransportedSetupProofMaterialSet;
}> => {
    const embeddedProofRecords = proofMaterialSet.proofRecords;
    if (!Array.isArray(embeddedProofRecords)) {
        throw new TypeError(
            `${parameters.proofFamily} proof material set proofRecords must be an array.`,
        );
    }

    const transportedProofMaterials: JsonRecord[] = [];
    const transportedProofRecords = embeddedProofRecords.map(
        (proofRecordValue, proofIndex) => {
            const proofRecord = proofRecordValue as JsonRecord;
            const proofBytesBase64 = proofRecord.proofBytesBase64;
            if (
                typeof proofBytesBase64 !== 'string' ||
                proofBytesBase64.length === 0
            ) {
                throw new TypeError(
                    `${parameters.proofFamily} proofRecords.${String(proofIndex)}.proofBytesBase64 must be non-empty.`,
                );
            }
            const proofBytes = bytesFromStandardBase64(
                proofBytesBase64,
                `${parameters.proofFamily} proofRecords.${String(proofIndex)}.proofBytesBase64`,
            );
            const expectedProofBytesHash = hash512Hex(
                parameters.proofBytesHashDomain,
                [proofBytes],
            );
            if (proofRecord.proofBytesHash !== expectedProofBytesHash) {
                throw new Error(
                    `${parameters.proofFamily} proofRecords.${String(proofIndex)}.proofBytesHash must match proofBytesBase64 before transport.`,
                );
            }
            const proofMaterialTransport = setupProofMaterialTransportMetadata(
                parameters.proofFamily,
                proofBytes,
                `${parameters.proofFamily} proofRecords.${String(proofIndex)}.proofBytesBase64 must produce at least one transported chunk.`,
            );
            const proofMaterialRoot = deriveCanonicalObjectHash({
                objectType: 'SetupProofMaterialReference',
                proofFamily: parameters.proofFamily,
                proofBytesHash: proofRecord.proofBytesHash,
                ...setupProofMaterialReferenceFields(proofMaterialTransport),
            });
            transportedProofMaterials.push({
                objectType: parameters.transportMaterialObjectType,
                proofFamily: parameters.proofFamily,
                ...setupTransportedProofMaterialFields(
                    proofMaterialTransport,
                    proofMaterialRoot,
                ),
                chunks: setupProofMaterialTransportChunks(
                    proofMaterialTransport,
                ),
            });

            const {
                proofBytesBase64: omittedProofBytesBase64,
                proofRecordRoot: omittedProofRecordRoot,
                ...proofRecordIdentity
            } = proofRecord;
            void omittedProofBytesBase64;
            void omittedProofRecordRoot;
            const transportedProofRecordWithoutRoot = {
                ...proofRecordIdentity,
                proofBytesEncoding: 'binary-chunked-proof-bytes',
                proofMaterialRoot,
                ...setupProofMaterialRecordTransportMetadataFields(
                    proofMaterialTransport,
                ),
            };

            return {
                ...transportedProofRecordWithoutRoot,
                proofRecordRoot: deriveCanonicalObjectHash(
                    transportedProofRecordWithoutRoot,
                ),
            };
        },
    );

    const {
        proofMaterialSetRoot: omittedProofMaterialSetRoot,
        ...proofMaterialSetIdentity
    } = proofMaterialSet;
    void omittedProofMaterialSetRoot;
    const transportedProofMaterialSetWithoutRoot = {
        ...proofMaterialSetIdentity,
        proofRecords: transportedProofRecords,
    };

    return {
        proofMaterialSet: {
            ...transportedProofMaterialSetWithoutRoot,
            proofMaterialSetRoot: deriveCanonicalObjectHash(
                transportedProofMaterialSetWithoutRoot,
            ),
        },
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

export const createBinaryChunkedVssShareLinkageProofMaterialTransport = (
    proofMaterialSet: JsonRecord,
): BinaryChunkedVssShareLinkageProofMaterialTransport => {
    const moved = moveProofBytesToTransport(proofMaterialSet, {
        proofFamily: vssShareLinkageProofFamily,
        proofBytesHashDomain: vssShareLinkageProofBytesHashDomain,
        transportSetObjectType:
            'SetupTransportedVssShareLinkageProofMaterialSet',
        transportMaterialObjectType:
            'SetupTransportedVssShareLinkageProofMaterial',
    });

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
    proofMaterialSet: JsonRecord,
): BinaryChunkedSameSecretBridgeProofMaterialTransport => {
    const moved = moveProofBytesToTransport(proofMaterialSet, {
        proofFamily: sameSecretBridgeProofFamily,
        proofBytesHashDomain: sameSecretBridgeProofBytesHashDomain,
        transportSetObjectType:
            'SetupTransportedSameSecretBridgeProofMaterialSet',
        transportMaterialObjectType:
            'SetupTransportedSameSecretBridgeProofMaterial',
    });

    return {
        proofMaterialSet: moved.proofMaterialSet,
        transportedSameSecretBridgeProofMaterial:
            moved.transportedProofMaterialSet as TransportedSameSecretBridgeProofMaterialSet,
    };
};
