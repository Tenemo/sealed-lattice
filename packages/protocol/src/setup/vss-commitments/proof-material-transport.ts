import { copyCanonicalStreamDescriptor } from '../canonical-stream-descriptor.js';
import type {
    SetupProofMaterialStream,
    SetupProofMaterialStreamSet,
} from '../setup-proof-material-transport.js';

import {
    type VssSameSecretBridgeProofMaterialBuild,
    type VssShareLinkageProofMaterialBuild,
} from './linkage-and-bridge.js';

type JsonRecord = Record<string, unknown>;

export type TransportedVssShareLinkageProofMaterialSet =
    SetupProofMaterialStreamSet;

export type TransportedSameSecretBridgeProofMaterialSet =
    SetupProofMaterialStreamSet;

type ProofMaterialTransportParameters = Readonly<{
    readonly proofDescription: string;
    readonly usesProofHashArray?: boolean;
}>;

const proofMaterialStreamsToTransport = (
    proofMaterialSet: JsonRecord,
    proofMaterialStreams: readonly SetupProofMaterialStream[],
    parameters: ProofMaterialTransportParameters,
): Readonly<{
    readonly proofMaterialSet: JsonRecord;
    readonly transportedProofMaterialSet: SetupProofMaterialStreamSet;
}> => {
    const proofRecords = proofMaterialSet.proofRecords;
    const proofBytesHashes = proofMaterialSet.proofBytesHashes;
    if (parameters.usesProofHashArray) {
        if (!Array.isArray(proofBytesHashes)) {
            throw new TypeError(
                `${parameters.proofDescription} proof material set proofBytesHashes must be an array.`,
            );
        }
    }
    if (!Array.isArray(proofRecords)) {
        if (!parameters.usesProofHashArray) {
            throw new TypeError(
                `${parameters.proofDescription} proof material set proofRecords must be an array.`,
            );
        }
    }
    const referencedProofBytesHashes = parameters.usesProofHashArray
        ? (proofBytesHashes as unknown[]).map((proofBytesHash, proofIndex) => {
              if (typeof proofBytesHash !== 'string') {
                  throw new TypeError(
                      `${parameters.proofDescription} proofBytesHashes.${String(proofIndex)} must be a proof-bytes hash.`,
                  );
              }
              return proofBytesHash;
          })
        : (proofRecords as unknown[]).map((proofRecordValue, proofIndex) => {
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
          });
    if (
        new Set(referencedProofBytesHashes).size !==
            referencedProofBytesHashes.length ||
        proofMaterialStreams.length !== referencedProofBytesHashes.length
    ) {
        throw new Error(
            `${parameters.proofDescription} proof material streams must cover every distinct proof reference exactly once in canonical order.`,
        );
    }
    const copiedProofMaterialStreams = proofMaterialStreams.map(
        (proofMaterialStream, proofIndex): SetupProofMaterialStream => {
            if (typeof proofMaterialStream.pullChunk !== 'function') {
                throw new TypeError(
                    `${parameters.proofDescription} proofMaterialStreams.${String(proofIndex)}.pullChunk must be a function.`,
                );
            }
            return {
                descriptorBytes: copyCanonicalStreamDescriptor(
                    proofMaterialStream.descriptorBytes,
                    `${parameters.proofDescription} proofMaterialStreams.${String(proofIndex)}.descriptorBytes`,
                ),
                pullChunk: proofMaterialStream.pullChunk,
            };
        },
    );

    return {
        proofMaterialSet,
        transportedProofMaterialSet: {
            proofMaterialStreams: copiedProofMaterialStreams,
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
    const moved = proofMaterialStreamsToTransport(
        build.proofMaterialSet,
        build.proofMaterialStreams,
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
    const moved = proofMaterialStreamsToTransport(
        build.proofMaterialSet,
        build.proofMaterialStreams,
        {
            proofDescription: 'same-secret-bridge',
            usesProofHashArray: true,
        },
    );

    return {
        proofMaterialSet: moved.proofMaterialSet,
        transportedSameSecretBridgeProofMaterial:
            moved.transportedProofMaterialSet,
    };
};
