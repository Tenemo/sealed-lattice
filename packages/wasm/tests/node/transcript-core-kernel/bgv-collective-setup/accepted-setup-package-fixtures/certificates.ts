import { type JsonRecord } from '../setup-fixture-primitives.js';

import { publicPrivateVssEnvelopeCommitmentSet } from './common-randomness.js';

import type {
    BgvCollectiveSetupParametersDescription,
    TranscriptCoreKernel,
} from '#packages/wasm/src/index';

function setupPackageHashInput(setupPackage: JsonRecord): JsonRecord {
    const hashInput: JsonRecord = { ...setupPackage };
    delete hashInput.setupPackageHash;
    hashInput.privateVssEnvelopeCommitments =
        publicPrivateVssEnvelopeCommitmentSet(
            hashInput.privateVssEnvelopeCommitments as JsonRecord,
        );

    return hashInput;
}

export function rebindCollectiveSetupPackageHash(
    kernel: TranscriptCoreKernel,
    setupPackage: JsonRecord,
): void {
    delete setupPackage.setupPackageHash;
    setupPackage.setupPackageHash = kernel.deriveCanonicalObjectHash({
        value: setupPackageHashInput(setupPackage),
    });
}

export function acceptedSetupTransportCertificate(
    kernel: TranscriptCoreKernel,
    parameters: BgvCollectiveSetupParametersDescription,
): JsonRecord {
    const certificate = {
        objectType: 'SetupTransportCertificate',
        setupParametersHash: parameters.setupParametersHash,
        largeObjectEncoding: 'binary',
        chunking: 'required',
        chunkCount: 0,
        totalByteLength: 0,
        streamVerificationOrder: 'ascending-chunk-index',
        transportedObjects: [],
    };

    return {
        ...certificate,
        setupTransportCertificateHash: kernel.deriveCanonicalObjectHash({
            value: certificate,
        }),
    };
}
