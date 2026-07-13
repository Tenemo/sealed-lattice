import { describe, expect, it } from 'vitest';

import { createSetupCertificates } from '#packages/protocol/src/index';
import { loadTranscriptCoreKernel } from '#packages/wasm/src/index';

describe('setup transport certificate conformance', () => {
    it('matches the Rust transport profile and canonical hash', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const setupParameters = kernel.describeCollectiveBgvSetupParameters({
            participantCount: 3,
        });
        const { setupTransportCertificate } = createSetupCertificates({
            setupParameters,
            bgvParameters: kernel.describeBgvRnsParameters(),
            transport: { transportedObjects: [] },
        });
        const {
            setupTransportCertificateHash,
            ...setupTransportCertificateBody
        } = setupTransportCertificate;

        expect(setupTransportCertificate).toMatchObject({
            objectType: 'SetupTransportCertificate',
            setupParametersHash: setupParameters.setupParametersHash,
            largeObjectEncoding:
                setupParameters.setupTransport.largeObjectEncoding,
            chunking: setupParameters.setupTransport.chunking,
            streamVerificationOrder:
                setupParameters.setupTransport.streamVerificationOrder,
            chunkCount: 0,
            totalByteLength: 0,
            transportedObjects: [],
        });
        expect(
            kernel.deriveCanonicalObjectHash({
                value: setupTransportCertificateBody,
            }),
        ).toBe(setupTransportCertificateHash);
    });
});
