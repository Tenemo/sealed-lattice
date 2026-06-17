import { describe, expect, it } from 'vitest';

import { hash512Hex, publicSetupApi } from './support.js';

describe('accepted setup public package API in Node', () => {
    it('exposes setup package verification without accepting legacy setup objects', async () => {
        const transportHash = hash512Hex(
            'sealed-lattice/test/setup-verification-vss-transport',
            [new Uint8Array([1, 2, 3, 4])],
        );
        const chunkHash = hash512Hex(
            'sealed-lattice/test/setup-verification-vss-chunk',
            [new Uint8Array([1, 2, 3, 4])],
        );
        const vssMaterialReference = {
            objectType: 'SetupTransportedVssCoefficientCommitmentMaterial',
            objectVersion: 1,
            binaryFormat:
                'sealed-lattice-vss-coefficient-commitment-material-binary-v1',
            chunkSizeBytes: 1_048_576,
            chunkCount: 1,
            totalByteLength: 4,
            fullObjectHash: transportHash,
            chunkHashes: [chunkHash],
            chunkRoot: chunkHash,
        };
        const transportedVssCoefficientCommitmentMaterial = {
            ...vssMaterialReference,
            chunks: [
                {
                    chunkIndex: 0,
                    bytesHex: '01020304',
                },
            ],
        };
        const verifiedVssCoefficientCommitmentMaterial = {
            objectType: 'VerifiedVssCoefficientCommitmentMaterial',
            objectVersion: 1,
            setupProfileId: 'CollectiveBgvSetup-v1',
            verificationId: 'sdk-public-verification-input-test',
            materialBinaryFormat:
                'sealed-lattice-vss-coefficient-commitment-material-binary-v1',
            publicMatrixSeedHash: transportHash,
            vssCoefficientCommitmentRoot: transportHash,
            vssCoefficientCommitmentMaterialRoot: transportHash,
            thresholdShareCommitmentRoot: transportHash,
            transportProfileId:
                'sealed-lattice-setup-binary-chunked-transport-v1',
            transportChunkSizeBytes: 1_048_576,
            transportChunkCount: 1,
            transportTotalByteLength: 4,
            transportFullObjectHash: transportHash,
            transportChunkRoot: chunkHash,
        };
        const setupPackage = {
            objectType: 'SetupPackage',
            objectVersion: 1,
            setupPackageHash: transportHash,
        };

        const verificationInput =
            publicSetupApi.createSetupPackageVerificationInput({
                setupPackage,
                transportedVssCoefficientCommitmentMaterial,
                verifiedVssCoefficientCommitmentMaterial,
            });

        expect(verificationInput.setupPackage).toBe(setupPackage);
        expect(verificationInput.verifiedVssCoefficientCommitmentMaterial).toBe(
            verifiedVssCoefficientCommitmentMaterial,
        );
        expect(
            verificationInput.transportedVssCoefficientCommitmentMaterial,
        ).toEqual(vssMaterialReference);
        expect(
            verificationInput.transportedVssCoefficientCommitmentMaterial,
        ).not.toHaveProperty('chunks');

        const verification = await publicSetupApi.verifySetupPackage({
            setupPackage: {
                objectType: 'BgvPassiveSetupPackage',
                objectVersion: 1,
            },
        });

        expect(verification).toMatchObject({
            ok: false,
            operation: 'verifyCollectiveBgvSetupPackage',
            verifierStatus: 'outsideProfile',
        });
        expect(verification.acceptedSetupHandoff).toBeUndefined();
    });
});
