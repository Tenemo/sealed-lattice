import { hash512Hex } from '@sealed-lattice/crypto';
import { describe, expect, it } from 'vitest';

import type { CompactVssShareLinkageBinaryProofMaterialTransport } from '#packages/protocol/src/setup/compact-vss-commitments';
import {
    createSetupPackageVerificationInput,
    type SetupPackage,
    type SetupPackageInput,
} from '#packages/protocol/src/setup/setup-package-assembly';
import { setupCertificateTransportedObjectsFromPackageInput } from '#packages/protocol/src/setup/setup-package-assembly/transported-material';

const compactTransportHash = (label: string): string =>
    hash512Hex('sealed-lattice/test/compact-vss-share-linkage-transport', [
        new TextEncoder().encode(label),
    ]);

const compactShareLinkageProofMaterialTransport =
    (): CompactVssShareLinkageBinaryProofMaterialTransport => ({
        objectType: 'CompactVssShareLinkageBinaryProofMaterialTransport',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        profileId: 'sealed-lattice-compact-vss-sparse-linear-v1',
        proofFamily: 'compact-vss-share-linkage',
        binaryFormat: 'compact-vss-share-linkage-proof-material-binary-v1',
        proofMaterialSetRoot: compactTransportHash('proof-material-set'),
        shareLinkageStatementRoot: compactTransportHash('statement'),
        chunkSizeBytes: 1_048_576,
        chunkCount: 2,
        totalByteLength: 5,
        fullObjectHash: compactTransportHash('full-object'),
        chunkRoot: compactTransportHash('chunk-root'),
        chunkHashes: [
            compactTransportHash('chunk-0'),
            compactTransportHash('chunk-1'),
        ],
        chunks: [Uint8Array.from([1, 2, 3]), Uint8Array.from([4, 5])],
    });

describe('setup package compact VSS transport companions', () => {
    it('binds compact share-linkage proof material in setup transport accounting', () => {
        const transportedCompactVssShareLinkageProofMaterial =
            compactShareLinkageProofMaterialTransport();

        expect(
            setupCertificateTransportedObjectsFromPackageInput({
                transportedCompactVssShareLinkageProofMaterial,
            } as unknown as SetupPackageInput),
        ).toEqual([
            {
                objectName: 'compactVssShareLinkageProofMaterial',
                objectRole: 'compact-vss-share-linkage-proof-material',
                objectRoot:
                    transportedCompactVssShareLinkageProofMaterial.proofMaterialSetRoot,
                byteLength:
                    transportedCompactVssShareLinkageProofMaterial.totalByteLength,
                fullObjectHash:
                    transportedCompactVssShareLinkageProofMaterial.fullObjectHash,
                chunkRoot:
                    transportedCompactVssShareLinkageProofMaterial.chunkRoot,
                chunkHashes:
                    transportedCompactVssShareLinkageProofMaterial.chunkHashes,
            },
        ]);

        expect(() =>
            setupCertificateTransportedObjectsFromPackageInput({
                transportedCompactVssShareLinkageProofMaterial: {
                    ...transportedCompactVssShareLinkageProofMaterial,
                    chunkHashes: [
                        transportedCompactVssShareLinkageProofMaterial
                            .chunkHashes[0],
                        'not-a-protocol-hash',
                    ],
                },
            } as unknown as SetupPackageInput),
        ).toThrow(/chunkHashes/u);
    });

    it('keeps compact share-linkage proof material chunks out of verifier input', () => {
        const transportedCompactVssShareLinkageProofMaterial =
            compactShareLinkageProofMaterialTransport();
        const setupPackage = {
            objectType: 'SetupPackage',
            objectVersion: 1,
            setupProfileId: 'CollectiveBgvSetup-v1',
            setupPackageHash: compactTransportHash('setup-package'),
        } as unknown as SetupPackage;

        const verificationInput = createSetupPackageVerificationInput({
            setupPackage,
            transportedCompactVssShareLinkageProofMaterial,
        });

        expect(
            verificationInput.transportedCompactVssShareLinkageProofMaterial,
        ).toEqual({
            objectType:
                transportedCompactVssShareLinkageProofMaterial.objectType,
            objectVersion:
                transportedCompactVssShareLinkageProofMaterial.objectVersion,
            setupProfileId:
                transportedCompactVssShareLinkageProofMaterial.setupProfileId,
            profileId: transportedCompactVssShareLinkageProofMaterial.profileId,
            proofFamily:
                transportedCompactVssShareLinkageProofMaterial.proofFamily,
            binaryFormat:
                transportedCompactVssShareLinkageProofMaterial.binaryFormat,
            proofMaterialSetRoot:
                transportedCompactVssShareLinkageProofMaterial.proofMaterialSetRoot,
            shareLinkageStatementRoot:
                transportedCompactVssShareLinkageProofMaterial.shareLinkageStatementRoot,
            chunkSizeBytes:
                transportedCompactVssShareLinkageProofMaterial.chunkSizeBytes,
            chunkCount:
                transportedCompactVssShareLinkageProofMaterial.chunkCount,
            totalByteLength:
                transportedCompactVssShareLinkageProofMaterial.totalByteLength,
            fullObjectHash:
                transportedCompactVssShareLinkageProofMaterial.fullObjectHash,
            chunkRoot: transportedCompactVssShareLinkageProofMaterial.chunkRoot,
            chunkHashes:
                transportedCompactVssShareLinkageProofMaterial.chunkHashes,
        });
        expect(
            verificationInput.transportedCompactVssShareLinkageProofMaterial,
        ).not.toHaveProperty('chunks');
    });
});
