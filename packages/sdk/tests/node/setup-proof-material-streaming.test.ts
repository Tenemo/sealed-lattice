import { beforeEach, describe, expect, it, vi } from 'vitest';

type JsonRecord = Record<string, unknown>;

const proofHash =
    '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

let mockKernel: {
    readonly beginSetupProofMaterialTransportStream: ReturnType<typeof vi.fn>;
    readonly absorbSetupProofMaterialTransportStreamChunk: ReturnType<
        typeof vi.fn
    >;
    readonly finishSetupProofMaterialTransportStream: ReturnType<typeof vi.fn>;
    readonly verifyCollectiveBgvSetup: ReturnType<typeof vi.fn>;
};

vi.mock('../../dist/kernel.js', () => ({
    loadTranscriptCoreKernel: () => Promise.resolve(mockKernel),
}));

const publicPackage = await import('../../dist/index.js');

const transportedSameSecretProofMaterial = () =>
    ({
        objectType: 'SetupTransportedSameSecretProofMaterialSet',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        setupProofProfileId: 'SealedLattice-SetupProof-v1',
        proofFamily: 'same-secret-linkage-anchor',
        proofMaterials: [
            {
                objectType: 'SetupTransportedSameSecretProofMaterial',
                objectVersion: 1,
                setupProfileId: 'CollectiveBgvSetup-v1',
                setupProofProfileId: 'SealedLattice-SetupProof-v1',
                proofFamily: 'same-secret-linkage-anchor',
                proofMaterialRoot: proofHash,
                chunkSizeBytes: 1_048_576,
                chunkCount: 1,
                totalByteLength: 2,
                fullObjectHash: proofHash,
                chunkHashes: [proofHash],
                chunkRoot: proofHash,
                chunks: [
                    {
                        chunkIndex: 0,
                        bytesHex: 'abcd',
                    },
                ],
            },
        ],
    }) as const;

const verifiedSetupProofMaterials = (proofFullObjectHash = proofHash) =>
    ({
        objectType: 'VerifiedSetupProofMaterialSet',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        setupProofProfileId: 'SealedLattice-SetupProof-v1',
        proofMaterials: [
            {
                objectType: 'VerifiedSetupProofMaterial',
                objectVersion: 1,
                setupProfileId: 'CollectiveBgvSetup-v1',
                setupProofProfileId: 'SealedLattice-SetupProof-v1',
                verificationId: 'caller-supplied-handle',
                proofFamily: 'same-secret-linkage-anchor',
                proofMaterialRoot: proofHash,
                proofBytesEncoding: 'binary-chunked-proof-bytes',
                proofChunkSizeBytes: 1_048_576,
                proofChunkCount: 1,
                proofTotalByteLength: 2,
                proofFullObjectHash,
                proofChunkRoot: proofHash,
                proofChunkHashes: [proofHash],
            },
        ],
    }) as const;

describe('setup proof material streaming in the public package', () => {
    beforeEach(() => {
        mockKernel = {
            beginSetupProofMaterialTransportStream: vi.fn(() => ({
                ok: true,
                operation: 'beginSetupProofMaterialTransportStream',
            })),
            absorbSetupProofMaterialTransportStreamChunk: vi.fn(() => ({
                ok: true,
                operation: 'absorbSetupProofMaterialTransportStreamChunk',
            })),
            finishSetupProofMaterialTransportStream: vi.fn(
                (input: { readonly verificationId: string }) => ({
                    ok: true,
                    operation: 'finishSetupProofMaterialTransportStream',
                    verifiedSetupProofMaterial: {
                        objectType: 'VerifiedSetupProofMaterial',
                        objectVersion: 1,
                        setupProfileId: 'CollectiveBgvSetup-v1',
                        setupProofProfileId: 'SealedLattice-SetupProof-v1',
                        verificationId: input.verificationId,
                        proofFamily: 'same-secret-linkage-anchor',
                        proofMaterialRoot: proofHash,
                        proofBytesEncoding: 'binary-chunked-proof-bytes',
                        proofChunkSizeBytes: 1_048_576,
                        proofChunkCount: 1,
                        proofTotalByteLength: 2,
                        proofFullObjectHash: proofHash,
                        proofChunkRoot: proofHash,
                        proofChunkHashes: [proofHash],
                    },
                }),
            ),
            verifyCollectiveBgvSetup: vi.fn((input: JsonRecord) => ({
                ok: false,
                operation: 'verifyCollectiveBgvSetupPackage',
                verifierStatus: 'outsideProfile',
                observedInput: input,
            })),
        };
    });

    it('streams setup proof chunks and verifies with compact handles', async () => {
        await publicPackage.verifySetupPackage({
            setupPackage: {
                objectType: 'SetupPackage',
                objectVersion: 1,
            },
            transportedSameSecretProofMaterial:
                transportedSameSecretProofMaterial(),
        });

        expect(
            mockKernel.beginSetupProofMaterialTransportStream,
        ).toHaveBeenCalledOnce();
        const beginInput = mockKernel.beginSetupProofMaterialTransportStream
            .mock.calls[0]?.[0] as JsonRecord | undefined;
        expect(beginInput?.transportedSetupProofMaterial).not.toHaveProperty(
            'chunks',
        );
        expect(
            mockKernel.absorbSetupProofMaterialTransportStreamChunk,
        ).toHaveBeenCalledWith(
            expect.objectContaining({
                chunkIndex: 0,
                bytesHex: 'abcd',
            }),
        );

        const finalVerifyInput = mockKernel.verifyCollectiveBgvSetup.mock
            .calls[0]?.[0] as JsonRecord | undefined;
        const finalSameSecretMaterial =
            finalVerifyInput?.transportedSameSecretProofMaterial as
                | Readonly<{ readonly proofMaterials: readonly JsonRecord[] }>
                | undefined;
        expect(finalSameSecretMaterial?.proofMaterials[0]).not.toHaveProperty(
            'chunks',
        );
        expect(finalVerifyInput?.verifiedSetupProofMaterials).toMatchObject({
            objectType: 'VerifiedSetupProofMaterialSet',
            objectVersion: 1,
            setupProfileId: 'CollectiveBgvSetup-v1',
            setupProofProfileId: 'SealedLattice-SetupProof-v1',
            proofMaterials: [
                expect.objectContaining({
                    objectType: 'VerifiedSetupProofMaterial',
                    proofMaterialRoot: proofHash,
                }),
            ],
        });
    });

    it('forwards caller-supplied proof handles without re-streaming chunks', async () => {
        const suppliedHandles = verifiedSetupProofMaterials(
            'fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210',
        );

        await publicPackage.verifySetupPackage({
            setupPackage: {
                objectType: 'SetupPackage',
                objectVersion: 1,
            },
            transportedSameSecretProofMaterial:
                transportedSameSecretProofMaterial(),
            verifiedSetupProofMaterials: suppliedHandles,
        });

        expect(
            mockKernel.beginSetupProofMaterialTransportStream,
        ).not.toHaveBeenCalled();
        expect(
            mockKernel.absorbSetupProofMaterialTransportStreamChunk,
        ).not.toHaveBeenCalled();
        expect(
            mockKernel.finishSetupProofMaterialTransportStream,
        ).not.toHaveBeenCalled();

        const finalVerifyInput = mockKernel.verifyCollectiveBgvSetup.mock
            .calls[0]?.[0] as JsonRecord | undefined;
        const finalSameSecretMaterial =
            finalVerifyInput?.transportedSameSecretProofMaterial as
                | Readonly<{ readonly proofMaterials: readonly JsonRecord[] }>
                | undefined;
        expect(finalSameSecretMaterial?.proofMaterials[0]).not.toHaveProperty(
            'chunks',
        );
        expect(finalVerifyInput?.verifiedSetupProofMaterials).toBe(
            suppliedHandles,
        );
    });
});
