import { beforeEach, describe, expect, it, vi } from 'vitest';

type JsonRecord = Record<string, unknown>;

const proofHash =
    '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

const alternateProofHash =
    'fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210';

const trusteeProofHash =
    '89abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567';

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

const setupProofMaterialSpecs = [
    {
        chunkBytesHex: 'abcd',
        fieldName: 'transportedSameSecretProofMaterial',
        materialObjectType: 'SetupTransportedSameSecretProofMaterial',
        proofFamily: 'same-secret-linkage-anchor',
        proofMaterialRoot: proofHash,
        setObjectType: 'SetupTransportedSameSecretProofMaterialSet',
    },
    {
        chunkBytesHex: 'bcde',
        fieldName: 'transportedPublicKeyShareProofMaterial',
        materialObjectType: 'SetupTransportedPublicKeyShareProofMaterial',
        proofFamily: 'public-key-share',
        proofMaterialRoot: alternateProofHash,
        setObjectType: 'SetupTransportedPublicKeyShareProofMaterialSet',
    },
    {
        chunkBytesHex: 'cdef',
        fieldName: 'transportedEvaluationKeyShareProofMaterial',
        materialObjectType: 'SetupTransportedEvaluationKeyShareProofMaterial',
        proofFamily: 'trustee-evaluation-key',
        proofMaterialRoot: trusteeProofHash,
        setObjectType: 'SetupTransportedEvaluationKeyShareProofMaterialSet',
    },
] as const;

const [
    sameSecretProofMaterialSpec,
    publicKeyShareProofMaterialSpec,
    evaluationKeyShareProofMaterialSpec,
] = setupProofMaterialSpecs;

type SetupProofMaterialSpec = (typeof setupProofMaterialSpecs)[number];

const transportedProofMaterialRecord = (
    spec: SetupProofMaterialSpec,
): JsonRecord =>
    ({
        objectType: spec.materialObjectType,
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        setupProofProfileId: 'SealedLattice-SetupProof-v1',
        proofFamily: spec.proofFamily,
        proofMaterialRoot: spec.proofMaterialRoot,
        chunkSizeBytes: 1_048_576,
        chunkCount: 1,
        totalByteLength: 2,
        fullObjectHash: spec.proofMaterialRoot,
        chunkHashes: [spec.proofMaterialRoot],
        chunkRoot: spec.proofMaterialRoot,
        chunks: [
            {
                chunkIndex: 0,
                bytesHex: spec.chunkBytesHex,
            },
        ],
    }) as const;

const transportedProofMaterialInput = () =>
    ({
        transportedSameSecretProofMaterial: {
            objectType: 'SetupTransportedSameSecretProofMaterialSet',
            objectVersion: 1,
            setupProfileId: 'CollectiveBgvSetup-v1',
            setupProofProfileId: 'SealedLattice-SetupProof-v1',
            proofFamily: sameSecretProofMaterialSpec.proofFamily,
            proofMaterials: [
                transportedProofMaterialRecord(sameSecretProofMaterialSpec),
            ],
        },
        transportedPublicKeyShareProofMaterial: {
            objectType: 'SetupTransportedPublicKeyShareProofMaterialSet',
            objectVersion: 1,
            setupProfileId: 'CollectiveBgvSetup-v1',
            setupProofProfileId: 'SealedLattice-SetupProof-v1',
            proofFamily: publicKeyShareProofMaterialSpec.proofFamily,
            proofMaterials: [
                transportedProofMaterialRecord(publicKeyShareProofMaterialSpec),
            ],
        },
        transportedEvaluationKeyShareProofMaterial: {
            objectType: 'SetupTransportedEvaluationKeyShareProofMaterialSet',
            objectVersion: 1,
            setupProfileId: 'CollectiveBgvSetup-v1',
            setupProofProfileId: 'SealedLattice-SetupProof-v1',
            proofFamily: evaluationKeyShareProofMaterialSpec.proofFamily,
            proofMaterials: [
                transportedProofMaterialRecord(
                    evaluationKeyShareProofMaterialSpec,
                ),
            ],
        },
    }) as const;

const verifiedSetupProofMaterials = (
    proofFullObjectHashByFamily: Readonly<Record<string, string>> = {},
) =>
    ({
        objectType: 'VerifiedSetupProofMaterialSet',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        setupProofProfileId: 'SealedLattice-SetupProof-v1',
        proofMaterials: setupProofMaterialSpecs.map(
            (spec) =>
                ({
                    objectType: 'VerifiedSetupProofMaterial',
                    objectVersion: 1,
                    setupProfileId: 'CollectiveBgvSetup-v1',
                    setupProofProfileId: 'SealedLattice-SetupProof-v1',
                    verificationId: `caller-supplied-${spec.proofFamily}`,
                    proofFamily: spec.proofFamily,
                    proofMaterialRoot: spec.proofMaterialRoot,
                    proofBytesEncoding: 'binary-chunked-proof-bytes',
                    proofChunkSizeBytes: 1_048_576,
                    proofChunkCount: 1,
                    proofTotalByteLength: 2,
                    proofFullObjectHash:
                        proofFullObjectHashByFamily[spec.proofFamily] ??
                        spec.proofMaterialRoot,
                    proofChunkRoot: spec.proofMaterialRoot,
                    proofChunkHashes: [spec.proofMaterialRoot],
                }) as const,
        ),
    }) as const;

describe('setup proof material streaming in the public package', () => {
    beforeEach(() => {
        const proofMaterialByVerificationId = new Map<string, JsonRecord>();
        mockKernel = {
            beginSetupProofMaterialTransportStream: vi.fn(
                (input: {
                    readonly verificationId: string;
                    readonly transportedSetupProofMaterial: JsonRecord;
                }) => {
                    proofMaterialByVerificationId.set(
                        input.verificationId,
                        input.transportedSetupProofMaterial,
                    );

                    return {
                        ok: true,
                        operation: 'beginSetupProofMaterialTransportStream',
                    };
                },
            ),
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
                        proofFamily: proofMaterialByVerificationId.get(
                            input.verificationId,
                        )?.proofFamily,
                        proofMaterialRoot: proofMaterialByVerificationId.get(
                            input.verificationId,
                        )?.proofMaterialRoot,
                        proofBytesEncoding: 'binary-chunked-proof-bytes',
                        proofChunkSizeBytes: 1_048_576,
                        proofChunkCount: 1,
                        proofTotalByteLength: 2,
                        proofFullObjectHash: proofMaterialByVerificationId.get(
                            input.verificationId,
                        )?.fullObjectHash,
                        proofChunkRoot: proofMaterialByVerificationId.get(
                            input.verificationId,
                        )?.chunkRoot,
                        proofChunkHashes: proofMaterialByVerificationId.get(
                            input.verificationId,
                        )?.chunkHashes,
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
            ...transportedProofMaterialInput(),
        });

        expect(
            mockKernel.beginSetupProofMaterialTransportStream,
        ).toHaveBeenCalledTimes(setupProofMaterialSpecs.length);
        const beginInputs =
            mockKernel.beginSetupProofMaterialTransportStream.mock.calls.map(
                (call) => call[0] as JsonRecord,
            );
        expect(
            beginInputs.map(
                (input) =>
                    (input.transportedSetupProofMaterial as JsonRecord)
                        .objectType,
            ),
        ).toEqual(
            setupProofMaterialSpecs.map((spec) => spec.materialObjectType),
        );
        expect(
            beginInputs.every(
                (input) =>
                    !Object.prototype.hasOwnProperty.call(
                        input.transportedSetupProofMaterial,
                        'chunks',
                    ),
            ),
        ).toBe(true);
        const absorbedChunkInputs: unknown[] = [];
        for (const call of mockKernel
            .absorbSetupProofMaterialTransportStreamChunk.mock.calls) {
            absorbedChunkInputs.push(call[0] as unknown);
        }
        const expectedAbsorbedChunkInputs: unknown[] = [];
        for (const spec of setupProofMaterialSpecs) {
            expectedAbsorbedChunkInputs.push(
                expect.objectContaining({
                    chunkIndex: 0,
                    bytesHex: spec.chunkBytesHex,
                }),
            );
        }
        expect(absorbedChunkInputs).toEqual(expectedAbsorbedChunkInputs);

        const finalVerifyInput = mockKernel.verifyCollectiveBgvSetup.mock
            .calls[0]?.[0] as JsonRecord | undefined;
        for (const spec of setupProofMaterialSpecs) {
            const finalMaterialSet = finalVerifyInput?.[spec.fieldName] as
                | Readonly<{ readonly proofMaterials: readonly JsonRecord[] }>
                | undefined;
            const finalProofMaterial = finalMaterialSet?.proofMaterials[0];
            expect(finalProofMaterial).toMatchObject({
                objectType: spec.materialObjectType,
                proofFamily: spec.proofFamily,
                proofMaterialRoot: spec.proofMaterialRoot,
            });
            expect(finalProofMaterial).not.toHaveProperty('chunks');
        }
        expect(finalVerifyInput?.verifiedSetupProofMaterials).toMatchObject({
            objectType: 'VerifiedSetupProofMaterialSet',
            objectVersion: 1,
            setupProfileId: 'CollectiveBgvSetup-v1',
            setupProofProfileId: 'SealedLattice-SetupProof-v1',
            proofMaterials: (() => {
                const expectedProofMaterials: unknown[] = [];
                for (const spec of setupProofMaterialSpecs) {
                    expectedProofMaterials.push(
                        expect.objectContaining({
                            objectType: 'VerifiedSetupProofMaterial',
                            proofFamily: spec.proofFamily,
                            proofMaterialRoot: spec.proofMaterialRoot,
                        }),
                    );
                }

                return expectedProofMaterials;
            })(),
        });
    });

    it('forwards caller-supplied proof handles without re-streaming chunks', async () => {
        const suppliedHandles = verifiedSetupProofMaterials({
            'public-key-share':
                '456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123',
        });

        await publicPackage.verifySetupPackage({
            setupPackage: {
                objectType: 'SetupPackage',
                objectVersion: 1,
            },
            ...transportedProofMaterialInput(),
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
        for (const spec of setupProofMaterialSpecs) {
            const finalMaterialSet = finalVerifyInput?.[spec.fieldName] as
                | Readonly<{ readonly proofMaterials: readonly JsonRecord[] }>
                | undefined;
            expect(finalMaterialSet?.proofMaterials[0]).not.toHaveProperty(
                'chunks',
            );
        }
        expect(finalVerifyInput?.verifiedSetupProofMaterials).toBe(
            suppliedHandles,
        );
    });
});
