import { beforeEach, describe, expect, it, vi } from 'vitest';

import type { TranscriptCoreKernel } from '#packages/wasm/src/index';

type JsonRecord = Record<string, unknown>;

const componentMaterialRoot = '4'.repeat(128);
const secondComponentMaterialRoot = '5'.repeat(128);
const otherHash = '6'.repeat(128);
const expectedManifestHash = '1'.repeat(128);
const expectedRosterHash = '2'.repeat(128);

const setupVerificationBindings = {
    expectedManifestHash,
    expectedRosterHash,
} as const;

const chunklessComponentMaterial = (keySwitchComponentMaterialRoot: string) =>
    ({
        objectType: 'SetupTransportedEvaluationKeyShareComponentMaterial',
        proofFamily: 'relinearization-key-share',
        keySwitchMaterialEncoding:
            'binary-chunked-key-switch-component-vectors',
        trusteeIdentity: 'trustee-alpha',
        trusteeRosterPosition: 0,
        keySwitchDomain: 'relinearization',
        keySwitchSeedHex: 'abcd',
        level: 0,
        ringDegree: 4,
        digitCount: 1,
        rnsLimbCount: 1,
        keySwitchComponentVectorRoot: otherHash,
        keySwitchComponentMaterialRoot,
        chunkSizeBytes: 1_048_576,
        chunkCount: 2,
        totalByteLength: 6,
        fullObjectHash: otherHash,
        chunkRoot: otherHash,
        chunkHashes: [otherHash, otherHash],
    }) as const;

const componentMaterialChunkStream = (
    keySwitchComponentMaterialRoot: string,
    firstChunkBytesHex: string,
) =>
    ({
        keySwitchComponentMaterialRoot,
        proofFamily: 'relinearization-key-share',
        chunks: [
            { chunkIndex: 0, bytesHex: firstChunkBytesHex },
            { chunkIndex: 1, bytesHex: '0102' },
        ],
    }) as const;

type MockKernel = {
    readonly beginEvaluationKeyShareComponentMaterialTransportStream: ReturnType<
        typeof vi.fn
    >;
    readonly absorbEvaluationKeyShareComponentMaterialTransportStreamChunk: ReturnType<
        typeof vi.fn
    >;
    readonly finishEvaluationKeyShareComponentMaterialTransportStream: ReturnType<
        typeof vi.fn
    >;
    readonly verifyCollectiveBgvSetup: ReturnType<typeof vi.fn>;
};

let mockKernel: MockKernel;

// prepareSetupPackageVerificationInputForKernel receives the kernel as a
// parameter, so the streaming orchestration is exercised directly against a
// mock kernel without loading the packaged WASM kernel.
const { prepareSetupPackageVerificationInputForKernel } =
    await import('#packages/sdk/src/setup-verification-input.js');

const makeMockKernel = (): MockKernel => ({
    beginEvaluationKeyShareComponentMaterialTransportStream: vi.fn(() => ({
        operation: 'beginEvaluationKeyShareComponentMaterialTransportStream',
    })),
    absorbEvaluationKeyShareComponentMaterialTransportStreamChunk: vi.fn(
        () => ({
            operation:
                'absorbEvaluationKeyShareComponentMaterialTransportStreamChunk',
        }),
    ),
    finishEvaluationKeyShareComponentMaterialTransportStream: vi.fn(() => ({
        operation: 'finishEvaluationKeyShareComponentMaterialTransportStream',
    })),
    verifyCollectiveBgvSetup: vi.fn((input: JsonRecord) => ({
        isValid: false,
        operation: 'verifyCollectiveBgvSetupPackage',
        observedInput: input,
    })),
});

const prepare = (input: JsonRecord): JsonRecord =>
    prepareSetupPackageVerificationInputForKernel(
        mockKernel as unknown as TranscriptCoreKernel,
        // The public verify input type is narrower than the mock payload here;
        // the streaming orchestration only reads the transported material and
        // the chunk streams, so a structural object is sufficient for the test.
        input as never,
    );

describe('evaluation-key component material streaming before terminal verification', () => {
    beforeEach(() => {
        mockKernel = makeMockKernel();
    });

    it('streams each chunkless component material through begin, absorb, and finish', () => {
        const verificationInput = prepare({
            setupPackage: { objectType: 'SetupPackage' },
            ...setupVerificationBindings,
            transportedEvaluationKeyShareComponentMaterial: {
                objectType:
                    'SetupTransportedEvaluationKeyShareComponentMaterialSet',
                componentMaterials: [
                    chunklessComponentMaterial(componentMaterialRoot),
                    chunklessComponentMaterial(secondComponentMaterialRoot),
                ],
            },
            evaluationKeyShareComponentMaterialChunkStreams: [
                componentMaterialChunkStream(componentMaterialRoot, 'aabb'),
                componentMaterialChunkStream(
                    secondComponentMaterialRoot,
                    'ccdd',
                ),
            ],
        });

        expect(
            mockKernel.beginEvaluationKeyShareComponentMaterialTransportStream,
        ).toHaveBeenCalledTimes(2);
        expect(
            mockKernel.finishEvaluationKeyShareComponentMaterialTransportStream,
        ).toHaveBeenCalledTimes(2);
        // Two chunks per stream, two streams.
        expect(
            mockKernel.absorbEvaluationKeyShareComponentMaterialTransportStreamChunk,
        ).toHaveBeenCalledTimes(4);

        // Begin must receive the chunkless component material reference, keyed
        // by its keySwitchComponentMaterialRoot, and never the raw chunk bytes.
        const beginCalls =
            mockKernel.beginEvaluationKeyShareComponentMaterialTransportStream
                .mock.calls;
        const streamedRoots = beginCalls.map((call) => {
            const reference = (call[0] as JsonRecord)
                .transportedEvaluationKeyShareComponentMaterial as JsonRecord;
            expect(
                Object.prototype.hasOwnProperty.call(reference, 'chunks'),
            ).toBe(false);

            return reference.keySwitchComponentMaterialRoot;
        });
        expect(new Set(streamedRoots)).toEqual(
            new Set([componentMaterialRoot, secondComponentMaterialRoot]),
        );

        // Absorb must forward the exact chunk bytes in ascending index order.
        const absorbCalls =
            mockKernel
                .absorbEvaluationKeyShareComponentMaterialTransportStreamChunk
                .mock.calls;
        expect(absorbCalls).toContainEqual([
            expect.objectContaining({ chunkIndex: 0, bytesHex: 'aabb' }),
        ]);
        expect(absorbCalls).toContainEqual([
            expect.objectContaining({ chunkIndex: 0, bytesHex: 'ccdd' }),
        ]);
        expect(absorbCalls).toContainEqual([
            expect.objectContaining({ chunkIndex: 1, bytesHex: '0102' }),
        ]);

        // The verify input keeps the chunkless component material set and must
        // not carry the out-of-band chunk streams field into the kernel verify.
        expect(
            Object.prototype.hasOwnProperty.call(
                verificationInput,
                'evaluationKeyShareComponentMaterialChunkStreams',
            ),
        ).toBe(false);
        const finalComponentMaterials = (
            verificationInput.transportedEvaluationKeyShareComponentMaterial as
                | Readonly<{
                      readonly componentMaterials: readonly JsonRecord[];
                  }>
                | undefined
        )?.componentMaterials;
        expect(finalComponentMaterials).toHaveLength(2);
        finalComponentMaterials?.forEach((componentMaterial) => {
            expect(
                Object.prototype.hasOwnProperty.call(
                    componentMaterial,
                    'chunks',
                ),
            ).toBe(false);
        });
    });

    it('surfaces a kernel chunk rejection instead of swallowing it', () => {
        mockKernel.absorbEvaluationKeyShareComponentMaterialTransportStreamChunk.mockImplementation(
            () => {
                throw new Error(
                    'evaluation-key component material chunks must be absorbed in ascending chunk-index order',
                );
            },
        );

        expect(() =>
            prepare({
                setupPackage: { objectType: 'SetupPackage' },
                ...setupVerificationBindings,
                transportedEvaluationKeyShareComponentMaterial: {
                    objectType:
                        'SetupTransportedEvaluationKeyShareComponentMaterialSet',
                    componentMaterials: [
                        chunklessComponentMaterial(componentMaterialRoot),
                    ],
                },
                evaluationKeyShareComponentMaterialChunkStreams: [
                    componentMaterialChunkStream(componentMaterialRoot, 'aabb'),
                ],
            }),
        ).toThrow(/ascending chunk-index order/);
    });

    it('does not stream when no component material chunk streams are supplied', () => {
        prepare({
            setupPackage: { objectType: 'SetupPackage' },
            ...setupVerificationBindings,
            transportedEvaluationKeyShareComponentMaterial: {
                objectType:
                    'SetupTransportedEvaluationKeyShareComponentMaterialSet',
                componentMaterials: [
                    chunklessComponentMaterial(componentMaterialRoot),
                ],
            },
        });

        expect(
            mockKernel.beginEvaluationKeyShareComponentMaterialTransportStream,
        ).not.toHaveBeenCalled();
        expect(
            mockKernel.absorbEvaluationKeyShareComponentMaterialTransportStreamChunk,
        ).not.toHaveBeenCalled();
        expect(
            mockKernel.finishEvaluationKeyShareComponentMaterialTransportStream,
        ).not.toHaveBeenCalled();
    });

    it('rebuilds the public-only verify input from a bare package plus bindings', () => {
        const verificationInput = prepare({
            setupPackage: { objectType: 'SetupPackage' },
            ...setupVerificationBindings,
        });

        // A bare package with no transported material must reduce to exactly the
        // public verification input, so no extra streaming or accounting fields
        // leak into the kernel verify call.
        expect(verificationInput).toEqual({
            setupPackage: { objectType: 'SetupPackage' },
            ...setupVerificationBindings,
        });
    });

    it('rejects a chunk stream that references an unknown component material root', () => {
        expect(() =>
            prepare({
                setupPackage: { objectType: 'SetupPackage' },
                ...setupVerificationBindings,
                transportedEvaluationKeyShareComponentMaterial: {
                    objectType:
                        'SetupTransportedEvaluationKeyShareComponentMaterialSet',
                    componentMaterials: [
                        chunklessComponentMaterial(componentMaterialRoot),
                    ],
                },
                evaluationKeyShareComponentMaterialChunkStreams: [
                    componentMaterialChunkStream(
                        secondComponentMaterialRoot,
                        'aabb',
                    ),
                ],
            }),
        ).toThrow(
            /keySwitchComponentMaterialRoot without a transported component material reference/u,
        );
    });
});
