import { foundationProfile } from '@sealed-lattice/types';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import {
    generateAcceptedSetupPublicKeyShareInClosedWorker,
    generateAcceptedSetupSameSecretInClosedWorker,
    verifyGeneratedAcceptedSetupPublicKeyShareInClosedWorker,
    verifyGeneratedAcceptedSetupSameSecretInClosedWorker,
} from '#packages/wasm/src/accepted-setup-key-relation-generation-runtime';
import { canonicalStreamDomains } from '#packages/wasm/src/canonical-stream-runtime';
import { registerCommonProofKernelContext } from '#packages/wasm/src/transcript-core-bridge/common-proof-kernel-context';
import type { TranscriptCoreKernelCommandRuntime } from '#packages/wasm/src/transcript-core-bridge/kernel-runtime';
import type { TranscriptCoreKernel } from '#packages/wasm/src/transcript-core-bridge/kernel-types';

const boundaryMocks = vi.hoisted(() => {
    const activeContext: {
        value: TranscriptCoreKernelCommandRuntime | undefined;
    } = { value: undefined };
    const generatedCapabilityRelease = vi.fn();
    const generatedCapability = Object.freeze({
        release: generatedCapabilityRelease,
    });
    return {
        activeContext,
        deriveProofDescriptor: vi.fn(async () => Uint8Array.of(0xd1, 0xd2)),
        generatedCapability,
        generatedCapabilityRelease,
        openGenerationAdapter: vi.fn(() => Object.freeze({})),
        releaseGenerationAdapter: vi.fn(),
        runGeneration: vi.fn(async () => generatedCapability),
        trackOutput: vi.fn((outputStore: unknown) =>
            Object.freeze({
                outputChunkByteLengths: Object.freeze([2]),
                outputStore,
            }),
        ),
        verifyGeneratedPublicKeyShare: vi.fn(
            async (_input: unknown, _capability: unknown) => undefined,
        ),
        verifyGeneratedSameSecret: vi.fn(
            async (_input: unknown, _capability: unknown) => undefined,
        ),
    };
});

vi.mock('#packages/wasm/src/action-randomness-runtime', () => ({
    resolveActionRandomnessKernelAuthorization: () => ({
        context: boundaryMocks.activeContext.value,
        handle: 13,
    }),
}));

vi.mock('#packages/wasm/src/setup-generation-recipient-payload', () => ({
    resolveSetupGenerationAuthorityKernelAuthorization: () => ({ handle: 14 }),
}));

vi.mock('#packages/wasm/src/state-verifier-runtime', () => ({
    resolveVerifiedStateReservationKernelAuthorization: () => ({
        capabilityMemory: boundaryMocks.activeContext.value?.memory,
        capabilityPointer: 128,
        reservationHandle: 15,
        sessionHandle: 16,
    }),
}));

vi.mock('#packages/wasm/src/vss-share-linkage-verification-runtime', () => ({
    resolveOrderedVerifiedBoardObjectAuthorization: () => {
        const handleBytes = new Uint8Array(4);
        new DataView(handleBytes.buffer).setUint32(0, 17, true);
        return Object.freeze({
            capabilityPointer: 192,
            handleBytes,
            sessionHandle: 18,
        });
    },
}));

vi.mock('#packages/wasm/src/generated-common-proof-output-runtime', () => ({
    deriveGeneratedCommonProofDescriptor:
        boundaryMocks.deriveProofDescriptor,
    trackCanonicalCommonProofOutputChunks: boundaryMocks.trackOutput,
}));

vi.mock('#packages/wasm/src/common-proof-worker-runtime/runtime', () => ({
    openClosedWorkerCommonProofGenerationFamilyAdapter:
        boundaryMocks.openGenerationAdapter,
    releaseClosedWorkerCommonProofGenerationFamilyAdapter:
        boundaryMocks.releaseGenerationAdapter,
    runClosedWorkerCommonProofGenerationFamilyAdapterRetainingGeneratedCapability:
        boundaryMocks.runGeneration,
}));

vi.mock('#packages/wasm/src/accepted-setup-proof-verification-runtime', () => ({
    verifyGeneratedAcceptedSetupPublicKeyShareCapabilityInClosedWorker:
        boundaryMocks.verifyGeneratedPublicKeyShare,
    verifyGeneratedAcceptedSetupSameSecretCapabilityInClosedWorker:
        boundaryMocks.verifyGeneratedSameSecret,
}));

type SetupKeyRelationFamily = 'publicKeyShare' | 'sameSecret';
type GenerationMode = 'fresh' | 'resumed';

type FakeSetupKeyRelationRuntime = Readonly<{
    allocations: ReadonlyMap<number, number>;
    copiedStatementSources: Array<Readonly<{ handle: number; output: number[] }>>;
    discardedStatementSources: number[];
    generationPreparations: Array<
        Readonly<{ family: SetupKeyRelationFamily; mode: GenerationMode }>
    >;
    kernel: TranscriptCoreKernel;
    selectedSuiteReleases: number[];
    statementByteLength: { value: number };
}>;

const writeStatus = (
    memory: WebAssembly.Memory,
    pointer: number,
    status: number,
): void => {
    new DataView(memory.buffer).setUint32(pointer, status, true);
};

const createFakeRuntime = (): FakeSetupKeyRelationRuntime => {
    const memory = new WebAssembly.Memory({ initial: 2 });
    const allocations = new Map<number, number>();
    const copiedStatementSources: Array<
        Readonly<{ handle: number; output: number[] }>
    > = [];
    const discardedStatementSources: number[] = [];
    const generationPreparations: Array<
        Readonly<{ family: SetupKeyRelationFamily; mode: GenerationMode }>
    > = [];
    const selectedSuiteReleases: number[] = [];
    const statementByteLength = { value: 4 };
    let nextPointer = 1_024;

    const allocate = (byteLength: number): number => {
        const pointer = Math.ceil(nextPointer / 8) * 8;
        nextPointer = pointer + byteLength;
        allocations.set(pointer, byteLength);
        return pointer;
    };
    const deallocate = (pointer: number, byteLength: number): void => {
        if (allocations.get(pointer) !== byteLength) {
            throw new Error(
                'The fake key-relation allocation was released with the wrong length.',
            );
        }
        allocations.delete(pointer);
    };
    const prepare = (
        family: SetupKeyRelationFamily,
        mode: GenerationMode,
        sourceHandlePointer: number,
        statusPointer: number,
    ): number => {
        generationPreparations.push({ family, mode });
        new DataView(memory.buffer).setUint32(
            sourceHandlePointer,
            family === 'sameSecret' ? 21 : 22,
            true,
        );
        writeStatus(memory, statusPointer, 0);
        return family === 'sameSecret' ? 31 : 32;
    };
    type PrepareArguments = [
        number,
        number,
        number,
        number,
        number,
        number,
        number,
        number,
        number,
        number,
        number,
        number,
        number,
        number,
        number,
    ];
    const preparation = (
        family: SetupKeyRelationFamily,
        mode: GenerationMode,
    ) =>
        (...parameters: PrepareArguments): number =>
            prepare(family, mode, parameters[13], parameters[14]);

    const wasmExports = {
        sealed_lattice_common_proof_release_suite: (handle: number) => {
            selectedSuiteReleases.push(handle);
            return 0;
        },
        sealed_lattice_common_proof_select_suite: (
            _pointer: number,
            _byteLength: number,
            statusPointer: number,
        ) => {
            writeStatus(memory, statusPointer, 0);
            return 11;
        },
        sealed_lattice_public_key_share_prepare_generation: preparation(
            'publicKeyShare',
            'fresh',
        ),
        sealed_lattice_public_key_share_prepare_resumed_generation:
            preparation('publicKeyShare', 'resumed'),
        sealed_lattice_same_secret_prepare_generation: preparation(
            'sameSecret',
            'fresh',
        ),
        sealed_lattice_same_secret_prepare_resumed_generation: preparation(
            'sameSecret',
            'resumed',
        ),
        sealed_lattice_setup_key_relation_generation_statement_byte_length: (
            _handle: number,
            statusPointer: number,
        ) => {
            writeStatus(memory, statusPointer, 0);
            return statementByteLength.value;
        },
        sealed_lattice_setup_key_relation_generation_statement_copy_and_release:
            (handle: number, outputPointer: number, outputByteLength: number) => {
                const output = new Uint8Array(
                    memory.buffer,
                    outputPointer,
                    outputByteLength,
                );
                output.forEach((_value, byteIndex) => {
                    output[byteIndex] = handle + byteIndex;
                });
                copiedStatementSources.push({
                    handle,
                    output: Array.from(output),
                });
                return 0;
            },
        sealed_lattice_setup_key_relation_generation_statement_discard: (
            handle: number,
        ) => {
            discardedStatementSources.push(handle);
            return 0;
        },
    };
    const kernel = Object.freeze({}) as TranscriptCoreKernel;
    const context = {
        allocate,
        deallocate,
        executeCommand: () => {
            throw new Error('The focused key-relation test does not use commands.');
        },
        memory,
        runExclusive: <Result>(
            _operationName: string,
            operation: () => Result,
        ): Result => operation(),
        wasmExports,
    } as unknown as TranscriptCoreKernelCommandRuntime;
    registerCommonProofKernelContext(kernel, context);
    boundaryMocks.activeContext.value = context;
    return Object.freeze({
        allocations,
        copiedStatementSources,
        discardedStatementSources,
        generationPreparations,
        kernel,
        selectedSuiteReleases,
        statementByteLength,
    });
};

const generationInput = (
    runtime: FakeSetupKeyRelationRuntime,
    mode: GenerationMode,
) => ({
    actionRandomnessSession: Object.freeze({}),
    canonicalSuiteRecordBytes: Uint8Array.of(1, 2, 3),
    checkpointLineageIdentifier: new Uint8Array(32).fill(7),
    externalMemory: Object.freeze({}),
    generationMode: mode,
    generationOptions:
        mode === 'resumed'
            ? Object.freeze({ resume: Object.freeze({}) })
            : undefined,
    kernel: runtime.kernel,
    outputStore: Object.freeze({}),
    setupGenerationAuthority: Object.freeze({}),
    setupIntentObject: Object.freeze({}),
    verifiedReservation: Object.freeze({}),
});

const verificationInput = (
    kernel: TranscriptCoreKernel,
    generatedProof: Awaited<
        ReturnType<typeof generateAcceptedSetupSameSecretInClosedWorker>
    >,
) => ({
    assembly: Object.freeze({}),
    canonicalSuiteRecordBytes: Uint8Array.of(1, 2, 3),
    generatedProof,
    inputStore: Object.freeze({}),
    kernel,
});

beforeEach(() => {
    vi.clearAllMocks();
    boundaryMocks.deriveProofDescriptor.mockResolvedValue(
        Uint8Array.of(0xd1, 0xd2),
    );
    boundaryMocks.verifyGeneratedPublicKeyShare.mockResolvedValue(undefined);
    boundaryMocks.verifyGeneratedSameSecret.mockResolvedValue(undefined);
});

describe('accepted-setup key-relation generation', () => {
    it.each([
        [
            'sameSecret',
            'fresh',
            generateAcceptedSetupSameSecretInClosedWorker,
            canonicalStreamDomains.sameSecretProof,
            21,
        ],
        [
            'sameSecret',
            'resumed',
            generateAcceptedSetupSameSecretInClosedWorker,
            canonicalStreamDomains.sameSecretProof,
            21,
        ],
        [
            'publicKeyShare',
            'fresh',
            generateAcceptedSetupPublicKeyShareInClosedWorker,
            canonicalStreamDomains.publicKeyShareProof,
            22,
        ],
        [
            'publicKeyShare',
            'resumed',
            generateAcceptedSetupPublicKeyShareInClosedWorker,
            canonicalStreamDomains.publicKeyShareProof,
            22,
        ],
    ] as const)(
        'retains the exact %s %s proof for package verification',
        async (
            family,
            mode,
            generate,
            expectedStreamDomain,
            statementSourceHandle,
        ) => {
            const runtime = createFakeRuntime();
            const proof = await generate(
                generationInput(runtime, mode) as never,
            );

            expect(runtime.generationPreparations).toEqual([{ family, mode }]);
            expect(runtime.copiedStatementSources).toEqual([
                {
                    handle: statementSourceHandle,
                    output: [
                        statementSourceHandle,
                        statementSourceHandle + 1,
                        statementSourceHandle + 2,
                        statementSourceHandle + 3,
                    ],
                },
            ]);
            expect(proof.copyCanonicalApplicationStatementBytes()).toEqual(
                Uint8Array.of(
                    statementSourceHandle,
                    statementSourceHandle + 1,
                    statementSourceHandle + 2,
                    statementSourceHandle + 3,
                ),
            );
            expect(proof.copyProofDescriptorBytes()).toEqual(
                Uint8Array.of(0xd1, 0xd2),
            );
            expect(boundaryMocks.deriveProofDescriptor).toHaveBeenCalledWith(
                expect.objectContaining({ streamDomain: expectedStreamDomain }),
            );
            expect(runtime.selectedSuiteReleases).toEqual([11]);
            expect(runtime.discardedStatementSources).toEqual([]);
            expect(runtime.allocations.size).toBe(0);

            proof.release();
            expect(boundaryMocks.generatedCapabilityRelease).toHaveBeenCalledTimes(
                1,
            );
            expect(() =>
                proof.copyCanonicalApplicationStatementBytes(),
            ).toThrow(/consumed/u);
        },
    );

    it('refuses a fresh/resume mismatch before preparing any family', async () => {
        const runtime = createFakeRuntime();
        await expect(
            generateAcceptedSetupSameSecretInClosedWorker({
                ...generationInput(runtime, 'fresh'),
                generationOptions: { resume: Object.freeze({}) },
            } as never),
        ).rejects.toThrow(/wrongContext/u);
        await expect(
            generateAcceptedSetupPublicKeyShareInClosedWorker({
                ...generationInput(runtime, 'resumed'),
                generationOptions: undefined,
            } as never),
        ).rejects.toThrow(/wrongContext/u);
        expect(runtime.generationPreparations).toEqual([]);
        expect(runtime.allocations.size).toBe(0);
    });

    it('discards the statement source when its exact bytes exceed the copy bound', async () => {
        const runtime = createFakeRuntime();
        runtime.statementByteLength.value =
            foundationProfile.maximumCopiedBufferByteLength + 1;
        await expect(
            generateAcceptedSetupSameSecretInClosedWorker(
                generationInput(runtime, 'fresh') as never,
            ),
        ).rejects.toThrow(/bound/u);
        expect(runtime.discardedStatementSources).toEqual([21]);
        expect(boundaryMocks.releaseGenerationAdapter).toHaveBeenCalledTimes(1);
        expect(boundaryMocks.runGeneration).not.toHaveBeenCalled();
        expect(runtime.allocations.size).toBe(0);
    });

    it('releases generated authority when proof-descriptor derivation fails', async () => {
        const runtime = createFakeRuntime();
        boundaryMocks.deriveProofDescriptor.mockRejectedValueOnce(
            new Error('descriptor failed'),
        );
        await expect(
            generateAcceptedSetupPublicKeyShareInClosedWorker(
                generationInput(runtime, 'fresh') as never,
            ),
        ).rejects.toThrow('descriptor failed');
        expect(boundaryMocks.generatedCapabilityRelease).toHaveBeenCalledTimes(
            1,
        );
        expect(runtime.selectedSuiteReleases).toEqual([11]);
        expect(runtime.allocations.size).toBe(0);
    });
});

describe('generated accepted-setup key-relation verification', () => {
    it.each([
        [
            generateAcceptedSetupSameSecretInClosedWorker,
            verifyGeneratedAcceptedSetupSameSecretInClosedWorker,
            boundaryMocks.verifyGeneratedSameSecret,
        ],
        [
            generateAcceptedSetupPublicKeyShareInClosedWorker,
            verifyGeneratedAcceptedSetupPublicKeyShareInClosedWorker,
            boundaryMocks.verifyGeneratedPublicKeyShare,
        ],
    ] as const)(
        'consumes generated authority only after package-backed positive verification',
        async (generate, verifyGenerated, verifyCapability) => {
            const runtime = createFakeRuntime();
            const proof = await generate(
                generationInput(runtime, 'resumed') as never,
            );
            await verifyGenerated(
                verificationInput(runtime.kernel, proof) as never,
            );

            expect(verifyCapability).toHaveBeenCalledTimes(1);
            expect(verifyCapability.mock.calls[0]?.[0]).toEqual(
                expect.objectContaining({
                    canonicalApplicationStatementBytes:
                        expect.any(Uint8Array),
                }),
            );
            expect(verifyCapability.mock.calls[0]?.[1]).toBe(
                boundaryMocks.generatedCapability,
            );
            expect(boundaryMocks.generatedCapabilityRelease).not.toHaveBeenCalled();
            expect(() => proof.copyProofDescriptorBytes()).toThrow(/consumed/u);
        },
    );

    it('keeps a refused generated proof retryable and rejects cross-family use', async () => {
        const runtime = createFakeRuntime();
        const proof = await generateAcceptedSetupSameSecretInClosedWorker(
            generationInput(runtime, 'fresh') as never,
        );
        await expect(
            verifyGeneratedAcceptedSetupPublicKeyShareInClosedWorker(
                verificationInput(runtime.kernel, proof) as never,
            ),
        ).rejects.toThrow(/wrongContext/u);
        boundaryMocks.verifyGeneratedSameSecret.mockRejectedValueOnce(
            new Error('package refused'),
        );
        await expect(
            verifyGeneratedAcceptedSetupSameSecretInClosedWorker(
                verificationInput(runtime.kernel, proof) as never,
            ),
        ).rejects.toThrow('package refused');
        expect(proof.copyProofDescriptorBytes()).toEqual(
            Uint8Array.of(0xd1, 0xd2),
        );

        await verifyGeneratedAcceptedSetupSameSecretInClosedWorker(
            verificationInput(runtime.kernel, proof) as never,
        );
        expect(boundaryMocks.verifyGeneratedSameSecret).toHaveBeenCalledTimes(2);
        expect(() => proof.copyProofDescriptorBytes()).toThrow(/consumed/u);
    });

    it('rejects cross-worker verification without consuming the proof', async () => {
        const sourceRuntime = createFakeRuntime();
        const proof = await generateAcceptedSetupSameSecretInClosedWorker(
            generationInput(sourceRuntime, 'fresh') as never,
        );
        const otherRuntime = createFakeRuntime();
        await expect(
            verifyGeneratedAcceptedSetupSameSecretInClosedWorker(
                verificationInput(otherRuntime.kernel, proof) as never,
            ),
        ).rejects.toThrow(/wrongContext/u);
        expect(proof.copyProofDescriptorBytes()).toEqual(
            Uint8Array.of(0xd1, 0xd2),
        );
        proof.release();
    });
});
