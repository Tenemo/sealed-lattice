import { refusalReasonCodes } from '@sealed-lattice/types';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import {
    generateGaloisKeyShareBatchInClosedWorker,
    verifyGaloisKeyShareBatchInClosedWorker,
    type GaloisKeyShareComponentStore,
} from '#packages/wasm/src/accepted-setup-galois-key-share-runtime';
import { registerCommonProofKernelContext } from '#packages/wasm/src/transcript-core-bridge/common-proof-kernel-context';
import type { TranscriptCoreKernelCommandRuntime } from '#packages/wasm/src/transcript-core-bridge/kernel-runtime';
import type { TranscriptCoreKernel } from '#packages/wasm/src/transcript-core-bridge/kernel-types';

const boundaryMocks = vi.hoisted(() => {
    const activeContext: {
        value: TranscriptCoreKernelCommandRuntime | undefined;
    } = { value: undefined };
    const retainedBackingInputs: Array<{
        readExactRange(
            sourceByteOffset: bigint,
            exactByteLength: number,
        ): Promise<Uint8Array>;
        release(): void;
    }> = [];
    const generatedCapabilityRelease = vi.fn();
    const verifiedCapabilityRelease = vi.fn();
    const generatedCapability = Object.freeze({
        release: generatedCapabilityRelease,
    });
    const verifiedCapability = Object.freeze({
        release: verifiedCapabilityRelease,
    });
    return {
        activeContext,
        applyGenerated: vi.fn(
            (
                _capability: unknown,
                _context: unknown,
                apply: (handle: number) => {
                    consumed: boolean;
                    result: unknown;
                },
            ) => apply(51).result,
        ),
        applyVerified: vi.fn(
            (
                _capability: unknown,
                _context: unknown,
                apply: (handle: number) => {
                    consumed: boolean;
                    result: unknown;
                },
            ) => apply(61).result,
        ),
        deriveProofDescriptor: vi.fn(() =>
            Promise.resolve(Uint8Array.of(0xd1, 0xd2)),
        ),
        generatedCapability,
        generatedCapabilityRelease,
        openGenerationAdapter: vi.fn(() => Object.freeze({})),
        openVerificationAdapter: vi.fn(() => Object.freeze({})),
        releaseGenerationAdapter: vi.fn(),
        releaseVerificationAdapter: vi.fn(),
        retainedBackingInputs,
        runGeneration: vi.fn(() => Promise.resolve(generatedCapability)),
        runVerification: vi.fn(() => Promise.resolve(verifiedCapability)),
        trackOutput: vi.fn((outputStore: unknown) =>
            Object.freeze({
                outputChunkByteLengths: Object.freeze([2]),
                outputStore,
            }),
        ),
        verifiedCapabilityRelease,
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
    deriveGeneratedCommonProofDescriptor: boundaryMocks.deriveProofDescriptor,
    trackCanonicalCommonProofOutputChunks: boundaryMocks.trackOutput,
}));

vi.mock('#packages/wasm/src/common-proof-worker-runtime/runtime', () => ({
    applyClosedWorkerGeneratedCommonProofCapability:
        boundaryMocks.applyGenerated,
    applyClosedWorkerVerifiedCommonProofCapability: boundaryMocks.applyVerified,
    openClosedWorkerCommonProofGenerationFamilyAdapter:
        boundaryMocks.openGenerationAdapter,
    openClosedWorkerCommonProofVerificationFamilyAdapter:
        boundaryMocks.openVerificationAdapter,
    releaseClosedWorkerCommonProofGenerationFamilyAdapter:
        boundaryMocks.releaseGenerationAdapter,
    releaseClosedWorkerCommonProofVerificationFamilyAdapter:
        boundaryMocks.releaseVerificationAdapter,
    runClosedWorkerCommonProofGenerationFamilyAdapterRetainingGeneratedCapability:
        boundaryMocks.runGeneration,
    runClosedWorkerCommonProofVerificationFamilyAdapter:
        boundaryMocks.runVerification,
}));

vi.mock('#packages/wasm/src/accepted-setup-assembly-runtime', () => ({
    createAcceptedSetupEvaluatorComponentBacking: (input: {
        readExactRange(
            sourceByteOffset: bigint,
            exactByteLength: number,
        ): Promise<Uint8Array>;
        release(): void;
    }) => {
        boundaryMocks.retainedBackingInputs.push(input);
        return Object.freeze({ input });
    },
    readAcceptedSetupPrepackageEvaluatorComponentExactRange: (input: {
        exactByteLength: number;
        materialRoot: Uint8Array;
        sourceByteOffset: bigint;
    }) => {
        const componentOrdinal = input.materialRoot[0] - 1;
        return boundaryMocks.retainedBackingInputs[
            componentOrdinal
        ].readExactRange(input.sourceByteOffset, input.exactByteLength);
    },
    releaseUnretainedAcceptedSetupEvaluatorComponentBackings: (
        backings: readonly Readonly<{ input: { release(): void } }>[],
    ) => backings.forEach((backing) => backing.input.release()),
    requireAcceptedSetupEvaluatorComponentBackingsRetainable: vi.fn(),
    requireAcceptedSetupEvaluatorSourceCatalogKernelOwner: () => ({
        handle: 91,
    }),
    retainAcceptedSetupEvaluatorComponentBackings: vi.fn(),
}));

vi.mock('#packages/wasm/src/accepted-setup-package-builder-runtime', () => ({
    requireAcceptedSetupPackageBuilderKernelOwner: () => ({ handle: 92 }),
}));

type GenerationMode = 'fresh' | 'resumed';

type FakeGaloisRuntime = Readonly<{
    absorbedComponents: Array<
        Readonly<{
            bytes: number[];
            componentOrdinal: number;
            descriptor: number[];
        }>
    >;
    cancelledReadbacks: number[];
    committedGeneratedSources: Array<
        Readonly<{
            builderHandle: number;
            catalogHandle: number;
            generationSourceHandle: number;
            proofHandle: number;
        }>
    >;
    discardedGenerationSources: number[];
    discardedTerminalSources: number[];
    finishVerificationStatus: { value: number };
    generationModes: GenerationMode[];
    kernel: TranscriptCoreKernel;
    verificationFinishes: Array<
        Readonly<{ proofHandle: number; terminalSourceHandle: number }>
    >;
}>;

const writeStatus = (
    memory: WebAssembly.Memory,
    pointer: number,
    status: number,
): void => {
    new DataView(memory.buffer).setUint32(pointer, status, true);
};

const createFakeRuntime = (): FakeGaloisRuntime => {
    const memory = new WebAssembly.Memory({ initial: 3 });
    const allocations = new Map<number, number>();
    const absorbedComponents: FakeGaloisRuntime['absorbedComponents'] = [];
    const cancelledReadbacks: number[] = [];
    const committedGeneratedSources: FakeGaloisRuntime['committedGeneratedSources'] =
        [];
    const discardedGenerationSources: number[] = [];
    const discardedTerminalSources: number[] = [];
    const finishVerificationStatus = { value: 0 };
    const generationModes: GenerationMode[] = [];
    const verificationFinishes: FakeGaloisRuntime['verificationFinishes'] = [];
    const verificationDescriptors = new Map<number, number[]>();
    let nextPointer = 2_048;

    const allocate = (byteLength: number): number => {
        const pointer = Math.ceil(nextPointer / 8) * 8;
        nextPointer = pointer + byteLength;
        allocations.set(pointer, byteLength);
        return pointer;
    };
    const deallocate = (pointer: number, byteLength: number): void => {
        if (allocations.get(pointer) !== byteLength) {
            throw new Error('The fake Galois allocation length changed.');
        }
        allocations.delete(pointer);
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
    const prepare =
        (mode: GenerationMode) =>
        (...parameters: PrepareArguments): number => {
            generationModes.push(mode);
            new DataView(memory.buffer).setUint32(parameters[13], 21, true);
            writeStatus(memory, parameters[14], 0);
            return 31;
        };
    const componentBytes = [
        Uint8Array.of(0xa1, 0xa2, 0xa3),
        Uint8Array.of(0xb1, 0xb2, 0xb3, 0xb4, 0xb5),
    ];
    const wasmExports = {
        sealed_lattice_common_proof_release_suite: () => 0,
        sealed_lattice_common_proof_select_suite: (
            _pointer: number,
            _byteLength: number,
            statusPointer: number,
        ) => {
            writeStatus(memory, statusPointer, 0);
            return 11;
        },
        sealed_lattice_galois_key_share_prepare_generation: prepare('fresh'),
        sealed_lattice_galois_key_share_prepare_resumed_generation:
            prepare('resumed'),
        sealed_lattice_galois_key_share_component_readback_open: (
            _sourceHandle: number,
            statusPointer: number,
        ) => {
            writeStatus(memory, statusPointer, 0);
            return 41;
        },
        sealed_lattice_galois_key_share_component_readback_component_count: (
            _readbackHandle: number,
            statusPointer: number,
        ) => {
            writeStatus(memory, statusPointer, 0);
            return componentBytes.length;
        },
        sealed_lattice_galois_key_share_component_readback_descriptor_byte_length:
            (
                _readbackHandle: number,
                _componentOrdinal: number,
                statusPointer: number,
            ) => {
                writeStatus(memory, statusPointer, 0);
                return 2;
            },
        sealed_lattice_galois_key_share_component_readback_copy_descriptor: (
            _readbackHandle: number,
            componentOrdinal: number,
            outputPointer: number,
            _outputByteLength: number,
            statusPointer: number,
        ) => {
            new Uint8Array(memory.buffer, outputPointer, 2).set([
                componentOrdinal,
                0xd0 + componentOrdinal,
            ]);
            writeStatus(memory, statusPointer, 0);
            return 0;
        },
        sealed_lattice_galois_key_share_component_readback_copy_material_root: (
            _readbackHandle: number,
            componentOrdinal: number,
            outputPointer: number,
            outputByteLength: number,
        ) => {
            new Uint8Array(memory.buffer, outputPointer, outputByteLength).fill(
                componentOrdinal + 1,
            );
            return 0;
        },
        sealed_lattice_galois_key_share_component_readback_total_byte_length: (
            _readbackHandle: number,
            componentOrdinal: number,
            statusPointer: number,
        ) => {
            writeStatus(memory, statusPointer, 0);
            return BigInt(componentBytes[componentOrdinal].byteLength);
        },
        sealed_lattice_galois_key_share_component_readback_read_chunk: (
            _readbackHandle: number,
            componentOrdinal: number,
            _chunkIndex: number,
            outputPointer: number,
            outputByteLength: number,
            statusPointer: number,
        ) => {
            new Uint8Array(memory.buffer, outputPointer, outputByteLength).set(
                componentBytes[componentOrdinal],
            );
            writeStatus(memory, statusPointer, 0);
            return 0;
        },
        sealed_lattice_galois_key_share_component_readback_finish: () => 0,
        sealed_lattice_galois_key_share_component_readback_cancel: (
            _sourceHandle: number,
            readbackHandle: number,
        ) => {
            cancelledReadbacks.push(readbackHandle);
            return 0;
        },
        sealed_lattice_galois_key_share_commit_generated_source: (
            builderHandle: number,
            catalogHandle: number,
            proofHandle: number,
            generationSourceHandle: number,
        ) => {
            committedGeneratedSources.push({
                builderHandle,
                catalogHandle,
                generationSourceHandle,
                proofHandle,
            });
            return 0;
        },
        sealed_lattice_galois_key_share_discard_generation_source: (
            handle: number,
        ) => {
            discardedGenerationSources.push(handle);
            return 0;
        },
        sealed_lattice_galois_key_share_verification_ingress_begin: (
            _suiteHandle: number,
            _catalogHandle: number,
            _rosterPosition: number,
            statusPointer: number,
        ) => {
            writeStatus(memory, statusPointer, 0);
            return 71;
        },
        sealed_lattice_galois_key_share_component_begin: (
            _ingressHandle: number,
            componentOrdinal: number,
            descriptorPointer: number,
            descriptorByteLength: number,
        ) => {
            verificationDescriptors.set(
                componentOrdinal,
                Array.from(
                    new Uint8Array(
                        memory.buffer,
                        descriptorPointer,
                        descriptorByteLength,
                    ),
                ),
            );
            return 0;
        },
        sealed_lattice_galois_key_share_component_absorb_chunk: (
            _ingressHandle: number,
            componentOrdinal: number,
            _chunkIndex: number,
            chunkPointer: number,
            chunkByteLength: number,
        ) => {
            absorbedComponents.push({
                bytes: Array.from(
                    new Uint8Array(
                        memory.buffer,
                        chunkPointer,
                        chunkByteLength,
                    ),
                ),
                componentOrdinal,
                descriptor: verificationDescriptors.get(componentOrdinal)!,
            });
            return 0;
        },
        sealed_lattice_galois_key_share_component_finish: () => 0,
        sealed_lattice_galois_key_share_prepare_verification: (
            _suiteHandle: number,
            _ingressHandle: number,
            terminalPointer: number,
            statusPointer: number,
        ) => {
            new DataView(memory.buffer).setUint32(terminalPointer, 81, true);
            writeStatus(memory, statusPointer, 0);
            return 82;
        },
        sealed_lattice_galois_key_share_finish_verification: (
            proofHandle: number,
            terminalSourceHandle: number,
        ) => {
            verificationFinishes.push({ proofHandle, terminalSourceHandle });
            return finishVerificationStatus.value;
        },
        sealed_lattice_galois_key_share_discard_verification_ingress: () => 0,
        sealed_lattice_galois_key_share_discard_verification_terminal_source: (
            handle: number,
        ) => {
            discardedTerminalSources.push(handle);
            return 0;
        },
    };
    const kernel = Object.freeze({
        decodeStreamDescriptor: ({
            canonicalBytesHex,
        }: {
            canonicalBytesHex: string;
        }) => {
            const componentOrdinal = Number.parseInt(
                canonicalBytesHex.slice(0, 2),
                16,
            );
            const totalByteLength = componentBytes[componentOrdinal].byteLength;
            return {
                value: {
                    fullObjectDigest: (componentOrdinal + 31)
                        .toString(16)
                        .padStart(2, '0')
                        .repeat(64),
                    orderedChunkDigests: ['11'.repeat(64)],
                    totalByteLength: totalByteLength.toString(),
                },
            };
        },
    }) as unknown as TranscriptCoreKernel;
    const context = {
        allocate,
        deallocate,
        executeCommand: () => {
            throw new Error('The focused Galois test does not use commands.');
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
        absorbedComponents,
        cancelledReadbacks,
        committedGeneratedSources,
        discardedGenerationSources,
        discardedTerminalSources,
        finishVerificationStatus,
        generationModes,
        kernel,
        verificationFinishes,
    });
};

const createComponentStore = () => {
    const chunks = new Map<number, Uint8Array<ArrayBuffer>>();
    const release = vi.fn(() => chunks.clear());
    const store: GaloisKeyShareComponentStore = Object.freeze({
        commitChunk: (chunkIndex, chunkBytes) => {
            chunks.set(chunkIndex, chunkBytes.slice());
            return Promise.resolve();
        },
        readChunk: (chunkIndex, exactByteLength) => {
            const chunk = chunks.get(chunkIndex);
            if (chunk === undefined || chunk.byteLength !== exactByteLength) {
                return Promise.reject(
                    new Error('Missing fake Galois component chunk.'),
                );
            }
            return Promise.resolve(chunk.slice());
        },
        release,
    });
    return { chunks, release, store };
};

const generationInput = (
    runtime: FakeGaloisRuntime,
    generationMode: GenerationMode,
    componentStores: readonly GaloisKeyShareComponentStore[],
) => ({
    actionRandomnessSession: Object.freeze({}),
    canonicalSuiteRecordBytes: Uint8Array.of(1, 2, 3),
    checkpointLineageIdentifier: new Uint8Array(32).fill(7),
    componentStores,
    evaluatorSourceCatalog: Object.freeze({}),
    externalMemory: Object.freeze({}),
    generationMode,
    kernel: runtime.kernel,
    options:
        generationMode === 'resumed'
            ? Object.freeze({ resume: Object.freeze({}) })
            : undefined,
    packageBuilder: Object.freeze({}),
    proofOutputStore: Object.freeze({}),
    setupGenerationAuthority: Object.freeze({}),
    setupIntentObject: Object.freeze({}),
    verifiedReservation: Object.freeze({}),
});

beforeEach(() => {
    vi.clearAllMocks();
    boundaryMocks.retainedBackingInputs.length = 0;
});

describe('accepted-setup Galois key-share runtime', () => {
    it.each(['fresh', 'resumed'] as const)(
        'commits and positively verifies every %s batch component',
        async (generationMode) => {
            const runtime = createFakeRuntime();
            const componentStores = [
                createComponentStore(),
                createComponentStore(),
            ];
            const generated = await generateGaloisKeyShareBatchInClosedWorker(
                generationInput(
                    runtime,
                    generationMode,
                    componentStores.map(({ store }) => store),
                ) as never,
            );

            expect(runtime.generationModes).toEqual([generationMode]);
            expect(runtime.committedGeneratedSources).toEqual([
                {
                    builderHandle: 92,
                    catalogHandle: 91,
                    generationSourceHandle: 21,
                    proofHandle: 51,
                },
            ]);
            expect(
                componentStores.map(({ chunks }) =>
                    Array.from(chunks.get(0) ?? []),
                ),
            ).toEqual([
                [0xa1, 0xa2, 0xa3],
                [0xb1, 0xb2, 0xb3, 0xb4, 0xb5],
            ]);
            expect(generated.proofDescriptorBytes).toEqual(
                Uint8Array.of(0xd1, 0xd2),
            );

            await verifyGaloisKeyShareBatchInClosedWorker({
                canonicalSuiteRecordBytes: Uint8Array.of(1, 2, 3),
                components: generated.components,
                evaluatorSourceCatalog: Object.freeze({}) as never,
                inputStore: Object.freeze({}) as never,
                kernel: runtime.kernel,
                rosterPosition: 4,
            });

            expect(runtime.absorbedComponents).toEqual([
                {
                    bytes: [0xa1, 0xa2, 0xa3],
                    componentOrdinal: 0,
                    descriptor: [0, 0xd0],
                },
                {
                    bytes: [0xb1, 0xb2, 0xb3, 0xb4, 0xb5],
                    componentOrdinal: 1,
                    descriptor: [1, 0xd1],
                },
            ]);
            expect(runtime.verificationFinishes).toEqual([
                { proofHandle: 61, terminalSourceHandle: 81 },
            ]);
            componentStores.forEach(({ release }) =>
                expect(release).not.toHaveBeenCalled(),
            );
        },
    );

    it('cancels readback and all stores when the suite-fixed count is wrong', async () => {
        const runtime = createFakeRuntime();
        const onlyStore = createComponentStore();

        await expect(
            generateGaloisKeyShareBatchInClosedWorker(
                generationInput(runtime, 'fresh', [onlyStore.store]) as never,
            ),
        ).rejects.toMatchObject({ refusalReason: 'wrongTypeOrLength' });

        expect(runtime.cancelledReadbacks).toEqual([41]);
        expect(runtime.discardedGenerationSources).toEqual([21]);
        expect(boundaryMocks.generatedCapabilityRelease).toHaveBeenCalledOnce();
        expect(onlyStore.release).toHaveBeenCalledOnce();
    });

    it('releases generic proof authority and terminal source after refusal', async () => {
        const runtime = createFakeRuntime();
        const componentStores = [
            createComponentStore(),
            createComponentStore(),
        ];
        const generated = await generateGaloisKeyShareBatchInClosedWorker(
            generationInput(
                runtime,
                'fresh',
                componentStores.map(({ store }) => store),
            ) as never,
        );
        runtime.finishVerificationStatus.value =
            refusalReasonCodes.invalidProof;

        await expect(
            verifyGaloisKeyShareBatchInClosedWorker({
                canonicalSuiteRecordBytes: Uint8Array.of(1, 2, 3),
                components: generated.components,
                evaluatorSourceCatalog: Object.freeze({}) as never,
                inputStore: Object.freeze({}) as never,
                kernel: runtime.kernel,
                rosterPosition: 4,
            }),
        ).rejects.toMatchObject({ refusalReason: 'invalidProof' });

        expect(boundaryMocks.verifiedCapabilityRelease).toHaveBeenCalledOnce();
        expect(runtime.discardedTerminalSources).toEqual([81]);
    });
});
