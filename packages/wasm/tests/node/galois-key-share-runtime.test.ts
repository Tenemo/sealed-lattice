import { refusalReasonCodes } from '@sealed-lattice/types';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import {
    bindGeneratedEvaluatorSourceProofsToAcceptedSetupPackage,
    generateGaloisKeyShareInClosedWorker,
    verifyGaloisKeyShareInClosedWorker,
    type GeneratedGaloisKeyShareTransport,
} from '#packages/wasm/src/galois-key-share-runtime';
import { registerCommonProofKernelContext } from '#packages/wasm/src/transcript-core-bridge/common-proof-kernel-context';
import type { TranscriptCoreKernelCommandRuntime } from '#packages/wasm/src/transcript-core-bridge/kernel-runtime';
import type { TranscriptCoreKernel } from '#packages/wasm/src/transcript-core-bridge/kernel-types';

const boundaryMocks = vi.hoisted(() => {
    const activeContext: {
        value: TranscriptCoreKernelCommandRuntime | undefined;
    } = { value: undefined };
    const generatedCapabilityRelease = vi.fn();
    const verifiedCapabilityRelease = vi.fn();
    return {
        activeContext,
        applyGeneratedCapability: vi.fn(
            (
                _capability: unknown,
                _context: unknown,
                apply: (
                    handle: number,
                ) => Readonly<{ consumed: boolean; result: unknown }>,
            ) => apply(301).result,
        ),
        applyVerifiedCapability: vi.fn(
            (
                _capability: unknown,
                _context: unknown,
                apply: (
                    handle: number,
                ) => Readonly<{ consumed: boolean; result: unknown }>,
            ) => apply(401).result,
        ),
        bindPackage: vi.fn(),
        createBacking: vi.fn(() => Object.freeze({})),
        deriveProofDescriptor: vi.fn(async () => Uint8Array.of(0xd1)),
        generatedCapabilityRelease,
        openGenerationAdapter: vi.fn(() => Object.freeze({})),
        openVerificationAdapter: vi.fn(() => Object.freeze({})),
        readComponentRange: vi.fn(
            async (input: {
                exactByteLength: number;
                materialRoot: Uint8Array;
            }) => {
                const bytes = new Uint8Array(input.exactByteLength);
                bytes.fill(input.materialRoot[0] ?? 0);
                return bytes;
            },
        ),
        releaseGenerationAdapter: vi.fn(),
        releaseUnretainedBackings: vi.fn(),
        releaseVerificationAdapter: vi.fn(),
        requireBackingsRetainable: vi.fn(),
        requireCatalogOwner: vi.fn(
            (
                _catalog: unknown,
                kernel: TranscriptCoreKernel,
                _phase: string,
            ) => Object.freeze({ handle: 91, kernel }),
        ),
        retainBackings: vi.fn(),
        runGeneration: vi.fn(async () =>
            Object.freeze({ release: generatedCapabilityRelease }),
        ),
        runVerification: vi.fn(async () =>
            Object.freeze({ release: verifiedCapabilityRelease }),
        ),
        trackOutput: vi.fn((outputStore: unknown) =>
            Object.freeze({
                outputChunkByteLengths: Object.freeze([2]),
                outputStore,
            }),
        ),
        verifiedCapabilityRelease,
    };
});

vi.mock('#packages/wasm/src/accepted-setup-assembly-runtime', () => ({
    bindAcceptedSetupEvaluatorGeneratedProofsToPackage:
        boundaryMocks.bindPackage,
    createAcceptedSetupEvaluatorComponentBacking: boundaryMocks.createBacking,
    readAcceptedSetupPrepackageEvaluatorComponentExactRange:
        boundaryMocks.readComponentRange,
    releaseUnretainedAcceptedSetupEvaluatorComponentBackings:
        boundaryMocks.releaseUnretainedBackings,
    requireAcceptedSetupEvaluatorComponentBackingsRetainable:
        boundaryMocks.requireBackingsRetainable,
    requireAcceptedSetupEvaluatorSourceCatalogKernelOwner:
        boundaryMocks.requireCatalogOwner,
    retainAcceptedSetupEvaluatorComponentBackings:
        boundaryMocks.retainBackings,
}));

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
        boundaryMocks.applyGeneratedCapability,
    applyClosedWorkerVerifiedCommonProofCapability:
        boundaryMocks.applyVerifiedCapability,
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

type FakeGaloisRuntime = Readonly<{
    allocations: ReadonlyMap<number, number>;
    componentBeginCalls: Array<Readonly<{ descriptor: number; ordinal: number }>>;
    componentBeginStatuses: Map<number, number>;
    componentCancelCalls: Array<
        Readonly<{ readbackHandle: number; sourceHandle: number }>
    >;
    componentChunkCalls: Array<
        Readonly<{ bytes: readonly number[]; chunkIndex: number; ordinal: number }>
    >;
    componentFinishCalls: number[];
    componentReadbackFinishCalls: Array<
        Readonly<{ readbackHandle: number; sourceHandle: number }>
    >;
    generatedSourceCommits: Array<
        Readonly<{
            catalogHandle: number;
            generatedProofHandle: number;
            sourceHandle: number;
        }>
    >;
    generatedSourceCommitStatus: { value: number };
    generationLifecycleEvents: string[];
    generationPreparations: Array<'fresh' | 'resumed'>;
    generationSourceDiscards: number[];
    kernel: TranscriptCoreKernel;
    selectedSuiteReleases: number[];
    verificationFinishes: Array<
        Readonly<{ terminalSourceHandle: number; verifiedProofHandle: number }>
    >;
    verificationIngressDiscards: number[];
    verificationTerminalSourceDiscards: number[];
}>;

const writeStatus = (
    memory: WebAssembly.Memory,
    pointer: number,
    status: number,
): void => {
    new DataView(memory.buffer).setUint32(pointer, status, true);
};

const createFakeGaloisRuntime = (): FakeGaloisRuntime => {
    const memory = new WebAssembly.Memory({ initial: 2 });
    const allocations = new Map<number, number>();
    const selectedSuiteReleases: number[] = [];
    const generationSourceDiscards: number[] = [];
    const componentCancelCalls: Array<
        Readonly<{ readbackHandle: number; sourceHandle: number }>
    > = [];
    const generatedSourceCommits: Array<
        Readonly<{
            catalogHandle: number;
            generatedProofHandle: number;
            sourceHandle: number;
        }>
    > = [];
    const generatedSourceCommitStatus = { value: 0 };
    const generationLifecycleEvents: string[] = [];
    const generationPreparations: Array<'fresh' | 'resumed'> = [];
    const componentBeginCalls: Array<
        Readonly<{ descriptor: number; ordinal: number }>
    > = [];
    const componentChunkCalls: Array<
        Readonly<{ bytes: readonly number[]; chunkIndex: number; ordinal: number }>
    > = [];
    const componentFinishCalls: number[] = [];
    const componentReadbackFinishCalls: Array<
        Readonly<{ readbackHandle: number; sourceHandle: number }>
    > = [];
    const componentBeginStatuses = new Map<number, number>();
    const verificationFinishes: Array<
        Readonly<{ terminalSourceHandle: number; verifiedProofHandle: number }>
    > = [];
    const verificationIngressDiscards: number[] = [];
    const verificationTerminalSourceDiscards: number[] = [];
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
                'The fake Galois allocation was released with the wrong length.',
            );
        }
        allocations.delete(pointer);
    };
    const readBytes = (pointer: number, byteLength: number): number[] =>
        Array.from(new Uint8Array(memory.buffer, pointer, byteLength));

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
        sealed_lattice_galois_key_share_commit_generated_source: (
            catalogHandle: number,
            generatedProofHandle: number,
            sourceHandle: number,
        ) => {
            generationLifecycleEvents.push('source commit attempted');
            generatedSourceCommits.push({
                catalogHandle,
                generatedProofHandle,
                sourceHandle,
            });
            return generatedSourceCommitStatus.value;
        },
        sealed_lattice_galois_key_share_component_absorb_chunk: (
            _ingressHandle: number,
            ordinal: number,
            chunkIndex: number,
            pointer: number,
            byteLength: number,
        ) => {
            componentChunkCalls.push({
                bytes: readBytes(pointer, byteLength),
                chunkIndex,
                ordinal,
            });
            return 0;
        },
        sealed_lattice_galois_key_share_component_begin: (
            _ingressHandle: number,
            ordinal: number,
            pointer: number,
            byteLength: number,
        ) => {
            componentBeginCalls.push({
                descriptor: readBytes(pointer, byteLength)[0] ?? 0,
                ordinal,
            });
            return componentBeginStatuses.get(ordinal) ?? 0;
        },
        sealed_lattice_galois_key_share_component_finish: (
            _ingressHandle: number,
            ordinal: number,
        ) => {
            componentFinishCalls.push(ordinal);
            return 0;
        },
        sealed_lattice_galois_key_share_component_readback_cancel: (
            sourceHandle: number,
            readbackHandle: number,
        ) => {
            componentCancelCalls.push({ readbackHandle, sourceHandle });
            return 0;
        },
        sealed_lattice_galois_key_share_component_readback_component_count: (
            _readbackHandle: number,
            statusPointer: number,
        ) => {
            writeStatus(memory, statusPointer, 0);
            return 4;
        },
        sealed_lattice_galois_key_share_component_readback_copy_descriptor: (
            _readbackHandle: number,
            ordinal: number,
            pointer: number,
            byteLength: number,
            statusPointer: number,
        ) => {
            new Uint8Array(memory.buffer, pointer, byteLength).fill(
                0x70 + ordinal,
            );
            writeStatus(memory, statusPointer, 0);
            return 0;
        },
        sealed_lattice_galois_key_share_component_readback_copy_material_root: (
            _readbackHandle: number,
            ordinal: number,
            pointer: number,
            byteLength: number,
        ) => {
            new Uint8Array(memory.buffer, pointer, byteLength).fill(ordinal + 1);
            return 0;
        },
        sealed_lattice_galois_key_share_component_readback_descriptor_byte_length:
            (
                _readbackHandle: number,
                _ordinal: number,
                statusPointer: number,
            ) => {
                writeStatus(memory, statusPointer, 0);
                return 1;
            },
        sealed_lattice_galois_key_share_component_readback_finish: (
            sourceHandle: number,
            readbackHandle: number,
        ) => {
            generationLifecycleEvents.push('component readback finished');
            componentReadbackFinishCalls.push({
                readbackHandle,
                sourceHandle,
            });
            return 0;
        },
        sealed_lattice_galois_key_share_component_readback_open: (
            _sourceHandle: number,
            statusPointer: number,
        ) => {
            writeStatus(memory, statusPointer, 0);
            return 44;
        },
        sealed_lattice_galois_key_share_component_readback_read_chunk: (
            _readbackHandle: number,
            ordinal: number,
            _chunkIndex: number,
            pointer: number,
            byteLength: number,
            statusPointer: number,
        ) => {
            new Uint8Array(memory.buffer, pointer, byteLength).fill(ordinal + 1);
            writeStatus(memory, statusPointer, 0);
            return 0;
        },
        sealed_lattice_galois_key_share_component_readback_total_byte_length: (
            _readbackHandle: number,
            _ordinal: number,
            statusPointer: number,
        ) => {
            writeStatus(memory, statusPointer, 0);
            return 2n;
        },
        sealed_lattice_galois_key_share_discard_generation_source: (
            handle: number,
        ) => {
            generationSourceDiscards.push(handle);
            return 0;
        },
        sealed_lattice_galois_key_share_discard_verification_ingress: (
            handle: number,
        ) => {
            verificationIngressDiscards.push(handle);
            return 0;
        },
        sealed_lattice_galois_key_share_discard_verification_terminal_source: (
            handle: number,
        ) => {
            verificationTerminalSourceDiscards.push(handle);
            return 0;
        },
        sealed_lattice_galois_key_share_finish_verification: (
            verifiedProofHandle: number,
            terminalSourceHandle: number,
        ) => {
            verificationFinishes.push({
                terminalSourceHandle,
                verifiedProofHandle,
            });
            return 0;
        },
        sealed_lattice_galois_key_share_prepare_generation: (
            _selectedSuiteHandle: number,
            _setupGenerationAuthorityHandle: number,
            _actionRandomnessHandle: number,
            _stateSessionHandle: number,
            _stateCapabilityPointer: number,
            _stateCapabilityByteLength: number,
            _reservationHandle: number,
            _boardSessionHandle: number,
            _boardCapabilityPointer: number,
            _boardCapabilityByteLength: number,
            _setupIntentHandle: number,
            _checkpointPointer: number,
            _checkpointByteLength: number,
            sourceHandlePointer: number,
            statusPointer: number,
        ) => {
            generationPreparations.push('fresh');
            new DataView(memory.buffer).setUint32(
                sourceHandlePointer,
                22,
                true,
            );
            writeStatus(memory, statusPointer, 0);
            return 33;
        },
        sealed_lattice_galois_key_share_prepare_resumed_generation: (
            _selectedSuiteHandle: number,
            _setupGenerationAuthorityHandle: number,
            _actionRandomnessHandle: number,
            _stateSessionHandle: number,
            _stateCapabilityPointer: number,
            _stateCapabilityByteLength: number,
            _reservationHandle: number,
            _boardSessionHandle: number,
            _boardCapabilityPointer: number,
            _boardCapabilityByteLength: number,
            _setupIntentHandle: number,
            _checkpointPointer: number,
            _checkpointByteLength: number,
            sourceHandlePointer: number,
            statusPointer: number,
        ) => {
            generationPreparations.push('resumed');
            new DataView(memory.buffer).setUint32(
                sourceHandlePointer,
                22,
                true,
            );
            writeStatus(memory, statusPointer, 0);
            return 33;
        },
        sealed_lattice_galois_key_share_prepare_verification: (
            _selectedSuiteHandle: number,
            _ingressHandle: number,
            sourceHandlePointer: number,
            statusPointer: number,
        ) => {
            new DataView(memory.buffer).setUint32(
                sourceHandlePointer,
                61,
                true,
            );
            writeStatus(memory, statusPointer, 0);
            return 62;
        },
        sealed_lattice_galois_key_share_verification_ingress_begin: (
            _selectedSuiteHandle: number,
            _catalogHandle: number,
            _rosterPosition: number,
            statusPointer: number,
        ) => {
            writeStatus(memory, statusPointer, 0);
            return 51;
        },
    };
    const kernel = Object.freeze({
        decodeStreamDescriptor: () => ({
            value: {
                fullObjectDigest: '21'.repeat(64),
                orderedChunkDigests: Object.freeze(['22'.repeat(64)]),
                totalByteLength: '2',
            },
        }),
    }) as unknown as TranscriptCoreKernel;
    const context = {
        allocate,
        deallocate,
        executeCommand: () => {
            throw new Error('The opaque boundary test does not use commands.');
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
        componentBeginCalls,
        componentBeginStatuses,
        componentCancelCalls,
        componentChunkCalls,
        componentFinishCalls,
        componentReadbackFinishCalls,
        generatedSourceCommits,
        generatedSourceCommitStatus,
        generationLifecycleEvents,
        generationPreparations,
        generationSourceDiscards,
        kernel,
        selectedSuiteReleases,
        verificationFinishes,
        verificationIngressDiscards,
        verificationTerminalSourceDiscards,
    });
};

const createCanonicalOutputStore = () => {
    const chunks = new Map<number, Uint8Array<ArrayBuffer>>();
    return Object.freeze({
        commitChunk: async (
            chunkIndex: number,
            chunkBytes: Uint8Array<ArrayBuffer>,
        ): Promise<void> => {
            chunks.set(chunkIndex, chunkBytes.slice());
        },
        readChunk: async (
            chunkIndex: number,
            exactByteLength: number,
        ): Promise<Uint8Array<ArrayBuffer>> => {
            const bytes = chunks.get(chunkIndex);
            if (bytes === undefined || bytes.byteLength !== exactByteLength) {
                throw new Error('The requested opaque test chunk is absent.');
            }
            return bytes.slice();
        },
    });
};

const generationInput = (runtime: FakeGaloisRuntime) => ({
    actionRandomnessSession: Object.freeze({}),
    canonicalSuiteRecordBytes: Uint8Array.of(0xa1),
    checkpointLineageIdentifier: new Uint8Array(32).fill(0xb2),
    componentOutputStores: {
        resolveOutputStore: vi.fn(async () => createCanonicalOutputStore()),
    },
    evaluatorSourceCatalog: Object.freeze({}),
    externalMemory: Object.freeze({}),
    generationMode: 'fresh' as const,
    kernel: runtime.kernel,
    outputStore: createCanonicalOutputStore(),
    setupGenerationAuthority: Object.freeze({}),
    setupIntentObject: Object.freeze({}),
    verifiedReservation: Object.freeze({}),
});

beforeEach(() => {
    vi.clearAllMocks();
});

describe('Galois key-share package-internal lifecycle', () => {
    it('persists every Rust-minted component before committing the generated source', async () => {
        const runtime = createFakeGaloisRuntime();

        const transport = await generateGaloisKeyShareInClosedWorker(
            generationInput(runtime) as never,
        );

        expect(transport.orderedComponents).toHaveLength(4);
        expect(
            transport.orderedComponents.map(
                (component) => component.canonicalDescriptorBytes[0],
            ),
        ).toEqual([0x70, 0x71, 0x72, 0x73]);
        expect(runtime.generatedSourceCommits).toEqual([
            {
                catalogHandle: 91,
                generatedProofHandle: 301,
                sourceHandle: 22,
            },
        ]);
        expect(runtime.generationPreparations).toEqual(['fresh']);
        expect(runtime.generationLifecycleEvents).toEqual([
            'component readback finished',
            'source commit attempted',
        ]);
        expect(boundaryMocks.retainBackings).toHaveBeenCalledOnce();
        expect(boundaryMocks.requireBackingsRetainable).toHaveBeenCalledOnce();
        expect(boundaryMocks.createBacking).toHaveBeenCalledTimes(4);
        expect(boundaryMocks.generatedCapabilityRelease).not.toHaveBeenCalled();
        expect(runtime.generationSourceDiscards).toEqual([]);
        expect(runtime.componentCancelCalls).toEqual([]);
        expect(runtime.componentReadbackFinishCalls).toEqual([
            { readbackHandle: 44, sourceHandle: 22 },
        ]);
        expect(runtime.selectedSuiteReleases).toEqual([11]);
        expect(runtime.allocations.size).toBe(0);
    });

    it('uses resumed preparation only with authenticated resume custody', async () => {
        const runtime = createFakeGaloisRuntime();
        const input = generationInput(runtime);
        const options = Object.freeze({
            resume: Object.freeze({
                checkpointCustody: Object.freeze({
                    publishAuthenticatedCheckpoint: vi.fn(),
                    restoreAuthenticatedCheckpointState: vi.fn(),
                }),
                prefixReplayExternalMemory: Object.freeze({
                    executeDeterministicPrefixReplayTransaction: vi.fn(),
                }),
            }),
        });

        await generateGaloisKeyShareInClosedWorker({
            ...input,
            generationMode: 'resumed',
            options,
        } as never);

        expect(runtime.generationPreparations).toEqual(['resumed']);
        expect(boundaryMocks.runGeneration).toHaveBeenCalledWith(
            expect.anything(),
            input.externalMemory,
            expect.anything(),
            options,
        );

        const mismatchedRuntime = createFakeGaloisRuntime();
        await expect(
            generateGaloisKeyShareInClosedWorker({
                ...generationInput(mismatchedRuntime),
                options,
            } as never),
        ).rejects.toThrow();
        expect(mismatchedRuntime.generationPreparations).toEqual([]);
        expect(mismatchedRuntime.allocations.size).toBe(0);

        const invalidModeRuntime = createFakeGaloisRuntime();
        await expect(
            generateGaloisKeyShareInClosedWorker({
                ...generationInput(invalidModeRuntime),
                generationMode: 'invalid',
            } as never),
        ).rejects.toThrow();
        expect(invalidModeRuntime.generationPreparations).toEqual([]);
        expect(invalidModeRuntime.allocations.size).toBe(0);
    });

    it('cancels forward-only readback and retires both proof owners after storage failure', async () => {
        const runtime = createFakeGaloisRuntime();
        const input = generationInput(runtime);
        input.componentOutputStores.resolveOutputStore.mockResolvedValue(
            Object.freeze({
                commitChunk: async () => {
                    throw new Error('authenticated component storage failed');
                },
                readChunk: async () => Uint8Array.of(0, 0),
            }),
        );

        await expect(
            generateGaloisKeyShareInClosedWorker(input as never),
        ).rejects.toThrow('authenticated component storage failed');

        expect(runtime.componentCancelCalls).toEqual([
            { readbackHandle: 44, sourceHandle: 22 },
        ]);
        expect(runtime.componentReadbackFinishCalls).toEqual([]);
        expect(boundaryMocks.generatedCapabilityRelease).toHaveBeenCalledOnce();
        expect(runtime.generationSourceDiscards).toEqual([22]);
        expect(runtime.generatedSourceCommits).toEqual([]);
        expect(runtime.allocations.size).toBe(0);
    });

    it('retires uncommitted proof, source, and component custody after catalog refusal', async () => {
        const runtime = createFakeGaloisRuntime();
        runtime.generatedSourceCommitStatus.value =
            refusalReasonCodes.wrongHashOrRoot;

        await expect(
            generateGaloisKeyShareInClosedWorker(
                generationInput(runtime) as never,
            ),
        ).rejects.toThrow();

        expect(runtime.generatedSourceCommits).toHaveLength(1);
        expect(boundaryMocks.generatedCapabilityRelease).toHaveBeenCalledOnce();
        expect(runtime.generationSourceDiscards).toEqual([22]);
        expect(boundaryMocks.releaseUnretainedBackings).toHaveBeenCalledOnce();
        expect(boundaryMocks.retainBackings).not.toHaveBeenCalled();
        expect(boundaryMocks.requireBackingsRetainable).toHaveBeenCalledOnce();
        expect(runtime.componentCancelCalls).toEqual([]);
        expect(runtime.componentReadbackFinishCalls).toEqual([
            { readbackHandle: 44, sourceHandle: 22 },
        ]);
        expect(runtime.selectedSuiteReleases).toEqual([11]);
        expect(runtime.allocations.size).toBe(0);
    });

    it('rejects component-custody collisions before consuming Rust proof authority', async () => {
        const runtime = createFakeGaloisRuntime();
        boundaryMocks.requireBackingsRetainable.mockImplementationOnce(() => {
            throw new Error('component custody collision');
        });

        await expect(
            generateGaloisKeyShareInClosedWorker(
                generationInput(runtime) as never,
            ),
        ).rejects.toThrow('component custody collision');

        expect(runtime.generatedSourceCommits).toEqual([]);
        expect(boundaryMocks.generatedCapabilityRelease).toHaveBeenCalledOnce();
        expect(runtime.generationSourceDiscards).toEqual([22]);
        expect(boundaryMocks.releaseUnretainedBackings).toHaveBeenCalledOnce();
        expect(boundaryMocks.retainBackings).not.toHaveBeenCalled();
        expect(runtime.componentReadbackFinishCalls).toEqual([
            { readbackHandle: 44, sourceHandle: 22 },
        ]);
        expect(runtime.allocations.size).toBe(0);
    });

    it('streams canonical component carriers into the positive verifier terminal', async () => {
        const runtime = createFakeGaloisRuntime();
        const generated = await generateGaloisKeyShareInClosedWorker(
            generationInput(runtime) as never,
        );
        runtime.componentBeginCalls.length = 0;
        runtime.componentChunkCalls.length = 0;
        runtime.componentFinishCalls.length = 0;
        runtime.selectedSuiteReleases.length = 0;

        await verifyGaloisKeyShareInClosedWorker({
            canonicalSuiteRecordBytes: Uint8Array.of(0xa1),
            evaluatorSourceCatalog: Object.freeze({}) as never,
            kernel: runtime.kernel,
            orderedComponents: generated.orderedComponents,
            proofInputStore: Object.freeze({}) as never,
            rosterPosition: 3,
        });

        expect(runtime.componentBeginCalls).toEqual([
            { descriptor: 0x70, ordinal: 0 },
            { descriptor: 0x71, ordinal: 1 },
            { descriptor: 0x72, ordinal: 2 },
            { descriptor: 0x73, ordinal: 3 },
        ]);
        expect(runtime.componentChunkCalls).toEqual([
            { bytes: [1, 1], chunkIndex: 0, ordinal: 0 },
            { bytes: [2, 2], chunkIndex: 0, ordinal: 1 },
            { bytes: [3, 3], chunkIndex: 0, ordinal: 2 },
            { bytes: [4, 4], chunkIndex: 0, ordinal: 3 },
        ]);
        expect(runtime.componentFinishCalls).toEqual([0, 1, 2, 3]);
        expect(runtime.verificationFinishes).toEqual([
            { terminalSourceHandle: 61, verifiedProofHandle: 401 },
        ]);
        expect(boundaryMocks.verifiedCapabilityRelease).not.toHaveBeenCalled();
        expect(runtime.verificationIngressDiscards).toEqual([]);
        expect(runtime.verificationTerminalSourceDiscards).toEqual([]);
        expect(runtime.selectedSuiteReleases).toEqual([11]);
        expect(runtime.allocations.size).toBe(0);
    });

    it('restores the package statement source when a component binding is refused', async () => {
        const runtime = createFakeGaloisRuntime();
        runtime.componentBeginStatuses.set(
            1,
            refusalReasonCodes.wrongHashOrRoot,
        );
        const components: GeneratedGaloisKeyShareTransport['orderedComponents'] =
            Object.freeze(
                Array.from({ length: 4 }, (_, ordinal) =>
                    Object.freeze({
                        canonicalDescriptorBytes: Uint8Array.of(
                            0x70 + ordinal,
                        ),
                        materialRoot: new Uint8Array(64).fill(ordinal + 1),
                    }),
                ),
            );

        await expect(
            verifyGaloisKeyShareInClosedWorker({
                canonicalSuiteRecordBytes: Uint8Array.of(0xa1),
                evaluatorSourceCatalog: Object.freeze({}) as never,
                kernel: runtime.kernel,
                orderedComponents: components,
                proofInputStore: Object.freeze({}) as never,
                rosterPosition: 4,
            }),
        ).rejects.toThrow();

        expect(runtime.verificationIngressDiscards).toEqual([51]);
        expect(runtime.verificationFinishes).toEqual([]);
        expect(boundaryMocks.runVerification).not.toHaveBeenCalled();
        expect(runtime.selectedSuiteReleases).toEqual([11]);
        expect(runtime.allocations.size).toBe(0);
    });

    it('discards the terminal source when generic verification is cancelled', async () => {
        const runtime = createFakeGaloisRuntime();
        boundaryMocks.runVerification.mockRejectedValueOnce(
            new Error('generic verifier cancelled'),
        );
        const components: GeneratedGaloisKeyShareTransport['orderedComponents'] =
            Object.freeze(
                Array.from({ length: 4 }, (_, ordinal) =>
                    Object.freeze({
                        canonicalDescriptorBytes: Uint8Array.of(
                            0x70 + ordinal,
                        ),
                        materialRoot: new Uint8Array(64).fill(ordinal + 1),
                    }),
                ),
            );

        await expect(
            verifyGaloisKeyShareInClosedWorker({
                canonicalSuiteRecordBytes: Uint8Array.of(0xa1),
                evaluatorSourceCatalog: Object.freeze({}) as never,
                kernel: runtime.kernel,
                orderedComponents: components,
                proofInputStore: Object.freeze({}) as never,
                rosterPosition: 6,
            }),
        ).rejects.toThrow('generic verifier cancelled');

        expect(runtime.verificationIngressDiscards).toEqual([]);
        expect(runtime.verificationTerminalSourceDiscards).toEqual([61]);
        expect(runtime.verificationFinishes).toEqual([]);
        expect(runtime.selectedSuiteReleases).toEqual([11]);
        expect(runtime.allocations.size).toBe(0);
    });

    it('delegates joint package binding without exposing either kernel handle', () => {
        const runtime = createFakeGaloisRuntime();
        const acceptedSetupVerification = Object.freeze({});
        const evaluatorSourceCatalog = Object.freeze({});

        bindGeneratedEvaluatorSourceProofsToAcceptedSetupPackage({
            acceptedSetupVerification: acceptedSetupVerification as never,
            evaluatorSourceCatalog: evaluatorSourceCatalog as never,
            kernel: runtime.kernel,
        });

        expect(boundaryMocks.bindPackage).toHaveBeenCalledExactlyOnceWith({
            acceptedSetupVerification,
            catalog: evaluatorSourceCatalog,
            kernel: runtime.kernel,
        });
    });
});
