import { foundationProfile } from '@sealed-lattice/types';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { activateRelinearizationRoundTwoInClosedWorker } from '#packages/wasm/src/accepted-setup-relinearization-generation-runtime';
import {
    CanonicalStreamCancellationError,
    CanonicalStreamInternalError,
} from '#packages/wasm/src/canonical-stream-runtime';
import { registerCommonProofKernelContext } from '#packages/wasm/src/transcript-core-bridge/common-proof-kernel-context';
import type { TranscriptCoreKernelCommandRuntime } from '#packages/wasm/src/transcript-core-bridge/kernel-runtime';
import type { TranscriptCoreKernel } from '#packages/wasm/src/transcript-core-bridge/kernel-types';

type SourceRequest = Readonly<{
    chunkIndex: number;
    componentOrdinal: number;
    materialRootByte: number;
    sourceBytes: Uint8Array<ArrayBuffer>;
    streamByteOffset: bigint;
    streamDigestByte: number;
    totalByteLength: bigint;
}>;

const boundaryMocks = vi.hoisted(() => ({
    activeContext: {
        value: undefined as TranscriptCoreKernelCommandRuntime | undefined,
    },
    readExactRange: vi.fn(),
}));

vi.mock('#packages/wasm/src/accepted-setup-assembly-runtime', () => ({
    readAcceptedSetupPrepackageEvaluatorComponentExactRange:
        boundaryMocks.readExactRange,
    requireAcceptedSetupEvaluatorSourceCatalogKernelOwner: () => ({
        handle: 91,
    }),
}));

vi.mock('#packages/wasm/src/setup-generation-recipient-payload', () => ({
    resolveSetupGenerationAuthorityKernelAuthorization: () => ({
        context: boundaryMocks.activeContext.value,
        handle: 14,
    }),
}));

type AbsorbedSource = Readonly<{
    bytes: number[];
    chunkIndex: number;
    componentOrdinal: number;
    materialRoot: number[];
    streamByteOffset: bigint;
    streamDigest: number[];
    totalByteLength: bigint;
}>;

type FakeRuntime = Readonly<{
    absorbedSources: AbsorbedSource[];
    beginArguments: Array<readonly [number, number, number]>;
    discardedActivationHandles: number[];
    finishedActivationHandles: number[];
    kernel: TranscriptCoreKernel;
    releasedSuiteHandles: number[];
}>;

const writeUnsigned32 = (
    memory: WebAssembly.Memory,
    pointer: number,
    value: number,
): void => {
    new DataView(memory.buffer).setUint32(pointer, value, true);
};

const writeUnsigned64 = (
    memory: WebAssembly.Memory,
    pointer: number,
    value: bigint,
): void => {
    new DataView(memory.buffer).setBigUint64(pointer, value, true);
};

const createFakeRuntime = (requests: readonly SourceRequest[]): FakeRuntime => {
    const memory = new WebAssembly.Memory({ initial: 2 });
    const allocations = new Map<number, number>();
    const absorbedSources: AbsorbedSource[] = [];
    const beginArguments: Array<readonly [number, number, number]> = [];
    const discardedActivationHandles: number[] = [];
    const finishedActivationHandles: number[] = [];
    const releasedSuiteHandles: number[] = [];
    let nextPointer = 4_096;
    let nextRequestOrdinal = 0;

    const allocate = (byteLength: number): number => {
        const pointer = Math.ceil(nextPointer / 8) * 8;
        nextPointer = pointer + byteLength;
        allocations.set(pointer, byteLength);
        return pointer;
    };
    const deallocate = (pointer: number, byteLength: number): void => {
        if (allocations.get(pointer) !== byteLength) {
            throw new Error(
                'The fake relinearization allocation length changed.',
            );
        }
        allocations.delete(pointer);
    };
    const unusedBoundary = () => 0;
    const wasmExports = {
        sealed_lattice_common_proof_release_suite: (handle: number) => {
            releasedSuiteHandles.push(handle);
            return 0;
        },
        sealed_lattice_common_proof_select_suite: (
            _pointer: number,
            _byteLength: number,
            statusPointer: number,
        ) => {
            writeUnsigned32(memory, statusPointer, 0);
            return 11;
        },
        sealed_lattice_relinearization_round_two_activation_begin: (
            selectedSuiteHandle: number,
            setupGenerationAuthorityHandle: number,
            prepackageCatalogHandle: number,
            statusPointer: number,
        ) => {
            beginArguments.push([
                selectedSuiteHandle,
                setupGenerationAuthorityHandle,
                prepackageCatalogHandle,
            ]);
            writeUnsigned32(memory, statusPointer, 0);
            return 21;
        },
        sealed_lattice_relinearization_round_two_activation_next_source_read: (
            _activationHandle: number,
            componentOrdinalPointer: number,
            materialRootPointer: number,
            materialRootByteLength: number,
            streamDigestPointer: number,
            streamDigestByteLength: number,
            totalByteLengthPointer: number,
            streamByteOffsetPointer: number,
            chunkIndexPointer: number,
            sourceByteLengthPointer: number,
            statusPointer: number,
        ) => {
            writeUnsigned32(memory, statusPointer, 0);
            const request = requests[nextRequestOrdinal];
            if (request === undefined) {
                return 0;
            }
            nextRequestOrdinal += 1;
            writeUnsigned32(
                memory,
                componentOrdinalPointer,
                request.componentOrdinal,
            );
            new Uint8Array(
                memory.buffer,
                materialRootPointer,
                materialRootByteLength,
            ).fill(request.materialRootByte);
            new Uint8Array(
                memory.buffer,
                streamDigestPointer,
                streamDigestByteLength,
            ).fill(request.streamDigestByte);
            writeUnsigned64(
                memory,
                totalByteLengthPointer,
                request.totalByteLength,
            );
            writeUnsigned64(
                memory,
                streamByteOffsetPointer,
                request.streamByteOffset,
            );
            writeUnsigned32(memory, chunkIndexPointer, request.chunkIndex);
            writeUnsigned32(
                memory,
                sourceByteLengthPointer,
                request.sourceBytes.byteLength,
            );
            return 1;
        },
        sealed_lattice_relinearization_round_two_activation_absorb_source: (
            _activationHandle: number,
            componentOrdinal: number,
            materialRootPointer: number,
            materialRootByteLength: number,
            streamDigestPointer: number,
            streamDigestByteLength: number,
            totalByteLength: bigint,
            streamByteOffset: bigint,
            chunkIndex: number,
            sourcePointer: number,
            sourceByteLength: number,
        ) => {
            absorbedSources.push(
                Object.freeze({
                    bytes: Array.from(
                        new Uint8Array(
                            memory.buffer,
                            sourcePointer,
                            sourceByteLength,
                        ),
                    ),
                    chunkIndex,
                    componentOrdinal,
                    materialRoot: Array.from(
                        new Uint8Array(
                            memory.buffer,
                            materialRootPointer,
                            materialRootByteLength,
                        ),
                    ),
                    streamByteOffset,
                    streamDigest: Array.from(
                        new Uint8Array(
                            memory.buffer,
                            streamDigestPointer,
                            streamDigestByteLength,
                        ),
                    ),
                    totalByteLength,
                }),
            );
            return 0;
        },
        sealed_lattice_relinearization_round_two_activation_finish: (
            handle: number,
        ) => {
            finishedActivationHandles.push(handle);
            return 0;
        },
        sealed_lattice_relinearization_round_two_activation_discard: (
            handle: number,
        ) => {
            discardedActivationHandles.push(handle);
            return 0;
        },
        sealed_lattice_relinearization_generation_source_commit: unusedBoundary,
        sealed_lattice_relinearization_generation_component_count:
            unusedBoundary,
        sealed_lattice_relinearization_generation_component_descriptor_byte_length:
            unusedBoundary,
        sealed_lattice_relinearization_generation_component_total_byte_length:
            unusedBoundary,
        sealed_lattice_relinearization_generation_component_copy_descriptor:
            unusedBoundary,
        sealed_lattice_relinearization_generation_component_copy_material_root:
            unusedBoundary,
        sealed_lattice_relinearization_generation_source_discard:
            unusedBoundary,
        sealed_lattice_relinearization_round_one_prepare_generation:
            unusedBoundary,
        sealed_lattice_relinearization_round_one_prepare_resumed_generation:
            unusedBoundary,
        sealed_lattice_relinearization_round_two_prepare_generation:
            unusedBoundary,
        sealed_lattice_relinearization_round_two_prepare_resumed_generation:
            unusedBoundary,
        sealed_lattice_relinearization_generation_component_read_chunk:
            unusedBoundary,
    };
    const kernel = Object.freeze({}) as TranscriptCoreKernel;
    const context = {
        allocate,
        deallocate,
        executeCommand: () => {
            throw new Error(
                'The focused relinearization test does not use commands.',
            );
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
        absorbedSources,
        beginArguments,
        discardedActivationHandles,
        finishedActivationHandles,
        kernel,
        releasedSuiteHandles,
    });
};

const activationInput = (runtime: FakeRuntime) => ({
    canonicalSuiteRecordBytes: Uint8Array.of(1, 2, 3),
    evaluatorSourceCatalog: Object.freeze({}),
    kernel: runtime.kernel,
    setupGenerationAuthority: Object.freeze({}),
    yieldControl: () => Promise.resolve(),
});

beforeEach(() => {
    vi.clearAllMocks();
});

describe('accepted-setup relinearization generation runtime', () => {
    it('streams each Rust-requested aggregate range before activation finishes', async () => {
        const sourceRequests = [
            Object.freeze({
                chunkIndex: 0,
                componentOrdinal: 0,
                materialRootByte: 0x11,
                sourceBytes: Uint8Array.of(0xa1, 0xa2, 0xa3),
                streamByteOffset: 0n,
                streamDigestByte: 0x31,
                totalByteLength: 3n,
            }),
            Object.freeze({
                chunkIndex: 0,
                componentOrdinal: 1,
                materialRootByte: 0x12,
                sourceBytes: Uint8Array.of(0xb1, 0xb2, 0xb3, 0xb4, 0xb5),
                streamByteOffset: 0n,
                streamDigestByte: 0x32,
                totalByteLength: 5n,
            }),
        ] as const;
        const runtime = createFakeRuntime(sourceRequests);
        boundaryMocks.readExactRange.mockImplementation(
            (input: { materialRoot: Uint8Array }) => {
                const request =
                    sourceRequests[input.materialRoot[0] === 0x11 ? 0 : 1];
                return Promise.resolve(request.sourceBytes);
            },
        );

        await activateRelinearizationRoundTwoInClosedWorker(
            activationInput(runtime) as never,
        );

        expect(runtime.beginArguments).toEqual([[11, 14, 91]]);
        expect(boundaryMocks.readExactRange).toHaveBeenCalledTimes(2);
        expect(boundaryMocks.readExactRange).toHaveBeenNthCalledWith(
            1,
            expect.objectContaining({
                authenticatedByteLength: 3n,
                exactByteLength: 3,
                sourceByteOffset: 0n,
            }),
        );
        expect(boundaryMocks.readExactRange).toHaveBeenNthCalledWith(
            2,
            expect.objectContaining({
                authenticatedByteLength: 5n,
                exactByteLength: 5,
                sourceByteOffset: 0n,
            }),
        );
        expect(runtime.absorbedSources).toEqual([
            expect.objectContaining({
                bytes: [0xa1, 0xa2, 0xa3],
                chunkIndex: 0,
                componentOrdinal: 0,
                streamByteOffset: 0n,
                totalByteLength: 3n,
            }),
            expect.objectContaining({
                bytes: [0xb1, 0xb2, 0xb3, 0xb4, 0xb5],
                chunkIndex: 0,
                componentOrdinal: 1,
                streamByteOffset: 0n,
                totalByteLength: 5n,
            }),
        ]);
        expect(runtime.finishedActivationHandles).toEqual([21]);
        expect(runtime.discardedActivationHandles).toEqual([]);
        expect(runtime.releasedSuiteHandles).toEqual([11]);
        sourceRequests.forEach((request) =>
            expect(request.sourceBytes).toEqual(
                new Uint8Array(request.sourceBytes.byteLength),
            ),
        );
    });

    it('discards activation when the Rust request exceeds the absolute stream bound', async () => {
        const runtime = createFakeRuntime([
            Object.freeze({
                chunkIndex: 0,
                componentOrdinal: 0,
                materialRootByte: 0x11,
                sourceBytes: Uint8Array.of(0xa1),
                streamByteOffset: 0n,
                streamDigestByte: 0x31,
                totalByteLength:
                    BigInt(foundationProfile.maximumCanonicalStreamByteLength) +
                    1n,
            }),
        ]);

        await expect(
            activateRelinearizationRoundTwoInClosedWorker(
                activationInput(runtime) as never,
            ),
        ).rejects.toBeInstanceOf(CanonicalStreamInternalError);

        expect(boundaryMocks.readExactRange).not.toHaveBeenCalled();
        expect(runtime.finishedActivationHandles).toEqual([]);
        expect(runtime.discardedActivationHandles).toEqual([21]);
        expect(runtime.releasedSuiteHandles).toEqual([11]);
    });

    it('zeros the completed source and discards activation after cancellation', async () => {
        const firstSourceBytes = Uint8Array.of(0xa1, 0xa2, 0xa3);
        const runtime = createFakeRuntime([
            Object.freeze({
                chunkIndex: 0,
                componentOrdinal: 0,
                materialRootByte: 0x11,
                sourceBytes: firstSourceBytes,
                streamByteOffset: 0n,
                streamDigestByte: 0x31,
                totalByteLength: 3n,
            }),
            Object.freeze({
                chunkIndex: 0,
                componentOrdinal: 1,
                materialRootByte: 0x12,
                sourceBytes: Uint8Array.of(0xb1),
                streamByteOffset: 0n,
                streamDigestByte: 0x32,
                totalByteLength: 1n,
            }),
        ]);
        boundaryMocks.readExactRange.mockResolvedValue(firstSourceBytes);
        const cancellationController = new AbortController();

        await expect(
            activateRelinearizationRoundTwoInClosedWorker({
                ...activationInput(runtime),
                signal: cancellationController.signal,
                yieldControl: () => {
                    cancellationController.abort();
                    return Promise.resolve();
                },
            } as never),
        ).rejects.toBeInstanceOf(CanonicalStreamCancellationError);

        expect(runtime.absorbedSources).toHaveLength(1);
        expect(firstSourceBytes).toEqual(new Uint8Array(3));
        expect(runtime.finishedActivationHandles).toEqual([]);
        expect(runtime.discardedActivationHandles).toEqual([21]);
        expect(runtime.releasedSuiteHandles).toEqual([11]);
    });
});
