import { beforeEach, describe, expect, it, vi } from 'vitest';

import {
    encodeRequest,
    runtimeBinding,
} from './common-proof-worker-runtime/wire-fixtures.js';

import {
    contributeGeneratedAcceptedSetupPublicKeyShareToPackage,
    contributeGeneratedAcceptedSetupSameSecretToPackage,
    generateAcceptedSetupCompactPublicKeyShareInClosedWorker,
    generateAcceptedSetupPublicKeyShareInClosedWorker,
    generateAcceptedSetupSameSecretInClosedWorker,
    type CompactPublicKeyGenerationOperationObservation,
    verifyGeneratedAcceptedSetupPublicKeyShareInClosedWorker,
    verifyGeneratedAcceptedSetupSameSecretInClosedWorker,
} from '#packages/wasm/src/accepted-setup-key-relation-generation-runtime';
import {
    canonicalStreamDomains,
    CanonicalStreamInternalError,
} from '#packages/wasm/src/canonical-stream-runtime';
import { CommonProofWorkerRuntimeError } from '#packages/wasm/src/common-proof-worker-runtime/external-memory';
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
    const vssLowDegreeEvidence = Object.freeze({});
    const generatedConsumptionOutcomes: boolean[] = [];
    const externalMemoryAccounting = Object.freeze({
        actualUsage: Object.freeze({
            deletedObjectLifecycleCount: 3n,
            peakStoredByteLength: 4_096n,
            totalReadByteLength: 8_192n,
            totalWrittenByteLength: 6_144n,
            transactionCount: 7n,
        }),
        browserStorage: Object.freeze({
            claimedBufferCount: 9n,
            claimedByteLength: 10_000n,
            maximumLiveBufferByteLength: 2_048n,
            maximumLiveBufferCount: 2,
            releasedBufferCount: 9n,
            releasedByteLength: 10_000n,
            secretRecordOpenByteLength: 5_000n,
            secretRecordOpenCount: 4n,
            secretRecordSealByteLength: 6_000n,
            secretRecordSealCount: 5n,
            transferredBufferCount: 12n,
            transferredByteLength: 13_000n,
        }),
        compiledRequirement: Object.freeze({
            distinctPhysicalObjectCount: 5,
            maximumChunkByteLength: 1_048_576,
            maximumTransactionPayloadByteLength: 1_048_576n,
            objectLifecycleCount: 6,
            peakStoredByteLength: 8_192n,
            stepCount: 10,
            totalReadByteLength: 12_288n,
            totalWrittenByteLength: 8_192n,
            transactionCount: 12n,
        }),
        deterministicPrefixReplayUsage: Object.freeze({
            deletedObjectLifecycleCount: 1n,
            peakStoredByteLength: 2_048n,
            totalReadByteLength: 1_024n,
            totalWrittenByteLength: 512n,
            transactionCount: 2n,
        }),
        workerTransport: Object.freeze({
            browserToWasmCopyByteLength: 2_000n,
            browserToWasmCopyCount: 7n,
            readResultTransferByteLength: 8_192n,
            readResultTransferCount: 4n,
            wasmToBrowserCopyByteLength: 3_000n,
            wasmToBrowserCopyCount: 7n,
        }),
    });
    return {
        activeContext,
        applyGeneratedCapability: vi.fn(
            (
                _capability: unknown,
                _context: unknown,
                apply: (
                    handle: number,
                ) => Readonly<{ consumed: boolean; result: number }>,
            ) => {
                const outcome = apply(301);
                generatedConsumptionOutcomes.push(outcome.consumed);
                return outcome.result;
            },
        ),
        deriveProofDescriptor: vi.fn(() =>
            Promise.resolve(Uint8Array.of(0xd1, 0xd2)),
        ),
        externalMemoryAccounting,
        generatedCapability,
        generatedCapabilityRelease,
        generatedConsumptionOutcomes,
        openGenerationAdapter: vi.fn(() => Object.freeze({})),
        releaseGenerationAdapter: vi.fn(),
        runGeneration: vi.fn(
            async (
                _adapter: unknown,
                openExecution: (description: unknown) => unknown,
                authenticatedTranscriptPrefixAuthority?: Readonly<{
                    supply(operationHandle: number): void;
                }>,
            ) => {
                authenticatedTranscriptPrefixAuthority?.supply(401);
                const execution = (await openExecution(Object.freeze({}))) as {
                    options?: unknown;
                    outputStore: unknown;
                };
                return Object.freeze({
                    externalMemoryAccounting,
                    generatedCapability,
                    options: execution.options,
                    outputChunkByteLengths: Object.freeze([2]),
                    outputStore: execution.outputStore,
                });
            },
        ),
        verifyGeneratedPublicKeyShare: vi.fn(
            (
                _input: unknown,
                _capability: unknown,
                _statementSourceHandle: number,
            ) => Promise.resolve(undefined),
        ),
        verifyGeneratedSameSecret: vi.fn(
            (
                _input: unknown,
                _capability: unknown,
                _statementSourceHandle: number,
            ) => Promise.resolve(undefined),
        ),
        vssLowDegreeEvidence,
    };
});

vi.mock('#packages/wasm/src/setup-generation-recipient-payload', () => ({
    resolveSetupGenerationAuthorityKernelAuthorization: () => ({ handle: 14 }),
}));

vi.mock(
    '#packages/wasm/src/local-storage-root-worker-kernel/worker-kernel',
    () => ({
        withClosedWorkerProductionOperationAuthority: (
            workerKernel: { kernel: TranscriptCoreKernel },
            _productionOperationIdentifiers: unknown,
            operation: (authority: unknown) => unknown,
        ) =>
            Promise.resolve().then(() =>
                operation(
                    Object.freeze({
                        withExactKernelAuthorization: <Result>(
                            callback: (authorization: unknown) => Result,
                        ): Result =>
                            callback(
                                Object.freeze({
                                    actionRandomnessContext:
                                        boundaryMocks.activeContext.value,
                                    actionRandomnessHandle: 13,
                                    kernel: workerKernel.kernel,
                                    stateReservationCapabilityMemory:
                                        boundaryMocks.activeContext.value
                                            ?.memory,
                                    stateReservationCapabilityPointer: 128,
                                    stateReservationHandle: 15,
                                    stateVerifierSessionHandle: 16,
                                }),
                            ),
                    }),
                ),
            ),
    }),
);

vi.mock('#packages/wasm/src/vss-share-linkage-verification-runtime', () => ({
    consumeVerifiedVssLowDegreeEvidence: (input: {
        consume(handle: number): unknown;
    }) => input.consume(501),
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
}));

vi.mock('#packages/wasm/src/common-proof-worker-runtime/runtime', () => ({
    applyClosedWorkerGeneratedCommonProofCapability:
        boundaryMocks.applyGeneratedCapability,
    CommonProofStorageRequestSequence: class {
        private nextRequestSequence = 1n;
        private runtimeBindingHash: Uint8Array<ArrayBuffer> | undefined;

        public accept(request: {
            requestSequence: bigint;
            runtimeBindingHash: Uint8Array<ArrayBuffer>;
        }): void {
            if (request.requestSequence !== this.nextRequestSequence) {
                throw new Error(
                    'The focused test observed a reordered request.',
                );
            }
            if (this.runtimeBindingHash === undefined) {
                this.runtimeBindingHash = request.runtimeBindingHash.slice();
            } else if (
                !this.runtimeBindingHash.every(
                    (byte, byteIndex) =>
                        request.runtimeBindingHash[byteIndex] === byte,
                )
            ) {
                throw new Error(
                    'The focused test observed a substituted runtime binding.',
                );
            }
        }

        public commit(): void {
            this.nextRequestSequence += 1n;
        }
    },
    openClosedWorkerCommonProofGenerationFamilyAdapter:
        boundaryMocks.openGenerationAdapter,
    releaseClosedWorkerCommonProofGenerationFamilyAdapter:
        boundaryMocks.releaseGenerationAdapter,
    runClosedWorkerCommonProofGenerationFamilyAdapterWithExecutionOpener:
        boundaryMocks.runGeneration,
    validateTransferredReadResults: (
        _request: unknown,
        readResults: readonly unknown[],
    ) => readResults,
}));

vi.mock('#packages/wasm/src/accepted-setup-package-builder-runtime', () => ({
    requireAcceptedSetupPackageBuilderKernelOwner: (
        _builder: unknown,
        kernel: TranscriptCoreKernel,
    ) => ({
        context: boundaryMocks.activeContext.value,
        handle: 41,
        kernel,
    }),
}));

vi.mock('#packages/wasm/src/accepted-setup-proof-verification-runtime', () => ({
    verifyGeneratedAcceptedSetupPublicKeyShareCapabilityInClosedWorker:
        boundaryMocks.verifyGeneratedPublicKeyShare,
    verifyGeneratedAcceptedSetupSameSecretCapabilityInClosedWorker:
        boundaryMocks.verifyGeneratedSameSecret,
}));

type SetupKeyRelationFamily = 'publicKeyShare' | 'sameSecret';
type GenerationMode = 'fresh' | 'resumed';

type CompactGenerationPollOutcome = Readonly<{
    checkpointReady: number;
    completedWorkUnitCount: number;
    firstOrdinal: number;
    pollCode: number;
    stage: number;
}>;

type FakeSetupKeyRelationRuntime = Readonly<{
    allocations: ReadonlyMap<number, number>;
    authenticatedTranscriptPrefixes: Array<
        Readonly<{
            operationHandle: number;
            statementSourceHandle: number;
        }>
    >;
    cancelledGeneratedSources: Array<
        Readonly<{
            family: SetupKeyRelationFamily;
            generatedProofHandle: number;
            statementSourceHandle: number;
        }>
    >;
    compactCancelledHandles: number[];
    compactGenerationPreparations: number[];
    compactPendingStorageOwnerCode: { value: number };
    compactPollOutcomes: CompactGenerationPollOutcome[];
    compactReleasedCompletedHandles: number[];
    compactSuppliedStorageOwners: number[];
    contributedGeneratedSources: Array<
        Readonly<{
            builderHandle: number;
            family: SetupKeyRelationFamily;
            generatedProofHandle: number;
            statementSourceHandle: number;
        }>
    >;
    discardedStatementSources: number[];
    generationPreparations: Array<
        Readonly<{ family: SetupKeyRelationFamily; mode: GenerationMode }>
    >;
    kernel: TranscriptCoreKernel;
    selectedSuiteReleases: number[];
}>;

const writeStatus = (
    memory: WebAssembly.Memory,
    pointer: number,
    status: number,
): void => {
    new DataView(memory.buffer).setUint32(pointer, status, true);
};

type CompactGenerationDiagnosticRecordWriter = (view: DataView) => void;

const writeValidCompactGenerationDiagnosticRecords: CompactGenerationDiagnosticRecordWriter =
    (view) => {
        view.setUint32(0, 2, true);
        view.setUint32(4, 0, true);
        view.setFloat64(8, 1, true);
        view.setFloat64(16, 3, true);
        view.setUint32(24, 20, true);
        view.setUint32(28, 0, true);
        view.setFloat64(32, 4, true);
        view.setFloat64(40, 4.5, true);
    };

const createFakeRuntime = (
    writeCompactGenerationDiagnosticRecords: CompactGenerationDiagnosticRecordWriter = writeValidCompactGenerationDiagnosticRecords,
): FakeSetupKeyRelationRuntime => {
    const memory = new WebAssembly.Memory({ initial: 2 });
    const allocations = new Map<number, number>();
    const authenticatedTranscriptPrefixes: Array<
        Readonly<{
            operationHandle: number;
            statementSourceHandle: number;
        }>
    > = [];
    const cancelledGeneratedSources: Array<
        Readonly<{
            family: SetupKeyRelationFamily;
            generatedProofHandle: number;
            statementSourceHandle: number;
        }>
    > = [];
    const compactCancelledHandles: number[] = [];
    const compactGenerationPreparations: number[] = [];
    const compactReleasedCompletedHandles: number[] = [];
    const compactSuppliedStorageOwners: number[] = [];
    const compactPendingStorageOwnerCode = { value: 0 };
    const compactPollOutcomes: CompactGenerationPollOutcome[] = [
        {
            checkpointReady: 0,
            completedWorkUnitCount: 0,
            firstOrdinal: 1,
            pollCode: 2,
            stage: 0,
        },
        {
            checkpointReady: 0,
            completedWorkUnitCount: 0,
            firstOrdinal: 2,
            pollCode: 2,
            stage: 0,
        },
        {
            checkpointReady: 1,
            completedWorkUnitCount: 0,
            firstOrdinal: 0,
            pollCode: 1,
            stage: 5,
        },
        {
            checkpointReady: 0,
            completedWorkUnitCount: 0,
            firstOrdinal: 0,
            pollCode: 5,
            stage: 17,
        },
    ];
    const compactStorageRequests = new Map([
        [
            1,
            encodeRequest({
                maximumPayloadByteLength: 1n,
                operations: [
                    {
                        kind: 1,
                        objectOrdinal: 0,
                        payloadByteLength: 1n,
                        position: 0n,
                        protection: 1,
                    },
                ],
                requestSequence: 1n,
                runtimeBindingHash: runtimeBinding(0x31),
            }),
        ],
        [
            2,
            encodeRequest({
                maximumPayloadByteLength: 1n,
                operations: [
                    {
                        kind: 1,
                        objectOrdinal: 0,
                        payloadByteLength: 1n,
                        position: 0n,
                        protection: 1,
                    },
                ],
                requestSequence: 1n,
                runtimeBindingHash: runtimeBinding(0x42),
            }),
        ],
    ]);
    const contributedGeneratedSources: Array<
        Readonly<{
            builderHandle: number;
            family: SetupKeyRelationFamily;
            generatedProofHandle: number;
            statementSourceHandle: number;
        }>
    > = [];
    const discardedStatementSources: number[] = [];
    const generationPreparations: Array<
        Readonly<{ family: SetupKeyRelationFamily; mode: GenerationMode }>
    > = [];
    const selectedSuiteReleases: number[] = [];
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
    const preparation =
        (family: SetupKeyRelationFamily, mode: GenerationMode) =>
        (...parameters: number[]): number =>
            prepare(
                family,
                mode,
                parameters[parameters.length - 2] ?? 0,
                parameters[parameters.length - 1] ?? 0,
            );
    const cancelGeneratedSource =
        (family: SetupKeyRelationFamily) =>
        (
            statementSourceHandle: number,
            generatedProofHandle: number,
        ): number => {
            cancelledGeneratedSources.push({
                family,
                generatedProofHandle,
                statementSourceHandle,
            });
            return 0;
        };
    const contributeGeneratedSource =
        (family: SetupKeyRelationFamily) =>
        (
            builderHandle: number,
            statementSourceHandle: number,
            generatedProofHandle: number,
        ): number => {
            contributedGeneratedSources.push({
                builderHandle,
                family,
                generatedProofHandle,
                statementSourceHandle,
            });
            return 0;
        };

    const wasmExports = {
        sealed_lattice_compact_public_key_generation_cancel: (
            handle: number,
        ) => {
            compactCancelledHandles.push(handle);
            return 0;
        },
        sealed_lattice_compact_public_key_generation_copy_diagnostic_observations:
            (
                _handle: number,
                outputPointer: number,
                outputByteLength: number,
            ) => {
                if (outputByteLength !== 48) {
                    return 11;
                }
                const view = new DataView(
                    memory.buffer,
                    outputPointer,
                    outputByteLength,
                );
                writeCompactGenerationDiagnosticRecords(view);
                return 0;
            },
        sealed_lattice_compact_public_key_generation_copy_external_memory_usage:
            (
                _handle: number,
                outputPointer: number,
                outputWordCount: number,
            ) => {
                const view = new DataView(memory.buffer, outputPointer);
                for (
                    let wordIndex = 0;
                    wordIndex < outputWordCount;
                    wordIndex += 1
                ) {
                    view.setBigUint64(
                        wordIndex * BigUint64Array.BYTES_PER_ELEMENT,
                        BigInt(wordIndex + 1),
                        true,
                    );
                }
                return 0;
            },
        sealed_lattice_compact_public_key_generation_copy_proof: (
            _handle: number,
            sourceOffset: number,
            outputPointer: number,
            outputByteLength: number,
        ) => {
            const proofBytes = Uint8Array.of(0xa1, 0xa2, 0xa3, 0xa4);
            new Uint8Array(memory.buffer, outputPointer, outputByteLength).set(
                proofBytes.subarray(
                    sourceOffset,
                    sourceOffset + outputByteLength,
                ),
            );
            return 0;
        },
        sealed_lattice_compact_public_key_generation_copy_public_input: (
            _handle: number,
            sourceOffset: number,
            outputPointer: number,
            outputByteLength: number,
        ) => {
            const publicInputBytes = Uint8Array.of(0xb1, 0xb2, 0xb3);
            new Uint8Array(memory.buffer, outputPointer, outputByteLength).set(
                publicInputBytes.subarray(
                    sourceOffset,
                    sourceOffset + outputByteLength,
                ),
            );
            return 0;
        },
        sealed_lattice_compact_public_key_generation_copy_storage_request: (
            _handle: number,
            storageOwnerCode: number,
            outputPointer: number,
            outputByteLength: number,
        ) => {
            const request = compactStorageRequests.get(storageOwnerCode);
            if (
                request === undefined ||
                request.byteLength !== outputByteLength
            ) {
                return 11;
            }
            new Uint8Array(memory.buffer, outputPointer, outputByteLength).set(
                request,
            );
            return 0;
        },
        sealed_lattice_compact_public_key_generation_copy_transport_bindings: (
            _handle: number,
            outputPointer: number,
            outputByteLength: number,
        ) => {
            const output = new Uint8Array(
                memory.buffer,
                outputPointer,
                outputByteLength,
            );
            for (
                let bindingOrdinal = 0;
                bindingOrdinal < 4;
                bindingOrdinal += 1
            ) {
                output
                    .subarray(bindingOrdinal * 64, (bindingOrdinal + 1) * 64)
                    .fill(bindingOrdinal + 1);
            }
            return 0;
        },
        sealed_lattice_compact_public_key_generation_external_memory_usage_word_count:
            () => 10,
        sealed_lattice_compact_public_key_generation_diagnostic_record_byte_length:
            () => 24,
        sealed_lattice_compact_public_key_generation_diagnostic_observation_count:
            (_handle: number, statusPointer: number) => {
                writeStatus(memory, statusPointer, 0);
                return 2;
            },
        sealed_lattice_compact_public_key_generation_pending_storage_request_byte_length:
            (
                _handle: number,
                storageOwnerOutputPointer: number,
                statusPointer: number,
            ) => {
                const request = compactStorageRequests.get(
                    compactPendingStorageOwnerCode.value,
                );
                writeStatus(
                    memory,
                    storageOwnerOutputPointer,
                    compactPendingStorageOwnerCode.value,
                );
                writeStatus(
                    memory,
                    statusPointer,
                    request === undefined ? 11 : 0,
                );
                return request?.byteLength ?? 0;
            },
        sealed_lattice_compact_public_key_generation_poll: (
            _handle: number,
            _maximumWorkUnitCount: number,
            stageOutputPointer: number,
            firstOrdinalOutputPointer: number,
            completedWorkUnitCountOutputPointer: number,
            checkpointReadyOutputPointer: number,
            statusPointer: number,
        ) => {
            const outcome = compactPollOutcomes.shift();
            if (outcome === undefined) {
                throw new Error(
                    'The focused key-relation test exhausted compact poll outcomes.',
                );
            }
            writeStatus(memory, stageOutputPointer, outcome.stage);
            writeStatus(
                memory,
                firstOrdinalOutputPointer,
                outcome.firstOrdinal,
            );
            writeStatus(
                memory,
                completedWorkUnitCountOutputPointer,
                outcome.completedWorkUnitCount,
            );
            writeStatus(
                memory,
                checkpointReadyOutputPointer,
                outcome.checkpointReady,
            );
            writeStatus(memory, statusPointer, 0);
            compactPendingStorageOwnerCode.value =
                outcome.pollCode === 2 ? outcome.firstOrdinal : 0;
            return outcome.pollCode;
        },
        sealed_lattice_compact_public_key_generation_proof_byte_length: (
            _handle: number,
            statusPointer: number,
        ) => {
            writeStatus(memory, statusPointer, 0);
            return 4;
        },
        sealed_lattice_compact_public_key_generation_public_input_byte_length: (
            _handle: number,
            statusPointer: number,
        ) => {
            writeStatus(memory, statusPointer, 0);
            return 3;
        },
        sealed_lattice_compact_public_key_generation_release_completed: (
            handle: number,
        ) => {
            compactReleasedCompletedHandles.push(handle);
            return 0;
        },
        sealed_lattice_compact_public_key_generation_supply_storage_response: (
            _handle: number,
            storageOwnerCode: number,
            _responsePointer: number,
            _responseByteLength: number,
        ) => {
            compactSuppliedStorageOwners.push(storageOwnerCode);
            compactPendingStorageOwnerCode.value = 0;
            return 0;
        },
        sealed_lattice_compact_public_key_transport_bindings_byte_length: () =>
            256,
        sealed_lattice_compact_public_key_share_prepare_generation: (
            ...parameters: number[]
        ) => {
            compactGenerationPreparations.push(parameters.length);
            writeStatus(memory, parameters[parameters.length - 1] ?? 0, 0);
            return 61;
        },
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
        sealed_lattice_public_key_share_prepare_resumed_generation: preparation(
            'publicKeyShare',
            'resumed',
        ),
        sealed_lattice_public_key_share_generation_cancel:
            cancelGeneratedSource('publicKeyShare'),
        sealed_lattice_public_key_share_generation_contribute_package:
            contributeGeneratedSource('publicKeyShare'),
        sealed_lattice_same_secret_prepare_generation: preparation(
            'sameSecret',
            'fresh',
        ),
        sealed_lattice_same_secret_prepare_resumed_generation: preparation(
            'sameSecret',
            'resumed',
        ),
        sealed_lattice_same_secret_generation_cancel:
            cancelGeneratedSource('sameSecret'),
        sealed_lattice_same_secret_generation_contribute_package:
            contributeGeneratedSource('sameSecret'),
        sealed_lattice_same_secret_generation_supply_authenticated_transcript_prefix:
            (statementSourceHandle: number, operationHandle: number) => {
                authenticatedTranscriptPrefixes.push({
                    operationHandle,
                    statementSourceHandle,
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
            throw new Error(
                'The focused key-relation test does not use commands.',
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
        allocations,
        authenticatedTranscriptPrefixes,
        cancelledGeneratedSources,
        compactCancelledHandles,
        compactGenerationPreparations,
        compactPendingStorageOwnerCode,
        compactPollOutcomes,
        compactReleasedCompletedHandles,
        compactSuppliedStorageOwners,
        contributedGeneratedSources,
        discardedStatementSources,
        generationPreparations,
        kernel,
        selectedSuiteReleases,
    });
};

const generationInput = (
    runtime: FakeSetupKeyRelationRuntime,
    mode: GenerationMode,
    family: SetupKeyRelationFamily = 'sameSecret',
) => ({
    canonicalSuiteRecordBytes: Uint8Array.of(1, 2, 3),
    checkpointLineageIdentifier: new Uint8Array(32).fill(7),
    generationMode: mode,
    kernel: runtime.kernel,
    openProofGenerationExecution: () =>
        Promise.resolve(
            Object.freeze({
                externalMemory: Object.freeze({}),
                options:
                    mode === 'resumed'
                        ? Object.freeze({ resume: Object.freeze({}) })
                        : undefined,
                outputStore: Object.freeze({}),
            }),
        ),
    productionOperationIdentifiers: Object.freeze({}),
    setupGenerationAuthority: Object.freeze({}),
    setupIntentObject: Object.freeze({}),
    ...(family === 'sameSecret'
        ? { vssLowDegreeEvidence: boundaryMocks.vssLowDegreeEvidence }
        : {}),
    workerKernel: Object.freeze({ kernel: runtime.kernel }),
});

const compactGenerationInput = (
    runtime: FakeSetupKeyRelationRuntime,
    openExternalMemory: (
        opening: Readonly<{
            runtimeBindingHash: Uint8Array<ArrayBuffer>;
            storageOwner: 'cfw' | 'responseTrees';
        }>,
    ) => unknown,
    signal?: AbortSignal,
    observeOperation?: (
        observation: CompactPublicKeyGenerationOperationObservation,
    ) => void,
) => ({
    canonicalSuiteRecordBytes: Uint8Array.of(1, 2, 3),
    checkpointLineageIdentifier: new Uint8Array(32).fill(7),
    kernel: runtime.kernel,
    openExternalMemory,
    productionOperationIdentifiers: Object.freeze({}),
    setupGenerationAuthority: Object.freeze({}),
    setupIntentObject: Object.freeze({}),
    ...(observeOperation === undefined ? {} : { observeOperation }),
    ...(signal === undefined ? {} : { signal }),
    workerKernel: Object.freeze({ kernel: runtime.kernel }),
    yieldControl: () => Promise.resolve(),
});

const openFakeCompactGenerationExternalMemory = () =>
    Object.freeze({
        copyBrowserStorageAccounting: () =>
            Object.freeze({
                claimedBufferCount: 1n,
                claimedByteLength: 2n,
                maximumLiveBufferByteLength: 3n,
                maximumLiveBufferCount: 1,
                releasedBufferCount: 4n,
                releasedByteLength: 5n,
                secretRecordOpenByteLength: 6n,
                secretRecordOpenCount: 7n,
                secretRecordSealByteLength: 8n,
                secretRecordSealCount: 9n,
                transferredBufferCount: 10n,
                transferredByteLength: 11n,
            }),
        executeTransaction: () => Promise.resolve([]),
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
    boundaryMocks.generatedConsumptionOutcomes.splice(0);
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
                generationInput(runtime, mode, family) as never,
            );

            expect(runtime.generationPreparations).toEqual([{ family, mode }]);
            expect(runtime.authenticatedTranscriptPrefixes).toEqual(
                family === 'sameSecret'
                    ? [
                          {
                              operationHandle: 401,
                              statementSourceHandle,
                          },
                      ]
                    : [],
            );
            expect(proof.copyProofDescriptorBytes()).toEqual(
                Uint8Array.of(0xd1, 0xd2),
            );
            const copiedExternalMemoryAccounting =
                proof.copyExternalMemoryAccounting();
            expect(copiedExternalMemoryAccounting).toEqual(
                boundaryMocks.externalMemoryAccounting,
            );
            expect(copiedExternalMemoryAccounting).not.toBe(
                boundaryMocks.externalMemoryAccounting,
            );
            expect(copiedExternalMemoryAccounting.actualUsage).not.toBe(
                boundaryMocks.externalMemoryAccounting.actualUsage,
            );
            expect(Object.isFrozen(copiedExternalMemoryAccounting)).toBe(true);
            expect(boundaryMocks.deriveProofDescriptor).toHaveBeenCalledWith(
                expect.objectContaining({ streamDomain: expectedStreamDomain }),
            );
            expect(runtime.selectedSuiteReleases).toEqual([11]);
            expect(runtime.discardedStatementSources).toEqual([]);
            expect(runtime.allocations.size).toBe(0);

            proof.release();
            expect(runtime.cancelledGeneratedSources).toEqual([
                {
                    family,
                    generatedProofHandle: 301,
                    statementSourceHandle,
                },
            ]);
            expect(boundaryMocks.generatedConsumptionOutcomes).toEqual([true]);
            expect(
                boundaryMocks.generatedCapabilityRelease,
            ).not.toHaveBeenCalled();
            expect(() => proof.copyProofDescriptorBytes()).toThrow(/consumed/u);
            expect(() => proof.copyExternalMemoryAccounting()).toThrow(
                /consumed/u,
            );
        },
    );

    it('refuses unsupported generation modes before preparing any family', async () => {
        const runtime = createFakeRuntime();
        await expect(
            generateAcceptedSetupSameSecretInClosedWorker({
                ...generationInput(runtime, 'fresh'),
                generationMode: 'invalid',
            } as never),
        ).rejects.toThrow(/wrongContext/u);
        await expect(
            generateAcceptedSetupPublicKeyShareInClosedWorker({
                ...generationInput(runtime, 'resumed', 'publicKeyShare'),
                generationMode: undefined,
            } as never),
        ).rejects.toThrow(/wrongContext/u);
        expect(runtime.generationPreparations).toEqual([]);
        expect(runtime.allocations.size).toBe(0);
    });

    it('releases generated authority when proof-descriptor derivation fails', async () => {
        const runtime = createFakeRuntime();
        boundaryMocks.deriveProofDescriptor.mockRejectedValueOnce(
            new Error('descriptor failed'),
        );
        await expect(
            generateAcceptedSetupPublicKeyShareInClosedWorker(
                generationInput(runtime, 'fresh', 'publicKeyShare') as never,
            ),
        ).rejects.toThrow('descriptor failed');
        expect(runtime.cancelledGeneratedSources).toEqual([
            {
                family: 'publicKeyShare',
                generatedProofHandle: 301,
                statementSourceHandle: 22,
            },
        ]);
        expect(boundaryMocks.generatedCapabilityRelease).not.toHaveBeenCalled();
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
                generationInput(
                    runtime,
                    'resumed',
                    generate === generateAcceptedSetupSameSecretInClosedWorker
                        ? 'sameSecret'
                        : 'publicKeyShare',
                ) as never,
            );
            await verifyGenerated(
                verificationInput(runtime.kernel, proof) as never,
            );

            expect(verifyCapability).toHaveBeenCalledTimes(1);
            expect(verifyCapability.mock.calls[0]?.[1]).toBe(
                boundaryMocks.generatedCapability,
            );
            expect(verifyCapability.mock.calls[0]?.[2]).toBe(
                generate === generateAcceptedSetupSameSecretInClosedWorker
                    ? 21
                    : 22,
            );
            expect(
                boundaryMocks.generatedCapabilityRelease,
            ).not.toHaveBeenCalled();
            expect(() => proof.copyProofDescriptorBytes()).toThrow(/consumed/u);
            expect(() => proof.copyExternalMemoryAccounting()).toThrow(
                /consumed/u,
            );
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
        expect(proof.copyExternalMemoryAccounting()).toEqual(
            boundaryMocks.externalMemoryAccounting,
        );

        await verifyGeneratedAcceptedSetupSameSecretInClosedWorker(
            verificationInput(runtime.kernel, proof) as never,
        );
        expect(boundaryMocks.verifyGeneratedSameSecret).toHaveBeenCalledTimes(
            2,
        );
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

describe('accepted-setup compact public-key generation', () => {
    it('returns exact unverified bytes after both storage owners complete', async () => {
        const runtime = createFakeRuntime();
        const operationObservations: CompactPublicKeyGenerationOperationObservation[] =
            [];
        const openings: Array<
            Readonly<{
                runtimeBindingHash: number[];
                storageOwner: 'cfw' | 'responseTrees';
            }>
        > = [];
        const result =
            await generateAcceptedSetupCompactPublicKeyShareInClosedWorker(
                compactGenerationInput(
                    runtime,
                    (opening) => {
                        openings.push({
                            runtimeBindingHash: Array.from(
                                opening.runtimeBindingHash,
                            ),
                            storageOwner: opening.storageOwner,
                        });
                        return openFakeCompactGenerationExternalMemory();
                    },
                    undefined,
                    (observation) => {
                        operationObservations.push(observation);
                    },
                ) as never,
            );

        expect(result.canonicalPublicInputBytes).toEqual(
            Uint8Array.of(0xb1, 0xb2, 0xb3),
        );
        expect(result.canonicalProofBytes).toEqual(
            Uint8Array.of(0xa1, 0xa2, 0xa3, 0xa4),
        );
        expect(result.transportBindings).toEqual({
            applicationStatementHash: new Uint8Array(64).fill(2),
            manifestHash: new Uint8Array(64).fill(3),
            relationPlanHash: new Uint8Array(64).fill(4),
            suiteIdentifier: new Uint8Array(64).fill(1),
        });
        expect(result.observedSafeBoundaryOrdinals).toEqual([0]);
        expect(openings).toEqual([
            {
                runtimeBindingHash: new Array<number>(64).fill(0x31),
                storageOwner: 'responseTrees',
            },
            {
                runtimeBindingHash: new Array<number>(64).fill(0x42),
                storageOwner: 'cfw',
            },
        ]);
        expect(
            result.externalMemoryAccounting.responseTrees.actualUsage,
        ).toEqual({
            deletedObjectLifecycleCount: 5n,
            peakStoredByteLength: 3n,
            totalReadByteLength: 2n,
            totalWrittenByteLength: 1n,
            transactionCount: 4n,
        });
        expect(result.externalMemoryAccounting.cfw.actualUsage).toEqual({
            deletedObjectLifecycleCount: 10n,
            peakStoredByteLength: 8n,
            totalReadByteLength: 7n,
            totalWrittenByteLength: 6n,
            transactionCount: 9n,
        });
        expect(result.externalMemoryAccounting.worker).toMatchObject({
            browserToWasmStorageResponseCount: 2n,
            canonicalOutputCopyByteLength: 7n,
            canonicalOutputCopyCount: 2n,
            readResultTransferByteLength: 0n,
            readResultTransferCount: 0n,
            wasmToBrowserStorageRequestCount: 2n,
        });
        expect(
            result.externalMemoryAccounting.worker
                .browserToWasmStorageResponseByteLength,
        ).toBeGreaterThan(0n);
        expect(
            result.externalMemoryAccounting.worker
                .wasmToBrowserStorageRequestByteLength,
        ).toBeGreaterThan(0n);
        expect(runtime.compactGenerationPreparations).toEqual([14]);
        expect(runtime.compactSuppliedStorageOwners).toEqual([1, 2]);
        expect(runtime.compactReleasedCompletedHandles).toEqual([61]);
        expect(runtime.compactCancelledHandles).toEqual([]);
        expect(runtime.selectedSuiteReleases).toEqual([11]);
        expect(runtime.compactPollOutcomes).toEqual([]);
        expect(runtime.allocations.size).toBe(0);
        expect(
            operationObservations.map(
                (observation) => observation.operationOwnerIdentifier,
            ),
        ).toEqual([
            'setup-generation-authorization',
            'setup-intent-authorization',
            'kernel-preparation',
            'selected-suite-release',
            'kernel-poll',
            'storage-request-copy-and-decode',
            'storage-open',
            'storage-transaction',
            'storage-response-encode-and-supply',
            'storage-request-cleanup',
            'kernel-poll',
            'storage-request-copy-and-decode',
            'storage-open',
            'storage-transaction',
            'storage-response-encode-and-supply',
            'storage-request-cleanup',
            'kernel-poll',
            'kernel-poll',
            'diagnostic-observation-copy',
            'common-secret-sampling',
            'fiat-shamir-public-input-absorption',
            'external-memory-accounting-copy',
            'transport-bindings-copy',
            'canonical-public-input-copy',
            'canonical-proof-copy',
            'kernel-release',
        ]);
        for (const observation of operationObservations) {
            expect(observation.startedAtMilliseconds).toBeGreaterThanOrEqual(0);
            expect(observation.finishedAtMilliseconds).toBeGreaterThanOrEqual(
                observation.startedAtMilliseconds,
            );
            expect(observation.durationMilliseconds).toBe(
                observation.finishedAtMilliseconds -
                    observation.startedAtMilliseconds,
            );
        }
        expect(
            operationObservations.filter(
                (observation) =>
                    observation.operationOwnerIdentifier === 'kernel-poll',
            ),
        ).toMatchObject([
            {
                pollKind: 'storage-request-ready',
                storageOwner: 'responseTrees',
            },
            { pollKind: 'storage-request-ready', storageOwner: 'cfw' },
            {
                checkpointSafeBoundaryOrdinal: 0,
                completedWorkUnitCount: 0,
                firstOrdinal: 0,
                generationStageIdentifier: 'cfw',
                pollKind: 'progress',
            },
            {
                pollKind: 'complete',
                precedingGenerationStageIdentifier: 'cfw',
            },
        ]);
    });

    it.each([
        [
            'unknown owner',
            (view: DataView) => {
                writeValidCompactGenerationDiagnosticRecords(view);
                view.setUint32(0, 21, true);
            },
        ],
        [
            'nonzero reserved word',
            (view: DataView) => {
                writeValidCompactGenerationDiagnosticRecords(view);
                view.setUint32(4, 1, true);
            },
        ],
        [
            'nonfinite start time',
            (view: DataView) => {
                writeValidCompactGenerationDiagnosticRecords(view);
                view.setFloat64(8, Number.NaN, true);
            },
        ],
        [
            'reversed interval',
            (view: DataView) => {
                writeValidCompactGenerationDiagnosticRecords(view);
                view.setFloat64(16, 0.5, true);
            },
        ],
    ])('refuses a diagnostic record with %s', async (_label, writer) => {
        const runtime = createFakeRuntime(writer);

        await expect(
            generateAcceptedSetupCompactPublicKeyShareInClosedWorker(
                compactGenerationInput(
                    runtime,
                    openFakeCompactGenerationExternalMemory,
                    undefined,
                    () => undefined,
                ) as never,
            ),
        ).rejects.toBeInstanceOf(CommonProofWorkerRuntimeError);
        expect(runtime.compactReleasedCompletedHandles).toEqual([]);
        expect(runtime.compactCancelledHandles).toEqual([61]);
        expect(runtime.allocations.size).toBe(0);
    });

    it('cancels retained producer authority when cancellation precedes polling', async () => {
        const runtime = createFakeRuntime();
        const controller = new AbortController();
        controller.abort('focused cancellation');
        const openExternalMemory = vi.fn();
        const operationOwnerIdentifiers: string[] = [];

        await expect(
            generateAcceptedSetupCompactPublicKeyShareInClosedWorker(
                compactGenerationInput(
                    runtime,
                    openExternalMemory,
                    controller.signal,
                    (observation) => {
                        operationOwnerIdentifiers.push(
                            observation.operationOwnerIdentifier,
                        );
                    },
                ) as never,
            ),
        ).rejects.toThrow(/cancel/u);
        expect(openExternalMemory).not.toHaveBeenCalled();
        expect(runtime.compactReleasedCompletedHandles).toEqual([]);
        expect(runtime.compactCancelledHandles).toEqual([61]);
        expect(runtime.selectedSuiteReleases).toEqual([11]);
        expect(runtime.compactPollOutcomes).toHaveLength(4);
        expect(runtime.allocations.size).toBe(0);
        expect(operationOwnerIdentifiers).toEqual([
            'setup-generation-authorization',
            'setup-intent-authorization',
            'kernel-preparation',
            'selected-suite-release',
            'kernel-cancellation',
        ]);
    });

    it('does not cancel an already released producer when timing observation fails', async () => {
        const runtime = createFakeRuntime();
        const observationFailure = new Error('timing observer failed');

        await expect(
            generateAcceptedSetupCompactPublicKeyShareInClosedWorker(
                compactGenerationInput(
                    runtime,
                    () =>
                        Object.freeze({
                            executeTransaction: () => Promise.resolve([]),
                        }),
                    undefined,
                    (observation) => {
                        if (
                            observation.operationOwnerIdentifier ===
                            'kernel-release'
                        ) {
                            throw observationFailure;
                        }
                    },
                ) as never,
            ),
        ).rejects.toBe(observationFailure);
        expect(runtime.compactReleasedCompletedHandles).toEqual([61]);
        expect(runtime.compactCancelledHandles).toEqual([]);
        expect(runtime.selectedSuiteReleases).toEqual([11]);
        expect(runtime.allocations.size).toBe(0);
    });

    it('reports timing observation failure separately from a kernel trap', async () => {
        const runtime = createFakeRuntime();
        const observationFailure = new Error('poll timing observer failed');
        const openExternalMemory = vi.fn();

        await expect(
            generateAcceptedSetupCompactPublicKeyShareInClosedWorker(
                compactGenerationInput(
                    runtime,
                    openExternalMemory,
                    undefined,
                    (observation) => {
                        if (
                            observation.operationOwnerIdentifier ===
                            'kernel-poll'
                        ) {
                            throw observationFailure;
                        }
                    },
                ) as never,
            ),
        ).rejects.toBe(observationFailure);
        expect(openExternalMemory).not.toHaveBeenCalled();
        expect(runtime.compactReleasedCompletedHandles).toEqual([]);
        expect(runtime.compactCancelledHandles).toEqual([61]);
        expect(runtime.selectedSuiteReleases).toEqual([11]);
        expect(runtime.allocations.size).toBe(0);
    });

    it('fails closed and retires the producer when storage opening fails', async () => {
        const runtime = createFakeRuntime();

        await expect(
            generateAcceptedSetupCompactPublicKeyShareInClosedWorker(
                compactGenerationInput(runtime, () => {
                    throw new Error('storage unavailable');
                }) as never,
            ),
        ).rejects.toThrow('storage unavailable');
        expect(runtime.compactReleasedCompletedHandles).toEqual([]);
        expect(runtime.compactCancelledHandles).toEqual([61]);
        expect(runtime.compactSuppliedStorageOwners).toEqual([]);
        expect(runtime.selectedSuiteReleases).toEqual([11]);
        expect(runtime.allocations.size).toBe(0);
    });

    it('reports the last successful bounded poll when the kernel traps', async () => {
        const runtime = createFakeRuntime();
        runtime.compactPollOutcomes.splice(
            0,
            runtime.compactPollOutcomes.length,
            {
                checkpointReady: 0,
                completedWorkUnitCount: 17,
                firstOrdinal: 29,
                pollCode: 1,
                stage: 9,
            },
        );
        const openExternalMemory = vi.fn();

        const failure: unknown =
            await generateAcceptedSetupCompactPublicKeyShareInClosedWorker(
                compactGenerationInput(runtime, openExternalMemory) as never,
            ).catch((error: unknown) => error);
        expect(failure).toBeInstanceOf(CanonicalStreamInternalError);
        if (!(failure instanceof CanonicalStreamInternalError)) {
            throw new Error(
                'The focused compact generator returned the wrong failure type.',
            );
        }
        expect(failure.message).toBe(
            'The compact public-key generation kernel trapped after progress stage 9, first ordinal 29, and 17 completed work units; WASM memory held 131072 bytes.',
        );
        expect(failure.failureCause).toBeInstanceOf(Error);
        expect((failure.failureCause as Error).message).toBe(
            'The focused key-relation test exhausted compact poll outcomes.',
        );
        expect(openExternalMemory).not.toHaveBeenCalled();
        expect(runtime.compactCancelledHandles).toEqual([61]);
        expect(runtime.compactReleasedCompletedHandles).toEqual([]);
        expect(runtime.selectedSuiteReleases).toEqual([11]);
        expect(runtime.allocations.size).toBe(0);
    });
});

describe('generated accepted-setup package contribution', () => {
    it.each([
        [
            'sameSecret',
            generateAcceptedSetupSameSecretInClosedWorker,
            contributeGeneratedAcceptedSetupSameSecretToPackage,
            21,
        ],
        [
            'publicKeyShare',
            generateAcceptedSetupPublicKeyShareInClosedWorker,
            contributeGeneratedAcceptedSetupPublicKeyShareToPackage,
            22,
        ],
    ] as const)(
        'contributes the retained %s source and proof without host descriptors',
        async (family, generate, contribute, statementSourceHandle) => {
            const runtime = createFakeRuntime();
            const proof = await generate(
                generationInput(runtime, 'fresh', family) as never,
            );

            contribute({
                generatedProof: proof,
                packageBuilder: Object.freeze({}) as never,
            });

            expect(runtime.contributedGeneratedSources).toEqual([
                {
                    builderHandle: 41,
                    family,
                    generatedProofHandle: 301,
                    statementSourceHandle,
                },
            ]);
            expect(boundaryMocks.generatedConsumptionOutcomes).toEqual([false]);

            proof.release();
        },
    );

    it('rejects a cross-family contribution without changing source custody', async () => {
        const runtime = createFakeRuntime();
        const proof = await generateAcceptedSetupSameSecretInClosedWorker(
            generationInput(runtime, 'fresh') as never,
        );

        expect(() =>
            contributeGeneratedAcceptedSetupPublicKeyShareToPackage({
                generatedProof: proof,
                packageBuilder: Object.freeze({}) as never,
            }),
        ).toThrow(/wrongContext/u);
        expect(runtime.contributedGeneratedSources).toEqual([]);
        expect(proof.copyProofDescriptorBytes()).toEqual(
            Uint8Array.of(0xd1, 0xd2),
        );

        proof.release();
    });
});
