import {
    refusalReasonCodes,
    type BrowserActionStorageWorkerKernel,
} from '@sealed-lattice/types';
import { describe, expect, it, vi } from 'vitest';

import type {
    AcceptedSetupEvaluatorSourceCatalogSession,
    AcceptedSetupVerificationSession,
} from '#packages/wasm/src/accepted-setup-assembly-runtime';
import type { AcceptedSetupPackageBuilder } from '#packages/wasm/src/accepted-setup-package-builder-runtime';
import {
    CanonicalStreamInternalError,
    CanonicalStreamRefusalError,
} from '#packages/wasm/src/canonical-stream-runtime';
import type {
    AuthenticatedCommonProofInputStore,
    CommonProofCanonicalOutputStore,
    CommonProofExternalMemoryTransactionExecutor,
    CommonProofGenerationExecutionOpener,
    CommonProofGenerationWorkerOptions,
} from '#packages/wasm/src/common-proof-worker-runtime';
import {
    constructEvaluatorAggregateInClosedWorker,
    type EvaluatorAggregateSession,
} from '#packages/wasm/src/evaluator-aggregate-runtime';
import type { ClosedWorkerProductionOperationIdentifiers } from '#packages/wasm/src/local-storage-root-worker-kernel/authorities';
import {
    activateSelectedSuiteRecordSource,
    releaseSelectedSuiteRecordSource,
} from '#packages/wasm/src/selected-suite-record-source';
import { registerCommonProofKernelContext } from '#packages/wasm/src/transcript-core-bridge/common-proof-kernel-context';
import type { TranscriptCoreKernelCommandRuntime } from '#packages/wasm/src/transcript-core-bridge/kernel-runtime';
import type { TranscriptCoreKernel } from '#packages/wasm/src/transcript-core-bridge/kernel-types';

type FakeRuntimeState = {
    readonly acceptedSetupVerification: AcceptedSetupVerificationSession;
    readonly acceptedSetupPackageBuilder: AcceptedSetupPackageBuilder;
    readonly allocations: Map<number, number>;
    readonly canonicalSuiteRecordBytes: Uint8Array<ArrayBuffer>;
    catalogPhase: 'collecting' | 'complete';
    commitGeneratedProofCalls: number[];
    commitVerifiedStoreCalls: number[];
    commitVerifiedStoreStatuses: number[];
    readonly evaluatorSourceCatalog: AcceptedSetupEvaluatorSourceCatalogSession;
    finishVerificationCalls: number[];
    freshGenerationPreparationCount: number;
    readonly kernel: TranscriptCoreKernel;
    readonly materialChunks: Uint8Array<ArrayBuffer>[];
    readonly outputChunks: Map<number, Uint8Array<ArrayBuffer>>;
    packageStatementTakeCount: number;
    packageStatementTakeStatuses: number[];
    packageContributions: Array<{
        builderHandle: number;
        generatedProofHandle: number;
        statement: Uint8Array<ArrayBuffer>;
    }>;
    packageContributionStatuses: number[];
    packageStatementBindCount: number;
    readonly productionOperationIdentifiers: ClosedWorkerProductionOperationIdentifiers;
    readonly readSourceOrdinals: number[];
    resumedGenerationPreparationCount: number;
    readonly runtimeTreeChunks: Uint8Array<ArrayBuffer>[];
    readonly sessionDiscardHandles: number[];
    sourceRequestOrdinal: number;
    sourceRangeSuppliedCount: number;
    storeConstructionPollStatus: number;
    storeOutputAcknowledged: boolean;
    wrongSourceLength: boolean;
    readonly workerKernel: BrowserActionStorageWorkerKernel;
};

const fakeStates = vi.hoisted(() => new WeakMap<object, FakeRuntimeState>());
const workerStates = vi.hoisted(() => new WeakMap<object, FakeRuntimeState>());
const generatedCapabilityRelease = vi.hoisted(() => vi.fn());
const verifiedCapabilityRelease = vi.hoisted(() => vi.fn());

vi.mock('#packages/wasm/src/accepted-setup-assembly-runtime', () => ({
    bindAcceptedSetupEvaluatorGeneratedProofsToPackage: (input: {
        kernel: TranscriptCoreKernel;
    }): void => {
        const state = fakeStates.get(input.kernel);
        if (state === undefined) {
            throw new Error('Unknown fake evaluator kernel.');
        }
        state.packageStatementBindCount += 1;
    },
    readAcceptedSetupPrepackageEvaluatorComponentExactRange: (input: {
        exactByteLength: number;
        kernel: TranscriptCoreKernel;
        materialRoot: Uint8Array;
    }): Promise<Uint8Array<ArrayBuffer>> => {
        const state = fakeStates.get(input.kernel);
        if (state === undefined) {
            throw new Error('Unknown fake evaluator kernel.');
        }
        const sourceOrdinal = input.materialRoot[0] ?? 0;
        state.readSourceOrdinals.push(sourceOrdinal);
        const byteLength = state.wrongSourceLength
            ? input.exactByteLength - 1
            : input.exactByteLength;
        return Promise.resolve(
            new Uint8Array(byteLength).fill(sourceOrdinal + 1),
        );
    },
    requireAcceptedSetupEvaluatorSourceCatalogKernelOwner: (
        catalog: AcceptedSetupEvaluatorSourceCatalogSession,
        kernel: TranscriptCoreKernel,
        expectedPhase: 'collecting' | 'complete' = 'collecting',
    ) => {
        const state = fakeStates.get(kernel);
        if (
            state?.evaluatorSourceCatalog !== catalog ||
            state.catalogPhase !== expectedPhase
        ) {
            throw new CanonicalStreamRefusalError('wrongContext');
        }
        return Object.freeze({ handle: 21, kernel });
    },
    requireAcceptedSetupVerificationAssemblyKernelOwner: (
        acceptedSetupVerification: AcceptedSetupVerificationSession,
        kernel: TranscriptCoreKernel,
    ) => {
        const state = fakeStates.get(kernel);
        if (state?.acceptedSetupVerification !== acceptedSetupVerification) {
            throw new CanonicalStreamRefusalError('wrongContext');
        }
        return Object.freeze({ handle: 31, kernel });
    },
}));

vi.mock('#packages/wasm/src/accepted-setup-package-builder-runtime', () => ({
    requireAcceptedSetupPackageBuilderKernelOwner: (
        builder: AcceptedSetupPackageBuilder,
        kernel: TranscriptCoreKernel,
    ) => {
        const state = fakeStates.get(kernel);
        if (state?.acceptedSetupPackageBuilder !== builder) {
            throw new CanonicalStreamRefusalError('wrongContext');
        }
        return Object.freeze({ handle: 71, kernel });
    },
}));

vi.mock(
    '#packages/wasm/src/local-storage-root-worker-kernel/worker-kernel',
    () => ({
        withClosedWorkerProductionOperationAuthority: (
            workerKernel: BrowserActionStorageWorkerKernel,
            productionOperationIdentifiers: ClosedWorkerProductionOperationIdentifiers,
            operation: (authority: {
                withExactKernelAuthorization<Result>(
                    callback: (authorization: object) => Result,
                ): Result;
            }) => unknown,
        ) => {
            const state = workerStates.get(workerKernel);
            if (
                state === undefined ||
                state.productionOperationIdentifiers !==
                    productionOperationIdentifiers
            ) {
                throw new CanonicalStreamRefusalError('wrongContext');
            }
            const context = resolveFakeContext(state.kernel);
            return Promise.resolve().then(() =>
                operation(
                    Object.freeze({
                        withExactKernelAuthorization: <Result>(
                            callback: (authorization: object) => Result,
                        ): Result =>
                            callback(
                                Object.freeze({
                                    actionRandomnessContext: context,
                                    actionRandomnessHandle: 41,
                                    kernel: state.kernel,
                                    stateReservationCapabilityMemory:
                                        context.memory,
                                    stateReservationCapabilityPointer: 64,
                                    stateReservationHandle: 43,
                                    stateVerifierSessionHandle: 42,
                                }),
                            ),
                    }),
                ),
            );
        },
    }),
);

vi.mock('#packages/wasm/src/common-proof-worker-runtime/runtime', () => ({
    applyClosedWorkerGeneratedCommonProofCapability: (
        _capability: object,
        _context: TranscriptCoreKernelCommandRuntime,
        apply: (handle: number) => Readonly<{
            consumed: boolean;
            result: unknown;
        }>,
    ) => apply(91).result,
    applyClosedWorkerVerifiedCommonProofCapability: (
        _capability: object,
        _context: TranscriptCoreKernelCommandRuntime,
        apply: (handle: number) => Readonly<{
            consumed: boolean;
            result: number;
        }>,
    ) => apply(92).result,
    openClosedWorkerCommonProofGenerationFamilyAdapter: () => Object.freeze({}),
    openClosedWorkerCommonProofVerificationFamilyAdapter: () =>
        Object.freeze({}),
    releaseClosedWorkerCommonProofGenerationFamilyAdapter: vi.fn(),
    releaseClosedWorkerCommonProofVerificationFamilyAdapter: vi.fn(),
    runClosedWorkerCommonProofGenerationFamilyAdapterWithExecutionOpener:
        async (
            _adapter: object,
            openExecution: CommonProofGenerationExecutionOpener,
        ) => {
            const execution = await openExecution(
                Object.freeze({
                    commonProofRuntimeBindingHash: new Uint8Array(64),
                    proofAttemptLineageIdentifier: new Uint8Array(32),
                }) as never,
            );
            await execution.outputStore.commitChunk(
                0,
                Uint8Array.of(0x51, 0x52),
            );
            return Object.freeze({
                generatedCapability: Object.freeze({
                    release: generatedCapabilityRelease,
                }),
                options: execution.options,
                outputChunkByteLengths: Object.freeze([2]),
                outputStore: execution.outputStore,
            });
        },
    runClosedWorkerCommonProofVerificationFamilyAdapter: () =>
        Promise.resolve(Object.freeze({ release: verifiedCapabilityRelease })),
}));

vi.mock('#packages/wasm/src/generated-common-proof-output-runtime', () => ({
    deriveGeneratedCommonProofDescriptor: () =>
        Promise.resolve(Uint8Array.of(0xd1, 0xd2)),
}));

const contextRecords = new WeakMap<
    TranscriptCoreKernel,
    TranscriptCoreKernelCommandRuntime
>();

const resolveFakeContext = (
    kernel: TranscriptCoreKernel,
): TranscriptCoreKernelCommandRuntime => {
    const context = contextRecords.get(kernel);
    if (context === undefined) {
        throw new Error('The fake evaluator context is unavailable.');
    }
    return context;
};

const writeStatus = (
    memory: WebAssembly.Memory,
    pointer: number,
    status: number,
): void => {
    new DataView(memory.buffer).setUint32(pointer, status, true);
};

const writeStoreSourceRequest = (
    memory: WebAssembly.Memory,
    pointer: number,
    sourceOrdinal: number,
): void => {
    const bytes = new Uint8Array(memory.buffer, pointer, 160);
    bytes.fill(0);
    const view = new DataView(memory.buffer, pointer, 160);
    view.setUint32(0, 0, true);
    view.setUint32(4, sourceOrdinal, true);
    bytes[8] = sourceOrdinal;
    bytes.fill(0x40 + sourceOrdinal, 72, 136);
    view.setBigUint64(136, 4n, true);
    view.setBigUint64(144, 0n, true);
    view.setUint32(152, 0, true);
    view.setUint32(156, 4, true);
};

const createFakeRuntime = (): FakeRuntimeState => {
    const memory = new WebAssembly.Memory({ initial: 2 });
    const allocations = new Map<number, number>();
    const selectedSuiteRecords = new Map<number, Uint8Array<ArrayBuffer>>();
    let nextPointer = 1024;
    let nextSelectedSuiteHandle = 51;
    const allocate = (byteLength: number): number => {
        const pointer = Math.ceil(nextPointer / 8) * 8;
        nextPointer = pointer + byteLength;
        allocations.set(pointer, byteLength);
        return pointer;
    };
    const deallocate = (pointer: number, byteLength: number): void => {
        if (allocations.get(pointer) !== byteLength) {
            throw new Error(
                'The fake evaluator allocation was released with the wrong byte length.',
            );
        }
        allocations.delete(pointer);
    };
    const kernel = Object.freeze(Object.create(null)) as TranscriptCoreKernel;
    const productionOperationIdentifiers = Object.freeze(
        Object.create(null),
    ) as ClosedWorkerProductionOperationIdentifiers;
    const workerKernel = Object.freeze(
        Object.create(null),
    ) as BrowserActionStorageWorkerKernel;
    const state: FakeRuntimeState = {
        acceptedSetupVerification: Object.freeze(
            {},
        ) as AcceptedSetupVerificationSession,
        acceptedSetupPackageBuilder: Object.freeze(
            {},
        ) as unknown as AcceptedSetupPackageBuilder,
        allocations,
        canonicalSuiteRecordBytes: Uint8Array.of(0xa1),
        catalogPhase: 'collecting',
        commitGeneratedProofCalls: [],
        commitVerifiedStoreCalls: [],
        commitVerifiedStoreStatuses: [],
        evaluatorSourceCatalog: Object.freeze(
            {},
        ) as AcceptedSetupEvaluatorSourceCatalogSession,
        finishVerificationCalls: [],
        freshGenerationPreparationCount: 0,
        kernel,
        materialChunks: [],
        outputChunks: new Map(),
        packageStatementTakeCount: 0,
        packageStatementTakeStatuses: [],
        packageContributions: [],
        packageContributionStatuses: [],
        packageStatementBindCount: 0,
        productionOperationIdentifiers,
        readSourceOrdinals: [],
        resumedGenerationPreparationCount: 0,
        runtimeTreeChunks: [],
        sessionDiscardHandles: [],
        sourceRangeSuppliedCount: 0,
        sourceRequestOrdinal: 0,
        storeConstructionPollStatus: 0,
        storeOutputAcknowledged: false,
        workerKernel,
        wrongSourceLength: false,
    };
    workerStates.set(workerKernel, state);
    const context = {
        allocate,
        deallocate,
        executeCommand: () => {
            throw new Error('The test does not use the JSON command boundary.');
        },
        memory,
        runExclusive: <Result>(
            _operationName: string,
            operation: () => Result,
        ): Result => operation(),
        wasmExports: {
            sealed_lattice_common_proof_copy_selected_suite_record: (
                selectedSuiteHandle: number,
                outputPointer: number,
                outputByteLength: number,
            ) => {
                const suiteRecord =
                    selectedSuiteRecords.get(selectedSuiteHandle);
                if (suiteRecord === undefined) {
                    return refusalReasonCodes.consumedState;
                }
                if (suiteRecord.byteLength !== outputByteLength) {
                    return refusalReasonCodes.wrongTypeOrLength;
                }
                new Uint8Array(
                    memory.buffer,
                    outputPointer,
                    outputByteLength,
                ).set(suiteRecord);
                return 0;
            },
            sealed_lattice_common_proof_release_suite: (
                selectedSuiteHandle: number,
            ) =>
                selectedSuiteRecords.delete(selectedSuiteHandle)
                    ? 0
                    : refusalReasonCodes.consumedState,
            sealed_lattice_common_proof_select_suite: (
                suitePointer: number,
                suiteByteLength: number,
                statusPointer: number,
            ) => {
                writeStatus(memory, statusPointer, 0);
                const selectedSuiteHandle = nextSelectedSuiteHandle;
                nextSelectedSuiteHandle += 1;
                selectedSuiteRecords.set(
                    selectedSuiteHandle,
                    Uint8Array.from(
                        new Uint8Array(
                            memory.buffer,
                            suitePointer,
                            suiteByteLength,
                        ),
                    ),
                );
                return selectedSuiteHandle;
            },
            sealed_lattice_common_proof_selected_suite_record_byte_length: (
                selectedSuiteHandle: number,
                statusPointer: number,
            ) => {
                const suiteRecord =
                    selectedSuiteRecords.get(selectedSuiteHandle);
                writeStatus(
                    memory,
                    statusPointer,
                    suiteRecord === undefined
                        ? refusalReasonCodes.consumedState
                        : 0,
                );
                return suiteRecord?.byteLength ?? 0;
            },
            sealed_lattice_evaluator_aggregate_absorb_runtime_component_chunk: (
                _sessionHandle: number,
                _logicalComponentOrdinal: number,
                _chunkIndex: number,
                chunkPointer: number,
                chunkByteLength: number,
            ) => {
                state.runtimeTreeChunks.push(
                    Uint8Array.from(
                        new Uint8Array(
                            memory.buffer,
                            chunkPointer,
                            chunkByteLength,
                        ),
                    ),
                );
                return 0;
            },
            sealed_lattice_evaluator_aggregate_absorb_store_material_chunk: (
                _sessionHandle: number,
                _chunkIndex: number,
                chunkPointer: number,
                chunkByteLength: number,
            ) => {
                state.materialChunks.push(
                    Uint8Array.from(
                        new Uint8Array(
                            memory.buffer,
                            chunkPointer,
                            chunkByteLength,
                        ),
                    ),
                );
                return 0;
            },
            sealed_lattice_evaluator_aggregate_acknowledge_store_output_chunk:
                () => {
                    state.storeOutputAcknowledged = true;
                    return 0;
                },
            sealed_lattice_evaluator_aggregate_application_statement_byte_length:
                (_sessionHandle: number, statusPointer: number) => {
                    writeStatus(memory, statusPointer, 0);
                    return 3n;
                },
            sealed_lattice_evaluator_aggregate_contribute_package: (
                _sessionHandle: number,
                packageBuilderHandle: number,
                generatedProofHandle: number,
                statementPointer: number,
                statementByteLength: number,
            ) => {
                state.packageContributions.push({
                    builderHandle: packageBuilderHandle,
                    generatedProofHandle,
                    statement: Uint8Array.from(
                        new Uint8Array(
                            memory.buffer,
                            statementPointer,
                            statementByteLength,
                        ),
                    ),
                });
                return state.packageContributionStatuses.shift() ?? 0;
            },
            sealed_lattice_evaluator_aggregate_begin_runtime_component_tree:
                () => 0,
            sealed_lattice_evaluator_aggregate_begin_store_construction: (
                _catalogHandle: number,
                statusPointer: number,
            ) => {
                writeStatus(memory, statusPointer, 0);
                return 7;
            },
            sealed_lattice_evaluator_aggregate_commit_generated_proof: (
                _sessionHandle: number,
                generatedCommonProofHandle: number,
            ) => {
                state.commitGeneratedProofCalls.push(
                    generatedCommonProofHandle,
                );
                return 0;
            },
            sealed_lattice_evaluator_aggregate_commit_verified_store: (
                _sessionHandle: number,
                acceptedSetupAssemblyHandle: number,
            ) => {
                state.commitVerifiedStoreCalls.push(
                    acceptedSetupAssemblyHandle,
                );
                return state.commitVerifiedStoreStatuses.shift() ?? 0;
            },
            sealed_lattice_evaluator_aggregate_copy_application_statement: (
                _sessionHandle: number,
                outputPointer: number,
                outputByteLength: number,
            ) => {
                new Uint8Array(
                    memory.buffer,
                    outputPointer,
                    outputByteLength,
                ).set([0xb1, 0xb2, 0xb3]);
                return 0;
            },
            sealed_lattice_evaluator_aggregate_copy_store_output_chunk: (
                _sessionHandle: number,
                _chunkIndex: number,
                outputPointer: number,
                outputByteLength: number,
            ) => {
                new Uint8Array(
                    memory.buffer,
                    outputPointer,
                    outputByteLength,
                ).set([9, 8, 7, 6]);
                return 0;
            },
            sealed_lattice_evaluator_aggregate_copy_store_source_request: (
                _sessionHandle: number,
                outputPointer: number,
            ) => {
                writeStoreSourceRequest(
                    memory,
                    outputPointer,
                    state.sourceRequestOrdinal,
                );
                return 0;
            },
            sealed_lattice_evaluator_aggregate_describe_store: (
                _sessionHandle: number,
                outputPointer: number,
            ) => {
                const bytes = new Uint8Array(memory.buffer, outputPointer, 72);
                new DataView(memory.buffer, outputPointer, 72).setBigUint64(
                    0,
                    4n,
                    true,
                );
                bytes.fill(0xaa, 8);
                return 0;
            },
            sealed_lattice_evaluator_aggregate_discard_session: (
                sessionHandle: number,
            ) => {
                state.sessionDiscardHandles.push(sessionHandle);
                return 0;
            },
            sealed_lattice_evaluator_aggregate_finalize_statement: () => 0,
            sealed_lattice_evaluator_aggregate_finish_runtime_component_tree:
                () => 0,
            sealed_lattice_evaluator_aggregate_finish_store_construction: () =>
                0,
            sealed_lattice_evaluator_aggregate_finish_store_material: () => 0,
            sealed_lattice_evaluator_aggregate_finish_verification: (
                _sessionHandle: number,
                verifiedCommonProofHandle: number,
            ) => {
                state.finishVerificationCalls.push(verifiedCommonProofHandle);
                return 0;
            },
            sealed_lattice_evaluator_aggregate_prepare_generation: (
                _sessionHandle: number,
                _randomnessHandle: number,
                _stateSessionHandle: number,
                _capabilityPointer: number,
                _capabilityByteLength: number,
                _reservationHandle: number,
                _checkpointPointer: number,
                _checkpointByteLength: number,
                statusPointer: number,
            ) => {
                state.freshGenerationPreparationCount += 1;
                writeStatus(memory, statusPointer, 0);
                return 61;
            },
            sealed_lattice_evaluator_aggregate_prepare_resumed_generation: (
                _sessionHandle: number,
                _randomnessHandle: number,
                _stateSessionHandle: number,
                _capabilityPointer: number,
                _capabilityByteLength: number,
                _reservationHandle: number,
                _checkpointPointer: number,
                _checkpointByteLength: number,
                statusPointer: number,
            ) => {
                state.resumedGenerationPreparationCount += 1;
                writeStatus(memory, statusPointer, 0);
                return 61;
            },
            sealed_lattice_evaluator_aggregate_prepare_verification: (
                _suiteHandle: number,
                _sessionHandle: number,
                statusPointer: number,
            ) => {
                writeStatus(memory, statusPointer, 0);
                return 62;
            },
            sealed_lattice_evaluator_aggregate_store_construction_poll: (
                _sessionHandle: number,
                firstValuePointer: number,
                secondValuePointer: number,
                statusPointer: number,
            ) => {
                writeStatus(
                    memory,
                    statusPointer,
                    state.storeConstructionPollStatus,
                );
                if (state.storeConstructionPollStatus !== 0) {
                    return 0;
                }
                if (state.sourceRequestOrdinal < 10) {
                    return 1;
                }
                if (!state.storeOutputAcknowledged) {
                    new DataView(memory.buffer).setUint32(
                        firstValuePointer,
                        0,
                        true,
                    );
                    new DataView(memory.buffer).setUint32(
                        secondValuePointer,
                        4,
                        true,
                    );
                    return 2;
                }
                return 3;
            },
            sealed_lattice_evaluator_aggregate_store_source_request_byte_length:
                () => 160,
            sealed_lattice_evaluator_aggregate_supply_store_source_range: (
                _sessionHandle: number,
                _requestPointer: number,
                _requestByteLength: number,
                sourcePointer: number,
                sourceByteLength: number,
            ) => {
                expect(
                    Array.from(
                        new Uint8Array(
                            memory.buffer,
                            sourcePointer,
                            sourceByteLength,
                        ),
                    ),
                ).toEqual(new Array(4).fill(state.sourceRequestOrdinal + 1));
                state.sourceRangeSuppliedCount += 1;
                state.sourceRequestOrdinal += 1;
                return 0;
            },
            sealed_lattice_evaluator_aggregate_take_package_statement_source:
                () => {
                    state.packageStatementTakeCount += 1;
                    return state.packageStatementTakeStatuses.shift() ?? 0;
                },
        },
    } as unknown as TranscriptCoreKernelCommandRuntime;
    contextRecords.set(kernel, context);
    fakeStates.set(kernel, state);
    registerCommonProofKernelContext(kernel, context);
    return state;
};

const createStore = (
    chunks: Map<number, Uint8Array<ArrayBuffer>>,
): CommonProofCanonicalOutputStore =>
    Object.freeze({
        commitChunk: (
            chunkIndex: number,
            chunkBytes: Uint8Array<ArrayBuffer>,
        ): Promise<void> => {
            chunks.set(chunkIndex, Uint8Array.from(chunkBytes));
            return Promise.resolve();
        },
        readChunk: (
            chunkIndex: number,
            exactByteLength: number,
        ): Promise<Uint8Array<ArrayBuffer>> => {
            const chunk = chunks.get(chunkIndex);
            if (chunk?.byteLength !== exactByteLength) {
                throw new Error('The fake store has no exact chunk.');
            }
            return Promise.resolve(Uint8Array.from(chunk));
        },
    });

const constructSession = async (
    state: FakeRuntimeState,
): Promise<EvaluatorAggregateSession> => {
    const selectedSuiteRecordSource = activateSelectedSuiteRecordSource({
        canonicalSuiteRecordBytes: state.canonicalSuiteRecordBytes,
        kernel: state.kernel,
    });
    try {
        return await constructEvaluatorAggregateInClosedWorker({
            evaluatorSourceCatalog: state.evaluatorSourceCatalog,
            kernel: state.kernel,
            options: { yieldControl: () => Promise.resolve() },
            selectedSuiteRecordSource,
            store: createStore(state.outputChunks),
        });
    } finally {
        releaseSelectedSuiteRecordSource({
            kernel: state.kernel,
            source: selectedSuiteRecordSource,
        });
    }
};

const emptyExternalMemory = Object.freeze(() =>
    Promise.resolve(Object.freeze({ readResults: [] })),
) as unknown as CommonProofExternalMemoryTransactionExecutor;

const createGenerationExecutionOpener = (
    outputStore: CommonProofCanonicalOutputStore,
    options?: CommonProofGenerationWorkerOptions,
): CommonProofGenerationExecutionOpener =>
    Object.freeze(() =>
        Promise.resolve(
            Object.freeze({
                externalMemory: emptyExternalMemory,
                options,
                outputStore,
            }),
        ),
    );

const unusedProofInputStore: AuthenticatedCommonProofInputStore = Object.freeze(
    {
        declaredByteLength: 2,
        readCommittedChunk: () => Promise.resolve(Uint8Array.of(0x51, 0x52)),
    },
);

const unusedResumeOptions = Object.freeze({
    resume: Object.freeze({
        checkpointCustody: Object.freeze({
            publishAuthenticatedCheckpoint: () => Promise.resolve(),
            restoreAuthenticatedCheckpointState: () =>
                Promise.resolve(new Uint8Array()),
        }),
        prefixReplayExternalMemory: Object.freeze({
            executeDeterministicPrefixReplayTransaction: () =>
                Promise.resolve([]),
        }),
    }),
});

describe('Evaluator aggregate Rust/WASM lifecycle', () => {
    it('streams the production-derived store and completes positive generation, verification, and store commit', async () => {
        const state = createFakeRuntime();
        const session = await constructSession(state);

        expect(state.readSourceOrdinals).toEqual([
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
        ]);
        expect(state.sourceRangeSuppliedCount).toBe(10);
        expect(state.runtimeTreeChunks).toEqual([Uint8Array.of(9, 8, 7, 6)]);
        expect(state.materialChunks).toEqual([Uint8Array.of(9, 8, 7, 6)]);
        expect(session.copyCanonicalApplicationStatement()).toEqual(
            Uint8Array.of(0xb1, 0xb2, 0xb3),
        );
        expect(session.describeStore()).toEqual({
            fullObjectDigest: new Uint8Array(64).fill(0xaa),
            totalByteLength: 4n,
        });

        const proofOutputChunks = new Map<number, Uint8Array<ArrayBuffer>>();
        const descriptor = await session.generate({
            checkpointLineageIdentifier: new Uint8Array(32).fill(0x31),
            generationMode: 'fresh',
            openProofGenerationExecution: createGenerationExecutionOpener(
                createStore(proofOutputChunks),
                { yieldControl: () => Promise.resolve() },
            ),
            productionOperationIdentifiers:
                state.productionOperationIdentifiers,
            workerKernel: state.workerKernel,
        });
        expect(descriptor).toEqual(Uint8Array.of(0xd1, 0xd2));
        expect(state.freshGenerationPreparationCount).toBe(1);
        expect(state.commitGeneratedProofCalls).toEqual([91]);

        session.contributeToPackage(state.acceptedSetupPackageBuilder);
        session.bindPackageStatement(state.acceptedSetupVerification);
        await expect(
            session.verify({ proofInputStore: unusedProofInputStore }),
        ).rejects.toThrow(CanonicalStreamRefusalError);
        state.catalogPhase = 'complete';
        await session.verify({ proofInputStore: unusedProofInputStore });
        session.commitVerifiedStore(state.acceptedSetupVerification);

        expect(state.packageStatementTakeCount).toBe(1);
        expect(state.packageStatementBindCount).toBe(1);
        expect(state.packageContributions).toEqual([
            {
                builderHandle: 71,
                generatedProofHandle: 91,
                statement: Uint8Array.of(0xb1, 0xb2, 0xb3),
            },
        ]);
        expect(state.finishVerificationCalls).toEqual([92]);
        expect(state.commitVerifiedStoreCalls).toEqual([31]);
        expect(state.sessionDiscardHandles).toEqual([7]);
        expect(state.allocations.size).toBe(0);
        expect(() => session.cancel()).toThrow(TypeError);
    });

    it('uses only the resumed preparation hook and enforces lifecycle order', async () => {
        const state = createFakeRuntime();
        const session = await constructSession(state);

        expect(() =>
            session.contributeToPackage(state.acceptedSetupPackageBuilder),
        ).toThrow(CanonicalStreamRefusalError);
        await expect(
            session.generate({
                checkpointLineageIdentifier: new Uint8Array(32),
                generationMode: 'invalid' as never,
                openProofGenerationExecution: createGenerationExecutionOpener(
                    createStore(new Map()),
                ),
                productionOperationIdentifiers:
                    state.productionOperationIdentifiers,
                workerKernel: state.workerKernel,
            }),
        ).rejects.toThrow(CanonicalStreamRefusalError);
        await session.generate({
            checkpointLineageIdentifier: new Uint8Array(32).fill(0x32),
            generationMode: 'resumed',
            openProofGenerationExecution: createGenerationExecutionOpener(
                createStore(new Map()),
                unusedResumeOptions,
            ),
            productionOperationIdentifiers:
                state.productionOperationIdentifiers,
            workerKernel: state.workerKernel,
        });
        session.contributeToPackage(state.acceptedSetupPackageBuilder);
        expect(state.freshGenerationPreparationCount).toBe(0);
        expect(state.resumedGenerationPreparationCount).toBe(1);
        await expect(
            session.generate({
                checkpointLineageIdentifier: new Uint8Array(32),
                generationMode: 'fresh',
                openProofGenerationExecution: createGenerationExecutionOpener(
                    createStore(new Map()),
                ),
                productionOperationIdentifiers:
                    state.productionOperationIdentifiers,
                workerKernel: state.workerKernel,
            }),
        ).rejects.toThrow(CanonicalStreamRefusalError);

        session.cancel();
        expect(state.sessionDiscardHandles).toEqual([7]);
        expect(state.allocations.size).toBe(0);
    });

    it('keeps package handoff and verified-store commit retryable after refusal', async () => {
        const state = createFakeRuntime();
        const session = await constructSession(state);
        await session.generate({
            checkpointLineageIdentifier: new Uint8Array(32).fill(0x33),
            generationMode: 'fresh',
            openProofGenerationExecution: createGenerationExecutionOpener(
                createStore(new Map()),
            ),
            productionOperationIdentifiers:
                state.productionOperationIdentifiers,
            workerKernel: state.workerKernel,
        });

        state.packageStatementTakeStatuses.push(
            refusalReasonCodes.missingPrerequisite,
            0,
        );
        state.packageContributionStatuses.push(
            refusalReasonCodes.missingPrerequisite,
            0,
        );
        expect(() =>
            session.contributeToPackage(state.acceptedSetupPackageBuilder),
        ).toThrow(CanonicalStreamRefusalError);
        expect(() =>
            session.contributeToPackage(state.acceptedSetupPackageBuilder),
        ).not.toThrow();
        expect(() =>
            session.bindPackageStatement(state.acceptedSetupVerification),
        ).toThrow(CanonicalStreamRefusalError);
        expect(() =>
            session.bindPackageStatement(state.acceptedSetupVerification),
        ).not.toThrow();
        state.catalogPhase = 'complete';
        await session.verify({ proofInputStore: unusedProofInputStore });

        state.commitVerifiedStoreStatuses.push(
            refusalReasonCodes.missingPrerequisite,
            0,
        );
        expect(() =>
            session.commitVerifiedStore(state.acceptedSetupVerification),
        ).toThrow(CanonicalStreamRefusalError);
        expect(state.sessionDiscardHandles).toEqual([]);
        expect(() =>
            session.commitVerifiedStore(state.acceptedSetupVerification),
        ).not.toThrow();

        expect(state.packageStatementTakeCount).toBe(2);
        expect(state.packageContributions).toHaveLength(2);
        expect(state.packageStatementBindCount).toBe(1);
        expect(state.commitVerifiedStoreCalls).toEqual([31, 31]);
        expect(state.sessionDiscardHandles).toEqual([7]);
        expect(state.allocations.size).toBe(0);
    });

    it('separates construction refusal status from poll state', async () => {
        const state = createFakeRuntime();
        state.storeConstructionPollStatus =
            refusalReasonCodes.malformedEncoding;

        await expect(constructSession(state)).rejects.toThrow(
            CanonicalStreamRefusalError,
        );
        expect(state.readSourceOrdinals).toEqual([]);
        expect(state.sessionDiscardHandles).toEqual([7]);
        expect(state.allocations.size).toBe(0);
    });

    it('discards the Rust session when authenticated source custody returns a truncated range', async () => {
        const state = createFakeRuntime();
        state.wrongSourceLength = true;

        await expect(constructSession(state)).rejects.toThrow(
            CanonicalStreamInternalError,
        );
        expect(state.sourceRangeSuppliedCount).toBe(0);
        expect(state.sessionDiscardHandles).toEqual([7]);
        expect(state.allocations.size).toBe(0);
    });
});
