import { refusalReasonCodes } from '@sealed-lattice/types';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import {
    generateAggregateThresholdShareInClosedWorker,
    verifyAggregateThresholdShareInClosedWorker,
    type PrivateShareAcceptanceSignatureOperation,
} from '#packages/wasm/src/aggregate-threshold-share-proof-runtime';
import { mlDsa65SignatureByteLength } from '#packages/wasm/src/state-verifier-runtime/contracts';
import { registerCommonProofKernelContext } from '#packages/wasm/src/transcript-core-bridge/common-proof-kernel-context';
import type { TranscriptCoreKernelCommandRuntime } from '#packages/wasm/src/transcript-core-bridge/kernel-runtime';
import type { TranscriptCoreKernel } from '#packages/wasm/src/transcript-core-bridge/kernel-types';

const boundaryMocks = vi.hoisted(() => {
    const activeContext: {
        value: TranscriptCoreKernelCommandRuntime | undefined;
    } = { value: undefined };
    const activeKernel: { value: TranscriptCoreKernel | undefined } = {
        value: undefined,
    };
    const generatedCapabilityRelease = vi.fn();
    const verifiedCapabilityRelease = vi.fn();
    const generatedCapability = Object.freeze({
        release: generatedCapabilityRelease,
    });
    const verifiedCapability = Object.freeze({
        release: verifiedCapabilityRelease,
    });
    const productionAuthorityActive = { value: false };
    return {
        activeContext,
        activeKernel,
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
        runGeneration: vi.fn(
            async (
                _adapter: unknown,
                openExecution: (description: unknown) => unknown,
            ) => {
                if (productionAuthorityActive.value) {
                    throw new Error(
                        'The asynchronous proof run retained the serialized production-authority lease.',
                    );
                }
                const execution = (await openExecution(Object.freeze({}))) as {
                    options?: unknown;
                    outputStore: unknown;
                };
                return Object.freeze({
                    generatedCapability,
                    options: execution.options,
                    outputChunkByteLengths: Object.freeze([2]),
                    outputStore: execution.outputStore,
                });
            },
        ),
        runVerification: vi.fn(() => Promise.resolve(verifiedCapability)),
        verifiedCapabilityRelease,
        withProductionAuthority: vi.fn(
            (
                _workerKernel: unknown,
                _identifiers: unknown,
                operation: (authority: {
                    withExactKernelAuthorization(
                        exactOperation: (authorization: {
                            actionRandomnessContext: TranscriptCoreKernelCommandRuntime;
                            actionRandomnessHandle: number;
                            kernel: TranscriptCoreKernel;
                            stateReservationCapabilityMemory: WebAssembly.Memory;
                            stateReservationCapabilityPointer: number;
                            stateReservationHandle: number;
                            stateVerifierSessionHandle: number;
                        }) => void,
                    ): void;
                }) => Promise<void> | void,
            ) => {
                const context = activeContext.value;
                const kernel = activeKernel.value;
                if (context === undefined || kernel === undefined) {
                    throw new Error(
                        'The focused production authority has no active kernel.',
                    );
                }
                productionAuthorityActive.value = true;
                let operationOutput: Promise<void> | void;
                try {
                    operationOutput = operation(
                        Object.freeze({
                            withExactKernelAuthorization: (
                                exactOperation: (authorization: {
                                    actionRandomnessContext: TranscriptCoreKernelCommandRuntime;
                                    actionRandomnessHandle: number;
                                    kernel: TranscriptCoreKernel;
                                    stateReservationCapabilityMemory: WebAssembly.Memory;
                                    stateReservationCapabilityPointer: number;
                                    stateReservationHandle: number;
                                    stateVerifierSessionHandle: number;
                                }) => void,
                            ): void =>
                                exactOperation(
                                    Object.freeze({
                                        actionRandomnessContext: context,
                                        actionRandomnessHandle: 13,
                                        kernel,
                                        stateReservationCapabilityMemory:
                                            context.memory,
                                        stateReservationCapabilityPointer: 128,
                                        stateReservationHandle: 16,
                                        stateVerifierSessionHandle: 15,
                                    }),
                                ),
                        }),
                    );
                } finally {
                    productionAuthorityActive.value = false;
                }
                return Promise.resolve(operationOutput).then(() => undefined);
            },
        ),
    };
});

vi.mock(
    '#packages/wasm/src/aggregate-threshold-share-authenticated-recipient',
    () => ({
        requireAggregateThresholdShareRecipientAuthorityKernelOwner: () => ({
            handle: 14,
        }),
    }),
);

vi.mock(
    '#packages/wasm/src/local-storage-root-worker-kernel/worker-kernel',
    () => ({
        withClosedWorkerProductionOperationAuthority:
            boundaryMocks.withProductionAuthority,
    }),
);

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
    runClosedWorkerCommonProofGenerationFamilyAdapterWithExecutionOpener:
        boundaryMocks.runGeneration,
    runClosedWorkerCommonProofVerificationFamilyAdapter:
        boundaryMocks.runVerification,
}));

type GenerationMode = 'fresh' | 'resumed';

type FakeAggregateThresholdShareRuntime = Readonly<{
    bindings: Array<
        Readonly<{
            boardBindingSourceHandle: number;
            boardObjectHandle: number;
            generatedProofHandle: number;
        }>
    >;
    bindingStatus: { value: number };
    completionFlag: { value: number };
    discardedBoardBindingSources: number[];
    discardedTerminalSources: number[];
    finishStatus: { value: number };
    generationModes: GenerationMode[];
    kernel: TranscriptCoreKernel;
    privateShareAcceptanceCancellations: number[];
    privateShareAcceptanceFinishes: number[];
    privateShareAcceptanceFinishStatus: { value: number };
    privateShareAcceptancePreparations: Array<
        Readonly<{
            boardBindingSourceHandle: number;
            canonicalRosterBytes: Uint8Array;
            generatedProofHandle: number;
            signatureMessage: Uint8Array;
        }>
    >;
    verificationFinishes: Array<
        Readonly<{
            terminalSourceHandle: number;
            verifiedProofHandle: number;
        }>
    >;
}>;

const writeStatus = (
    memory: WebAssembly.Memory,
    pointer: number,
    status: number,
): void => {
    new DataView(memory.buffer).setUint32(pointer, status, true);
};

const createFakeRuntime = (): FakeAggregateThresholdShareRuntime => {
    const memory = new WebAssembly.Memory({ initial: 3 });
    const allocations = new Map<number, number>();
    const bindings: FakeAggregateThresholdShareRuntime['bindings'] = [];
    const bindingStatus = { value: 0 };
    const completionFlag = { value: 0 };
    const discardedBoardBindingSources: number[] = [];
    const discardedTerminalSources: number[] = [];
    const finishStatus = { value: 0 };
    const generationModes: GenerationMode[] = [];
    const privateShareAcceptanceCancellations: number[] = [];
    const privateShareAcceptanceFinishes: number[] = [];
    const privateShareAcceptanceFinishStatus = { value: 0 };
    const privateShareAcceptancePreparations: FakeAggregateThresholdShareRuntime['privateShareAcceptancePreparations'] =
        [];
    let privateShareAcceptanceCarrierState: 'available' | 'prepared' | 'spent' =
        'available';
    const verificationFinishes: FakeAggregateThresholdShareRuntime['verificationFinishes'] =
        [];
    let nextPointer = 2_048;

    const allocate = (byteLength: number): number => {
        const pointer = Math.ceil(nextPointer / 8) * 8;
        nextPointer = pointer + byteLength;
        allocations.set(pointer, byteLength);
        return pointer;
    };
    const deallocate = (pointer: number, byteLength: number): void => {
        if (allocations.get(pointer) !== byteLength) {
            throw new Error('The fake allocation length changed.');
        }
        allocations.delete(pointer);
    };
    const prepareGeneration = (
        generationMode: GenerationMode,
        selectedSuiteHandle: number,
        recipientAuthorityHandle: number,
        actionRandomnessHandle: number,
        stateVerifierSessionHandle: number,
        stateVerifierSessionCapabilityPointer: number,
        stateVerifierSessionCapabilityByteLength: number,
        verifiedReservationHandle: number,
        boardVerifierSessionHandle: number,
        boardVerifierSessionCapabilityPointer: number,
        boardVerifierSessionCapabilityByteLength: number,
        setupIntentObjectHandle: number,
        checkpointPointer: number,
        checkpointByteLength: number,
        sourceHandleOutputPointer: number,
        statusPointer: number,
    ): number => {
        expect([
            selectedSuiteHandle,
            recipientAuthorityHandle,
            actionRandomnessHandle,
            stateVerifierSessionHandle,
            stateVerifierSessionCapabilityPointer,
            stateVerifierSessionCapabilityByteLength,
            verifiedReservationHandle,
            boardVerifierSessionHandle,
            boardVerifierSessionCapabilityPointer,
            boardVerifierSessionCapabilityByteLength,
            setupIntentObjectHandle,
            checkpointByteLength,
        ]).toEqual([7, 14, 13, 15, 128, 32, 16, 18, 192, 32, 17, 32]);
        expect(
            Array.from(new Uint8Array(memory.buffer, checkpointPointer, 32)),
        ).toEqual(Array.from(new Uint8Array(32).fill(0x71)));
        generationModes.push(generationMode);
        new DataView(memory.buffer).setUint32(
            sourceHandleOutputPointer,
            21,
            true,
        );
        writeStatus(memory, statusPointer, 0);
        return 31;
    };
    const wasmExports = {
        sealed_lattice_aggregate_threshold_share_bind_generated_proof_to_board:
            (
                generatedProofHandle: number,
                boardBindingSourceHandle: number,
                boardVerifierSessionHandle: number,
                boardVerifierSessionCapabilityPointer: number,
                boardVerifierSessionCapabilityByteLength: number,
                boardObjectHandle: number,
            ): number => {
                expect([
                    boardVerifierSessionHandle,
                    boardVerifierSessionCapabilityPointer,
                    boardVerifierSessionCapabilityByteLength,
                ]).toEqual([18, 192, 32]);
                bindings.push({
                    boardBindingSourceHandle,
                    boardObjectHandle,
                    generatedProofHandle,
                });
                return bindingStatus.value;
            },
        sealed_lattice_aggregate_threshold_share_cancel_private_share_acceptance_carrier:
            (
                boardBindingSourceHandle: number,
                preparedCarrierHandle: number,
            ): number => {
                if (
                    boardBindingSourceHandle !== 21 ||
                    preparedCarrierHandle !== 71 ||
                    privateShareAcceptanceCarrierState !== 'prepared'
                ) {
                    return refusalReasonCodes.consumedState;
                }
                privateShareAcceptanceCarrierState = 'available';
                privateShareAcceptanceCancellations.push(preparedCarrierHandle);
                return 0;
            },
        sealed_lattice_aggregate_threshold_share_discard_generation_board_binding_source:
            (sourceHandle: number): number => {
                discardedBoardBindingSources.push(sourceHandle);
                return 0;
            },
        sealed_lattice_aggregate_threshold_share_discard_verification_terminal_source:
            (sourceHandle: number): number => {
                discardedTerminalSources.push(sourceHandle);
                return 0;
            },
        sealed_lattice_aggregate_threshold_share_finish_verification: (
            verifiedProofHandle: number,
            terminalSourceHandle: number,
            statusPointer: number,
        ): number => {
            verificationFinishes.push({
                terminalSourceHandle,
                verifiedProofHandle,
            });
            writeStatus(memory, statusPointer, finishStatus.value);
            return completionFlag.value;
        },
        sealed_lattice_aggregate_threshold_share_finish_private_share_acceptance_carrier:
            (
                boardBindingSourceHandle: number,
                preparedCarrierHandle: number,
                signaturePointer: number,
                signatureByteLength: number,
                outputPointer: number,
                outputByteLength: number,
            ): number => {
                if (
                    boardBindingSourceHandle !== 21 ||
                    preparedCarrierHandle !== 71 ||
                    privateShareAcceptanceCarrierState !== 'prepared'
                ) {
                    return refusalReasonCodes.consumedState;
                }
                privateShareAcceptanceCarrierState = 'spent';
                privateShareAcceptanceFinishes.push(preparedCarrierHandle);
                if (
                    signatureByteLength !== mlDsa65SignatureByteLength ||
                    outputByteLength !== 5 ||
                    new Uint8Array(
                        memory.buffer,
                        signaturePointer,
                        signatureByteLength,
                    ).some((byte) => byte !== 0x6a)
                ) {
                    return refusalReasonCodes.wrongTypeOrLength;
                }
                if (privateShareAcceptanceFinishStatus.value !== 0) {
                    return privateShareAcceptanceFinishStatus.value;
                }
                new Uint8Array(memory.buffer).set(
                    [0xe1, 0xe2, 0xe3, 0xe4, 0xe5],
                    outputPointer,
                );
                return 0;
            },
        sealed_lattice_aggregate_threshold_share_prepare_generation: (
            ...parameters: Parameters<typeof prepareGeneration> extends [
                unknown,
                ...infer Remaining,
            ]
                ? Remaining
                : never
        ) => prepareGeneration('fresh', ...parameters),
        sealed_lattice_aggregate_threshold_share_prepare_private_share_acceptance_carrier:
            (
                generatedProofHandle: number,
                boardBindingSourceHandle: number,
                canonicalRosterPointer: number,
                canonicalRosterByteLength: number,
                canonicalCarrierByteLengthOutputPointer: number,
                signatureMessageOutputPointer: number,
                signatureMessageOutputByteLength: number,
                statusPointer: number,
            ): number => {
                if (privateShareAcceptanceCarrierState !== 'available') {
                    writeStatus(
                        memory,
                        statusPointer,
                        refusalReasonCodes.consumedState,
                    );
                    return 0;
                }
                if (
                    generatedProofHandle !== 51 ||
                    boardBindingSourceHandle !== 21 ||
                    signatureMessageOutputByteLength !== 64
                ) {
                    writeStatus(
                        memory,
                        statusPointer,
                        refusalReasonCodes.wrongTypeOrLength,
                    );
                    return 0;
                }
                const signatureMessage = new Uint8Array(64).fill(0xb5);
                privateShareAcceptancePreparations.push(
                    Object.freeze({
                        boardBindingSourceHandle,
                        canonicalRosterBytes: new Uint8Array(
                            memory.buffer,
                            canonicalRosterPointer,
                            canonicalRosterByteLength,
                        ).slice(),
                        generatedProofHandle,
                        signatureMessage: signatureMessage.slice(),
                    }),
                );
                privateShareAcceptanceCarrierState = 'prepared';
                new DataView(memory.buffer).setUint32(
                    canonicalCarrierByteLengthOutputPointer,
                    5,
                    true,
                );
                new Uint8Array(memory.buffer).set(
                    signatureMessage,
                    signatureMessageOutputPointer,
                );
                writeStatus(memory, statusPointer, 0);
                return 71;
            },
        sealed_lattice_aggregate_threshold_share_prepare_resumed_generation: (
            ...parameters: Parameters<typeof prepareGeneration> extends [
                unknown,
                ...infer Remaining,
            ]
                ? Remaining
                : never
        ) => prepareGeneration('resumed', ...parameters),
        sealed_lattice_aggregate_threshold_share_prepare_verification: (
            selectedSuiteHandle: number,
            recipientAuthorityHandle: number,
            boardVerifierSessionHandle: number,
            boardVerifierSessionCapabilityPointer: number,
            boardVerifierSessionCapabilityByteLength: number,
            privateShareAcceptanceObjectHandle: number,
            terminalSourceHandleOutputPointer: number,
            statusPointer: number,
        ): number => {
            expect([
                selectedSuiteHandle,
                recipientAuthorityHandle,
                boardVerifierSessionHandle,
                boardVerifierSessionCapabilityPointer,
                boardVerifierSessionCapabilityByteLength,
                privateShareAcceptanceObjectHandle,
            ]).toEqual([7, 14, 18, 192, 32, 17]);
            new DataView(memory.buffer).setUint32(
                terminalSourceHandleOutputPointer,
                41,
                true,
            );
            writeStatus(memory, statusPointer, 0);
            return 32;
        },
        sealed_lattice_common_proof_release_suite: (handle: number): number => {
            expect(handle).toBe(7);
            return 0;
        },
        sealed_lattice_common_proof_select_suite: (
            suitePointer: number,
            suiteByteLength: number,
            statusPointer: number,
        ): number => {
            expect(
                Array.from(
                    new Uint8Array(
                        memory.buffer,
                        suitePointer,
                        suiteByteLength,
                    ),
                ),
            ).toEqual([1, 2, 3]);
            writeStatus(memory, statusPointer, 0);
            return 7;
        },
    };
    const kernel = Object.freeze({}) as TranscriptCoreKernel;
    const context = {
        allocate,
        deallocate,
        executeCommand: () => {
            throw new Error(
                'The focused aggregate-threshold-share test does not use commands.',
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
    boundaryMocks.activeKernel.value = kernel;
    return Object.freeze({
        bindings,
        bindingStatus,
        completionFlag,
        discardedBoardBindingSources,
        discardedTerminalSources,
        finishStatus,
        generationModes,
        kernel,
        privateShareAcceptanceCancellations,
        privateShareAcceptanceFinishes,
        privateShareAcceptanceFinishStatus,
        privateShareAcceptancePreparations,
        verificationFinishes,
    });
};

const generationInput = (
    runtime: FakeAggregateThresholdShareRuntime,
    generationMode: GenerationMode,
) => ({
    canonicalRosterBytes: Uint8Array.of(0xa1, 0xa2, 0xa3),
    canonicalSuiteRecordBytes: Uint8Array.of(1, 2, 3),
    checkpointLineageIdentifier: new Uint8Array(32).fill(0x71),
    generationMode,
    kernel: runtime.kernel,
    openProofGenerationExecution: () =>
        Promise.resolve(
            Object.freeze({
                externalMemory: Object.freeze({}),
                options:
                    generationMode === 'resumed'
                        ? Object.freeze({ resume: Object.freeze({}) })
                        : undefined,
                outputStore: Object.freeze({}),
            }),
        ),
    productionOperationIdentifiers: Object.freeze({
        actionRandomnessSessionIdentifier: 'action-randomness',
        stateReservationIdentifier: 'state-reservation',
        stateVerifierSessionIdentifier: 'state-session',
    }),
    recipientAuthority: Object.freeze({}),
    resolveVerifiedPrivateShareAcceptance: vi.fn(
        (input: {
            canonicalPrivateShareAcceptanceCarrier: Uint8Array;
            proofDescriptorBytes: Uint8Array;
        }) => {
            expect(input.canonicalPrivateShareAcceptanceCarrier).toEqual(
                Uint8Array.of(0xe1, 0xe2, 0xe3, 0xe4, 0xe5),
            );
            expect(input.proofDescriptorBytes).toEqual(
                Uint8Array.of(0xd1, 0xd2),
            );
            return Promise.resolve(Object.freeze({}));
        },
    ),
    signatureOperation: Object.freeze({
        signPrivateShareAcceptanceMessage: (
            signatureMessageHash: Uint8Array,
        ) => {
            expect(signatureMessageHash).toEqual(new Uint8Array(64).fill(0xb5));
            return new Uint8Array(mlDsa65SignatureByteLength).fill(0x6a);
        },
    }) satisfies PrivateShareAcceptanceSignatureOperation,
    setupIntentObject: Object.freeze({}),
    workerKernel: Object.freeze({}),
});

beforeEach(() => {
    vi.clearAllMocks();
});

describe('aggregate-threshold-share proof runtime', () => {
    it.each(['fresh', 'resumed'] as const)(
        'binds one positively generated %s proof to the verified acceptance object',
        async (generationMode) => {
            const runtime = createFakeRuntime();

            await generateAggregateThresholdShareInClosedWorker(
                generationInput(runtime, generationMode) as never,
            );

            expect(runtime.generationModes).toEqual([generationMode]);
            expect(runtime.bindings).toEqual([
                {
                    boardBindingSourceHandle: 21,
                    boardObjectHandle: 17,
                    generatedProofHandle: 51,
                },
            ]);
            expect(runtime.privateShareAcceptancePreparations).toEqual([
                {
                    boardBindingSourceHandle: 21,
                    canonicalRosterBytes: Uint8Array.of(0xa1, 0xa2, 0xa3),
                    generatedProofHandle: 51,
                    signatureMessage: new Uint8Array(64).fill(0xb5),
                },
            ]);
            expect(runtime.privateShareAcceptanceFinishes).toEqual([71]);
            expect(runtime.privateShareAcceptanceCancellations).toEqual([]);
            expect(
                boundaryMocks.generatedCapabilityRelease,
            ).not.toHaveBeenCalled();
            expect(runtime.discardedBoardBindingSources).toEqual([]);
        },
    );

    it('cancels an unsigned acceptance but spends an exact refused signature', async () => {
        const cancelledRuntime = createFakeRuntime();
        const cancelledInput = generationInput(cancelledRuntime, 'fresh');
        await expect(
            generateAggregateThresholdShareInClosedWorker({
                ...cancelledInput,
                signatureOperation: {
                    signPrivateShareAcceptanceMessage: () =>
                        new Uint8Array(mlDsa65SignatureByteLength - 1),
                },
            } as never),
        ).rejects.toMatchObject({ refusalReason: 'wrongTypeOrLength' });
        expect(cancelledRuntime.privateShareAcceptanceCancellations).toEqual([
            71,
        ]);
        expect(cancelledRuntime.privateShareAcceptanceFinishes).toEqual([]);
        expect(cancelledRuntime.discardedBoardBindingSources).toEqual([21]);
        expect(boundaryMocks.generatedCapabilityRelease).toHaveBeenCalledOnce();

        vi.clearAllMocks();
        const refusedRuntime = createFakeRuntime();
        refusedRuntime.privateShareAcceptanceFinishStatus.value =
            refusalReasonCodes.invalidSignature;
        await expect(
            generateAggregateThresholdShareInClosedWorker(
                generationInput(refusedRuntime, 'fresh') as never,
            ),
        ).rejects.toMatchObject({ refusalReason: 'invalidSignature' });
        expect(refusedRuntime.privateShareAcceptanceFinishes).toEqual([71]);
        expect(refusedRuntime.privateShareAcceptanceCancellations).toEqual([]);
        expect(refusedRuntime.discardedBoardBindingSources).toEqual([21]);
        expect(boundaryMocks.generatedCapabilityRelease).toHaveBeenCalledOnce();
    });

    it('returns only the Rust qualification-completion bit after positive verification', async () => {
        const runtime = createFakeRuntime();
        runtime.completionFlag.value = 1;

        const qualificationComplete =
            await verifyAggregateThresholdShareInClosedWorker({
                canonicalSuiteRecordBytes: Uint8Array.of(1, 2, 3),
                inputStore: Object.freeze({}) as never,
                kernel: runtime.kernel,
                privateShareAcceptanceObject: Object.freeze({}) as never,
                recipientAuthority: Object.freeze({}) as never,
            });

        expect(qualificationComplete).toBe(true);
        expect(runtime.verificationFinishes).toEqual([
            { terminalSourceHandle: 41, verifiedProofHandle: 61 },
        ]);
        expect(boundaryMocks.verifiedCapabilityRelease).not.toHaveBeenCalled();
        expect(runtime.discardedTerminalSources).toEqual([]);
    });

    it('releases generic and family authority after generation or verification refusal', async () => {
        const generationRuntime = createFakeRuntime();
        generationRuntime.bindingStatus.value =
            refusalReasonCodes.wrongHashOrRoot;
        await expect(
            generateAggregateThresholdShareInClosedWorker(
                generationInput(generationRuntime, 'fresh') as never,
            ),
        ).rejects.toMatchObject({ refusalReason: 'wrongHashOrRoot' });
        expect(boundaryMocks.generatedCapabilityRelease).toHaveBeenCalledOnce();
        expect(generationRuntime.discardedBoardBindingSources).toEqual([21]);

        vi.clearAllMocks();
        const verificationRuntime = createFakeRuntime();
        verificationRuntime.finishStatus.value =
            refusalReasonCodes.invalidProof;
        await expect(
            verifyAggregateThresholdShareInClosedWorker({
                canonicalSuiteRecordBytes: Uint8Array.of(1, 2, 3),
                inputStore: Object.freeze({}) as never,
                kernel: verificationRuntime.kernel,
                privateShareAcceptanceObject: Object.freeze({}) as never,
                recipientAuthority: Object.freeze({}) as never,
            }),
        ).rejects.toMatchObject({ refusalReason: 'invalidProof' });
        expect(boundaryMocks.verifiedCapabilityRelease).toHaveBeenCalledOnce();
        expect(verificationRuntime.discardedTerminalSources).toEqual([41]);
    });
});
