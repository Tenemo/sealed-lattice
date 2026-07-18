import { refusalReasonCodes } from '@sealed-lattice/types';
import { describe, expect, it } from 'vitest';

import {
    createVerifiedAcceptedSetupAuthorityKernelOwner,
    type VerifiedAcceptedSetupAuthority,
} from '#packages/wasm/src/accepted-setup-verification-runtime';
import {
    openVerifiedBallotAggregationInClosedWorker,
    type VerifiedEvaluatorAggregateAuthority,
} from '#packages/wasm/src/ballot-aggregation-runtime';
import {
    createVerifiedBallotOutputKernelAuthority,
    type VerifiedBallotOutput,
} from '#packages/wasm/src/ballot-validity-runtime';
import {
    openCanonicalBoardVerifierSession,
    registerCanonicalBoardKernelContext,
    type CanonicalBoardContextInput,
    type CanonicalBoardKernelContext,
    type CanonicalBoardVerifierSession,
    type VerifiedTranscriptObject,
} from '#packages/wasm/src/canonical-board-runtime';
import { CanonicalStreamRefusalError } from '#packages/wasm/src/canonical-stream-runtime';
import {
    prepareEvaluatorReplayInClosedWorker,
    type EvaluatorKeyStoreRangeReadObservation,
    type EvaluatorKeyStoreRangeSource,
} from '#packages/wasm/src/evaluator-replay-runtime';
import { releaseVerifiedEvaluatorReplay } from '#packages/wasm/src/finality-verifier-runtime';
import { registerCommonProofKernelContext } from '#packages/wasm/src/transcript-core-bridge/common-proof-kernel-context';
import type { TranscriptCoreKernelCommandRuntime } from '#packages/wasm/src/transcript-core-bridge/kernel-runtime';
import type { TranscriptCoreKernel } from '#packages/wasm/src/transcript-core-bridge/kernel-types';

const evaluatorStoreByteOffset = 0x0020_0000_0000_0001n;
const replayCarrier = Uint8Array.of(0xa1, 0xb2, 0xc3);

const boardContextInput = (): CanonicalBoardContextInput => ({
    actionIdentifier: 'action',
    canonicalActionDefinitionBytes: Uint8Array.of(0xa1),
    canonicalBoardPolicyBytes: Uint8Array.of(0xb1),
    canonicalManifestBytes: Uint8Array.of(0xc1),
    canonicalRosterBytes: Uint8Array.of(0xaa, 0xbb),
    canonicalSuiteRecordBytes: Uint8Array.of(0xd1),
    ceremonyIdentifier: 'ceremony',
    expectedActionContextHash: new Uint8Array(64).fill(0x33),
    expectedCeremonyContextHash: new Uint8Array(64).fill(0x22),
    expectedSuiteIdentifier: new Uint8Array(64).fill(0x11),
});

const requireValid = <Value>(result: {
    readonly isValid: boolean;
    readonly refusalReason?: string;
    readonly value?: Value;
}): Value => {
    if (!result.isValid) {
        throw new Error(result.refusalReason ?? 'verification refused');
    }
    return result.value as Value;
};

type FakeEvaluatorRuntime = Readonly<{
    absorbedBallotHandles: number[];
    absorbedStoreRanges: Array<Readonly<{ bytes: Uint8Array; offset: bigint }>>;
    acceptedSetupAuthority: VerifiedAcceptedSetupAuthority;
    aggregateCancelHandles: number[];
    aggregateDiscardHandles: number[];
    allocations: ReadonlyMap<number, number>;
    ballotReleaseHandles: number[];
    boardCarrierInputs: Uint8Array[];
    boardSession: CanonicalBoardVerifierSession;
    createVerifiedBallot(handle: number): VerifiedBallotOutput;
    evaluatorCancelHandles: number[];
    evaluatorReplayReleaseHandles: number[];
    kernel: TranscriptCoreKernel;
    verifyBoardCarrier(carrier: Uint8Array): VerifiedTranscriptObject;
}>;

const createFakeEvaluatorRuntime = (
    options: {
        absorbBallotStatuses?: readonly number[];
        bindReplayStatuses?: readonly number[];
        evaluatorPollStatuses?: readonly number[];
    } = {},
): FakeEvaluatorRuntime => {
    const memory = new WebAssembly.Memory({ initial: 4 });
    const allocations = new Map<number, number>();
    const absorbedBallotHandles: number[] = [];
    const absorbedStoreRanges: Array<
        Readonly<{ bytes: Uint8Array; offset: bigint }>
    > = [];
    const aggregateCancelHandles: number[] = [];
    const aggregateDiscardHandles: number[] = [];
    const ballotReleaseHandles: number[] = [];
    const boardCarrierInputs: Uint8Array[] = [];
    const evaluatorCancelHandles: number[] = [];
    const evaluatorReplayReleaseHandles: number[] = [];
    const bindReplayStatuses = [...(options.bindReplayStatuses ?? [0])];
    const evaluatorPollStatuses = [...(options.evaluatorPollStatuses ?? [])];
    const absorbBallotStatuses = [...(options.absorbBallotStatuses ?? [0, 0])];
    let nextPointer = 8;
    let nextBoardObjectHandle = 70;
    let evaluatorHasAbsorbedStoreRange = false;

    const ensureCapacity = (requiredByteLength: number): void => {
        const missingByteLength = requiredByteLength - memory.buffer.byteLength;
        if (missingByteLength > 0) {
            memory.grow(Math.ceil(missingByteLength / 65_536));
        }
    };
    const allocate = (byteLength: number): number => {
        const pointer = Math.ceil(nextPointer / 8) * 8;
        nextPointer = pointer + byteLength;
        ensureCapacity(nextPointer);
        allocations.set(pointer, byteLength);
        return pointer;
    };
    const deallocate = (pointer: number, byteLength: number): void => {
        if (allocations.get(pointer) !== byteLength) {
            throw new Error('test deallocation does not match its allocation');
        }
        allocations.delete(pointer);
    };
    const writeStatus = (pointer: number, status: number): void => {
        new DataView(memory.buffer).setUint32(pointer, status, true);
    };

    const kernel = Object.freeze(Object.create(null)) as TranscriptCoreKernel;
    const commonContext = {
        allocate,
        deallocate,
        executeCommand: () => {
            throw new Error('the test does not use the JSON command boundary');
        },
        memory,
        runExclusive: <Result>(
            _operationName: string,
            operation: () => Result,
        ): Result => operation(),
        wasmExports: {
            sealed_lattice_ballot_aggregation_absorb: (
                _aggregationHandle: number,
                verifiedBallotOutputHandle: number,
            ) => {
                absorbedBallotHandles.push(verifiedBallotOutputHandle);
                return absorbBallotStatuses.shift() ?? 0;
            },
            sealed_lattice_ballot_aggregation_begin: (
                statusPointer: number,
            ) => {
                writeStatus(statusPointer, 0);
                return 11;
            },
            sealed_lattice_ballot_aggregation_cancel: (
                aggregationHandle: number,
            ) => {
                aggregateCancelHandles.push(aggregationHandle);
                return 0;
            },
            sealed_lattice_ballot_aggregation_discard_verified_aggregate: (
                verifiedAggregateHandle: number,
            ) => {
                aggregateDiscardHandles.push(verifiedAggregateHandle);
                return 0;
            },
            sealed_lattice_ballot_aggregation_finish: (
                _aggregationHandle: number,
                _boardSessionHandle: number,
                _boardCapabilityPointer: number,
                _boardCapabilityByteLength: number,
                _verifiedAggregateObjectHandle: number,
                statusPointer: number,
            ) => {
                writeStatus(statusPointer, 0);
                return 21;
            },
            sealed_lattice_evaluator_execution_absorb_store_chunk: (
                _executionHandle: number,
                storeByteOffset: bigint,
                chunkPointer: number,
                chunkByteLength: number,
            ) => {
                absorbedStoreRanges.push({
                    bytes: Uint8Array.from(
                        new Uint8Array(
                            memory.buffer,
                            chunkPointer,
                            chunkByteLength,
                        ),
                    ),
                    offset: storeByteOffset,
                });
                evaluatorHasAbsorbedStoreRange = true;
                return 0;
            },
            sealed_lattice_evaluator_execution_begin: (
                _acceptedSetupHandle: number,
                _verifiedAggregateHandle: number,
                statusPointer: number,
            ) => {
                writeStatus(statusPointer, 0);
                return 31;
            },
            sealed_lattice_evaluator_execution_bind_replay_object: (
                _executionHandle: number,
                _boardSessionHandle: number,
                _boardCapabilityPointer: number,
                _boardCapabilityByteLength: number,
                _verifiedReplayObjectHandle: number,
                statusPointer: number,
            ) => {
                const status = bindReplayStatuses.shift() ?? 0;
                writeStatus(statusPointer, status);
                return status === 0 ? 41 : 0;
            },
            sealed_lattice_evaluator_execution_cancel: (
                executionHandle: number,
            ) => {
                evaluatorCancelHandles.push(executionHandle);
                return 0;
            },
            sealed_lattice_evaluator_execution_copy_replay_carrier: (
                _executionHandle: number,
                outputPointer: number,
                outputByteLength: number,
            ) => {
                if (outputByteLength !== replayCarrier.byteLength) {
                    return refusalReasonCodes.wrongTypeOrLength;
                }
                new Uint8Array(memory.buffer).set(replayCarrier, outputPointer);
                return 0;
            },
            sealed_lattice_evaluator_execution_finish: () => 0,
            sealed_lattice_evaluator_execution_poll: (
                _executionHandle: number,
                outputPointer: number,
                outputByteLength: number,
            ) => {
                const status = evaluatorPollStatuses.shift() ?? 0;
                if (status !== 0) {
                    return status;
                }
                if (outputByteLength !== 16) {
                    return refusalReasonCodes.wrongTypeOrLength;
                }
                const view = new DataView(memory.buffer);
                view.setUint16(outputPointer, 1, true);
                view.setUint16(
                    outputPointer + 2,
                    evaluatorHasAbsorbedStoreRange ? 2 : 1,
                    true,
                );
                view.setBigUint64(
                    outputPointer + 4,
                    evaluatorHasAbsorbedStoreRange
                        ? 0n
                        : evaluatorStoreByteOffset,
                    true,
                );
                view.setUint32(
                    outputPointer + 12,
                    evaluatorHasAbsorbedStoreRange ? 0 : 3,
                    true,
                );
                return 0;
            },
            sealed_lattice_evaluator_execution_replay_carrier_byte_length: (
                _executionHandle: number,
                statusPointer: number,
            ) => {
                writeStatus(statusPointer, 0);
                return replayCarrier.byteLength;
            },
            sealed_lattice_evaluator_replay_release: (
                verifiedReplayHandle: number,
            ) => {
                evaluatorReplayReleaseHandles.push(verifiedReplayHandle);
                return 0;
            },
        },
    } as unknown as TranscriptCoreKernelCommandRuntime;
    registerCommonProofKernelContext(kernel, commonContext);

    const boardContext: CanonicalBoardKernelContext = {
        allocate,
        begin: (...parameters) => {
            const statusPointer = parameters[parameters.length - 1];
            if (statusPointer === undefined) {
                throw new Error('board begin has no status pointer');
            }
            writeStatus(statusPointer, 0);
            return 1;
        },
        cachedCarrierLength: () => 0,
        cancel: () => 0,
        copyCachedCarrier: () => 0,
        deallocate,
        describe: () => 0,
        memory,
        release: () => 0,
        runExclusive: (_operationName, operation) => operation(),
        verifyUnordered: (
            _sessionHandle,
            _capabilityPointer,
            _capabilityLength,
            framedCarrierPointer,
            framedCarrierLength,
            outputPointer,
            _outputLength,
            statusPointer,
        ) => {
            boardCarrierInputs.push(
                Uint8Array.from(
                    new Uint8Array(
                        memory.buffer,
                        framedCarrierPointer,
                        framedCarrierLength,
                    ),
                ),
            );
            writeStatus(statusPointer, 0);
            const objectHandle = nextBoardObjectHandle;
            nextBoardObjectHandle += 1;
            const view = new DataView(memory.buffer);
            view.setUint32(outputPointer, 1, true);
            view.setUint32(outputPointer + 4, objectHandle, true);
            return 8;
        },
    };
    registerCanonicalBoardKernelContext(kernel, boardContext);
    const boardSession = requireValid(
        openCanonicalBoardVerifierSession({
            contextInput: boardContextInput(),
            kernel,
        }),
    );
    const verifyBoardCarrier = (
        carrier: Uint8Array,
    ): VerifiedTranscriptObject =>
        requireValid(
            boardSession.verifyUnorderedCarriers([
                { canonicalCarrier: carrier },
            ]),
        )[0];
    const acceptedSetupAuthority =
        createVerifiedAcceptedSetupAuthorityKernelOwner({
            handle: 51,
            kernel,
            releaseKernelAuthority: () => undefined,
        });
    const createVerifiedBallot = (handle: number): VerifiedBallotOutput =>
        createVerifiedBallotOutputKernelAuthority({
            handle,
            kernel,
            releaseKernelOutput: (releasedHandle) => {
                ballotReleaseHandles.push(releasedHandle);
            },
        });

    return {
        absorbedBallotHandles,
        absorbedStoreRanges,
        acceptedSetupAuthority,
        aggregateCancelHandles,
        aggregateDiscardHandles,
        allocations,
        ballotReleaseHandles,
        boardCarrierInputs,
        boardSession,
        createVerifiedBallot,
        evaluatorCancelHandles,
        evaluatorReplayReleaseHandles,
        kernel,
        verifyBoardCarrier,
    };
};

const aggregateVerifiedBallots = (
    runtime: FakeEvaluatorRuntime,
): Readonly<{
    aggregateAuthority: VerifiedEvaluatorAggregateAuthority;
    aggregateObject: VerifiedTranscriptObject;
}> => {
    const aggregateObject = runtime.verifyBoardCarrier(Uint8Array.of(0x71));
    const aggregation = openVerifiedBallotAggregationInClosedWorker({
        kernel: runtime.kernel,
    });
    aggregation.absorb(runtime.createVerifiedBallot(61));
    aggregation.absorb(runtime.createVerifiedBallot(62));
    return {
        aggregateAuthority: aggregation.finish(aggregateObject),
        aggregateObject,
    };
};

describe('evaluator replay worker runtime', () => {
    it('streams the exact bigint store range and binds only after board ingestion', async () => {
        const runtime = createFakeEvaluatorRuntime();
        const { aggregateAuthority, aggregateObject } =
            aggregateVerifiedBallots(runtime);
        const requestedRanges: Array<
            Readonly<{ byteLength: number; offset: bigint }>
        > = [];
        const observedRanges: Array<
            Readonly<{
                requestedByteLength: number;
                returnedByteLength: number;
                storeByteOffset: bigint;
            }>
        > = [];
        const source: EvaluatorKeyStoreRangeSource = {
            readExactRange: (offset, exactByteLength) => {
                requestedRanges.push({ byteLength: exactByteLength, offset });
                return Promise.resolve(Uint8Array.of(0x10, 0x20, 0x30));
            },
        };

        const prepared = await prepareEvaluatorReplayInClosedWorker({
            acceptedSetupAuthority: runtime.acceptedSetupAuthority,
            evaluatorKeyStore: source,
            kernel: runtime.kernel,
            options: {
                observeEvaluatorKeyStoreRangeRead: (
                    observation: EvaluatorKeyStoreRangeReadObservation,
                ) => {
                    observedRanges.push(observation);
                },
                yieldControl: () => Promise.resolve(),
            },
            verifiedAggregateAuthority: aggregateAuthority,
        });

        expect(requestedRanges).toEqual([
            { byteLength: 3, offset: evaluatorStoreByteOffset },
        ]);
        expect(observedRanges).toEqual([
            {
                requestedByteLength: 3,
                returnedByteLength: 3,
                storeByteOffset: evaluatorStoreByteOffset,
            },
        ]);
        expect(runtime.absorbedStoreRanges).toEqual([
            {
                bytes: Uint8Array.of(0x10, 0x20, 0x30),
                offset: evaluatorStoreByteOffset,
            },
        ]);
        expect(prepared.copyCanonicalCarrier()).toEqual(replayCarrier);
        expect(() => aggregateAuthority.release()).toThrow(
            CanonicalStreamRefusalError,
        );

        const replayObject = runtime.verifyBoardCarrier(
            prepared.copyCanonicalCarrier(),
        );
        const verifiedReplay = prepared.bind(replayObject);
        releaseVerifiedEvaluatorReplay(verifiedReplay);
        expect(runtime.evaluatorReplayReleaseHandles).toEqual([41]);
        expect(() => prepared.copyCanonicalCarrier()).toThrow(
            CanonicalStreamRefusalError,
        );
        expect(runtime.absorbedBallotHandles).toEqual([61, 62]);
        expect(runtime.ballotReleaseHandles).toEqual([]);
        expect(runtime.aggregateDiscardHandles).toEqual([]);
        expect(runtime.evaluatorCancelHandles).toEqual([]);

        runtime.boardSession.release(replayObject);
        runtime.boardSession.release(aggregateObject);
        runtime.acceptedSetupAuthority.release();
        runtime.boardSession.close();
        expect(runtime.allocations.size).toBe(0);
    });

    it('keeps a prepared replay live after a board-binding refusal and accepts a corrected retry', async () => {
        const runtime = createFakeEvaluatorRuntime({
            bindReplayStatuses: [refusalReasonCodes.wrongHashOrRoot, 0],
        });
        const { aggregateAuthority, aggregateObject } =
            aggregateVerifiedBallots(runtime);
        const prepared = await prepareEvaluatorReplayInClosedWorker({
            acceptedSetupAuthority: runtime.acceptedSetupAuthority,
            evaluatorKeyStore: {
                readExactRange: () => Promise.resolve(Uint8Array.of(1, 2, 3)),
            },
            kernel: runtime.kernel,
            options: { yieldControl: () => Promise.resolve() },
            verifiedAggregateAuthority: aggregateAuthority,
        });
        const replayObject = runtime.verifyBoardCarrier(
            prepared.copyCanonicalCarrier(),
        );

        expect(() => prepared.bind(replayObject)).toThrow(
            CanonicalStreamRefusalError,
        );
        expect(prepared.copyCanonicalCarrier()).toEqual(replayCarrier);
        const verifiedReplay = prepared.bind(replayObject);
        releaseVerifiedEvaluatorReplay(verifiedReplay);
        expect(runtime.evaluatorReplayReleaseHandles).toEqual([41]);
        expect(runtime.evaluatorCancelHandles).toEqual([]);

        runtime.boardSession.release(replayObject);
        runtime.boardSession.release(aggregateObject);
        runtime.acceptedSetupAuthority.release();
        runtime.boardSession.close();
        expect(runtime.allocations.size).toBe(0);
    });

    it('retains the refused and unvisited ballot authorities when aggregation poisons', () => {
        const runtime = createFakeEvaluatorRuntime({
            absorbBallotStatuses: [0, refusalReasonCodes.wrongContext],
        });
        const aggregateObject = runtime.verifyBoardCarrier(Uint8Array.of(0x71));
        const aggregation = openVerifiedBallotAggregationInClosedWorker({
            kernel: runtime.kernel,
        });
        const firstBallot = runtime.createVerifiedBallot(61);
        aggregation.absorb(firstBallot);
        const refusedBallot = runtime.createVerifiedBallot(62);

        expect(() => aggregation.absorb(refusedBallot)).toThrow(
            CanonicalStreamRefusalError,
        );
        expect(() => firstBallot.release()).toThrow(
            CanonicalStreamRefusalError,
        );
        refusedBallot.release();
        expect(runtime.ballotReleaseHandles).toEqual([62]);
        expect(runtime.aggregateCancelHandles).toEqual([11]);
        expect(runtime.aggregateDiscardHandles).toEqual([]);

        runtime.boardSession.release(aggregateObject);
        runtime.acceptedSetupAuthority.release();
        runtime.boardSession.close();
        expect(runtime.allocations.size).toBe(0);
    });

    it('cancels the resident evaluator when the store returns a wrong-length range', async () => {
        const runtime = createFakeEvaluatorRuntime();
        const { aggregateAuthority, aggregateObject } =
            aggregateVerifiedBallots(runtime);
        const wrongRange = Uint8Array.of(1, 2);

        await expect(
            prepareEvaluatorReplayInClosedWorker({
                acceptedSetupAuthority: runtime.acceptedSetupAuthority,
                evaluatorKeyStore: {
                    readExactRange: () => Promise.resolve(wrongRange),
                },
                kernel: runtime.kernel,
                options: { yieldControl: () => Promise.resolve() },
                verifiedAggregateAuthority: aggregateAuthority,
            }),
        ).rejects.toThrow(CanonicalStreamRefusalError);
        expect(wrongRange).toEqual(Uint8Array.of(0, 0));
        expect(runtime.evaluatorCancelHandles).toEqual([31]);
        expect(() => aggregateAuthority.release()).toThrow(
            CanonicalStreamRefusalError,
        );

        runtime.boardSession.release(aggregateObject);
        runtime.acceptedSetupAuthority.release();
        runtime.boardSession.close();
        expect(runtime.allocations.size).toBe(0);
    });

    it('zeroes the returned range and cancels when measurement observation fails', async () => {
        const runtime = createFakeEvaluatorRuntime();
        const { aggregateAuthority, aggregateObject } =
            aggregateVerifiedBallots(runtime);
        const returnedRange = Uint8Array.of(1, 2, 3);
        const observationFailure = new Error(
            'The evaluator range observation failed.',
        );

        await expect(
            prepareEvaluatorReplayInClosedWorker({
                acceptedSetupAuthority: runtime.acceptedSetupAuthority,
                evaluatorKeyStore: {
                    readExactRange: () => Promise.resolve(returnedRange),
                },
                kernel: runtime.kernel,
                options: {
                    observeEvaluatorKeyStoreRangeRead: () => {
                        throw observationFailure;
                    },
                    yieldControl: () => Promise.resolve(),
                },
                verifiedAggregateAuthority: aggregateAuthority,
            }),
        ).rejects.toBe(observationFailure);
        expect(returnedRange).toEqual(Uint8Array.of(0, 0, 0));
        expect(runtime.evaluatorCancelHandles).toEqual([31]);

        runtime.boardSession.release(aggregateObject);
        runtime.acceptedSetupAuthority.release();
        runtime.boardSession.close();
        expect(runtime.allocations.size).toBe(0);
    });

    it('does not cancel an execution Rust already discarded after refusal', async () => {
        const runtime = createFakeEvaluatorRuntime({
            evaluatorPollStatuses: [refusalReasonCodes.wrongHashOrRoot],
        });
        const { aggregateAuthority, aggregateObject } =
            aggregateVerifiedBallots(runtime);

        await expect(
            prepareEvaluatorReplayInClosedWorker({
                acceptedSetupAuthority: runtime.acceptedSetupAuthority,
                evaluatorKeyStore: {
                    readExactRange: () =>
                        Promise.reject(
                            new Error('the refused evaluator must not read'),
                        ),
                },
                kernel: runtime.kernel,
                options: { yieldControl: () => Promise.resolve() },
                verifiedAggregateAuthority: aggregateAuthority,
            }),
        ).rejects.toThrow(CanonicalStreamRefusalError);
        expect(runtime.evaluatorCancelHandles).toEqual([]);
        expect(() => aggregateAuthority.release()).toThrow(
            CanonicalStreamRefusalError,
        );

        runtime.boardSession.release(aggregateObject);
        runtime.acceptedSetupAuthority.release();
        runtime.boardSession.close();
        expect(runtime.allocations.size).toBe(0);
    });
});
