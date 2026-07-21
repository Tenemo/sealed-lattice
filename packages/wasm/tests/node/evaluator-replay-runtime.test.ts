import { refusalReasonCodes } from '@sealed-lattice/types';
import { describe, expect, it } from 'vitest';

import {
    createVerifiedAcceptedSetupAuthorityKernelOwner,
    type VerifiedAcceptedSetupAuthority,
} from '#packages/wasm/src/accepted-setup-verification-runtime';
import {
    openVerifiedBallotAggregationInClosedWorker,
    resumeVerifiedBallotAggregationFromCheckpointInClosedWorker,
    type BallotAggregationCheckpointBoundary,
    type BallotAggregationCheckpointCustody,
    type BallotAggregationCheckpointOperationIdentity,
    type BallotAggregationCheckpointReplaySource,
    type BallotAggregationSelectionIdentity,
    type ExpectedBallotAggregationCheckpointBoundary,
    type EvaluatorKeyStoreRangeSource,
    type ResumedBallotAggregationCheckpoint,
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
import {
    CanonicalStreamCancellationError,
    CanonicalStreamCleanupError,
    CanonicalStreamRefusalError,
    CanonicalStreamResourceError,
} from '#packages/wasm/src/canonical-stream-runtime';
import { prepareEvaluatorReplayInClosedWorker } from '#packages/wasm/src/evaluator-replay-runtime';
import { releaseVerifiedEvaluatorReplay } from '#packages/wasm/src/finality-verifier-runtime';
import { registerCommonProofKernelContext } from '#packages/wasm/src/transcript-core-bridge/common-proof-kernel-context';
import type { TranscriptCoreKernelCommandRuntime } from '#packages/wasm/src/transcript-core-bridge/kernel-runtime';
import type { TranscriptCoreKernel } from '#packages/wasm/src/transcript-core-bridge/kernel-types';

const aggregationStoreByteOffset = 0x0020_0000_0000_0001n;
const evaluatorStoreByteOffset = 0x0020_0000_0000_0101n;
const aggregateCarrier = Uint8Array.of(0x71, 0x72, 0x73, 0x74);
const replayCarrier = Uint8Array.of(0xa1, 0xb2, 0xc3);
const acceptedSetupSourceHash = new Uint8Array(64).fill(0x81);
const ballotCandidateViewRoot = new Uint8Array(64).fill(0x82);

const selectionIdentity = (
    producerRosterPosition: number,
): BallotAggregationSelectionIdentity => ({
    ballotObjectHash: new Uint8Array(64).fill(0x90 + producerRosterPosition),
    producerRosterPosition,
});

type CheckpointManifestScope = Readonly<{
    actionContextHash: Uint8Array;
    ceremonyContextHash: Uint8Array;
    ownerParticipantIdentity: Uint8Array;
    runtimeBuildManifestHash: Uint8Array;
    suiteIdentifier: Uint8Array;
}>;

type StoredSelectionCheckpoint = {
    boundary: BallotAggregationCheckpointBoundary;
    canonicalManifestBytes: Uint8Array;
    scope: CheckpointManifestScope;
    stateBytes: Uint8Array;
};

type FakeCheckpointDurableState = {
    nextLineageByte: number;
    records: Map<string, StoredSelectionCheckpoint>;
};

type FakeCheckpointCustodyFixture = Readonly<{
    custody: BallotAggregationCheckpointCustody;
    durableState: FakeCheckpointDurableState;
    replaceAuthenticatedState(
        checkpointLineageIdentifier: Uint8Array,
        replacementState: Uint8Array,
    ): void;
}>;

const defaultCheckpointManifestScope = (): CheckpointManifestScope => ({
    actionContextHash: new Uint8Array(64).fill(0xa1),
    ceremonyContextHash: new Uint8Array(64).fill(0xa2),
    ownerParticipantIdentity: new Uint8Array(64).fill(0xa3),
    runtimeBuildManifestHash: new Uint8Array(64).fill(0xa4),
    suiteIdentifier: new Uint8Array(64).fill(0xa5),
});

const testBytesEqual = (left: Uint8Array, right: Uint8Array): boolean =>
    left.byteLength === right.byteLength &&
    left.every((byte, index) => byte === right[index]);

const checkpointLineageKey = (bytes: Uint8Array): string =>
    [...bytes].map((byte) => byte.toString(16).padStart(2, '0')).join('');

const copyCheckpointScope = (
    scope: CheckpointManifestScope,
): CheckpointManifestScope => ({
    actionContextHash: scope.actionContextHash.slice(),
    ceremonyContextHash: scope.ceremonyContextHash.slice(),
    ownerParticipantIdentity: scope.ownerParticipantIdentity.slice(),
    runtimeBuildManifestHash: scope.runtimeBuildManifestHash.slice(),
    suiteIdentifier: scope.suiteIdentifier.slice(),
});

const checkpointScopesEqual = (
    left: CheckpointManifestScope,
    right: CheckpointManifestScope,
): boolean =>
    testBytesEqual(left.actionContextHash, right.actionContextHash) &&
    testBytesEqual(left.ceremonyContextHash, right.ceremonyContextHash) &&
    testBytesEqual(
        left.ownerParticipantIdentity,
        right.ownerParticipantIdentity,
    ) &&
    testBytesEqual(
        left.runtimeBuildManifestHash,
        right.runtimeBuildManifestHash,
    ) &&
    testBytesEqual(left.suiteIdentifier, right.suiteIdentifier);

const describeTestCheckpointState = (stateBytes: Uint8Array): Uint8Array => {
    const descriptor = new Uint8Array(8);
    const view = new DataView(descriptor.buffer);
    view.setUint32(0, stateBytes.byteLength, true);
    view.setUint32(
        4,
        stateBytes.reduce(
            (checksum, byte, index) => (checksum + byte * (index + 1)) >>> 0,
            0,
        ),
        true,
    );
    return descriptor;
};

const copyCheckpointBoundary = (
    boundary: BallotAggregationCheckpointBoundary,
): BallotAggregationCheckpointBoundary => ({
    operationKind: boundary.operationKind,
    orderedSourceDigests: boundary.orderedSourceDigests.map((digest) =>
        digest.slice(),
    ),
    privateRandomCursorManifestBytes:
        boundary.privateRandomCursorManifestBytes.slice(),
    safeBoundaryOrdinal: boundary.safeBoundaryOrdinal,
    stateStreamDescriptorBytes: boundary.stateStreamDescriptorBytes.slice(),
    stateStreamDomain: boundary.stateStreamDomain,
});

const checkpointBoundaryMatches = (
    stored: BallotAggregationCheckpointBoundary,
    expected: ExpectedBallotAggregationCheckpointBoundary,
): boolean =>
    stored.operationKind === expected.operationKind &&
    stored.safeBoundaryOrdinal === expected.safeBoundaryOrdinal &&
    stored.stateStreamDomain === expected.stateStreamDomain &&
    testBytesEqual(
        stored.privateRandomCursorManifestBytes,
        expected.privateRandomCursorManifestBytes,
    ) &&
    stored.orderedSourceDigests.length ===
        expected.orderedSourceDigests.length &&
    stored.orderedSourceDigests.every((digest, index) =>
        testBytesEqual(digest, expected.orderedSourceDigests[index]),
    );

const createFakeCheckpointCustody = (input?: {
    durableState?: FakeCheckpointDurableState;
    scope?: CheckpointManifestScope;
}): FakeCheckpointCustodyFixture => {
    const durableState = input?.durableState ?? {
        nextLineageByte: 1,
        records: new Map<string, StoredSelectionCheckpoint>(),
    };
    const scope = copyCheckpointScope(
        input?.scope ?? defaultCheckpointManifestScope(),
    );
    const activeIdentities = new WeakSet<object>();
    const beginOperation = (
        signal: AbortSignal,
    ): Promise<BallotAggregationCheckpointOperationIdentity> => {
        signal.throwIfAborted();
        const identity = Object.freeze({
            checkpointLineageIdentifier: new Uint8Array(32).fill(
                durableState.nextLineageByte,
            ),
        });
        durableState.nextLineageByte += 1;
        activeIdentities.add(identity);
        return Promise.resolve(identity);
    };
    const custody: BallotAggregationCheckpointCustody = {
        beginOperation,
        describeStateStream: ({ stateBytes }) =>
            describeTestCheckpointState(stateBytes),
        publish: async ({ boundary, identity, signal, stateChunks }) => {
            signal.throwIfAborted();
            if (!activeIdentities.has(identity)) {
                throw new CanonicalStreamRefusalError('consumedState');
            }
            const chunks: Uint8Array[] = [];
            for await (const chunk of stateChunks) {
                signal.throwIfAborted();
                chunks.push(chunk.slice());
            }
            const stateByteLength = chunks.reduce(
                (total, chunk) => total + chunk.byteLength,
                0,
            );
            const stateBytes = new Uint8Array(stateByteLength);
            let offset = 0;
            for (const chunk of chunks) {
                stateBytes.set(chunk, offset);
                offset += chunk.byteLength;
                chunk.fill(0);
            }
            if (
                !testBytesEqual(
                    boundary.stateStreamDescriptorBytes,
                    describeTestCheckpointState(stateBytes),
                )
            ) {
                stateBytes.fill(0);
                throw new CanonicalStreamRefusalError('wrongHashOrRoot');
            }
            const key = checkpointLineageKey(
                identity.checkpointLineageIdentifier,
            );
            const canonicalManifestBytes = Uint8Array.of(
                0xc1,
                identity.checkpointLineageIdentifier[0] ?? 0,
            );
            durableState.records.set(key, {
                boundary: copyCheckpointBoundary(boundary),
                canonicalManifestBytes: canonicalManifestBytes.slice(),
                scope: copyCheckpointScope(scope),
                stateBytes,
            });
            signal.throwIfAborted();
            return canonicalManifestBytes;
        },
        releaseOperationIdentity: (identity) => {
            if (!activeIdentities.has(identity)) {
                return Promise.reject(
                    new CanonicalStreamRefusalError('consumedState'),
                );
            }
            activeIdentities.delete(identity);
            identity.checkpointLineageIdentifier.fill(0);
            return Promise.resolve();
        },
        resume: ({ checkpointLineageIdentifier, expectedBoundary, signal }) => {
            signal.throwIfAborted();
            const stored = durableState.records.get(
                checkpointLineageKey(checkpointLineageIdentifier),
            );
            if (stored === undefined) {
                return Promise.reject(
                    new CanonicalStreamRefusalError('missingPrerequisite'),
                );
            }
            if (
                !checkpointScopesEqual(stored.scope, scope) ||
                !checkpointBoundaryMatches(stored.boundary, expectedBoundary)
            ) {
                return Promise.reject(
                    new CanonicalStreamRefusalError('wrongContext'),
                );
            }
            if (
                !testBytesEqual(
                    stored.boundary.stateStreamDescriptorBytes,
                    describeTestCheckpointState(stored.stateBytes),
                )
            ) {
                return Promise.reject(
                    new CanonicalStreamRefusalError('wrongHashOrRoot'),
                );
            }
            const operationIdentity = Object.freeze({
                checkpointLineageIdentifier:
                    checkpointLineageIdentifier.slice(),
            });
            activeIdentities.add(operationIdentity);
            const resumed: ResumedBallotAggregationCheckpoint = Object.freeze({
                canonicalManifestBytes: stored.canonicalManifestBytes.slice(),
                operationIdentity,
                stateStreamDescriptorBytes:
                    stored.boundary.stateStreamDescriptorBytes.slice(),
                restoreState: async (consumeChunk, restoreSignal) => {
                    restoreSignal.throwIfAborted();
                    await consumeChunk(0, stored.stateBytes.slice());
                    restoreSignal.throwIfAborted();
                },
            });
            return Promise.resolve(resumed);
        },
    };
    return Object.freeze({
        custody: Object.freeze(custody),
        durableState,
        replaceAuthenticatedState: (
            checkpointLineageIdentifier,
            replacementState,
        ): void => {
            const stored = durableState.records.get(
                checkpointLineageKey(checkpointLineageIdentifier),
            );
            if (stored === undefined) {
                throw new Error('the test checkpoint is missing');
            }
            stored.stateBytes.fill(0);
            stored.stateBytes = replacementState.slice();
            stored.boundary = {
                ...stored.boundary,
                stateStreamDescriptorBytes:
                    describeTestCheckpointState(replacementState),
            };
        },
    });
};

type DeferredPromise<Value> = Readonly<{
    promise: Promise<Value>;
    reject(reason?: unknown): void;
    resolve(value: Value | PromiseLike<Value>): void;
}>;

const createDeferredPromise = <Value>(): DeferredPromise<Value> => {
    let resolvePromise = (_value: Value | PromiseLike<Value>): void =>
        undefined;
    let rejectPromise = (_reason?: unknown): void => undefined;
    const promise = new Promise<Value>((resolve, reject) => {
        resolvePromise = resolve;
        rejectPromise = reject;
    });
    return Object.freeze({
        promise,
        reject: rejectPromise,
        resolve: resolvePromise,
    });
};

const waitForNextHostTask = (): Promise<void> =>
    new Promise((resolve) => {
        const channel = new MessageChannel();
        channel.port1.onmessage = () => {
            channel.port1.close();
            channel.port2.close();
            resolve();
        };
        channel.port2.postMessage(undefined);
    });

type PromptPromiseSettlement =
    | Readonly<{ error: unknown; kind: 'rejected' }>
    | Readonly<{ kind: 'pending' }>
    | Readonly<{ kind: 'fulfilled' }>;

const settleBeforeNextHostTask = async (
    promise: Promise<unknown>,
): Promise<PromptPromiseSettlement> =>
    await Promise.race([
        promise.then(
            () => Object.freeze({ kind: 'fulfilled' as const }),
            (error: unknown) =>
                Object.freeze({ error, kind: 'rejected' as const }),
        ),
        waitForNextHostTask().then(() =>
            Object.freeze({ kind: 'pending' as const }),
        ),
    ]);

const expectPromptCancellation = async (
    promise: Promise<unknown>,
): Promise<void> => {
    const settlement = await settleBeforeNextHostTask(promise);
    expect(settlement.kind).toBe('rejected');
    if (settlement.kind !== 'rejected') {
        throw new Error(
            'The worker operation did not reject before the next host task.',
        );
    }
    expect(settlement.error).toBeInstanceOf(CanonicalStreamCancellationError);
};

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

type AbsorbedStoreRange = Readonly<{
    bytes: Uint8Array;
    offset: bigint;
}>;

type FakeEvaluatorRuntime = Readonly<{
    acceptedSetupAuthority: VerifiedAcceptedSetupAuthority;
    acceptedSetupBeginHandles: number[];
    acceptedSetupReleaseHandles: number[];
    aggregateBindObjectHandles: number[];
    aggregateCancelHandles: number[];
    aggregateCarrierStagingBytesAtDeallocation: Uint8Array[];
    aggregateDiscardHandles: number[];
    aggregatePollHandles: number[];
    aggregationStoreRanges: AbsorbedStoreRange[];
    allocations: ReadonlyMap<number, number>;
    absorbedBallotHandles: number[];
    ballotReleaseHandles: number[];
    boardCarrierInputs: Uint8Array[];
    boardSession: CanonicalBoardVerifierSession;
    createVerifiedBallot(
        handle: number,
        identity: BallotAggregationSelectionIdentity,
    ): VerifiedBallotOutput;
    evaluatorBeginAuthorityHandles: number[];
    evaluatorCancelHandles: number[];
    evaluatorReplayReleaseHandles: number[];
    evaluatorStoreRanges: AbsorbedStoreRange[];
    kernel: TranscriptCoreKernel;
    verifyBoardCarrier(carrier: Uint8Array): VerifiedTranscriptObject;
}>;

const createFakeEvaluatorRuntime = (
    options: {
        aggregateBindStatuses?: readonly number[];
        aggregateCarrierBytes?: Uint8Array;
        aggregateCarrierCopyStatuses?: readonly number[];
        aggregateCarrierLengthStatuses?: readonly number[];
        evaluatorBindStatuses?: readonly number[];
        verifiedSetupSourceHash?: Uint8Array;
    } = {},
): FakeEvaluatorRuntime => {
    const memory = new WebAssembly.Memory({ initial: 4 });
    const allocations = new Map<number, number>();
    const acceptedSetupBeginHandles: number[] = [];
    const acceptedSetupReleaseHandles: number[] = [];
    const absorbedBallotHandles: number[] = [];
    const aggregateBindObjectHandles: number[] = [];
    const aggregateCancelHandles: number[] = [];
    const aggregateCarrierStagingBytesAtDeallocation: Uint8Array[] = [];
    const aggregateDiscardHandles: number[] = [];
    const aggregatePollHandles: number[] = [];
    const aggregationStoreRanges: AbsorbedStoreRange[] = [];
    const ballotReleaseHandles: number[] = [];
    const ballotSelectionByHandle = new Map<
        number,
        BallotAggregationSelectionIdentity
    >();
    const boardCarrierInputs: Uint8Array[] = [];
    const evaluatorBeginAuthorityHandles: number[] = [];
    const evaluatorCancelHandles: number[] = [];
    const evaluatorReplayReleaseHandles: number[] = [];
    const evaluatorStoreRanges: AbsorbedStoreRange[] = [];
    const aggregateBindStatuses = [...(options.aggregateBindStatuses ?? [0])];
    const selectedAggregateCarrier =
        options.aggregateCarrierBytes ?? aggregateCarrier;
    const aggregateCarrierCopyStatuses = [
        ...(options.aggregateCarrierCopyStatuses ?? [0]),
    ];
    const aggregateCarrierLengthStatuses = [
        ...(options.aggregateCarrierLengthStatuses ?? [0]),
    ];
    const evaluatorBindStatuses = [...(options.evaluatorBindStatuses ?? [0])];
    const selectedVerifiedSetupSourceHash =
        options.verifiedSetupSourceHash ?? acceptedSetupSourceHash;
    let nextPointer = 8;
    let nextBoardObjectHandle = 70;
    let pendingBallotHandle: number | undefined;
    let absorbedBallotCount = 0;
    let aggregationHasAbsorbedStoreRange = false;
    let aggregationKeyLoaded = false;
    let aggregateCarrierStagingRange:
        | Readonly<{ byteLength: number; pointer: number }>
        | undefined;
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
        if (
            aggregateCarrierStagingRange?.pointer === pointer &&
            aggregateCarrierStagingRange.byteLength === byteLength
        ) {
            aggregateCarrierStagingBytesAtDeallocation.push(
                copyInputBytes(pointer, byteLength),
            );
            aggregateCarrierStagingRange = undefined;
        }
        allocations.delete(pointer);
    };
    const writeStatus = (pointer: number, status: number): void => {
        new DataView(memory.buffer).setUint32(pointer, status, true);
    };
    const writeProgress = (input: {
        byteLength: number;
        code: number;
        exactByteLength?: number;
        outputPointer: number;
        selectionIdentity?: BallotAggregationSelectionIdentity;
        storeByteOffset?: bigint;
    }): number => {
        if (input.byteLength !== 16 && input.byteLength !== 136) {
            return refusalReasonCodes.wrongTypeOrLength;
        }
        new Uint8Array(
            memory.buffer,
            input.outputPointer,
            input.byteLength,
        ).fill(0);
        const view = new DataView(memory.buffer);
        view.setUint16(
            input.outputPointer,
            input.byteLength === 136 ? 2 : 1,
            true,
        );
        view.setUint16(input.outputPointer + 2, input.code, true);
        if (input.selectionIdentity === undefined) {
            view.setBigUint64(
                input.outputPointer + 4,
                input.storeByteOffset ?? 0n,
                true,
            );
            view.setUint32(
                input.outputPointer + 12,
                input.exactByteLength ?? 0,
                true,
            );
        } else {
            view.setUint16(
                input.outputPointer + 4,
                input.selectionIdentity.producerRosterPosition,
                true,
            );
            new Uint8Array(memory.buffer).set(
                input.selectionIdentity.ballotObjectHash,
                input.outputPointer + 8,
            );
            new Uint8Array(memory.buffer).set(
                selectedVerifiedSetupSourceHash,
                input.outputPointer + 72,
            );
        }
        return 0;
    };
    const copyInputBytes = (pointer: number, byteLength: number): Uint8Array =>
        Uint8Array.from(new Uint8Array(memory.buffer, pointer, byteLength));

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
                if (pendingBallotHandle !== undefined) {
                    return refusalReasonCodes.consumedState;
                }
                absorbedBallotHandles.push(verifiedBallotOutputHandle);
                pendingBallotHandle = verifiedBallotOutputHandle;
                aggregationHasAbsorbedStoreRange = false;
                return 0;
            },
            sealed_lattice_ballot_aggregation_absorb_store_chunk: (
                _aggregationHandle: number,
                storeByteOffset: bigint,
                chunkPointer: number,
                chunkByteLength: number,
            ) => {
                aggregationStoreRanges.push({
                    bytes: copyInputBytes(chunkPointer, chunkByteLength),
                    offset: storeByteOffset,
                });
                aggregationHasAbsorbedStoreRange = true;
                aggregationKeyLoaded = true;
                return 0;
            },
            sealed_lattice_ballot_aggregation_aggregate_carrier_byte_length: (
                _aggregationHandle: number,
                statusPointer: number,
            ) => {
                const status = aggregateCarrierLengthStatuses.shift() ?? 0;
                writeStatus(statusPointer, status);
                return status === 0 ? selectedAggregateCarrier.byteLength : 0;
            },
            sealed_lattice_ballot_aggregation_begin: (
                acceptedSetupAuthorityHandle: number,
                statusPointer: number,
            ) => {
                acceptedSetupBeginHandles.push(acceptedSetupAuthorityHandle);
                writeStatus(statusPointer, 0);
                return 11;
            },
            sealed_lattice_ballot_aggregation_bind_aggregate_object: (
                _aggregationHandle: number,
                _boardSessionHandle: number,
                _boardCapabilityPointer: number,
                _boardCapabilityByteLength: number,
                verifiedAggregateObjectHandle: number,
                statusPointer: number,
            ) => {
                aggregateBindObjectHandles.push(verifiedAggregateObjectHandle);
                const status = aggregateBindStatuses.shift() ?? 0;
                writeStatus(statusPointer, status);
                return status === 0 ? 21 : 0;
            },
            sealed_lattice_ballot_aggregation_cancel: (
                aggregationHandle: number,
            ) => {
                aggregateCancelHandles.push(aggregationHandle);
                pendingBallotHandle = undefined;
                return 0;
            },
            sealed_lattice_ballot_aggregation_copy_aggregate_carrier: (
                _aggregationHandle: number,
                outputPointer: number,
                outputByteLength: number,
            ) => {
                if (outputByteLength !== selectedAggregateCarrier.byteLength) {
                    return refusalReasonCodes.wrongTypeOrLength;
                }
                aggregateCarrierStagingRange = {
                    byteLength: outputByteLength,
                    pointer: outputPointer,
                };
                new Uint8Array(memory.buffer).set(
                    selectedAggregateCarrier,
                    outputPointer,
                );
                return aggregateCarrierCopyStatuses.shift() ?? 0;
            },
            sealed_lattice_ballot_aggregation_discard_verified_aggregate: (
                aggregateAuthorityHandle: number,
            ) => {
                aggregateDiscardHandles.push(aggregateAuthorityHandle);
                return 0;
            },
            sealed_lattice_ballot_aggregation_poll: (
                aggregationHandle: number,
                outputPointer: number,
                outputByteLength: number,
            ) => {
                aggregatePollHandles.push(aggregationHandle);
                if (pendingBallotHandle === undefined) {
                    return refusalReasonCodes.consumedState;
                }
                if (
                    absorbedBallotCount > 0 &&
                    !aggregationKeyLoaded &&
                    !aggregationHasAbsorbedStoreRange
                ) {
                    return writeProgress({
                        byteLength: outputByteLength,
                        code: 1,
                        exactByteLength: 3,
                        outputPointer,
                        storeByteOffset: aggregationStoreByteOffset,
                    });
                }
                const completedBallotHandle = pendingBallotHandle;
                const completedSelectionIdentity = ballotSelectionByHandle.get(
                    completedBallotHandle,
                );
                if (completedSelectionIdentity === undefined) {
                    return refusalReasonCodes.wrongContext;
                }
                ballotSelectionByHandle.delete(completedBallotHandle);
                pendingBallotHandle = undefined;
                absorbedBallotCount += 1;
                return writeProgress({
                    byteLength: outputByteLength,
                    code: 2,
                    outputPointer,
                    selectionIdentity: completedSelectionIdentity,
                });
            },
            sealed_lattice_ballot_aggregation_prepare: () => 0,
            sealed_lattice_evaluator_execution_absorb_store_chunk: (
                _executionHandle: number,
                storeByteOffset: bigint,
                chunkPointer: number,
                chunkByteLength: number,
            ) => {
                evaluatorStoreRanges.push({
                    bytes: copyInputBytes(chunkPointer, chunkByteLength),
                    offset: storeByteOffset,
                });
                evaluatorHasAbsorbedStoreRange = true;
                return 0;
            },
            sealed_lattice_evaluator_execution_begin: (
                verifiedAggregateAuthorityHandle: number,
                statusPointer: number,
            ) => {
                evaluatorBeginAuthorityHandles.push(
                    verifiedAggregateAuthorityHandle,
                );
                evaluatorHasAbsorbedStoreRange = false;
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
                const status = evaluatorBindStatuses.shift() ?? 0;
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
            ) =>
                writeProgress({
                    byteLength: outputByteLength,
                    code: evaluatorHasAbsorbedStoreRange ? 2 : 1,
                    exactByteLength: evaluatorHasAbsorbedStoreRange ? 0 : 4,
                    outputPointer,
                    storeByteOffset: evaluatorHasAbsorbedStoreRange
                        ? 0n
                        : evaluatorStoreByteOffset,
                }),
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
                copyInputBytes(framedCarrierPointer, framedCarrierLength),
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
            releaseKernelAuthority: (releasedHandle) => {
                acceptedSetupReleaseHandles.push(releasedHandle);
            },
        });
    const createVerifiedBallot = (
        handle: number,
        identity: BallotAggregationSelectionIdentity,
    ): VerifiedBallotOutput => {
        if (ballotSelectionByHandle.has(handle)) {
            throw new Error('test ballot handle is already retained');
        }
        ballotSelectionByHandle.set(handle, {
            ballotObjectHash: identity.ballotObjectHash.slice(),
            producerRosterPosition: identity.producerRosterPosition,
        });
        return createVerifiedBallotOutputKernelAuthority({
            handle,
            kernel,
            releaseKernelOutput: (releasedHandle) => {
                ballotSelectionByHandle.delete(releasedHandle);
                ballotReleaseHandles.push(releasedHandle);
            },
        });
    };

    return {
        acceptedSetupAuthority,
        acceptedSetupBeginHandles,
        acceptedSetupReleaseHandles,
        aggregateBindObjectHandles,
        aggregateCancelHandles,
        aggregateCarrierStagingBytesAtDeallocation,
        aggregateDiscardHandles,
        aggregatePollHandles,
        aggregationStoreRanges,
        allocations,
        absorbedBallotHandles,
        ballotReleaseHandles,
        boardCarrierInputs,
        boardSession,
        createVerifiedBallot,
        evaluatorBeginAuthorityHandles,
        evaluatorCancelHandles,
        evaluatorReplayReleaseHandles,
        evaluatorStoreRanges,
        kernel,
        verifyBoardCarrier,
    };
};

const openAggregation = (input: {
    evaluatorKeyStore: EvaluatorKeyStoreRangeSource;
    options?: {
        signal?: AbortSignal;
        yieldControl?(): Promise<void>;
    };
    runtime: FakeEvaluatorRuntime;
}) =>
    openVerifiedBallotAggregationInClosedWorker({
        acceptedSetupAuthority: input.runtime.acceptedSetupAuthority,
        ballotCandidateViewRoot,
        evaluatorKeyStore: input.evaluatorKeyStore,
        kernel: input.runtime.kernel,
        options: input.options,
    });

const absorbOneBallot = async (
    runtime: FakeEvaluatorRuntime,
    evaluatorKeyStore: EvaluatorKeyStoreRangeSource,
) => {
    const aggregation = openAggregation({ evaluatorKeyStore, runtime });
    await aggregation.absorb({
        verifiedBallot: runtime.createVerifiedBallot(61, selectionIdentity(0)),
    });
    return aggregation;
};

const createReplaySource = (input: {
    runtime: FakeEvaluatorRuntime;
    selection: readonly BallotAggregationSelectionIdentity[];
}): Readonly<{
    borrowedPreflightPositions: number[];
    replaySource: BallotAggregationCheckpointReplaySource;
    reverifiedPositions: number[];
}> => {
    const borrowedPreflightPositions: number[] = [];
    const reverifiedPositions: number[] = [];
    const expectedByPosition = new Map(
        input.selection.map((entry) => [
            entry.producerRosterPosition,
            entry.ballotObjectHash,
        ]),
    );
    const requireExpectedIdentity = (
        identity: BallotAggregationSelectionIdentity,
    ): void => {
        const expectedHash = expectedByPosition.get(
            identity.producerRosterPosition,
        );
        if (
            expectedHash === undefined ||
            !testBytesEqual(expectedHash, identity.ballotObjectHash)
        ) {
            throw new CanonicalStreamRefusalError('wrongHashOrRoot');
        }
    };
    return Object.freeze({
        borrowedPreflightPositions,
        replaySource: Object.freeze({
            borrowPreflightAcceptedSetupSource: (
                sourceHash: Uint8Array,
                signal: AbortSignal,
            ): Promise<void> => {
                signal.throwIfAborted();
                if (!testBytesEqual(sourceHash, acceptedSetupSourceHash)) {
                    return Promise.reject(
                        new CanonicalStreamRefusalError('wrongHashOrRoot'),
                    );
                }
                return Promise.resolve();
            },
            borrowPreflightSelectedBallot: (
                identity: BallotAggregationSelectionIdentity,
                signal: AbortSignal,
            ): Promise<void> => {
                signal.throwIfAborted();
                requireExpectedIdentity(identity);
                borrowedPreflightPositions.push(
                    identity.producerRosterPosition,
                );
                return Promise.resolve();
            },
            reverifyAcceptedSetup: (
                signal: AbortSignal,
            ): Promise<VerifiedAcceptedSetupAuthority> => {
                signal.throwIfAborted();
                if (
                    borrowedPreflightPositions.length !== input.selection.length
                ) {
                    return Promise.reject(
                        new Error(
                            'the complete selection was not preflighted before setup remint',
                        ),
                    );
                }
                return Promise.resolve(input.runtime.acceptedSetupAuthority);
            },
            reverifySelectedBallot: (
                identity: BallotAggregationSelectionIdentity,
                signal: AbortSignal,
            ): Promise<VerifiedBallotOutput> => {
                signal.throwIfAborted();
                requireExpectedIdentity(identity);
                reverifiedPositions.push(identity.producerRosterPosition);
                return Promise.resolve(
                    input.runtime.createVerifiedBallot(
                        100 + identity.producerRosterPosition,
                        identity,
                    ),
                );
            },
        }),
        reverifiedPositions,
    });
};

const bindPreparedAggregate = (input: {
    prepared: Readonly<{
        bind(
            aggregateObject: VerifiedTranscriptObject,
        ): VerifiedEvaluatorAggregateAuthority;
        copyCanonicalCarrier(): Uint8Array;
    }>;
    runtime: FakeEvaluatorRuntime;
}): Readonly<{
    aggregateAuthority: VerifiedEvaluatorAggregateAuthority;
    aggregateObject: VerifiedTranscriptObject;
}> => {
    const aggregateObject = input.runtime.verifyBoardCarrier(
        input.prepared.copyCanonicalCarrier(),
    );
    return Object.freeze({
        aggregateAuthority: input.prepared.bind(aggregateObject),
        aggregateObject,
    });
};

describe('integrated ballot aggregation and evaluator replay runtime', () => {
    it('rebuilds every selected ballot count from an authenticated selection checkpoint with byte-identical output and key behavior', async () => {
        for (let ballotCount = 1; ballotCount <= 10; ballotCount += 1) {
            const expectedSelection = Array.from(
                { length: ballotCount },
                (_unused, producerRosterPosition) =>
                    selectionIdentity(producerRosterPosition),
            );
            const selectedCarrier = Uint8Array.of(
                0xd0,
                ballotCount,
                ...expectedSelection.map(
                    (entry) => entry.ballotObjectHash[0] ?? 0,
                ),
            );
            const checkpointFixture = createFakeCheckpointCustody();
            const freshRuntime = createFakeEvaluatorRuntime({
                aggregateCarrierBytes: selectedCarrier,
            });
            const freshStoreReads: bigint[] = [];
            const freshAggregation = openAggregation({
                evaluatorKeyStore: {
                    readExactRange: (storeByteOffset, exactByteLength) => {
                        freshStoreReads.push(storeByteOffset);
                        expect(storeByteOffset).toBe(
                            aggregationStoreByteOffset,
                        );
                        expect(exactByteLength).toBe(3);
                        return Promise.resolve(Uint8Array.of(0x11, 0x12, 0x13));
                    },
                },
                options: { yieldControl: () => Promise.resolve() },
                runtime: freshRuntime,
            });
            for (const entry of expectedSelection) {
                await freshAggregation.absorb({
                    verifiedBallot: freshRuntime.createVerifiedBallot(
                        100 + entry.producerRosterPosition,
                        entry,
                    ),
                });
            }
            const checkpoint =
                await freshAggregation.publishSelectionCheckpoint(
                    checkpointFixture.custody,
                );
            const storedCheckpoint = checkpointFixture.durableState.records.get(
                checkpointLineageKey(checkpoint.checkpointLineageIdentifier),
            );
            if (storedCheckpoint === undefined) {
                throw new Error('the published checkpoint is missing');
            }
            expect(storedCheckpoint.boundary).toMatchObject({
                operationKind: 0x1404,
                safeBoundaryOrdinal: 0,
                stateStreamDomain:
                    'sealed-lattice/ballot-aggregation-selection-checkpoint/v1',
            });
            expect(storedCheckpoint.boundary.orderedSourceDigests).toHaveLength(
                ballotCount + 2,
            );
            expect(
                storedCheckpoint.boundary.privateRandomCursorManifestBytes,
            ).toEqual(
                Uint8Array.of(
                    0x53,
                    0x4c,
                    0x43,
                    0x50,
                    0x43,
                    0x4d,
                    0x30,
                    0x33,
                    0x03,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                ),
            );
            expect(
                new DataView(storedCheckpoint.stateBytes.buffer).getUint16(
                    0,
                    true,
                ),
            ).toBe(0x180a);
            await expect(
                freshAggregation.publishSelectionCheckpoint(
                    checkpointFixture.custody,
                ),
            ).rejects.toThrow(CanonicalStreamRefusalError);
            const rejectedExtraBallot = freshRuntime.createVerifiedBallot(
                200 + ballotCount,
                selectionIdentity(ballotCount),
            );
            await expect(
                freshAggregation.absorb({
                    verifiedBallot: rejectedExtraBallot,
                }),
            ).rejects.toThrow(CanonicalStreamRefusalError);
            rejectedExtraBallot.release();
            const freshPrepared = freshAggregation.prepareAggregate();
            const freshCarrier = freshPrepared.copyCanonicalCarrier();
            freshPrepared.cancel();
            freshRuntime.acceptedSetupAuthority.release();
            freshRuntime.boardSession.close();

            const resumedRuntime = createFakeEvaluatorRuntime({
                aggregateCarrierBytes: selectedCarrier,
            });
            const resumedStoreReads: bigint[] = [];
            const replay = createReplaySource({
                runtime: resumedRuntime,
                selection: expectedSelection,
            });
            const resumedAggregation =
                await resumeVerifiedBallotAggregationFromCheckpointInClosedWorker(
                    {
                        acceptedSetupSourceHash,
                        ballotCandidateViewRoot,
                        checkpointCustody: checkpointFixture.custody,
                        checkpointLineageIdentifier:
                            checkpoint.checkpointLineageIdentifier,
                        evaluatorKeyStore: {
                            readExactRange: (
                                storeByteOffset,
                                exactByteLength,
                            ) => {
                                resumedStoreReads.push(storeByteOffset);
                                expect(storeByteOffset).toBe(
                                    aggregationStoreByteOffset,
                                );
                                expect(exactByteLength).toBe(3);
                                return Promise.resolve(
                                    Uint8Array.of(0x21, 0x22, 0x23),
                                );
                            },
                        },
                        expectedSelection,
                        kernel: resumedRuntime.kernel,
                        options: {
                            yieldControl: () => Promise.resolve(),
                        },
                        replaySource: replay.replaySource,
                    },
                );
            expect(replay.borrowedPreflightPositions).toEqual(
                expectedSelection.map((entry) => entry.producerRosterPosition),
            );
            expect(replay.reverifiedPositions).toEqual(
                expectedSelection.map((entry) => entry.producerRosterPosition),
            );
            expect(resumedRuntime.acceptedSetupBeginHandles).toEqual([51]);
            expect(resumedRuntime.acceptedSetupReleaseHandles).toEqual([51]);
            expect(resumedRuntime.absorbedBallotHandles).toEqual(
                expectedSelection.map(
                    (entry) => 100 + entry.producerRosterPosition,
                ),
            );
            expect(freshStoreReads).toEqual(
                ballotCount === 1 ? [] : [aggregationStoreByteOffset],
            );
            expect(resumedStoreReads).toEqual(freshStoreReads);
            expect(resumedRuntime.aggregationStoreRanges.length).toBe(
                freshRuntime.aggregationStoreRanges.length,
            );
            const resumedPrepared = resumedAggregation.prepareAggregate();
            expect(resumedPrepared.copyCanonicalCarrier()).toEqual(
                freshCarrier,
            );
            resumedPrepared.cancel();
            resumedRuntime.boardSession.close();
            expect(freshRuntime.allocations.size).toBe(0);
            expect(resumedRuntime.allocations.size).toBe(0);
        }
    });

    it('refuses resumed capabilities whose Rust-authenticated ballot identity or setup source diverges from the checkpoint', async () => {
        const expectedSelection = [selectionIdentity(0)];
        const checkpointFixture = createFakeCheckpointCustody();
        const freshRuntime = createFakeEvaluatorRuntime();
        const freshAggregation = openAggregation({
            evaluatorKeyStore: {
                readExactRange: () =>
                    Promise.reject(new Error('ballot one needs no key read')),
            },
            runtime: freshRuntime,
        });
        const expectedIdentity = expectedSelection[0];
        if (expectedIdentity === undefined) {
            throw new Error('the selected ballot identity is missing');
        }
        await freshAggregation.absorb({
            verifiedBallot: freshRuntime.createVerifiedBallot(
                61,
                expectedIdentity,
            ),
        });
        const checkpoint = await freshAggregation.publishSelectionCheckpoint(
            checkpointFixture.custody,
        );
        freshAggregation.cancel();
        freshRuntime.acceptedSetupAuthority.release();
        freshRuntime.boardSession.close();

        const mismatchedIdentityRuntime = createFakeEvaluatorRuntime();
        const identityReplay = createReplaySource({
            runtime: mismatchedIdentityRuntime,
            selection: expectedSelection,
        });
        const mismatchedIdentityReplaySource: BallotAggregationCheckpointReplaySource =
            Object.freeze({
                ...identityReplay.replaySource,
                reverifySelectedBallot: (
                    _requestedIdentity,
                    signal,
                ): Promise<VerifiedBallotOutput> => {
                    signal.throwIfAborted();
                    return Promise.resolve(
                        mismatchedIdentityRuntime.createVerifiedBallot(
                            100,
                            selectionIdentity(1),
                        ),
                    );
                },
            });
        await expect(
            resumeVerifiedBallotAggregationFromCheckpointInClosedWorker({
                acceptedSetupSourceHash,
                ballotCandidateViewRoot,
                checkpointCustody: checkpointFixture.custody,
                checkpointLineageIdentifier:
                    checkpoint.checkpointLineageIdentifier,
                evaluatorKeyStore: {
                    readExactRange: () =>
                        Promise.reject(
                            new Error('ballot one needs no key read'),
                        ),
                },
                expectedSelection,
                kernel: mismatchedIdentityRuntime.kernel,
                replaySource: mismatchedIdentityReplaySource,
            }),
        ).rejects.toThrow(CanonicalStreamRefusalError);
        expect(mismatchedIdentityRuntime.aggregateCancelHandles).toEqual([11]);
        expect(mismatchedIdentityRuntime.acceptedSetupReleaseHandles).toEqual([
            51,
        ]);
        mismatchedIdentityRuntime.boardSession.close();

        const mismatchedSetupRuntime = createFakeEvaluatorRuntime({
            verifiedSetupSourceHash: new Uint8Array(64).fill(0xee),
        });
        const setupReplay = createReplaySource({
            runtime: mismatchedSetupRuntime,
            selection: expectedSelection,
        });
        await expect(
            resumeVerifiedBallotAggregationFromCheckpointInClosedWorker({
                acceptedSetupSourceHash,
                ballotCandidateViewRoot,
                checkpointCustody: checkpointFixture.custody,
                checkpointLineageIdentifier:
                    checkpoint.checkpointLineageIdentifier,
                evaluatorKeyStore: {
                    readExactRange: () =>
                        Promise.reject(
                            new Error('ballot one needs no key read'),
                        ),
                },
                expectedSelection,
                kernel: mismatchedSetupRuntime.kernel,
                replaySource: setupReplay.replaySource,
            }),
        ).rejects.toThrow(CanonicalStreamRefusalError);
        expect(mismatchedSetupRuntime.aggregateCancelHandles).toEqual([11]);
        expect(mismatchedSetupRuntime.acceptedSetupReleaseHandles).toEqual([
            51,
        ]);
        mismatchedSetupRuntime.boardSession.close();
    });

    it('releases a resumed custody identity returned beside a malformed record and permits an authenticated retry', async () => {
        const expectedSelection = [selectionIdentity(0)];
        const expectedIdentity = expectedSelection[0];
        if (expectedIdentity === undefined) {
            throw new Error('the selected ballot identity is missing');
        }
        const checkpointFixture = createFakeCheckpointCustody();
        const freshRuntime = createFakeEvaluatorRuntime();
        const freshAggregation = openAggregation({
            evaluatorKeyStore: {
                readExactRange: () =>
                    Promise.reject(new Error('ballot one needs no key read')),
            },
            runtime: freshRuntime,
        });
        await freshAggregation.absorb({
            verifiedBallot: freshRuntime.createVerifiedBallot(
                61,
                expectedIdentity,
            ),
        });
        const checkpoint = await freshAggregation.publishSelectionCheckpoint(
            checkpointFixture.custody,
        );
        freshAggregation.cancel();
        freshRuntime.acceptedSetupAuthority.release();
        freshRuntime.boardSession.close();

        let returnedIdentity:
            | BallotAggregationCheckpointOperationIdentity
            | undefined;
        const malformedCustody: BallotAggregationCheckpointCustody =
            Object.freeze({
                ...checkpointFixture.custody,
                resume: async (input) => {
                    const resumed =
                        await checkpointFixture.custody.resume(input);
                    returnedIdentity = resumed.operationIdentity;
                    return Object.freeze({
                        ...resumed,
                        canonicalManifestBytes: new Uint8Array(),
                    });
                },
            });
        const refusedRuntime = createFakeEvaluatorRuntime();
        const refusedReplay = createReplaySource({
            runtime: refusedRuntime,
            selection: expectedSelection,
        });
        await expect(
            resumeVerifiedBallotAggregationFromCheckpointInClosedWorker({
                acceptedSetupSourceHash,
                ballotCandidateViewRoot,
                checkpointCustody: malformedCustody,
                checkpointLineageIdentifier:
                    checkpoint.checkpointLineageIdentifier,
                evaluatorKeyStore: {
                    readExactRange: () =>
                        Promise.reject(
                            new Error('a malformed resume needs no key read'),
                        ),
                },
                expectedSelection,
                kernel: refusedRuntime.kernel,
                replaySource: refusedReplay.replaySource,
            }),
        ).rejects.toThrow(CanonicalStreamRefusalError);
        if (returnedIdentity === undefined) {
            throw new Error('the malformed custody returned no identity');
        }
        expect(returnedIdentity.checkpointLineageIdentifier).toEqual(
            new Uint8Array(32),
        );
        expect(refusedReplay.borrowedPreflightPositions).toEqual([]);
        expect(refusedReplay.reverifiedPositions).toEqual([]);
        refusedRuntime.acceptedSetupAuthority.release();
        refusedRuntime.boardSession.close();

        const retryRuntime = createFakeEvaluatorRuntime();
        const retryReplay = createReplaySource({
            runtime: retryRuntime,
            selection: expectedSelection,
        });
        const retriedAggregation =
            await resumeVerifiedBallotAggregationFromCheckpointInClosedWorker({
                acceptedSetupSourceHash,
                ballotCandidateViewRoot,
                checkpointCustody: checkpointFixture.custody,
                checkpointLineageIdentifier:
                    checkpoint.checkpointLineageIdentifier,
                evaluatorKeyStore: {
                    readExactRange: () =>
                        Promise.reject(
                            new Error('ballot one needs no key read'),
                        ),
                },
                expectedSelection,
                kernel: retryRuntime.kernel,
                replaySource: retryReplay.replaySource,
            });
        retriedAggregation.prepareAggregate().cancel();
        retryRuntime.boardSession.close();
        expect(retryRuntime.allocations.size).toBe(0);
    });

    it('zeroes a delivered restore chunk and releases custody when restore rejects after staging', async () => {
        const expectedSelection = [selectionIdentity(0)];
        const expectedIdentity = expectedSelection[0];
        if (expectedIdentity === undefined) {
            throw new Error('the selected ballot identity is missing');
        }
        const checkpointFixture = createFakeCheckpointCustody();
        const freshRuntime = createFakeEvaluatorRuntime();
        const freshAggregation = openAggregation({
            evaluatorKeyStore: {
                readExactRange: () =>
                    Promise.reject(new Error('ballot one needs no key read')),
            },
            runtime: freshRuntime,
        });
        await freshAggregation.absorb({
            verifiedBallot: freshRuntime.createVerifiedBallot(
                61,
                expectedIdentity,
            ),
        });
        const checkpoint = await freshAggregation.publishSelectionCheckpoint(
            checkpointFixture.custody,
        );
        freshAggregation.cancel();
        freshRuntime.acceptedSetupAuthority.release();
        freshRuntime.boardSession.close();

        const stagedChunk = Uint8Array.of(0x31, 0x32, 0x33, 0x34);
        let restoredIdentity:
            | BallotAggregationCheckpointOperationIdentity
            | undefined;
        const rejectingRestoreCustody: BallotAggregationCheckpointCustody =
            Object.freeze({
                ...checkpointFixture.custody,
                resume: async (input) => {
                    const resumed =
                        await checkpointFixture.custody.resume(input);
                    restoredIdentity = resumed.operationIdentity;
                    return Object.freeze({
                        ...resumed,
                        restoreState: async (consumeChunk) => {
                            await consumeChunk(0, stagedChunk);
                            throw new CanonicalStreamRefusalError(
                                'wrongHashOrRoot',
                            );
                        },
                    });
                },
            });
        const refusedRuntime = createFakeEvaluatorRuntime();
        const refusedReplay = createReplaySource({
            runtime: refusedRuntime,
            selection: expectedSelection,
        });
        await expect(
            resumeVerifiedBallotAggregationFromCheckpointInClosedWorker({
                acceptedSetupSourceHash,
                ballotCandidateViewRoot,
                checkpointCustody: rejectingRestoreCustody,
                checkpointLineageIdentifier:
                    checkpoint.checkpointLineageIdentifier,
                evaluatorKeyStore: {
                    readExactRange: () =>
                        Promise.reject(
                            new Error('ballot one needs no key read'),
                        ),
                },
                expectedSelection,
                kernel: refusedRuntime.kernel,
                replaySource: refusedReplay.replaySource,
            }),
        ).rejects.toThrow(CanonicalStreamRefusalError);
        expect(stagedChunk).toEqual(new Uint8Array(4));
        if (restoredIdentity === undefined) {
            throw new Error('checkpoint resume returned no identity');
        }
        expect(restoredIdentity.checkpointLineageIdentifier).toEqual(
            new Uint8Array(32),
        );
        expect(refusedReplay.borrowedPreflightPositions).toEqual([]);
        expect(refusedReplay.reverifiedPositions).toEqual([]);
        refusedRuntime.acceptedSetupAuthority.release();
        refusedRuntime.boardSession.close();
        expect(refusedRuntime.allocations.size).toBe(0);
    });

    it('refuses every checkpoint, selection, scope, lineage, and canonical-state mutation before touching fresh authorities, then retries successfully', async () => {
        const expectedSelection = [
            selectionIdentity(0),
            selectionIdentity(1),
            selectionIdentity(2),
        ];
        const checkpointFixture = createFakeCheckpointCustody();
        const freshRuntime = createFakeEvaluatorRuntime();
        const freshAggregation = openAggregation({
            evaluatorKeyStore: {
                readExactRange: () =>
                    Promise.resolve(Uint8Array.of(0x31, 0x32, 0x33)),
            },
            options: { yieldControl: () => Promise.resolve() },
            runtime: freshRuntime,
        });
        for (const entry of expectedSelection) {
            await freshAggregation.absorb({
                verifiedBallot: freshRuntime.createVerifiedBallot(
                    100 + entry.producerRosterPosition,
                    entry,
                ),
            });
        }
        const checkpoint = await freshAggregation.publishSelectionCheckpoint(
            checkpointFixture.custody,
        );
        const freshPrepared = freshAggregation.prepareAggregate();
        const expectedCarrier = freshPrepared.copyCanonicalCarrier();
        freshPrepared.cancel();
        freshRuntime.acceptedSetupAuthority.release();
        freshRuntime.boardSession.close();

        const attemptRefusedResume = async (overrides?: {
            acceptedSetupSourceHash?: Uint8Array;
            ballotCandidateViewRoot?: Uint8Array;
            checkpointCustody?: BallotAggregationCheckpointCustody;
            checkpointLineageIdentifier?: Uint8Array;
            expectedSelection?: readonly BallotAggregationSelectionIdentity[];
        }): Promise<void> => {
            const runtime = createFakeEvaluatorRuntime();
            const replay = createReplaySource({
                runtime,
                selection: expectedSelection,
            });
            await expect(
                resumeVerifiedBallotAggregationFromCheckpointInClosedWorker({
                    acceptedSetupSourceHash:
                        overrides?.acceptedSetupSourceHash ??
                        acceptedSetupSourceHash,
                    ballotCandidateViewRoot:
                        overrides?.ballotCandidateViewRoot ??
                        ballotCandidateViewRoot,
                    checkpointCustody:
                        overrides?.checkpointCustody ??
                        checkpointFixture.custody,
                    checkpointLineageIdentifier:
                        overrides?.checkpointLineageIdentifier ??
                        checkpoint.checkpointLineageIdentifier,
                    evaluatorKeyStore: {
                        readExactRange: () =>
                            Promise.reject(
                                new Error(
                                    'a refused resume must not read the evaluator store',
                                ),
                            ),
                    },
                    expectedSelection:
                        overrides?.expectedSelection ?? expectedSelection,
                    kernel: runtime.kernel,
                    replaySource: replay.replaySource,
                }),
            ).rejects.toThrow(CanonicalStreamRefusalError);
            expect(replay.borrowedPreflightPositions).toEqual([]);
            expect(replay.reverifiedPositions).toEqual([]);
            expect(runtime.acceptedSetupBeginHandles).toEqual([]);
            expect(runtime.absorbedBallotHandles).toEqual([]);
            runtime.acceptedSetupAuthority.release();
            expect(runtime.acceptedSetupReleaseHandles).toEqual([51]);
            runtime.boardSession.close();
            expect(runtime.allocations.size).toBe(0);
        };

        const mutatedHashSelection = expectedSelection.map((entry) => ({
            ballotObjectHash: entry.ballotObjectHash.slice(),
            producerRosterPosition: entry.producerRosterPosition,
        }));
        mutatedHashSelection[1]?.ballotObjectHash.fill(0xee);
        await attemptRefusedResume({
            expectedSelection: mutatedHashSelection,
        });
        await attemptRefusedResume({
            expectedSelection: [
                expectedSelection[1],
                expectedSelection[0],
                expectedSelection[2],
            ],
        });
        await attemptRefusedResume({
            expectedSelection: expectedSelection.slice(0, 2),
        });
        await attemptRefusedResume({
            expectedSelection: [
                expectedSelection[0],
                {
                    ballotObjectHash:
                        expectedSelection[1]?.ballotObjectHash.slice() ??
                        new Uint8Array(64),
                    producerRosterPosition: 0,
                },
                expectedSelection[2],
            ],
        });
        await attemptRefusedResume({
            expectedSelection: [
                expectedSelection[0],
                {
                    ballotObjectHash:
                        expectedSelection[0]?.ballotObjectHash.slice() ??
                        new Uint8Array(64),
                    producerRosterPosition: 1,
                },
                expectedSelection[2],
            ],
        });
        await attemptRefusedResume({
            acceptedSetupSourceHash: new Uint8Array(64).fill(0xe1),
        });
        await attemptRefusedResume({
            ballotCandidateViewRoot: new Uint8Array(64).fill(0xe2),
        });
        await attemptRefusedResume({
            checkpointLineageIdentifier: new Uint8Array(32).fill(0xe3),
        });

        for (const scopeField of [
            'runtimeBuildManifestHash',
            'suiteIdentifier',
            'ceremonyContextHash',
            'actionContextHash',
            'ownerParticipantIdentity',
        ] as const) {
            const wrongScope = defaultCheckpointManifestScope();
            wrongScope[scopeField].fill(0xe4);
            const wrongScopeFixture = createFakeCheckpointCustody({
                durableState: checkpointFixture.durableState,
                scope: wrongScope,
            });
            await attemptRefusedResume({
                checkpointCustody: wrongScopeFixture.custody,
            });
        }

        const storedCheckpoint = checkpointFixture.durableState.records.get(
            checkpointLineageKey(checkpoint.checkpointLineageIdentifier),
        );
        if (storedCheckpoint === undefined) {
            throw new Error('the published checkpoint is unavailable');
        }
        const originalState = storedCheckpoint.stateBytes.slice();
        const malformedStates = [
            (() => {
                const state = originalState.slice();
                state[0] = (state[0] ?? 0) ^ 1;
                return state;
            })(),
            originalState.slice(0, -1),
            Uint8Array.of(...originalState, 0xff),
            (() => {
                const state = originalState.slice();
                state[174] = 1;
                return state;
            })(),
            (() => {
                const state = originalState.slice();
                state[182] = (state[182] ?? 0) ^ 1;
                return state;
            })(),
        ];
        for (const malformedState of malformedStates) {
            checkpointFixture.replaceAuthenticatedState(
                checkpoint.checkpointLineageIdentifier,
                malformedState,
            );
            await attemptRefusedResume();
        }
        checkpointFixture.replaceAuthenticatedState(
            checkpoint.checkpointLineageIdentifier,
            originalState,
        );

        const resumedRuntime = createFakeEvaluatorRuntime();
        const replay = createReplaySource({
            runtime: resumedRuntime,
            selection: expectedSelection,
        });
        const resumedAggregation =
            await resumeVerifiedBallotAggregationFromCheckpointInClosedWorker({
                acceptedSetupSourceHash,
                ballotCandidateViewRoot,
                checkpointCustody: checkpointFixture.custody,
                checkpointLineageIdentifier:
                    checkpoint.checkpointLineageIdentifier,
                evaluatorKeyStore: {
                    readExactRange: () =>
                        Promise.resolve(Uint8Array.of(0x41, 0x42, 0x43)),
                },
                expectedSelection,
                kernel: resumedRuntime.kernel,
                options: { yieldControl: () => Promise.resolve() },
                replaySource: replay.replaySource,
            });
        expect(replay.borrowedPreflightPositions).toEqual([0, 1, 2]);
        expect(replay.reverifiedPositions).toEqual([0, 1, 2]);
        const resumedPrepared = resumedAggregation.prepareAggregate();
        expect(resumedPrepared.copyCanonicalCarrier()).toEqual(expectedCarrier);
        resumedPrepared.cancel();
        resumedRuntime.boardSession.close();
        expect(resumedRuntime.allocations.size).toBe(0);
    });

    it('blocks worker reuse during late checkpoint-begin cleanup and poisons the worker when identity release fails', async () => {
        const runtime = createFakeEvaluatorRuntime();
        const abortController = new AbortController();
        const aggregation = openAggregation({
            evaluatorKeyStore: {
                readExactRange: () =>
                    Promise.reject(new Error('ballot one needs no key read')),
            },
            options: { signal: abortController.signal },
            runtime,
        });
        await aggregation.absorb({
            verifiedBallot: runtime.createVerifiedBallot(
                61,
                selectionIdentity(0),
            ),
        });
        const beginStarted = createDeferredPromise<void>();
        const lateBegin =
            createDeferredPromise<BallotAggregationCheckpointOperationIdentity>();
        const lateIdentity = Object.freeze({
            checkpointLineageIdentifier: new Uint8Array(32).fill(0xb1),
        });
        const cleanupFailure = new Error(
            'late checkpoint identity release failed',
        );
        const custody: BallotAggregationCheckpointCustody = Object.freeze({
            ...createFakeCheckpointCustody().custody,
            beginOperation: () => {
                beginStarted.resolve(undefined);
                return lateBegin.promise;
            },
            releaseOperationIdentity: () => Promise.reject(cleanupFailure),
        });
        const publication = aggregation.publishSelectionCheckpoint(custody);
        await beginStarted.promise;

        abortController.abort();
        await expectPromptCancellation(publication);
        expect(runtime.aggregateCancelHandles).toEqual([11]);
        expect(() =>
            openAggregation({
                evaluatorKeyStore: {
                    readExactRange: () =>
                        Promise.reject(
                            new Error('ballot one needs no key read'),
                        ),
                },
                runtime,
            }),
        ).toThrow(CanonicalStreamResourceError);

        lateBegin.resolve(lateIdentity);
        await waitForNextHostTask();
        expect(() =>
            openAggregation({
                evaluatorKeyStore: {
                    readExactRange: () =>
                        Promise.reject(
                            new Error('ballot one needs no key read'),
                        ),
                },
                runtime,
            }),
        ).toThrow(CanonicalStreamCleanupError);
        expect(lateIdentity.checkpointLineageIdentifier).toEqual(
            new Uint8Array(32).fill(0xb1),
        );
        lateIdentity.checkpointLineageIdentifier.fill(0);
        runtime.acceptedSetupAuthority.release();
        runtime.boardSession.close();
        expect(runtime.allocations.size).toBe(0);
    });

    it('zeroes a late checkpoint manifest and keeps the worker unavailable until publication settles', async () => {
        const runtime = createFakeEvaluatorRuntime();
        const abortController = new AbortController();
        const aggregation = openAggregation({
            evaluatorKeyStore: {
                readExactRange: () =>
                    Promise.reject(new Error('ballot one needs no key read')),
            },
            options: { signal: abortController.signal },
            runtime,
        });
        await aggregation.absorb({
            verifiedBallot: runtime.createVerifiedBallot(
                61,
                selectionIdentity(0),
            ),
        });
        const checkpointFixture = createFakeCheckpointCustody();
        const publishStarted = createDeferredPromise<void>();
        const latePublish = createDeferredPromise<Uint8Array>();
        const custody: BallotAggregationCheckpointCustody = Object.freeze({
            ...checkpointFixture.custody,
            publish: () => {
                publishStarted.resolve(undefined);
                return latePublish.promise;
            },
        });
        const publication = aggregation.publishSelectionCheckpoint(custody);
        await publishStarted.promise;

        abortController.abort();
        await expectPromptCancellation(publication);
        expect(checkpointFixture.durableState.records.size).toBe(0);
        expect(() =>
            openAggregation({
                evaluatorKeyStore: {
                    readExactRange: () =>
                        Promise.reject(
                            new Error('ballot one needs no key read'),
                        ),
                },
                runtime,
            }),
        ).toThrow(CanonicalStreamResourceError);
        const lateManifest = Uint8Array.of(0xc1, 0x71);
        latePublish.resolve(lateManifest);
        await waitForNextHostTask();
        expect(lateManifest).toEqual(new Uint8Array(2));

        const replacement = openAggregation({
            evaluatorKeyStore: {
                readExactRange: () =>
                    Promise.reject(new Error('ballot one needs no key read')),
            },
            runtime,
        });
        replacement.cancel();
        runtime.acceptedSetupAuthority.release();
        runtime.boardSession.close();
        expect(runtime.allocations.size).toBe(0);
    });

    it('returns a committed checkpoint when cancellation wins during delayed identity release and keeps it resumable', async () => {
        const expectedSelection = [selectionIdentity(0)];
        const expectedIdentity = expectedSelection[0];
        if (expectedIdentity === undefined) {
            throw new Error('the selected ballot identity is missing');
        }
        const runtime = createFakeEvaluatorRuntime();
        const abortController = new AbortController();
        const aggregation = openAggregation({
            evaluatorKeyStore: {
                readExactRange: () =>
                    Promise.reject(new Error('ballot one needs no key read')),
            },
            options: { signal: abortController.signal },
            runtime,
        });
        await aggregation.absorb({
            verifiedBallot: runtime.createVerifiedBallot(61, expectedIdentity),
        });
        const checkpointFixture = createFakeCheckpointCustody();
        const releaseStarted = createDeferredPromise<void>();
        const releaseGate = createDeferredPromise<void>();
        let publicationIdentity:
            | BallotAggregationCheckpointOperationIdentity
            | undefined;
        const delayedReleaseCustody: BallotAggregationCheckpointCustody =
            Object.freeze({
                ...checkpointFixture.custody,
                beginOperation: async (signal) => {
                    const identity =
                        await checkpointFixture.custody.beginOperation(signal);
                    publicationIdentity = identity;
                    return identity;
                },
                releaseOperationIdentity: async (identity) => {
                    releaseStarted.resolve(undefined);
                    await releaseGate.promise;
                    await checkpointFixture.custody.releaseOperationIdentity(
                        identity,
                    );
                },
            });
        const publication = aggregation.publishSelectionCheckpoint(
            delayedReleaseCustody,
        );
        await releaseStarted.promise;

        abortController.abort();
        const publicationSettlement =
            await settleBeforeNextHostTask(publication);
        expect(publicationSettlement.kind).toBe('fulfilled');
        const checkpoint = await publication;
        expect(runtime.aggregateCancelHandles).toEqual([11]);
        expect(
            checkpointFixture.durableState.records.has(
                checkpointLineageKey(checkpoint.checkpointLineageIdentifier),
            ),
        ).toBe(true);
        expect(() =>
            openAggregation({
                evaluatorKeyStore: {
                    readExactRange: () =>
                        Promise.reject(
                            new Error('ballot one needs no key read'),
                        ),
                },
                runtime,
            }),
        ).toThrow(CanonicalStreamResourceError);
        releaseGate.resolve(undefined);
        await waitForNextHostTask();
        if (publicationIdentity === undefined) {
            throw new Error('checkpoint publication returned no identity');
        }
        expect(publicationIdentity.checkpointLineageIdentifier).toEqual(
            new Uint8Array(32),
        );

        const replacement = openAggregation({
            evaluatorKeyStore: {
                readExactRange: () =>
                    Promise.reject(new Error('ballot one needs no key read')),
            },
            runtime,
        });
        replacement.cancel();
        runtime.acceptedSetupAuthority.release();
        runtime.boardSession.close();
        expect(runtime.allocations.size).toBe(0);

        const resumedRuntime = createFakeEvaluatorRuntime();
        const replay = createReplaySource({
            runtime: resumedRuntime,
            selection: expectedSelection,
        });
        const resumedAggregation =
            await resumeVerifiedBallotAggregationFromCheckpointInClosedWorker({
                acceptedSetupSourceHash,
                ballotCandidateViewRoot,
                checkpointCustody: checkpointFixture.custody,
                checkpointLineageIdentifier:
                    checkpoint.checkpointLineageIdentifier,
                evaluatorKeyStore: {
                    readExactRange: () =>
                        Promise.reject(
                            new Error('ballot one needs no key read'),
                        ),
                },
                expectedSelection,
                kernel: resumedRuntime.kernel,
                replaySource: replay.replaySource,
            });
        resumedAggregation.prepareAggregate().cancel();
        resumedRuntime.boardSession.close();
        expect(resumedRuntime.allocations.size).toBe(0);
    });

    it('returns recoverable lineage for a committed checkpoint whose direct identity release fails and poisons that worker', async () => {
        const expectedSelection = [selectionIdentity(0)];
        const expectedIdentity = expectedSelection[0];
        if (expectedIdentity === undefined) {
            throw new Error('the selected ballot identity is missing');
        }
        const runtime = createFakeEvaluatorRuntime();
        const aggregation = openAggregation({
            evaluatorKeyStore: {
                readExactRange: () =>
                    Promise.reject(new Error('ballot one needs no key read')),
            },
            runtime,
        });
        await aggregation.absorb({
            verifiedBallot: runtime.createVerifiedBallot(61, expectedIdentity),
        });
        const checkpointFixture = createFakeCheckpointCustody();
        let failedReleaseIdentity:
            | BallotAggregationCheckpointOperationIdentity
            | undefined;
        const failingReleaseCustody: BallotAggregationCheckpointCustody =
            Object.freeze({
                ...checkpointFixture.custody,
                releaseOperationIdentity: (identity) => {
                    failedReleaseIdentity = identity;
                    return Promise.reject(
                        Object.assign(
                            new Error(
                                'committed checkpoint identity release failed',
                            ),
                            { code: 'CleanupFailed' as const },
                        ),
                    );
                },
            });
        const checkpoint = await aggregation.publishSelectionCheckpoint(
            failingReleaseCustody,
        );
        expect(runtime.aggregateCancelHandles).toEqual([11]);
        expect(
            checkpointFixture.durableState.records.has(
                checkpointLineageKey(checkpoint.checkpointLineageIdentifier),
            ),
        ).toBe(true);
        expect(() =>
            openAggregation({
                evaluatorKeyStore: {
                    readExactRange: () =>
                        Promise.reject(
                            new Error('ballot one needs no key read'),
                        ),
                },
                runtime,
            }),
        ).toThrow(CanonicalStreamCleanupError);
        if (failedReleaseIdentity === undefined) {
            throw new Error('checkpoint publication returned no identity');
        }
        await checkpointFixture.custody.releaseOperationIdentity(
            failedReleaseIdentity,
        );
        runtime.acceptedSetupAuthority.release();
        runtime.boardSession.close();
        expect(runtime.allocations.size).toBe(0);

        const resumedRuntime = createFakeEvaluatorRuntime();
        const replay = createReplaySource({
            runtime: resumedRuntime,
            selection: expectedSelection,
        });
        const resumedAggregation =
            await resumeVerifiedBallotAggregationFromCheckpointInClosedWorker({
                acceptedSetupSourceHash,
                ballotCandidateViewRoot,
                checkpointCustody: checkpointFixture.custody,
                checkpointLineageIdentifier:
                    checkpoint.checkpointLineageIdentifier,
                evaluatorKeyStore: {
                    readExactRange: () =>
                        Promise.reject(
                            new Error('ballot one needs no key read'),
                        ),
                },
                expectedSelection,
                kernel: resumedRuntime.kernel,
                replaySource: replay.replaySource,
            });
        resumedAggregation.prepareAggregate().cancel();
        resumedRuntime.boardSession.close();
        expect(resumedRuntime.allocations.size).toBe(0);
    });

    it('poisons the worker when checkpoint publication reports a late cleanup failure after cancellation', async () => {
        const runtime = createFakeEvaluatorRuntime();
        const abortController = new AbortController();
        const aggregation = openAggregation({
            evaluatorKeyStore: {
                readExactRange: () =>
                    Promise.reject(new Error('ballot one needs no key read')),
            },
            options: { signal: abortController.signal },
            runtime,
        });
        await aggregation.absorb({
            verifiedBallot: runtime.createVerifiedBallot(
                61,
                selectionIdentity(0),
            ),
        });
        const checkpointFixture = createFakeCheckpointCustody();
        const publishStarted = createDeferredPromise<void>();
        const latePublish = createDeferredPromise<Uint8Array>();
        const custody: BallotAggregationCheckpointCustody = Object.freeze({
            ...checkpointFixture.custody,
            publish: () => {
                publishStarted.resolve(undefined);
                return latePublish.promise;
            },
        });
        const publication = aggregation.publishSelectionCheckpoint(custody);
        await publishStarted.promise;

        abortController.abort();
        await expectPromptCancellation(publication);
        latePublish.reject(
            Object.assign(
                new Error(
                    'checkpoint custody cleanup failed after cancellation',
                ),
                { code: 'CleanupFailed' as const },
            ),
        );
        await waitForNextHostTask();
        expect(() =>
            openAggregation({
                evaluatorKeyStore: {
                    readExactRange: () =>
                        Promise.reject(
                            new Error('ballot one needs no key read'),
                        ),
                },
                runtime,
            }),
        ).toThrow(CanonicalStreamCleanupError);
        runtime.acceptedSetupAuthority.release();
        runtime.boardSession.close();
        expect(runtime.allocations.size).toBe(0);
    });

    it('cancels pending checkpoint resume and restore calls, releases late identities, and permits reuse only after settlement', async () => {
        const expectedSelection = [selectionIdentity(0)];
        const expectedIdentity = expectedSelection[0];
        if (expectedIdentity === undefined) {
            throw new Error('the selected ballot identity is missing');
        }
        const checkpointFixture = createFakeCheckpointCustody();
        const freshRuntime = createFakeEvaluatorRuntime();
        const freshAggregation = openAggregation({
            evaluatorKeyStore: {
                readExactRange: () =>
                    Promise.reject(new Error('ballot one needs no key read')),
            },
            runtime: freshRuntime,
        });
        await freshAggregation.absorb({
            verifiedBallot: freshRuntime.createVerifiedBallot(
                61,
                expectedIdentity,
            ),
        });
        const checkpoint = await freshAggregation.publishSelectionCheckpoint(
            checkpointFixture.custody,
        );
        freshAggregation.cancel();
        freshRuntime.acceptedSetupAuthority.release();
        freshRuntime.boardSession.close();

        const resumeRuntime = createFakeEvaluatorRuntime();
        const resumeReplay = createReplaySource({
            runtime: resumeRuntime,
            selection: expectedSelection,
        });
        const resumeStarted = createDeferredPromise<void>();
        const resumeGate = createDeferredPromise<void>();
        let lateResumeIdentity:
            | BallotAggregationCheckpointOperationIdentity
            | undefined;
        let lateResumeManifest: Uint8Array | undefined;
        let lateResumeStateDescriptor: Uint8Array | undefined;
        const delayedResumeCustody: BallotAggregationCheckpointCustody =
            Object.freeze({
                ...checkpointFixture.custody,
                resume: async (input) => {
                    const resumed =
                        await checkpointFixture.custody.resume(input);
                    lateResumeIdentity = resumed.operationIdentity;
                    lateResumeManifest = resumed.canonicalManifestBytes;
                    lateResumeStateDescriptor =
                        resumed.stateStreamDescriptorBytes;
                    resumeStarted.resolve(undefined);
                    await resumeGate.promise;
                    return resumed;
                },
            });
        const resumeAbortController = new AbortController();
        const pendingResume =
            resumeVerifiedBallotAggregationFromCheckpointInClosedWorker({
                acceptedSetupSourceHash,
                ballotCandidateViewRoot,
                checkpointCustody: delayedResumeCustody,
                checkpointLineageIdentifier:
                    checkpoint.checkpointLineageIdentifier,
                evaluatorKeyStore: {
                    readExactRange: () =>
                        Promise.reject(
                            new Error('ballot one needs no key read'),
                        ),
                },
                expectedSelection,
                kernel: resumeRuntime.kernel,
                options: { signal: resumeAbortController.signal },
                replaySource: resumeReplay.replaySource,
            });
        await resumeStarted.promise;
        resumeAbortController.abort();
        await expectPromptCancellation(pendingResume);
        expect(() =>
            openAggregation({
                evaluatorKeyStore: {
                    readExactRange: () =>
                        Promise.reject(
                            new Error('ballot one needs no key read'),
                        ),
                },
                runtime: resumeRuntime,
            }),
        ).toThrow(CanonicalStreamResourceError);
        resumeGate.resolve(undefined);
        await waitForNextHostTask();
        if (lateResumeIdentity === undefined) {
            throw new Error('the delayed resume returned no identity');
        }
        expect(lateResumeIdentity.checkpointLineageIdentifier).toEqual(
            new Uint8Array(32),
        );
        expect(lateResumeManifest).toEqual(new Uint8Array(2));
        expect(lateResumeStateDescriptor).toEqual(new Uint8Array(8));
        const resumeReplacement = openAggregation({
            evaluatorKeyStore: {
                readExactRange: () =>
                    Promise.reject(new Error('ballot one needs no key read')),
            },
            runtime: resumeRuntime,
        });
        resumeReplacement.cancel();
        resumeRuntime.acceptedSetupAuthority.release();
        resumeRuntime.boardSession.close();

        const restoreRuntime = createFakeEvaluatorRuntime();
        const restoreReplay = createReplaySource({
            runtime: restoreRuntime,
            selection: expectedSelection,
        });
        const restoreStarted = createDeferredPromise<void>();
        const restoreGate = createDeferredPromise<void>();
        const lateRestoreChunk = Uint8Array.of(0x71, 0x72, 0x73);
        let restoreIdentity:
            | BallotAggregationCheckpointOperationIdentity
            | undefined;
        const delayedRestoreCustody: BallotAggregationCheckpointCustody =
            Object.freeze({
                ...checkpointFixture.custody,
                resume: async (input) => {
                    const resumed =
                        await checkpointFixture.custody.resume(input);
                    restoreIdentity = resumed.operationIdentity;
                    return Object.freeze({
                        ...resumed,
                        restoreState: async (consumeChunk) => {
                            restoreStarted.resolve(undefined);
                            await restoreGate.promise;
                            await consumeChunk(0, lateRestoreChunk);
                        },
                    });
                },
            });
        const restoreAbortController = new AbortController();
        const pendingRestore =
            resumeVerifiedBallotAggregationFromCheckpointInClosedWorker({
                acceptedSetupSourceHash,
                ballotCandidateViewRoot,
                checkpointCustody: delayedRestoreCustody,
                checkpointLineageIdentifier:
                    checkpoint.checkpointLineageIdentifier,
                evaluatorKeyStore: {
                    readExactRange: () =>
                        Promise.reject(
                            new Error('ballot one needs no key read'),
                        ),
                },
                expectedSelection,
                kernel: restoreRuntime.kernel,
                options: { signal: restoreAbortController.signal },
                replaySource: restoreReplay.replaySource,
            });
        await restoreStarted.promise;
        restoreAbortController.abort();
        await expectPromptCancellation(pendingRestore);
        if (restoreIdentity === undefined) {
            throw new Error('the delayed restore returned no identity');
        }
        expect(restoreIdentity.checkpointLineageIdentifier).toEqual(
            new Uint8Array(32),
        );
        expect(() =>
            openAggregation({
                evaluatorKeyStore: {
                    readExactRange: () =>
                        Promise.reject(
                            new Error('ballot one needs no key read'),
                        ),
                },
                runtime: restoreRuntime,
            }),
        ).toThrow(CanonicalStreamResourceError);
        restoreGate.resolve(undefined);
        await waitForNextHostTask();
        expect(lateRestoreChunk).toEqual(new Uint8Array(3));
        expect(restoreReplay.borrowedPreflightPositions).toEqual([]);
        expect(restoreReplay.reverifiedPositions).toEqual([]);
        const restoreReplacement = openAggregation({
            evaluatorKeyStore: {
                readExactRange: () =>
                    Promise.reject(new Error('ballot one needs no key read')),
            },
            runtime: restoreRuntime,
        });
        restoreReplacement.cancel();
        restoreRuntime.acceptedSetupAuthority.release();
        restoreRuntime.boardSession.close();
        expect(resumeRuntime.allocations.size).toBe(0);
        expect(restoreRuntime.allocations.size).toBe(0);
    });

    it('cancels promptly while resumed checkpoint identity release is delayed and starts that release only once', async () => {
        const expectedSelection = [selectionIdentity(0)];
        const expectedIdentity = expectedSelection[0];
        if (expectedIdentity === undefined) {
            throw new Error('the selected ballot identity is missing');
        }
        const checkpointFixture = createFakeCheckpointCustody();
        const freshRuntime = createFakeEvaluatorRuntime();
        const freshAggregation = openAggregation({
            evaluatorKeyStore: {
                readExactRange: () =>
                    Promise.reject(new Error('ballot one needs no key read')),
            },
            runtime: freshRuntime,
        });
        await freshAggregation.absorb({
            verifiedBallot: freshRuntime.createVerifiedBallot(
                61,
                expectedIdentity,
            ),
        });
        const checkpoint = await freshAggregation.publishSelectionCheckpoint(
            checkpointFixture.custody,
        );
        freshAggregation.cancel();
        freshRuntime.acceptedSetupAuthority.release();
        freshRuntime.boardSession.close();

        const runtime = createFakeEvaluatorRuntime();
        const replay = createReplaySource({
            runtime,
            selection: expectedSelection,
        });
        const releaseStarted = createDeferredPromise<void>();
        const releaseGate = createDeferredPromise<void>();
        let releaseCallCount = 0;
        let resumedIdentity:
            | BallotAggregationCheckpointOperationIdentity
            | undefined;
        const delayedReleaseCustody: BallotAggregationCheckpointCustody =
            Object.freeze({
                ...checkpointFixture.custody,
                releaseOperationIdentity: async (identity) => {
                    releaseCallCount += 1;
                    resumedIdentity = identity;
                    releaseStarted.resolve(undefined);
                    await releaseGate.promise;
                    await checkpointFixture.custody.releaseOperationIdentity(
                        identity,
                    );
                },
            });
        const abortController = new AbortController();
        const resumed =
            resumeVerifiedBallotAggregationFromCheckpointInClosedWorker({
                acceptedSetupSourceHash,
                ballotCandidateViewRoot,
                checkpointCustody: delayedReleaseCustody,
                checkpointLineageIdentifier:
                    checkpoint.checkpointLineageIdentifier,
                evaluatorKeyStore: {
                    readExactRange: () =>
                        Promise.reject(
                            new Error('ballot one needs no key read'),
                        ),
                },
                expectedSelection,
                kernel: runtime.kernel,
                options: { signal: abortController.signal },
                replaySource: replay.replaySource,
            });
        await releaseStarted.promise;

        abortController.abort();
        await expectPromptCancellation(resumed);
        expect(releaseCallCount).toBe(1);
        expect(replay.borrowedPreflightPositions).toEqual([]);
        expect(replay.reverifiedPositions).toEqual([]);
        expect(() =>
            openAggregation({
                evaluatorKeyStore: {
                    readExactRange: () =>
                        Promise.reject(
                            new Error('ballot one needs no key read'),
                        ),
                },
                runtime,
            }),
        ).toThrow(CanonicalStreamResourceError);
        releaseGate.resolve(undefined);
        await waitForNextHostTask();
        if (resumedIdentity === undefined) {
            throw new Error('checkpoint resume returned no identity');
        }
        expect(resumedIdentity.checkpointLineageIdentifier).toEqual(
            new Uint8Array(32),
        );
        expect(releaseCallCount).toBe(1);

        const replacement = openAggregation({
            evaluatorKeyStore: {
                readExactRange: () =>
                    Promise.reject(new Error('ballot one needs no key read')),
            },
            runtime,
        });
        replacement.cancel();
        runtime.acceptedSetupAuthority.release();
        runtime.boardSession.close();
        expect(runtime.allocations.size).toBe(0);
    });

    it('cancels resumed replay during its key read, releases the pending reminted ballot, and zeroes the late range', async () => {
        const expectedSelection = [selectionIdentity(0), selectionIdentity(1)];
        const checkpointFixture = createFakeCheckpointCustody();
        const freshRuntime = createFakeEvaluatorRuntime();
        const freshAggregation = openAggregation({
            evaluatorKeyStore: {
                readExactRange: () =>
                    Promise.resolve(Uint8Array.of(0x51, 0x52, 0x53)),
            },
            options: { yieldControl: () => Promise.resolve() },
            runtime: freshRuntime,
        });
        for (const entry of expectedSelection) {
            await freshAggregation.absorb({
                verifiedBallot: freshRuntime.createVerifiedBallot(
                    100 + entry.producerRosterPosition,
                    entry,
                ),
            });
        }
        const checkpoint = await freshAggregation.publishSelectionCheckpoint(
            checkpointFixture.custody,
        );
        freshAggregation.prepareAggregate().cancel();
        freshRuntime.acceptedSetupAuthority.release();
        freshRuntime.boardSession.close();

        const resumedRuntime = createFakeEvaluatorRuntime();
        const replay = createReplaySource({
            runtime: resumedRuntime,
            selection: expectedSelection,
        });
        const storeReadStarted = createDeferredPromise<void>();
        const lateStoreRead = createDeferredPromise<Uint8Array>();
        const abortController = new AbortController();
        const resumePromise =
            resumeVerifiedBallotAggregationFromCheckpointInClosedWorker({
                acceptedSetupSourceHash,
                ballotCandidateViewRoot,
                checkpointCustody: checkpointFixture.custody,
                checkpointLineageIdentifier:
                    checkpoint.checkpointLineageIdentifier,
                evaluatorKeyStore: {
                    readExactRange: () => {
                        storeReadStarted.resolve(undefined);
                        return lateStoreRead.promise;
                    },
                },
                expectedSelection,
                kernel: resumedRuntime.kernel,
                options: {
                    signal: abortController.signal,
                    yieldControl: () => Promise.resolve(),
                },
                replaySource: replay.replaySource,
            });
        await storeReadStarted.promise;
        abortController.abort();
        await expectPromptCancellation(resumePromise);
        const lateRange = Uint8Array.of(0x61, 0x62, 0x63);
        lateStoreRead.resolve(lateRange);
        await waitForNextHostTask();

        expect(replay.borrowedPreflightPositions).toEqual([0, 1]);
        expect(replay.reverifiedPositions).toEqual([0, 1]);
        expect(resumedRuntime.acceptedSetupReleaseHandles).toEqual([51]);
        expect(resumedRuntime.ballotReleaseHandles).toEqual([101]);
        expect(resumedRuntime.aggregateCancelHandles).toEqual([11]);
        expect(resumedRuntime.aggregationStoreRanges).toEqual([]);
        expect(lateRange).toEqual(new Uint8Array(3));
        resumedRuntime.boardSession.close();
        expect(resumedRuntime.allocations.size).toBe(0);
    });

    it('reads no key for ballot one, streams the authenticated key for ballot two, and continues the same authority into replay binding', async () => {
        const runtime = createFakeEvaluatorRuntime({
            evaluatorBindStatuses: [refusalReasonCodes.wrongHashOrRoot, 0],
        });
        const requestedRanges: Array<
            Readonly<{ byteLength: number; offset: bigint }>
        > = [];
        const aggregationRange = Uint8Array.of(0x10, 0x20, 0x30);
        const evaluatorRange = Uint8Array.of(0x40, 0x50, 0x60, 0x70);
        const evaluatorKeyStore: EvaluatorKeyStoreRangeSource = {
            readExactRange: (offset, exactByteLength) => {
                requestedRanges.push({ byteLength: exactByteLength, offset });
                if (offset === aggregationStoreByteOffset) {
                    return Promise.resolve(aggregationRange);
                }
                if (offset === evaluatorStoreByteOffset) {
                    return Promise.resolve(evaluatorRange);
                }
                return Promise.reject(new Error('unexpected store range'));
            },
        };
        const aggregation = openAggregation({
            evaluatorKeyStore,
            options: { yieldControl: () => Promise.resolve() },
            runtime,
        });

        await aggregation.absorb({
            verifiedBallot: runtime.createVerifiedBallot(
                61,
                selectionIdentity(0),
            ),
        });
        expect(requestedRanges).toEqual([]);
        expect(runtime.aggregatePollHandles).toEqual([11]);

        await aggregation.absorb({
            verifiedBallot: runtime.createVerifiedBallot(
                62,
                selectionIdentity(1),
            ),
        });
        expect(requestedRanges).toEqual([
            { byteLength: 3, offset: aggregationStoreByteOffset },
        ]);
        expect(runtime.aggregationStoreRanges).toEqual([
            {
                bytes: Uint8Array.of(0x10, 0x20, 0x30),
                offset: aggregationStoreByteOffset,
            },
        ]);
        expect(aggregationRange).toEqual(new Uint8Array(3));
        expect(runtime.absorbedBallotHandles).toEqual([61, 62]);

        const preparedAggregate = aggregation.prepareAggregate();
        expect(preparedAggregate.copyCanonicalCarrier()).toEqual(
            aggregateCarrier,
        );
        const { aggregateAuthority, aggregateObject } = bindPreparedAggregate({
            prepared: preparedAggregate,
            runtime,
        });
        expect(() => openAggregation({ evaluatorKeyStore, runtime })).toThrow(
            CanonicalStreamResourceError,
        );
        const preparedReplay = await prepareEvaluatorReplayInClosedWorker({
            verifiedAggregateAuthority: aggregateAuthority,
        });

        expect(requestedRanges).toEqual([
            { byteLength: 3, offset: aggregationStoreByteOffset },
            { byteLength: 4, offset: evaluatorStoreByteOffset },
        ]);
        expect(runtime.evaluatorStoreRanges).toEqual([
            {
                bytes: Uint8Array.of(0x40, 0x50, 0x60, 0x70),
                offset: evaluatorStoreByteOffset,
            },
        ]);
        expect(evaluatorRange).toEqual(new Uint8Array(4));
        expect(runtime.acceptedSetupBeginHandles).toEqual([51]);
        expect(runtime.evaluatorBeginAuthorityHandles).toEqual([21]);

        const replayObject = runtime.verifyBoardCarrier(
            preparedReplay.copyCanonicalCarrier(),
        );
        expect(() => openAggregation({ evaluatorKeyStore, runtime })).toThrow(
            CanonicalStreamResourceError,
        );
        expect(() => preparedReplay.bind(replayObject)).toThrow(
            CanonicalStreamRefusalError,
        );
        expect(preparedReplay.copyCanonicalCarrier()).toEqual(replayCarrier);
        expect(() => openAggregation({ evaluatorKeyStore, runtime })).toThrow(
            CanonicalStreamResourceError,
        );
        const verifiedReplay = preparedReplay.bind(replayObject);
        releaseVerifiedEvaluatorReplay(verifiedReplay);
        const replacementAggregation = openAggregation({
            evaluatorKeyStore,
            runtime,
        });
        replacementAggregation.cancel();
        expect(runtime.boardCarrierInputs).toEqual([
            Uint8Array.of(1, 0, 0, 0, 4, 0, 0, 0, ...aggregateCarrier),
            Uint8Array.of(1, 0, 0, 0, 3, 0, 0, 0, ...replayCarrier),
        ]);
        expect(runtime.evaluatorReplayReleaseHandles).toEqual([41]);
        expect(runtime.aggregateCancelHandles).toEqual([11]);
        expect(runtime.evaluatorCancelHandles).toEqual([]);
        expect(() => aggregateAuthority.release()).toThrow(
            CanonicalStreamRefusalError,
        );
        await expect(
            prepareEvaluatorReplayInClosedWorker({
                verifiedAggregateAuthority: aggregateAuthority,
            }),
        ).rejects.toThrow(CanonicalStreamRefusalError);

        runtime.boardSession.release(replayObject);
        runtime.boardSession.release(aggregateObject);
        runtime.acceptedSetupAuthority.release();
        runtime.boardSession.close();
        expect(runtime.acceptedSetupReleaseHandles).toEqual([51]);
        expect(runtime.allocations.size).toBe(0);
    });

    it('keeps a prepared aggregate retryable after board mismatch and makes every successful handoff one-shot', async () => {
        const runtime = createFakeEvaluatorRuntime({
            aggregateBindStatuses: [refusalReasonCodes.wrongHashOrRoot, 0],
        });
        const evaluatorKeyStore: EvaluatorKeyStoreRangeSource = {
            readExactRange: () =>
                Promise.reject(new Error('one ballot must not read a key')),
        };
        const aggregation = await absorbOneBallot(runtime, evaluatorKeyStore);
        const preparedAggregate = aggregation.prepareAggregate();
        const aggregateObject = runtime.verifyBoardCarrier(aggregateCarrier);

        expect(() => preparedAggregate.bind(aggregateObject)).toThrow(
            CanonicalStreamRefusalError,
        );
        expect(() => openAggregation({ evaluatorKeyStore, runtime })).toThrow(
            CanonicalStreamResourceError,
        );
        expect(preparedAggregate.copyCanonicalCarrier()).toEqual(
            aggregateCarrier,
        );
        const aggregateAuthority = preparedAggregate.bind(aggregateObject);
        expect(() => openAggregation({ evaluatorKeyStore, runtime })).toThrow(
            CanonicalStreamResourceError,
        );
        expect(runtime.aggregateBindObjectHandles).toEqual([70, 70]);
        expect(() => preparedAggregate.copyCanonicalCarrier()).toThrow(
            CanonicalStreamRefusalError,
        );
        expect(() => preparedAggregate.bind(aggregateObject)).toThrow(
            CanonicalStreamRefusalError,
        );
        expect(() => aggregation.prepareAggregate()).toThrow(
            CanonicalStreamRefusalError,
        );
        expect(() => aggregation.cancel()).toThrow(CanonicalStreamRefusalError);

        aggregateAuthority.release();
        expect(runtime.aggregateDiscardHandles).toEqual([21]);
        expect(() => aggregateAuthority.release()).toThrow(
            CanonicalStreamRefusalError,
        );
        const replacementAggregation = openAggregation({
            evaluatorKeyStore,
            runtime,
        });
        replacementAggregation.cancel();
        expect(runtime.aggregateCancelHandles).toEqual([11]);

        runtime.boardSession.release(aggregateObject);
        runtime.acceptedSetupAuthority.release();
        runtime.boardSession.close();
        expect(runtime.allocations.size).toBe(0);
    });

    it('holds the worker lease during evaluator execution and releases it after abort cleanup', async () => {
        const runtime = createFakeEvaluatorRuntime();
        const evaluatorReadStarted = createDeferredPromise<void>();
        const lateEvaluatorRead = createDeferredPromise<Uint8Array>();
        const abortController = new AbortController();
        const evaluatorKeyStore: EvaluatorKeyStoreRangeSource = {
            readExactRange: (storeByteOffset) => {
                if (storeByteOffset !== evaluatorStoreByteOffset) {
                    return Promise.reject(
                        new Error(
                            'one ballot must not read an aggregation key',
                        ),
                    );
                }
                evaluatorReadStarted.resolve(undefined);
                return lateEvaluatorRead.promise;
            },
        };
        const aggregation = openAggregation({
            evaluatorKeyStore,
            options: {
                signal: abortController.signal,
                yieldControl: () => Promise.resolve(),
            },
            runtime,
        });
        await aggregation.absorb({
            verifiedBallot: runtime.createVerifiedBallot(
                61,
                selectionIdentity(0),
            ),
        });
        const preparedAggregate = aggregation.prepareAggregate();
        const { aggregateAuthority, aggregateObject } = bindPreparedAggregate({
            prepared: preparedAggregate,
            runtime,
        });
        const replayPromise = prepareEvaluatorReplayInClosedWorker({
            verifiedAggregateAuthority: aggregateAuthority,
        });
        await evaluatorReadStarted.promise;

        expect(() => openAggregation({ evaluatorKeyStore, runtime })).toThrow(
            CanonicalStreamResourceError,
        );
        abortController.abort();
        await expectPromptCancellation(replayPromise);
        expect(runtime.evaluatorCancelHandles).toEqual([31]);
        const lateRange = Uint8Array.of(0x61, 0x62, 0x63, 0x64);
        lateEvaluatorRead.resolve(lateRange);
        await waitForNextHostTask();
        expect(lateRange).toEqual(new Uint8Array(4));
        expect(runtime.evaluatorStoreRanges).toEqual([]);

        const replacementAggregation = openAggregation({
            evaluatorKeyStore,
            runtime,
        });
        replacementAggregation.cancel();
        expect(runtime.aggregateCancelHandles).toEqual([11]);

        runtime.boardSession.release(aggregateObject);
        runtime.acceptedSetupAuthority.release();
        runtime.boardSession.close();
        expect(runtime.allocations.size).toBe(0);
    });

    it('holds the worker lease for a prepared replay and releases it on cancellation', async () => {
        const runtime = createFakeEvaluatorRuntime();
        const evaluatorKeyStore: EvaluatorKeyStoreRangeSource = {
            readExactRange: (storeByteOffset, exactByteLength) => {
                if (
                    storeByteOffset !== evaluatorStoreByteOffset ||
                    exactByteLength !== 4
                ) {
                    return Promise.reject(
                        new Error(
                            'the evaluator requested an unexpected range',
                        ),
                    );
                }
                return Promise.resolve(Uint8Array.of(1, 2, 3, 4));
            },
        };
        const aggregation = await absorbOneBallot(runtime, evaluatorKeyStore);
        const preparedAggregate = aggregation.prepareAggregate();
        const { aggregateAuthority, aggregateObject } = bindPreparedAggregate({
            prepared: preparedAggregate,
            runtime,
        });
        const preparedReplay = await prepareEvaluatorReplayInClosedWorker({
            verifiedAggregateAuthority: aggregateAuthority,
        });

        expect(() => openAggregation({ evaluatorKeyStore, runtime })).toThrow(
            CanonicalStreamResourceError,
        );
        preparedReplay.cancel();
        expect(runtime.evaluatorCancelHandles).toEqual([31]);
        const replacementAggregation = openAggregation({
            evaluatorKeyStore,
            runtime,
        });
        replacementAggregation.cancel();
        expect(runtime.aggregateCancelHandles).toEqual([11]);

        runtime.boardSession.release(aggregateObject);
        runtime.acceptedSetupAuthority.release();
        runtime.boardSession.close();
        expect(runtime.allocations.size).toBe(0);
    });

    it('cancels retained Rust custody after an aggregate-carrier length refusal', async () => {
        const runtime = createFakeEvaluatorRuntime({
            aggregateCarrierLengthStatuses: [
                refusalReasonCodes.wrongHashOrRoot,
            ],
        });
        const evaluatorKeyStore: EvaluatorKeyStoreRangeSource = {
            readExactRange: () =>
                Promise.reject(new Error('one ballot must not read a key')),
        };
        const aggregation = await absorbOneBallot(runtime, evaluatorKeyStore);

        expect(() => aggregation.prepareAggregate()).toThrow(
            CanonicalStreamRefusalError,
        );
        expect(runtime.aggregateCancelHandles).toEqual([11]);
        expect(runtime.aggregateCarrierStagingBytesAtDeallocation).toEqual([]);
        expect(() => aggregation.cancel()).toThrow(CanonicalStreamRefusalError);
        const replacementAggregation = openAggregation({
            evaluatorKeyStore,
            runtime,
        });
        replacementAggregation.cancel();
        expect(runtime.aggregateCancelHandles).toEqual([11, 11]);

        runtime.acceptedSetupAuthority.release();
        runtime.boardSession.close();
        expect(runtime.allocations.size).toBe(0);
    });

    it('zeroes aggregate-carrier staging and cancels retained Rust custody after a copy refusal', async () => {
        const runtime = createFakeEvaluatorRuntime({
            aggregateCarrierCopyStatuses: [refusalReasonCodes.wrongHashOrRoot],
        });
        const evaluatorKeyStore: EvaluatorKeyStoreRangeSource = {
            readExactRange: () =>
                Promise.reject(new Error('one ballot must not read a key')),
        };
        const aggregation = await absorbOneBallot(runtime, evaluatorKeyStore);

        expect(() => aggregation.prepareAggregate()).toThrow(
            CanonicalStreamRefusalError,
        );
        expect(runtime.aggregateCancelHandles).toEqual([11]);
        expect(runtime.aggregateCarrierStagingBytesAtDeallocation).toEqual([
            new Uint8Array(aggregateCarrier.byteLength),
        ]);
        expect(() => aggregation.prepareAggregate()).toThrow(
            CanonicalStreamRefusalError,
        );
        const replacementAggregation = openAggregation({
            evaluatorKeyStore,
            runtime,
        });
        replacementAggregation.cancel();
        expect(runtime.aggregateCancelHandles).toEqual([11, 11]);

        runtime.acceptedSetupAuthority.release();
        runtime.boardSession.close();
        expect(runtime.allocations.size).toBe(0);
    });

    it('zeroes a wrong-length aggregation range, cancels the live session, and leaves the pending ballot releasable', async () => {
        const runtime = createFakeEvaluatorRuntime();
        const wrongLengthRange = Uint8Array.of(0x31, 0x32);
        const evaluatorKeyStore: EvaluatorKeyStoreRangeSource = {
            readExactRange: () => Promise.resolve(wrongLengthRange),
        };
        const aggregation = await absorbOneBallot(runtime, evaluatorKeyStore);
        const pendingBallot = runtime.createVerifiedBallot(
            62,
            selectionIdentity(1),
        );

        await expect(
            aggregation.absorb({
                verifiedBallot: pendingBallot,
            }),
        ).rejects.toThrow(CanonicalStreamRefusalError);
        expect(wrongLengthRange).toEqual(new Uint8Array(2));
        expect(runtime.aggregationStoreRanges).toEqual([]);
        expect(runtime.aggregateCancelHandles).toEqual([11]);
        expect(() => aggregation.prepareAggregate()).toThrow(
            CanonicalStreamRefusalError,
        );
        pendingBallot.release();
        expect(runtime.ballotReleaseHandles).toEqual([62]);

        runtime.acceptedSetupAuthority.release();
        runtime.boardSession.close();
        expect(runtime.allocations.size).toBe(0);
    });

    it('cancels promptly during a pending aggregation read and zeroes a late range without absorbing it', async () => {
        const runtime = createFakeEvaluatorRuntime();
        const lateStoreRead = createDeferredPromise<Uint8Array>();
        const storeReadStarted = createDeferredPromise<void>();
        const abortController = new AbortController();
        const evaluatorKeyStore: EvaluatorKeyStoreRangeSource = {
            readExactRange: () => {
                storeReadStarted.resolve(undefined);
                return lateStoreRead.promise;
            },
        };
        const aggregation = openAggregation({
            evaluatorKeyStore,
            options: {
                signal: abortController.signal,
                yieldControl: () => Promise.resolve(),
            },
            runtime,
        });
        await aggregation.absorb({
            verifiedBallot: runtime.createVerifiedBallot(
                61,
                selectionIdentity(0),
            ),
        });
        const pendingBallot = runtime.createVerifiedBallot(
            62,
            selectionIdentity(1),
        );
        const absorptionPromise = aggregation.absorb({
            verifiedBallot: pendingBallot,
        });
        await storeReadStarted.promise;

        abortController.abort();
        await expectPromptCancellation(absorptionPromise);
        expect(runtime.aggregateCancelHandles).toEqual([11]);
        expect(runtime.aggregationStoreRanges).toEqual([]);
        const lateRange = Uint8Array.of(0x41, 0x42, 0x43);
        lateStoreRead.resolve(lateRange);
        await waitForNextHostTask();

        expect(lateRange).toEqual(new Uint8Array(3));
        expect(runtime.aggregationStoreRanges).toEqual([]);
        expect(() => aggregation.cancel()).toThrow(CanonicalStreamRefusalError);
        pendingBallot.release();
        expect(runtime.ballotReleaseHandles).toEqual([62]);

        runtime.acceptedSetupAuthority.release();
        runtime.boardSession.close();
        expect(runtime.allocations.size).toBe(0);
    });

    it('explicitly cancels a pending aggregation read and retires its late result', async () => {
        const runtime = createFakeEvaluatorRuntime();
        const lateStoreRead = createDeferredPromise<Uint8Array>();
        const storeReadStarted = createDeferredPromise<void>();
        const aggregation = openAggregation({
            evaluatorKeyStore: {
                readExactRange: () => {
                    storeReadStarted.resolve(undefined);
                    return lateStoreRead.promise;
                },
            },
            options: { yieldControl: () => Promise.resolve() },
            runtime,
        });
        await aggregation.absorb({
            verifiedBallot: runtime.createVerifiedBallot(
                61,
                selectionIdentity(0),
            ),
        });
        const pendingBallot = runtime.createVerifiedBallot(
            62,
            selectionIdentity(1),
        );
        const absorptionPromise = aggregation.absorb({
            verifiedBallot: pendingBallot,
        });
        await storeReadStarted.promise;

        aggregation.cancel();
        await expectPromptCancellation(absorptionPromise);
        const lateRange = Uint8Array.of(0x51, 0x52, 0x53);
        lateStoreRead.resolve(lateRange);
        await waitForNextHostTask();

        expect(lateRange).toEqual(new Uint8Array(3));
        expect(runtime.aggregationStoreRanges).toEqual([]);
        expect(runtime.aggregateCancelHandles).toEqual([11]);
        expect(() => aggregation.prepareAggregate()).toThrow(
            CanonicalStreamRefusalError,
        );
        pendingBallot.release();
        expect(runtime.ballotReleaseHandles).toEqual([62]);

        runtime.acceptedSetupAuthority.release();
        runtime.boardSession.close();
        expect(runtime.allocations.size).toBe(0);
    });
});
