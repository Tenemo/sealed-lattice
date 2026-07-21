import { foundationProfile } from '@sealed-lattice/types';

import {
    requireVerifiedAcceptedSetupAuthorityKernelOwner,
    type VerifiedAcceptedSetupAuthority,
} from './accepted-setup-verification-runtime.js';
import {
    markVerifiedBallotOutputConsumedAfterKernelSuccess,
    requireVerifiedBallotOutputKernelAuthority,
    type VerifiedBallotOutput,
} from './ballot-validity-runtime.js';
import { isUint8Array } from './byte-array.js';
import {
    resolveVerifiedTranscriptObjectKernelAuthorization,
    type VerifiedTranscriptObject,
} from './canonical-board-runtime.js';
import {
    CanonicalStreamCancellationError,
    CanonicalStreamCleanupError,
    CanonicalStreamInternalError,
    CanonicalStreamRefusalError,
    CanonicalStreamResourceError,
} from './canonical-stream-runtime.js';
import { yieldBrowserWorkerTurn } from './common-proof-worker-runtime/kernel-boundaries.js';
import { resolveCommonProofKernelContext } from './transcript-core-bridge/common-proof-kernel-context.js';
import type { TranscriptCoreKernelCommandRuntime } from './transcript-core-bridge/kernel-runtime.js';
import type { TranscriptCoreKernel } from './transcript-core-bridge/kernel-types.js';
import { WasmMemoryBoundary } from './wasm-memory-boundary.js';
import { WasmStatusBoundary } from './wasm-status-boundary.js';

const aggregationProgressByteLength = 136;
const aggregationProgressVersion = 2;
const aggregationStoreReadRequired = 1;
const aggregationBallotAbsorbed = 2;
const boardVerifierCapabilityByteLength = 32;
const maximumWasm32UnsignedInteger = 0xffff_ffff;
const wasm32WordByteLength = Uint32Array.BYTES_PER_ELEMENT;
const hashByteLength = 64;
const checkpointLineageIdentifierByteLength = 32;
const ballotAggregationCheckpointOperationKind = 0x1404;
const ballotAggregationCheckpointSafeBoundaryOrdinal = 0;
const ballotAggregationCheckpointStateSchemaIdentifier = 0x180a;
const ballotAggregationCheckpointSelectionSchemaIdentifier = 0x180b;
const canonicalTupleVersion = 1;
const canonicalItemTypes = Object.freeze({
    unsigned16: 0x03,
    hash512: 0x06,
    nestedTuple: 0x09,
    homogeneousList: 0x0e,
});
const ballotAggregationCheckpointStateStreamDomain =
    'sealed-lattice/ballot-aggregation-selection-checkpoint/v1';
const emptyPrivateRandomCursorManifestBytes = Uint8Array.of(
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
);
const maximumBallotAggregationCheckpointStateByteLength = 2_048;

type BallotAggregationKernel = Readonly<{
    absorb: NonNullable<
        TranscriptCoreKernelCommandRuntime['wasmExports']['sealed_lattice_ballot_aggregation_absorb']
    >;
    absorbStoreChunk: NonNullable<
        TranscriptCoreKernelCommandRuntime['wasmExports']['sealed_lattice_ballot_aggregation_absorb_store_chunk']
    >;
    aggregateCarrierByteLength: NonNullable<
        TranscriptCoreKernelCommandRuntime['wasmExports']['sealed_lattice_ballot_aggregation_aggregate_carrier_byte_length']
    >;
    begin: NonNullable<
        TranscriptCoreKernelCommandRuntime['wasmExports']['sealed_lattice_ballot_aggregation_begin']
    >;
    bindAggregateObject: NonNullable<
        TranscriptCoreKernelCommandRuntime['wasmExports']['sealed_lattice_ballot_aggregation_bind_aggregate_object']
    >;
    cancel: NonNullable<
        TranscriptCoreKernelCommandRuntime['wasmExports']['sealed_lattice_ballot_aggregation_cancel']
    >;
    copyAggregateCarrier: NonNullable<
        TranscriptCoreKernelCommandRuntime['wasmExports']['sealed_lattice_ballot_aggregation_copy_aggregate_carrier']
    >;
    discardVerifiedAggregate: NonNullable<
        TranscriptCoreKernelCommandRuntime['wasmExports']['sealed_lattice_ballot_aggregation_discard_verified_aggregate']
    >;
    poll: NonNullable<
        TranscriptCoreKernelCommandRuntime['wasmExports']['sealed_lattice_ballot_aggregation_poll']
    >;
    prepare: NonNullable<
        TranscriptCoreKernelCommandRuntime['wasmExports']['sealed_lattice_ballot_aggregation_prepare']
    >;
}>;

type AggregationProgress =
    | Readonly<{
          exactByteLength: number;
          kind: 'store-read-required';
          storeByteOffset: bigint;
      }>
    | Readonly<{
          acceptedSetupSourceHash: Uint8Array<ArrayBuffer>;
          kind: 'ballot-absorbed';
          selectionIdentity: BallotAggregationSelectionIdentity;
      }>;

const verifiedBallotAggregationSessionBrand: unique symbol = Symbol(
    'sealed-lattice/verified-ballot-aggregation-session',
);
const preparedVerifiedBallotAggregateBrand: unique symbol = Symbol(
    'sealed-lattice/prepared-verified-ballot-aggregate',
);
const verifiedEvaluatorAggregateAuthorityBrand: unique symbol = Symbol(
    'sealed-lattice/verified-evaluator-aggregate-authority',
);

export type EvaluatorKeyStoreRangeSource = Readonly<{
    /** Transfers one fresh owned byte range requested by the Rust verifier. */
    readExactRange(
        storeByteOffset: bigint,
        exactByteLength: number,
    ): Promise<Uint8Array>;
}>;

export type EvaluatorKeyStoreRangeReadObservation = Readonly<{
    requestedByteLength: number;
    returnedByteLength: number;
    storeByteOffset: bigint;
}>;

export type BallotEvaluationWorkerOptions = Readonly<{
    observeEvaluatorKeyStoreRangeRead?(
        observation: EvaluatorKeyStoreRangeReadObservation,
    ): void;
    signal?: AbortSignal;
    yieldControl?(): Promise<void>;
}>;

export type BallotAggregationSelectionIdentity = Readonly<{
    ballotObjectHash: Uint8Array;
    producerRosterPosition: number;
}>;

export type VerifiedBallotAggregationInput = Readonly<{
    verifiedBallot: VerifiedBallotOutput;
}>;

export type BallotAggregationCheckpointBoundary = Readonly<{
    operationKind: number;
    orderedSourceDigests: readonly Uint8Array[];
    privateRandomCursorManifestBytes: Uint8Array;
    safeBoundaryOrdinal: number;
    stateStreamDescriptorBytes: Uint8Array;
    stateStreamDomain: string;
}>;

export type ExpectedBallotAggregationCheckpointBoundary = Omit<
    BallotAggregationCheckpointBoundary,
    'stateStreamDescriptorBytes'
>;

export type BallotAggregationCheckpointOperationIdentity = Readonly<{
    checkpointLineageIdentifier: Uint8Array;
}>;

export type ResumedBallotAggregationCheckpoint = Readonly<{
    canonicalManifestBytes: Uint8Array;
    operationIdentity: BallotAggregationCheckpointOperationIdentity;
    stateStreamDescriptorBytes: Uint8Array;
    restoreState(
        consumeChunk: (
            chunkIndex: number,
            chunkBytes: Uint8Array,
        ) => Promise<void> | void,
        signal: AbortSignal,
    ): Promise<void>;
}>;

/**
 * Dependency-safe adapter around the protocol-owned authenticated checkpoint
 * store. The adapter derives the canonical stream descriptor with the same
 * producer used by that store; this package cannot import protocol without
 * creating a package cycle.
 */
export type BallotAggregationCheckpointCustody = Readonly<{
    beginOperation(
        signal: AbortSignal,
    ): Promise<BallotAggregationCheckpointOperationIdentity>;
    describeStateStream(input: {
        stateBytes: Uint8Array;
        stateStreamDomain: string;
    }): Uint8Array;
    publish(input: {
        boundary: BallotAggregationCheckpointBoundary;
        identity: BallotAggregationCheckpointOperationIdentity;
        signal: AbortSignal;
        stateChunks: AsyncIterable<Uint8Array> | Iterable<Uint8Array>;
    }): Promise<Uint8Array>;
    releaseOperationIdentity(
        identity: BallotAggregationCheckpointOperationIdentity,
    ): Promise<void>;
    resume(input: {
        checkpointLineageIdentifier: Uint8Array;
        expectedBoundary: ExpectedBallotAggregationCheckpointBoundary;
        signal: AbortSignal;
    }): Promise<ResumedBallotAggregationCheckpoint>;
}>;

export type BallotAggregationSelectionCheckpoint = Readonly<{
    canonicalManifestBytes: Uint8Array<ArrayBuffer>;
    checkpointLineageIdentifier: Uint8Array<ArrayBuffer>;
    stateStreamDescriptorBytes: Uint8Array<ArrayBuffer>;
}>;

export type BallotAggregationCheckpointReplaySource = Readonly<{
    /** Positively rechecks the setup source without minting its one-shot owner. */
    borrowPreflightAcceptedSetupSource(
        acceptedSetupSourceHash: Uint8Array,
        signal: AbortSignal,
    ): Promise<void>;
    /** Positively rechecks one selected ballot without retaining its output. */
    borrowPreflightSelectedBallot(
        selectionIdentity: BallotAggregationSelectionIdentity,
        signal: AbortSignal,
    ): Promise<void>;
    /** Transfers a fresh accepted-setup owner to this resumed replay. */
    reverifyAcceptedSetup(
        signal: AbortSignal,
    ): Promise<VerifiedAcceptedSetupAuthority>;
    /** Transfers one fresh verified-ballot output in the requested order. */
    reverifySelectedBallot(
        selectionIdentity: BallotAggregationSelectionIdentity,
        signal: AbortSignal,
    ): Promise<VerifiedBallotOutput>;
}>;

/** Single-resident multiplicative ballot aggregation in one dedicated worker. */
export type VerifiedBallotAggregationSession = Readonly<{
    readonly [verifiedBallotAggregationSessionBrand]: true;
    absorb(input: VerifiedBallotAggregationInput): Promise<void>;
    cancel(): void;
    prepareAggregate(): PreparedVerifiedBallotAggregate;
    publishSelectionCheckpoint(
        custody: BallotAggregationCheckpointCustody,
    ): Promise<BallotAggregationSelectionCheckpoint>;
}>;

/** Exact aggregate carrier retained until positive canonical-board binding. */
export type PreparedVerifiedBallotAggregate = Readonly<{
    readonly [preparedVerifiedBallotAggregateBrand]: true;
    bind(
        verifiedAggregateObject: VerifiedTranscriptObject,
    ): VerifiedEvaluatorAggregateAuthority;
    cancel(): void;
    copyCanonicalCarrier(): Uint8Array<ArrayBuffer>;
}>;

/** One verified two-ciphertext aggregate retained exclusively in its worker. */
export type VerifiedEvaluatorAggregateAuthority = Readonly<{
    readonly [verifiedEvaluatorAggregateAuthorityBrand]: true;
    release(): void;
}>;

type PipelineCustody = Readonly<{
    cancellationController: AbortController;
    context: TranscriptCoreKernelCommandRuntime;
    evaluatorKeyStore: EvaluatorKeyStoreRangeSource;
    kernel: BallotAggregationKernel;
    options: BallotEvaluationWorkerOptions;
    transcriptCoreKernel: TranscriptCoreKernel;
}>;

type VerifiedBallotAggregationSessionRecord = PipelineCustody & {
    acceptedSetupSourceHash?: Uint8Array<ArrayBuffer>;
    ballotCandidateViewRoot: Uint8Array<ArrayBuffer>;
    handle: number;
    operationInProgress: boolean;
    rustStateLive: boolean;
    selectionEntries: BallotAggregationSelectionIdentity[];
    selectionFrozen: boolean;
};

type PreparedVerifiedBallotAggregateRecord = PipelineCustody & {
    canonicalCarrier: Uint8Array<ArrayBuffer>;
    handle: number;
};

type VerifiedEvaluatorAggregateAuthorityRecord = PipelineCustody & {
    handle: number;
};

type VerifiedEvaluatorAggregateKernelAuthority = Readonly<{
    cancellationController: AbortController;
    context: TranscriptCoreKernelCommandRuntime;
    evaluatorKeyStore: EvaluatorKeyStoreRangeSource;
    handle: number;
    kernel: TranscriptCoreKernel;
    options: BallotEvaluationWorkerOptions;
}>;

const verifiedBallotAggregationSessionRecords = new WeakMap<
    VerifiedBallotAggregationSession,
    VerifiedBallotAggregationSessionRecord
>();
const preparedVerifiedBallotAggregateRecords = new WeakMap<
    PreparedVerifiedBallotAggregate,
    PreparedVerifiedBallotAggregateRecord
>();
const verifiedEvaluatorAggregateAuthorityRecords = new WeakMap<
    VerifiedEvaluatorAggregateAuthority,
    VerifiedEvaluatorAggregateAuthorityRecord
>();
const activeAggregationContexts = new WeakSet<object>();
type LateHostCleanupState = {
    cleanupFailure?: CanonicalStreamCleanupError;
    pendingOperationCount: number;
};
const lateHostCleanupStates = new WeakMap<
    TranscriptCoreKernelCommandRuntime,
    LateHostCleanupState
>();

const retainLateHostCleanup = (
    context: TranscriptCoreKernelCommandRuntime,
): LateHostCleanupState => {
    const existingState = lateHostCleanupStates.get(context);
    if (existingState !== undefined) {
        existingState.pendingOperationCount += 1;
        return existingState;
    }
    const state: LateHostCleanupState = { pendingOperationCount: 1 };
    lateHostCleanupStates.set(context, state);
    return state;
};

const releaseLateHostCleanup = (
    context: TranscriptCoreKernelCommandRuntime,
    state: LateHostCleanupState,
): void => {
    state.pendingOperationCount -= 1;
    if (
        state.pendingOperationCount === 0 &&
        state.cleanupFailure === undefined
    ) {
        lateHostCleanupStates.delete(context);
    }
};

const poisonLateHostCleanup = (
    state: LateHostCleanupState,
    cleanupFailure: unknown,
): void => {
    state.cleanupFailure ??=
        cleanupFailure instanceof CanonicalStreamCleanupError
            ? cleanupFailure
            : new CanonicalStreamCleanupError(
                  new CanonicalStreamCancellationError(),
                  cleanupFailure,
              );
};

const poisonAggregationContext = (
    context: TranscriptCoreKernelCommandRuntime,
    cleanupFailure: unknown,
): CanonicalStreamCleanupError => {
    const existingState = lateHostCleanupStates.get(context);
    const state = existingState ?? { pendingOperationCount: 0 };
    if (existingState === undefined) {
        lateHostCleanupStates.set(context, state);
    }
    state.cleanupFailure ??=
        cleanupFailure instanceof CanonicalStreamCleanupError
            ? cleanupFailure
            : new CanonicalStreamCleanupError(
                  new CanonicalStreamInternalError(
                      'Checkpoint operation identity cleanup failed.',
                  ),
                  cleanupFailure,
              );
    return state.cleanupFailure;
};

const requireReusableAggregationContext = (
    context: TranscriptCoreKernelCommandRuntime,
): void => {
    const state = lateHostCleanupStates.get(context);
    if (state?.cleanupFailure !== undefined) {
        throw state.cleanupFailure;
    }
    if (state !== undefined) {
        throw new CanonicalStreamResourceError(
            'The WASM worker is still retiring cancelled host custody.',
        );
    }
};

const lateHostRejectionRequiresPoison = (operationFailure: unknown): boolean =>
    operationFailure instanceof CanonicalStreamCleanupError ||
    (typeof operationFailure === 'object' &&
        operationFailure !== null &&
        'code' in operationFailure &&
        operationFailure.code === 'CleanupFailed');

/** Internal terminal handoff shared only with evaluator replay in this worker. */
export const retireVerifiedBallotEvaluationWorkerLease = (
    context: TranscriptCoreKernelCommandRuntime,
    cancellationController: AbortController,
): void => {
    activeAggregationContexts.delete(context);
    cancellationController.abort();
};

const createStatusBoundary = (): WasmStatusBoundary =>
    new WasmStatusBoundary({
        createInternalError: (message) =>
            new CanonicalStreamInternalError(message),
        createRefusalError: (refusalReason) =>
            new CanonicalStreamRefusalError(refusalReason),
        createResourceError: () => new CanonicalStreamResourceError(),
        internalFailureMessage:
            'The verified-ballot aggregation kernel failed internally.',
        unknownStatusMessage:
            'The verified-ballot aggregation kernel returned an unknown status code.',
    });

const concatenateBytes = (
    parts: readonly Uint8Array[],
): Uint8Array<ArrayBuffer> => {
    const totalByteLength = parts.reduce(
        (total, part) => total + part.byteLength,
        0,
    );
    if (
        !Number.isSafeInteger(totalByteLength) ||
        totalByteLength > maximumBallotAggregationCheckpointStateByteLength
    ) {
        throw new CanonicalStreamResourceError(
            'The ballot-aggregation checkpoint state exceeds its fixed bound.',
        );
    }
    const output = new Uint8Array(totalByteLength);
    let offset = 0;
    for (const part of parts) {
        output.set(part, offset);
        offset += part.byteLength;
    }
    return output;
};

const unsigned16LittleEndian = (value: number): Uint8Array<ArrayBuffer> => {
    if (!Number.isInteger(value) || value < 0 || value > 0xffff) {
        throw new CanonicalStreamRefusalError('wrongTypeOrLength');
    }
    const bytes = new Uint8Array(2);
    new DataView(bytes.buffer).setUint16(0, value, true);
    return bytes;
};

const unsigned32LittleEndian = (value: number): Uint8Array<ArrayBuffer> => {
    if (!Number.isInteger(value) || value < 0 || value > 0xffff_ffff) {
        throw new CanonicalStreamRefusalError('wrongTypeOrLength');
    }
    const bytes = new Uint8Array(4);
    new DataView(bytes.buffer).setUint32(0, value, true);
    return bytes;
};

const encodeCanonicalItem = (
    itemType: number,
    payload: Uint8Array,
): Uint8Array<ArrayBuffer> =>
    concatenateBytes([
        unsigned16LittleEndian(itemType),
        unsigned32LittleEndian(payload.byteLength),
        payload,
    ]);

const encodeCanonicalTuple = (
    schemaIdentifier: number,
    items: readonly Uint8Array[],
): Uint8Array<ArrayBuffer> =>
    concatenateBytes([
        unsigned16LittleEndian(schemaIdentifier),
        unsigned16LittleEndian(canonicalTupleVersion),
        unsigned32LittleEndian(items.length),
        ...items,
    ]);

const bytesEqual = (left: Uint8Array, right: Uint8Array): boolean => {
    if (left.byteLength !== right.byteLength) {
        return false;
    }
    let difference = 0;
    for (let index = 0; index < left.byteLength; index += 1) {
        difference |= (left[index] ?? 0) ^ (right[index] ?? 0);
    }
    return difference === 0;
};

const copyFixedBytes = (
    value: Uint8Array,
    byteLength: number,
): Uint8Array<ArrayBuffer> => {
    if (!isUint8Array(value) || value.byteLength !== byteLength) {
        throw new CanonicalStreamRefusalError('wrongTypeOrLength');
    }
    return Uint8Array.from(value);
};

const copySelectionIdentity = (
    value: BallotAggregationSelectionIdentity,
): BallotAggregationSelectionIdentity => {
    if (
        typeof value !== 'object' ||
        value === null ||
        !Number.isSafeInteger(value.producerRosterPosition) ||
        value.producerRosterPosition < 0 ||
        value.producerRosterPosition >= foundationProfile.participantCount
    ) {
        throw new CanonicalStreamRefusalError('wrongTypeOrLength');
    }
    return Object.freeze({
        ballotObjectHash: copyFixedBytes(
            value.ballotObjectHash,
            hashByteLength,
        ),
        producerRosterPosition: value.producerRosterPosition,
    });
};

const copyOrderedSelection = (
    values: readonly BallotAggregationSelectionIdentity[],
): BallotAggregationSelectionIdentity[] => {
    if (
        !Array.isArray(values) ||
        values.length === 0 ||
        values.length > foundationProfile.participantCount
    ) {
        throw new CanonicalStreamRefusalError('wrongTypeOrLength');
    }
    const copied = values.map(copySelectionIdentity);
    for (let index = 0; index < copied.length; index += 1) {
        const current = copied[index];
        const previous = copied[index - 1];
        if (
            current === undefined ||
            (previous !== undefined &&
                previous.producerRosterPosition >=
                    current.producerRosterPosition) ||
            copied
                .slice(0, index)
                .some((entry) =>
                    bytesEqual(
                        entry.ballotObjectHash,
                        current.ballotObjectHash,
                    ),
                )
        ) {
            for (const entry of copied) {
                entry.ballotObjectHash.fill(0);
            }
            throw new CanonicalStreamRefusalError('wrongContext');
        }
    }
    return copied;
};

const encodeSelectionCheckpointState = (input: {
    acceptedSetupSourceHash: Uint8Array;
    ballotCandidateViewRoot: Uint8Array;
    selectionEntries: readonly BallotAggregationSelectionIdentity[];
}): Uint8Array<ArrayBuffer> => {
    const entryTuples = input.selectionEntries.map((entry) =>
        encodeCanonicalTuple(
            ballotAggregationCheckpointSelectionSchemaIdentifier,
            [
                encodeCanonicalItem(
                    canonicalItemTypes.unsigned16,
                    unsigned16LittleEndian(entry.producerRosterPosition),
                ),
                encodeCanonicalItem(
                    canonicalItemTypes.hash512,
                    entry.ballotObjectHash,
                ),
            ],
        ),
    );
    const listPayload = concatenateBytes([
        unsigned16LittleEndian(canonicalItemTypes.nestedTuple),
        unsigned32LittleEndian(entryTuples.length),
        ...entryTuples,
    ]);
    return encodeCanonicalTuple(
        ballotAggregationCheckpointStateSchemaIdentifier,
        [
            encodeCanonicalItem(
                canonicalItemTypes.hash512,
                input.acceptedSetupSourceHash,
            ),
            encodeCanonicalItem(
                canonicalItemTypes.hash512,
                input.ballotCandidateViewRoot,
            ),
            encodeCanonicalItem(
                canonicalItemTypes.homogeneousList,
                listPayload,
            ),
        ],
    );
};

const decodeSelectionCheckpointState = (
    bytes: Uint8Array,
): Readonly<{
    acceptedSetupSourceHash: Uint8Array<ArrayBuffer>;
    ballotCandidateViewRoot: Uint8Array<ArrayBuffer>;
    selectionEntries: readonly BallotAggregationSelectionIdentity[];
}> => {
    if (
        !isUint8Array(bytes) ||
        bytes.byteLength === 0 ||
        bytes.byteLength > maximumBallotAggregationCheckpointStateByteLength
    ) {
        throw new CanonicalStreamRefusalError('wrongTypeOrLength');
    }
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    let offset = 0;
    const readUnsigned16 = (): number => {
        if (offset + 2 > bytes.byteLength) {
            throw new CanonicalStreamRefusalError('wrongTypeOrLength');
        }
        const value = view.getUint16(offset, true);
        offset += 2;
        return value;
    };
    const readUnsigned32 = (): number => {
        if (offset + 4 > bytes.byteLength) {
            throw new CanonicalStreamRefusalError('wrongTypeOrLength');
        }
        const value = view.getUint32(offset, true);
        offset += 4;
        return value;
    };
    const readItem = (
        expectedItemType: number,
        expectedByteLength?: number,
    ): Uint8Array<ArrayBuffer> => {
        if (readUnsigned16() !== expectedItemType) {
            throw new CanonicalStreamRefusalError('wrongTypeOrLength');
        }
        const byteLength = readUnsigned32();
        if (
            (expectedByteLength !== undefined &&
                byteLength !== expectedByteLength) ||
            offset + byteLength > bytes.byteLength
        ) {
            throw new CanonicalStreamRefusalError('wrongTypeOrLength');
        }
        const value = Uint8Array.from(
            bytes.subarray(offset, offset + byteLength),
        );
        offset += byteLength;
        return value;
    };
    if (
        readUnsigned16() !== ballotAggregationCheckpointStateSchemaIdentifier ||
        readUnsigned16() !== canonicalTupleVersion ||
        readUnsigned32() !== 3
    ) {
        throw new CanonicalStreamRefusalError('wrongTypeOrLength');
    }
    const acceptedSetupSourceHash = readItem(
        canonicalItemTypes.hash512,
        hashByteLength,
    );
    const ballotCandidateViewRoot = readItem(
        canonicalItemTypes.hash512,
        hashByteLength,
    );
    const selectionList = readItem(canonicalItemTypes.homogeneousList);
    const listView = new DataView(
        selectionList.buffer,
        selectionList.byteOffset,
        selectionList.byteLength,
    );
    let listOffset = 0;
    const readListUnsigned16 = (): number => {
        if (listOffset + 2 > selectionList.byteLength) {
            throw new CanonicalStreamRefusalError('wrongTypeOrLength');
        }
        const value = listView.getUint16(listOffset, true);
        listOffset += 2;
        return value;
    };
    const readListUnsigned32 = (): number => {
        if (listOffset + 4 > selectionList.byteLength) {
            throw new CanonicalStreamRefusalError('wrongTypeOrLength');
        }
        const value = listView.getUint32(listOffset, true);
        listOffset += 4;
        return value;
    };
    if (readListUnsigned16() !== canonicalItemTypes.nestedTuple) {
        throw new CanonicalStreamRefusalError('wrongTypeOrLength');
    }
    const entryCount = readListUnsigned32();
    if (entryCount === 0 || entryCount > foundationProfile.participantCount) {
        throw new CanonicalStreamRefusalError('wrongTypeOrLength');
    }
    const selectionEntries: BallotAggregationSelectionIdentity[] = [];
    for (let entryIndex = 0; entryIndex < entryCount; entryIndex += 1) {
        if (
            readListUnsigned16() !==
                ballotAggregationCheckpointSelectionSchemaIdentifier ||
            readListUnsigned16() !== canonicalTupleVersion ||
            readListUnsigned32() !== 2 ||
            readListUnsigned16() !== canonicalItemTypes.unsigned16 ||
            readListUnsigned32() !== 2
        ) {
            throw new CanonicalStreamRefusalError('wrongTypeOrLength');
        }
        const producerRosterPosition = readListUnsigned16();
        if (
            readListUnsigned16() !== canonicalItemTypes.hash512 ||
            readListUnsigned32() !== hashByteLength ||
            listOffset + hashByteLength > selectionList.byteLength
        ) {
            throw new CanonicalStreamRefusalError('wrongTypeOrLength');
        }
        const ballotObjectHash = Uint8Array.from(
            selectionList.subarray(listOffset, listOffset + hashByteLength),
        );
        listOffset += hashByteLength;
        selectionEntries.push(
            Object.freeze({ ballotObjectHash, producerRosterPosition }),
        );
    }
    if (
        listOffset !== selectionList.byteLength ||
        offset !== bytes.byteLength
    ) {
        throw new CanonicalStreamRefusalError('wrongTypeOrLength');
    }
    try {
        return Object.freeze({
            acceptedSetupSourceHash,
            ballotCandidateViewRoot,
            selectionEntries: Object.freeze(
                copyOrderedSelection(selectionEntries),
            ),
        });
    } finally {
        for (const entry of selectionEntries) {
            entry.ballotObjectHash.fill(0);
        }
    }
};

const selectionCheckpointBoundary = (input: {
    acceptedSetupSourceHash: Uint8Array;
    ballotCandidateViewRoot: Uint8Array;
    selectionEntries: readonly BallotAggregationSelectionIdentity[];
    stateStreamDescriptorBytes?: Uint8Array;
}):
    | BallotAggregationCheckpointBoundary
    | ExpectedBallotAggregationCheckpointBoundary => ({
    operationKind: ballotAggregationCheckpointOperationKind,
    orderedSourceDigests: Object.freeze([
        Uint8Array.from(input.acceptedSetupSourceHash),
        Uint8Array.from(input.ballotCandidateViewRoot),
        ...input.selectionEntries.map((entry) =>
            Uint8Array.from(entry.ballotObjectHash),
        ),
    ]),
    privateRandomCursorManifestBytes: Uint8Array.from(
        emptyPrivateRandomCursorManifestBytes,
    ),
    safeBoundaryOrdinal: ballotAggregationCheckpointSafeBoundaryOrdinal,
    ...(input.stateStreamDescriptorBytes === undefined
        ? {}
        : {
              stateStreamDescriptorBytes: Uint8Array.from(
                  input.stateStreamDescriptorBytes,
              ),
          }),
    stateStreamDomain: ballotAggregationCheckpointStateStreamDomain,
});

const selectionIdentityMatches = (
    left: BallotAggregationSelectionIdentity,
    right: BallotAggregationSelectionIdentity,
): boolean =>
    left.producerRosterPosition === right.producerRosterPosition &&
    bytesEqual(left.ballotObjectHash, right.ballotObjectHash);

const recordAuthenticatedBallotSelection = (
    record: VerifiedBallotAggregationSessionRecord,
    progress: Extract<AggregationProgress, { kind: 'ballot-absorbed' }>,
): void => {
    const previousSelectionIdentity =
        record.selectionEntries[record.selectionEntries.length - 1];
    if (
        (previousSelectionIdentity !== undefined &&
            previousSelectionIdentity.producerRosterPosition >=
                progress.selectionIdentity.producerRosterPosition) ||
        record.selectionEntries.some((entry) =>
            bytesEqual(
                entry.ballotObjectHash,
                progress.selectionIdentity.ballotObjectHash,
            ),
        ) ||
        (record.acceptedSetupSourceHash !== undefined &&
            !bytesEqual(
                record.acceptedSetupSourceHash,
                progress.acceptedSetupSourceHash,
            ))
    ) {
        progress.acceptedSetupSourceHash.fill(0);
        progress.selectionIdentity.ballotObjectHash.fill(0);
        throw new CanonicalStreamInternalError(
            'The ballot aggregation returned selection metadata that contradicts its verified Rust state.',
        );
    }
    if (record.acceptedSetupSourceHash === undefined) {
        record.acceptedSetupSourceHash = progress.acceptedSetupSourceHash;
    } else {
        progress.acceptedSetupSourceHash.fill(0);
    }
    record.selectionEntries.push(progress.selectionIdentity);
};

const clearSelectionCheckpointState = (
    record: VerifiedBallotAggregationSessionRecord,
): void => {
    record.acceptedSetupSourceHash?.fill(0);
    record.acceptedSetupSourceHash = undefined;
    record.ballotCandidateViewRoot.fill(0);
    for (const entry of record.selectionEntries) {
        entry.ballotObjectHash.fill(0);
    }
    record.selectionEntries.length = 0;
};

const requireLiveHandle = (value: number, label: string): number => {
    if (
        !Number.isSafeInteger(value) ||
        value <= 0 ||
        value > maximumWasm32UnsignedInteger
    ) {
        throw new CanonicalStreamInternalError(`${label} is invalid.`);
    }
    return value;
};

const requireBallotAggregationKernel = (
    context: TranscriptCoreKernelCommandRuntime,
): BallotAggregationKernel => {
    const {
        sealed_lattice_ballot_aggregation_absorb: absorb,
        sealed_lattice_ballot_aggregation_absorb_store_chunk: absorbStoreChunk,
        sealed_lattice_ballot_aggregation_aggregate_carrier_byte_length:
            aggregateCarrierByteLength,
        sealed_lattice_ballot_aggregation_begin: begin,
        sealed_lattice_ballot_aggregation_bind_aggregate_object:
            bindAggregateObject,
        sealed_lattice_ballot_aggregation_cancel: cancel,
        sealed_lattice_ballot_aggregation_copy_aggregate_carrier:
            copyAggregateCarrier,
        sealed_lattice_ballot_aggregation_discard_verified_aggregate:
            discardVerifiedAggregate,
        sealed_lattice_ballot_aggregation_poll: poll,
        sealed_lattice_ballot_aggregation_prepare: prepare,
    } = context.wasmExports;
    if (
        typeof absorb !== 'function' ||
        typeof absorbStoreChunk !== 'function' ||
        typeof aggregateCarrierByteLength !== 'function' ||
        typeof begin !== 'function' ||
        typeof bindAggregateObject !== 'function' ||
        typeof cancel !== 'function' ||
        typeof copyAggregateCarrier !== 'function' ||
        typeof discardVerifiedAggregate !== 'function' ||
        typeof poll !== 'function' ||
        typeof prepare !== 'function'
    ) {
        throw new CanonicalStreamInternalError(
            'The transcript-core kernel lacks the verified-ballot aggregation boundary.',
        );
    }
    return Object.freeze({
        absorb,
        absorbStoreChunk,
        aggregateCarrierByteLength,
        begin,
        bindAggregateObject,
        cancel,
        copyAggregateCarrier,
        discardVerifiedAggregate,
        poll,
        prepare,
    });
};

const throwIfCancelled = (
    cancellationController: AbortController,
    signal?: AbortSignal,
): void => {
    if (cancellationController.signal.aborted || signal?.aborted === true) {
        throw new CanonicalStreamCancellationError();
    }
};

const awaitAbortableHostOperation = async <Result>(
    cancellationController: AbortController,
    signal: AbortSignal | undefined,
    context: TranscriptCoreKernelCommandRuntime,
    startOperation: (operationSignal: AbortSignal) => Promise<Result>,
    disposeLateResult?: (result: Result) => Promise<void> | void,
    lateRejectionRequiresPoison: (
        operationFailure: unknown,
    ) => boolean = lateHostRejectionRequiresPoison,
): Promise<Result> => {
    throwIfCancelled(cancellationController, signal);
    const signals = [cancellationController.signal];
    if (signal !== undefined && signal !== cancellationController.signal) {
        signals.push(signal);
    }
    const cancellationError = new CanonicalStreamCancellationError();
    const operationState: {
        cancellationWon: boolean;
        lateCleanupState?: LateHostCleanupState;
    } = { cancellationWon: false };
    const hostCancellationController = new AbortController();
    const listeners: Array<
        Readonly<{ listener: () => void; signal: AbortSignal }>
    > = [];
    const hostOperationPromise = Promise.resolve()
        .then(() => startOperation(hostCancellationController.signal))
        .then(
            async (result) => {
                if (operationState.cancellationWon) {
                    try {
                        await disposeLateResult?.(result);
                    } catch (cleanupFailure) {
                        const lateCleanupState =
                            operationState.lateCleanupState;
                        if (lateCleanupState !== undefined) {
                            poisonLateHostCleanup(
                                lateCleanupState,
                                cleanupFailure,
                            );
                        }
                    }
                    throw cancellationError;
                }
                return result;
            },
            (operationFailure: unknown) => {
                if (operationState.cancellationWon) {
                    const lateCleanupState = operationState.lateCleanupState;
                    if (
                        lateCleanupState !== undefined &&
                        lateRejectionRequiresPoison(operationFailure)
                    ) {
                        poisonLateHostCleanup(
                            lateCleanupState,
                            operationFailure,
                        );
                    }
                    throw cancellationError;
                }
                throw operationFailure;
            },
        );
    const cancellationPromise = new Promise<never>((_resolve, reject) => {
        for (const currentSignal of signals) {
            const listener = (): void => {
                if (operationState.cancellationWon) {
                    return;
                }
                operationState.cancellationWon = true;
                const lateCleanupState = retainLateHostCleanup(context);
                operationState.lateCleanupState = lateCleanupState;
                void hostOperationPromise
                    .catch(() => undefined)
                    .finally(() =>
                        releaseLateHostCleanup(context, lateCleanupState),
                    );
                hostCancellationController.abort();
                reject(cancellationError);
            };
            listeners.push({ listener, signal: currentSignal });
            currentSignal.addEventListener('abort', listener, { once: true });
            if (currentSignal.aborted) {
                listener();
            }
        }
    });
    try {
        return await Promise.race([hostOperationPromise, cancellationPromise]);
    } finally {
        for (const entry of listeners) {
            entry.signal.removeEventListener('abort', entry.listener);
        }
    }
};

const releaseCheckpointOperationIdentity = async (input: {
    cancellationController: AbortController;
    context: TranscriptCoreKernelCommandRuntime;
    custody: BallotAggregationCheckpointCustody;
    identity: BallotAggregationCheckpointOperationIdentity;
    signal?: AbortSignal;
}): Promise<void> => {
    const releaseIdentity = (): Promise<void> =>
        input.custody.releaseOperationIdentity(input.identity);
    const cancellationRequested = (): boolean =>
        input.cancellationController.signal.aborted ||
        input.signal?.aborted === true;
    if (cancellationRequested()) {
        const lateCleanupState = retainLateHostCleanup(input.context);
        void Promise.resolve()
            .then(releaseIdentity)
            .catch((cleanupFailure: unknown) => {
                poisonLateHostCleanup(lateCleanupState, cleanupFailure);
            })
            .finally(() =>
                releaseLateHostCleanup(input.context, lateCleanupState),
            );
        return;
    }
    try {
        await awaitAbortableHostOperation(
            input.cancellationController,
            input.signal,
            input.context,
            releaseIdentity,
            undefined,
            () => true,
        );
    } catch (operationFailure) {
        if (
            operationFailure instanceof CanonicalStreamCancellationError &&
            cancellationRequested()
        ) {
            return;
        }
        throw poisonAggregationContext(input.context, operationFailure);
    }
};

const decodeProgress = (bytes: Uint8Array): AggregationProgress => {
    if (bytes.byteLength !== aggregationProgressByteLength) {
        throw new CanonicalStreamInternalError(
            'The ballot aggregation progress record has the wrong byte length.',
        );
    }
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    if (view.getUint16(0, true) !== aggregationProgressVersion) {
        throw new CanonicalStreamInternalError(
            'The ballot aggregation progress record has an unsupported version.',
        );
    }
    const progressCode = view.getUint16(2, true);
    if (progressCode === aggregationStoreReadRequired) {
        const storeByteOffset = view.getBigUint64(4, true);
        const exactByteLength = view.getUint32(12, true);
        if (
            exactByteLength === 0 ||
            bytes.subarray(16).some((byte) => byte !== 0)
        ) {
            throw new CanonicalStreamInternalError(
                'The ballot aggregation returned a malformed key-store request.',
            );
        }
        return Object.freeze({
            exactByteLength,
            kind: 'store-read-required' as const,
            storeByteOffset,
        });
    }
    if (progressCode === aggregationBallotAbsorbed) {
        const producerRosterPosition = view.getUint16(4, true);
        if (
            view.getUint16(6, true) !== 0 ||
            producerRosterPosition >= foundationProfile.participantCount
        ) {
            throw new CanonicalStreamInternalError(
                'The ballot aggregation returned a malformed verified selection identity.',
            );
        }
        return Object.freeze({
            acceptedSetupSourceHash: bytes.slice(72, 136),
            kind: 'ballot-absorbed' as const,
            selectionIdentity: Object.freeze({
                ballotObjectHash: bytes.slice(8, 72),
                producerRosterPosition,
            }),
        });
    }
    throw new CanonicalStreamInternalError(
        'The ballot aggregation returned an invalid progress code or payload.',
    );
};

const readExactStoreRange = async (input: {
    exactByteLength: number;
    source: EvaluatorKeyStoreRangeSource;
    storeByteOffset: bigint;
}): Promise<Uint8Array<ArrayBuffer>> => {
    let chunkBytes: Uint8Array;
    try {
        chunkBytes = await input.source.readExactRange(
            input.storeByteOffset,
            input.exactByteLength,
        );
    } catch (error) {
        throw new CanonicalStreamInternalError(
            'The evaluator key store could not read the exact requested range.',
            error,
        );
    }
    if (
        !isUint8Array(chunkBytes) ||
        !(chunkBytes.buffer instanceof ArrayBuffer) ||
        chunkBytes.byteOffset !== 0 ||
        chunkBytes.byteLength !== chunkBytes.buffer.byteLength ||
        chunkBytes.byteLength !== input.exactByteLength
    ) {
        if (isUint8Array(chunkBytes)) {
            chunkBytes.fill(0);
        }
        throw new CanonicalStreamRefusalError('wrongTypeOrLength');
    }
    return chunkBytes as Uint8Array<ArrayBuffer>;
};

const requireLiveAggregationRecord = (
    session: VerifiedBallotAggregationSession,
): VerifiedBallotAggregationSessionRecord => {
    if (
        (typeof session !== 'object' && typeof session !== 'function') ||
        session === null
    ) {
        throw new CanonicalStreamRefusalError('consumedState');
    }
    const record = verifiedBallotAggregationSessionRecords.get(session);
    if (record === undefined) {
        throw new CanonicalStreamRefusalError('consumedState');
    }
    return record;
};

const retireAggregationSession = (
    session: VerifiedBallotAggregationSession,
    record: VerifiedBallotAggregationSessionRecord,
): void => {
    verifiedBallotAggregationSessionRecords.delete(session);
    clearSelectionCheckpointState(record);
    retireVerifiedBallotEvaluationWorkerLease(
        record.context,
        record.cancellationController,
    );
};

const cancelRustAggregation = (
    record: VerifiedBallotAggregationSessionRecord,
    operationName: string,
): void => {
    if (!record.rustStateLive) {
        return;
    }
    const status = record.context.runExclusive(operationName, () =>
        record.kernel.cancel(record.handle),
    );
    record.rustStateLive = false;
    createStatusBoundary().throwIfError(status);
};

const retireFailedAggregation = (
    session: VerifiedBallotAggregationSession,
    record: VerifiedBallotAggregationSessionRecord,
    operationFailure: unknown,
): never => {
    if (verifiedBallotAggregationSessionRecords.get(session) !== record) {
        throw operationFailure;
    }
    let cleanupFailure: unknown;
    try {
        cancelRustAggregation(
            record,
            'failed verified-ballot aggregation cleanup',
        );
    } catch (error) {
        cleanupFailure = error;
    }
    retireAggregationSession(session, record);
    if (cleanupFailure !== undefined) {
        throw new CanonicalStreamCleanupError(operationFailure, cleanupFailure);
    }
    throw operationFailure;
};

const retireAggregationAfterCommittedCheckpoint = (
    session: VerifiedBallotAggregationSession,
    record: VerifiedBallotAggregationSessionRecord,
): void => {
    try {
        cancelRustAggregation(
            record,
            'committed checkpoint aggregation retirement',
        );
    } catch (cleanupFailure) {
        poisonAggregationContext(record.context, cleanupFailure);
    }
    retireAggregationSession(session, record);
};

const cancelAggregationSession = (
    session: VerifiedBallotAggregationSession,
): void => {
    const record = requireLiveAggregationRecord(session);
    record.cancellationController.abort();
    let operationFailure: Error | undefined;
    try {
        cancelRustAggregation(
            record,
            'verified-ballot aggregation cancellation',
        );
    } catch (error) {
        operationFailure =
            error instanceof Error
                ? error
                : new CanonicalStreamInternalError(
                      'The verified-ballot aggregation cancellation failed with a non-error value.',
                      error,
                  );
    } finally {
        retireAggregationSession(session, record);
    }
    if (operationFailure !== undefined) {
        throw operationFailure;
    }
};

const absorbVerifiedBallot = async (
    session: VerifiedBallotAggregationSession,
    input: VerifiedBallotAggregationInput,
): Promise<void> => {
    const record = requireLiveAggregationRecord(session);
    if (record.operationInProgress) {
        throw new CanonicalStreamResourceError(
            'The verified-ballot aggregation already has an operation in progress.',
        );
    }
    if (record.selectionFrozen) {
        throw new CanonicalStreamRefusalError('consumedState');
    }
    record.operationInProgress = true;
    try {
        throwIfCancelled(record.cancellationController, record.options.signal);
        const ballotAuthority = requireVerifiedBallotOutputKernelAuthority(
            input.verifiedBallot,
            record.transcriptCoreKernel,
        );
        const absorbStatus = record.context.runExclusive(
            'verified-ballot aggregation absorption begin',
            () => record.kernel.absorb(record.handle, ballotAuthority.handle),
        );
        if (absorbStatus !== 0) {
            record.rustStateLive = false;
        }
        createStatusBoundary().throwIfError(absorbStatus);

        const memoryBoundary = new WasmMemoryBoundary({
            context: record.context,
            createInternalError: (message) =>
                new CanonicalStreamInternalError(message),
            createResourceError: (message) =>
                new CanonicalStreamResourceError(message),
            label: 'verified-ballot aggregation progress boundary',
        });
        const progressPointer = memoryBoundary.allocate(
            aggregationProgressByteLength,
        );
        try {
            for (;;) {
                throwIfCancelled(
                    record.cancellationController,
                    record.options.signal,
                );
                const progress = record.context.runExclusive(
                    'verified-ballot aggregation progress',
                    () => {
                        const status = record.kernel.poll(
                            record.handle,
                            progressPointer,
                            aggregationProgressByteLength,
                        );
                        if (status !== 0) {
                            record.rustStateLive = false;
                        }
                        createStatusBoundary().throwIfError(status);
                        return decodeProgress(
                            new Uint8Array(
                                record.context.memory.buffer,
                                progressPointer,
                                aggregationProgressByteLength,
                            ),
                        );
                    },
                );
                if (progress.kind === 'ballot-absorbed') {
                    markVerifiedBallotOutputConsumedAfterKernelSuccess(
                        input.verifiedBallot,
                        record.transcriptCoreKernel,
                    );
                    recordAuthenticatedBallotSelection(record, progress);
                    return;
                }

                memoryBoundary.validateAllocationByteLength(
                    progress.exactByteLength,
                );
                const chunkBytes = await awaitAbortableHostOperation(
                    record.cancellationController,
                    record.options.signal,
                    record.context,
                    () =>
                        readExactStoreRange({
                            exactByteLength: progress.exactByteLength,
                            source: record.evaluatorKeyStore,
                            storeByteOffset: progress.storeByteOffset,
                        }),
                    (lateChunkBytes) => {
                        lateChunkBytes.fill(0);
                    },
                );
                try {
                    record.options.observeEvaluatorKeyStoreRangeRead?.(
                        Object.freeze({
                            requestedByteLength: progress.exactByteLength,
                            returnedByteLength: chunkBytes.byteLength,
                            storeByteOffset: progress.storeByteOffset,
                        }),
                    );
                    throwIfCancelled(
                        record.cancellationController,
                        record.options.signal,
                    );
                    record.context.runExclusive(
                        'verified-ballot aggregation store-range absorption',
                        () => {
                            const chunkPointer =
                                memoryBoundary.copy(chunkBytes);
                            try {
                                const status = record.kernel.absorbStoreChunk(
                                    record.handle,
                                    progress.storeByteOffset,
                                    chunkPointer,
                                    chunkBytes.byteLength,
                                );
                                if (status !== 0) {
                                    record.rustStateLive = false;
                                }
                                createStatusBoundary().throwIfError(status);
                            } finally {
                                memoryBoundary.zeroAndDeallocate(
                                    chunkPointer,
                                    chunkBytes.byteLength,
                                );
                            }
                        },
                    );
                } finally {
                    chunkBytes.fill(0);
                }
                await awaitAbortableHostOperation(
                    record.cancellationController,
                    record.options.signal,
                    record.context,
                    record.options.yieldControl ?? yieldBrowserWorkerTurn,
                );
            }
        } finally {
            memoryBoundary.zeroAndDeallocate(
                progressPointer,
                aggregationProgressByteLength,
            );
        }
    } catch (operationFailure) {
        retireFailedAggregation(session, record, operationFailure);
    } finally {
        if (verifiedBallotAggregationSessionRecords.get(session) === record) {
            record.operationInProgress = false;
        }
    }
};

const publishSelectionCheckpoint = async (
    session: VerifiedBallotAggregationSession,
    custody: BallotAggregationCheckpointCustody,
): Promise<BallotAggregationSelectionCheckpoint> => {
    const record = requireLiveAggregationRecord(session);
    if (record.operationInProgress) {
        throw new CanonicalStreamResourceError(
            'The verified-ballot aggregation already has an operation in progress.',
        );
    }
    if (record.selectionFrozen || record.selectionEntries.length === 0) {
        throw new CanonicalStreamRefusalError('consumedState');
    }
    if (record.acceptedSetupSourceHash === undefined) {
        throw new CanonicalStreamInternalError(
            'The verified ballot selection lacks its Rust-authenticated setup source.',
        );
    }
    if (
        typeof custody !== 'object' ||
        custody === null ||
        typeof custody.beginOperation !== 'function' ||
        typeof custody.describeStateStream !== 'function' ||
        typeof custody.publish !== 'function' ||
        typeof custody.releaseOperationIdentity !== 'function' ||
        typeof custody.resume !== 'function'
    ) {
        throw new CanonicalStreamRefusalError('wrongTypeOrLength');
    }

    record.operationInProgress = true;
    let identity: BallotAggregationCheckpointOperationIdentity | undefined;
    let operationFailure: unknown;
    let result: BallotAggregationSelectionCheckpoint | undefined;
    const checkpointAcceptedSetupSourceHash =
        record.acceptedSetupSourceHash.slice();
    const checkpointBallotCandidateViewRoot =
        record.ballotCandidateViewRoot.slice();
    const checkpointSelectionEntries = copyOrderedSelection(
        record.selectionEntries,
    );
    const stateBytes = encodeSelectionCheckpointState({
        acceptedSetupSourceHash: checkpointAcceptedSetupSourceHash,
        ballotCandidateViewRoot: checkpointBallotCandidateViewRoot,
        selectionEntries: checkpointSelectionEntries,
    });
    try {
        throwIfCancelled(record.cancellationController, record.options.signal);
        identity = await awaitAbortableHostOperation(
            record.cancellationController,
            record.options.signal,
            record.context,
            (operationSignal) => custody.beginOperation(operationSignal),
            (lateIdentity) => custody.releaseOperationIdentity(lateIdentity),
        );
        const checkpointOperationIdentity = identity;
        const checkpointLineageIdentifier = copyFixedBytes(
            checkpointOperationIdentity.checkpointLineageIdentifier,
            checkpointLineageIdentifierByteLength,
        );
        const stateStreamDescriptorBytes = custody.describeStateStream({
            stateBytes,
            stateStreamDomain: ballotAggregationCheckpointStateStreamDomain,
        });
        if (
            !isUint8Array(stateStreamDescriptorBytes) ||
            stateStreamDescriptorBytes.byteLength === 0 ||
            stateStreamDescriptorBytes.byteLength >
                maximumBallotAggregationCheckpointStateByteLength
        ) {
            checkpointLineageIdentifier.fill(0);
            throw new CanonicalStreamRefusalError('wrongTypeOrLength');
        }
        const copiedStateStreamDescriptorBytes = Uint8Array.from(
            stateStreamDescriptorBytes,
        );
        try {
            const canonicalManifestBytes = await awaitAbortableHostOperation(
                record.cancellationController,
                record.options.signal,
                record.context,
                (operationSignal) =>
                    custody.publish({
                        boundary: selectionCheckpointBoundary({
                            acceptedSetupSourceHash:
                                checkpointAcceptedSetupSourceHash,
                            ballotCandidateViewRoot:
                                checkpointBallotCandidateViewRoot,
                            selectionEntries: checkpointSelectionEntries,
                            stateStreamDescriptorBytes:
                                copiedStateStreamDescriptorBytes,
                        }) as BallotAggregationCheckpointBoundary,
                        identity: checkpointOperationIdentity,
                        signal: operationSignal,
                        stateChunks: [stateBytes],
                    }),
                (lateManifestBytes) => {
                    lateManifestBytes.fill(0);
                },
            );
            if (
                !isUint8Array(canonicalManifestBytes) ||
                canonicalManifestBytes.byteLength === 0 ||
                canonicalManifestBytes.byteLength >
                    foundationProfile.maximumCopiedBufferByteLength
            ) {
                checkpointLineageIdentifier.fill(0);
                throw new CanonicalStreamRefusalError('wrongTypeOrLength');
            }
            record.selectionFrozen = true;
            result = Object.freeze({
                canonicalManifestBytes: Uint8Array.from(canonicalManifestBytes),
                checkpointLineageIdentifier,
                stateStreamDescriptorBytes:
                    copiedStateStreamDescriptorBytes.slice(),
            });
        } finally {
            copiedStateStreamDescriptorBytes.fill(0);
        }
    } catch (error) {
        operationFailure = error;
    } finally {
        stateBytes.fill(0);
        checkpointAcceptedSetupSourceHash.fill(0);
        checkpointBallotCandidateViewRoot.fill(0);
        for (const entry of checkpointSelectionEntries) {
            entry.ballotObjectHash.fill(0);
        }
        if (identity !== undefined) {
            try {
                await releaseCheckpointOperationIdentity({
                    cancellationController: record.cancellationController,
                    context: record.context,
                    custody,
                    identity,
                    signal: record.options.signal,
                });
            } catch (cleanupFailure) {
                if (operationFailure !== undefined) {
                    operationFailure = new CanonicalStreamCleanupError(
                        operationFailure,
                        cleanupFailure,
                    );
                } else {
                    operationFailure = cleanupFailure;
                }
            }
        }
        if (verifiedBallotAggregationSessionRecords.get(session) === record) {
            record.operationInProgress = false;
        }
    }
    if (
        operationFailure === undefined &&
        (record.cancellationController.signal.aborted ||
            record.options.signal?.aborted === true)
    ) {
        operationFailure = new CanonicalStreamCancellationError();
    }
    if (operationFailure !== undefined) {
        const normalizedFailure =
            operationFailure instanceof Error
                ? operationFailure
                : new CanonicalStreamInternalError(
                      'The ballot-aggregation checkpoint publication failed with a non-error value.',
                      operationFailure,
                  );
        if (result !== undefined) {
            retireAggregationAfterCommittedCheckpoint(session, record);
            return result;
        }
        if (
            normalizedFailure instanceof CanonicalStreamCancellationError ||
            normalizedFailure instanceof CanonicalStreamCleanupError ||
            record.cancellationController.signal.aborted ||
            record.options.signal?.aborted === true
        ) {
            return retireFailedAggregation(session, record, normalizedFailure);
        }
        throw normalizedFailure;
    }
    if (result === undefined) {
        throw new CanonicalStreamInternalError(
            'The ballot-aggregation checkpoint publication returned no result.',
        );
    }
    return result;
};

const copyAggregateCarrierFromKernel = (
    record: VerifiedBallotAggregationSessionRecord,
): Uint8Array<ArrayBuffer> => {
    const memoryBoundary = new WasmMemoryBoundary({
        context: record.context,
        createInternalError: (message) =>
            new CanonicalStreamInternalError(message),
        createResourceError: (message) =>
            new CanonicalStreamResourceError(message),
        label: 'verified-ballot aggregate carrier boundary',
    });
    const statusBoundary = createStatusBoundary();
    return record.context.runExclusive(
        'verified-ballot aggregate carrier copy',
        () => {
            const statusPointer = memoryBoundary.allocateZeroedWords(1);
            let outputPointer = 0;
            let outputByteLength = 0;
            try {
                outputByteLength = record.kernel.aggregateCarrierByteLength(
                    record.handle,
                    statusPointer,
                );
                const [lengthStatus] = memoryBoundary.readWords(
                    statusPointer,
                    1,
                );
                statusBoundary.throwIfError(lengthStatus);
                memoryBoundary.validateAllocationByteLength(outputByteLength);
                outputPointer = memoryBoundary.allocate(outputByteLength);
                const copyStatus = record.kernel.copyAggregateCarrier(
                    record.handle,
                    outputPointer,
                    outputByteLength,
                );
                statusBoundary.throwIfError(copyStatus);
                return Uint8Array.from(
                    new Uint8Array(
                        record.context.memory.buffer,
                        outputPointer,
                        outputByteLength,
                    ),
                );
            } finally {
                memoryBoundary.zeroAndDeallocate(
                    outputPointer,
                    outputByteLength,
                );
                memoryBoundary.zeroAndDeallocate(
                    statusPointer,
                    wasm32WordByteLength,
                );
            }
        },
    );
};

const requirePreparedAggregateRecord = (
    preparedAggregate: PreparedVerifiedBallotAggregate,
): PreparedVerifiedBallotAggregateRecord => {
    if (
        (typeof preparedAggregate !== 'object' &&
            typeof preparedAggregate !== 'function') ||
        preparedAggregate === null
    ) {
        throw new CanonicalStreamRefusalError('consumedState');
    }
    const record =
        preparedVerifiedBallotAggregateRecords.get(preparedAggregate);
    if (record === undefined) {
        throw new CanonicalStreamRefusalError('consumedState');
    }
    return record;
};

const retirePreparedAggregate = (
    preparedAggregate: PreparedVerifiedBallotAggregate,
    record: PreparedVerifiedBallotAggregateRecord,
    releaseWorkerLease: boolean,
): void => {
    preparedVerifiedBallotAggregateRecords.delete(preparedAggregate);
    record.canonicalCarrier.fill(0);
    if (releaseWorkerLease) {
        retireVerifiedBallotEvaluationWorkerLease(
            record.context,
            record.cancellationController,
        );
    }
};

const cancelPreparedAggregate = (
    preparedAggregate: PreparedVerifiedBallotAggregate,
): void => {
    const record = requirePreparedAggregateRecord(preparedAggregate);
    record.cancellationController.abort();
    let invocationEntered = false;
    let status: number;
    try {
        status = record.context.runExclusive(
            'prepared verified-ballot aggregate cancellation',
            () => {
                invocationEntered = true;
                return record.kernel.cancel(record.handle);
            },
        );
    } finally {
        if (invocationEntered) {
            retirePreparedAggregate(preparedAggregate, record, true);
        }
    }
    createStatusBoundary().throwIfError(status);
};

const requireLiveAggregateRecord = (
    authority: VerifiedEvaluatorAggregateAuthority,
): VerifiedEvaluatorAggregateAuthorityRecord => {
    if (
        (typeof authority !== 'object' && typeof authority !== 'function') ||
        authority === null
    ) {
        throw new CanonicalStreamRefusalError('consumedState');
    }
    const record = verifiedEvaluatorAggregateAuthorityRecords.get(authority);
    if (record === undefined) {
        throw new CanonicalStreamRefusalError('consumedState');
    }
    return record;
};

const createVerifiedEvaluatorAggregateAuthority = (
    record: VerifiedEvaluatorAggregateAuthorityRecord,
): VerifiedEvaluatorAggregateAuthority => {
    const authority: VerifiedEvaluatorAggregateAuthority = Object.freeze({
        [verifiedEvaluatorAggregateAuthorityBrand]: true as const,
        release: (): void => {
            const liveRecord = requireLiveAggregateRecord(authority);
            const status = liveRecord.context.runExclusive(
                'verified evaluator aggregate release',
                () =>
                    liveRecord.kernel.discardVerifiedAggregate(
                        liveRecord.handle,
                    ),
            );
            createStatusBoundary().throwIfError(status);
            verifiedEvaluatorAggregateAuthorityRecords.delete(authority);
            retireVerifiedBallotEvaluationWorkerLease(
                liveRecord.context,
                liveRecord.cancellationController,
            );
        },
    });
    verifiedEvaluatorAggregateAuthorityRecords.set(authority, record);
    return authority;
};

const bindPreparedAggregate = (
    preparedAggregate: PreparedVerifiedBallotAggregate,
    verifiedAggregateObject: VerifiedTranscriptObject,
): VerifiedEvaluatorAggregateAuthority => {
    const record = requirePreparedAggregateRecord(preparedAggregate);
    throwIfCancelled(record.cancellationController, record.options.signal);
    const boardAuthorization =
        resolveVerifiedTranscriptObjectKernelAuthorization(
            verifiedAggregateObject,
            record.transcriptCoreKernel,
        );
    if (
        boardAuthorization.capabilityMemory !== record.context.memory ||
        boardAuthorization.capabilityPointer <= 0 ||
        boardAuthorization.capabilityPointer +
            boardVerifierCapabilityByteLength >
            record.context.memory.buffer.byteLength
    ) {
        throw new CanonicalStreamRefusalError('wrongContext');
    }
    const memoryBoundary = new WasmMemoryBoundary({
        context: record.context,
        createInternalError: (message) =>
            new CanonicalStreamInternalError(message),
        createResourceError: (message) =>
            new CanonicalStreamResourceError(message),
        label: 'verified-ballot aggregate board-binding boundary',
    });
    const statusPointer = memoryBoundary.allocateZeroedWords(1);
    let verifiedAggregateHandle = 0;
    try {
        verifiedAggregateHandle = record.context.runExclusive(
            'verified-ballot aggregate board binding',
            () =>
                record.kernel.bindAggregateObject(
                    record.handle,
                    boardAuthorization.sessionHandle,
                    boardAuthorization.capabilityPointer,
                    boardVerifierCapabilityByteLength,
                    boardAuthorization.objectHandle,
                    statusPointer,
                ),
        );
        const [status] = memoryBoundary.readWords(statusPointer, 1);
        createStatusBoundary().throwIfError(status);
        requireLiveHandle(
            verifiedAggregateHandle,
            'The verified evaluator aggregate authority handle',
        );
    } finally {
        memoryBoundary.zeroAndDeallocate(statusPointer, wasm32WordByteLength);
    }

    let authority: VerifiedEvaluatorAggregateAuthority;
    try {
        authority = createVerifiedEvaluatorAggregateAuthority({
            ...record,
            handle: verifiedAggregateHandle,
        });
    } catch (operationFailure) {
        let cleanupFailure: unknown;
        try {
            const status = record.context.runExclusive(
                'unwrapped verified aggregate cleanup',
                () =>
                    record.kernel.discardVerifiedAggregate(
                        verifiedAggregateHandle,
                    ),
            );
            createStatusBoundary().throwIfError(status);
        } catch (error) {
            cleanupFailure = error;
        }
        retirePreparedAggregate(preparedAggregate, record, true);
        if (cleanupFailure !== undefined) {
            throw new CanonicalStreamCleanupError(
                operationFailure,
                cleanupFailure,
            );
        }
        throw operationFailure;
    }
    retirePreparedAggregate(preparedAggregate, record, false);
    return authority;
};

const createPreparedAggregate = (
    record: PreparedVerifiedBallotAggregateRecord,
): PreparedVerifiedBallotAggregate => {
    const preparedAggregate: PreparedVerifiedBallotAggregate = Object.freeze({
        [preparedVerifiedBallotAggregateBrand]: true as const,
        bind: (verifiedAggregateObject) =>
            bindPreparedAggregate(preparedAggregate, verifiedAggregateObject),
        cancel: () => cancelPreparedAggregate(preparedAggregate),
        copyCanonicalCarrier: () =>
            Uint8Array.from(
                requirePreparedAggregateRecord(preparedAggregate)
                    .canonicalCarrier,
            ),
    });
    preparedVerifiedBallotAggregateRecords.set(preparedAggregate, record);
    return preparedAggregate;
};

const prepareAggregate = (
    session: VerifiedBallotAggregationSession,
): PreparedVerifiedBallotAggregate => {
    const record = requireLiveAggregationRecord(session);
    if (record.operationInProgress) {
        throw new CanonicalStreamResourceError(
            'The verified-ballot aggregation already has an operation in progress.',
        );
    }
    try {
        throwIfCancelled(record.cancellationController, record.options.signal);
        const status = record.context.runExclusive(
            'verified-ballot aggregate preparation',
            () => record.kernel.prepare(record.handle),
        );
        if (status !== 0) {
            record.rustStateLive = false;
        }
        createStatusBoundary().throwIfError(status);
        const canonicalCarrier = copyAggregateCarrierFromKernel(record);
        const preparedAggregate = createPreparedAggregate({
            cancellationController: record.cancellationController,
            canonicalCarrier,
            context: record.context,
            evaluatorKeyStore: record.evaluatorKeyStore,
            handle: record.handle,
            kernel: record.kernel,
            options: record.options,
            transcriptCoreKernel: record.transcriptCoreKernel,
        });
        verifiedBallotAggregationSessionRecords.delete(session);
        clearSelectionCheckpointState(record);
        return preparedAggregate;
    } catch (operationFailure) {
        return retireFailedAggregation(session, record, operationFailure);
    }
};

const createVerifiedBallotAggregationSession = (
    record: VerifiedBallotAggregationSessionRecord,
): VerifiedBallotAggregationSession => {
    const session: VerifiedBallotAggregationSession = Object.freeze({
        [verifiedBallotAggregationSessionBrand]: true as const,
        absorb: (input) => absorbVerifiedBallot(session, input),
        cancel: () => cancelAggregationSession(session),
        prepareAggregate: () => prepareAggregate(session),
        publishSelectionCheckpoint: (custody) =>
            publishSelectionCheckpoint(session, custody),
    });
    verifiedBallotAggregationSessionRecords.set(session, record);
    return session;
};

/** Internal borrow used only by evaluator begin in the same worker. */
export const requireVerifiedEvaluatorAggregateKernelAuthority = (
    authority: VerifiedEvaluatorAggregateAuthority,
): VerifiedEvaluatorAggregateKernelAuthority => {
    const record = requireLiveAggregateRecord(authority);
    return Object.freeze({
        cancellationController: record.cancellationController,
        context: record.context,
        evaluatorKeyStore: record.evaluatorKeyStore,
        handle: record.handle,
        kernel: record.transcriptCoreKernel,
        options: record.options,
    });
};

/** Retires browser custody after evaluator begin entered Rust. */
export const markVerifiedEvaluatorAggregateConsumedAfterKernelInvocation = (
    authority: VerifiedEvaluatorAggregateAuthority,
    kernel: TranscriptCoreKernel,
): void => {
    const record = requireLiveAggregateRecord(authority);
    if (record.transcriptCoreKernel !== kernel) {
        throw new CanonicalStreamRefusalError('wrongContext');
    }
    verifiedEvaluatorAggregateAuthorityRecords.delete(authority);
};

/**
 * Opens the one-shot ballot-product and evaluator-store pipeline in a dedicated
 * WASM worker. The authenticated source remains private to this custody chain.
 */
export const openVerifiedBallotAggregationInClosedWorker = (input: {
    acceptedSetupAuthority: VerifiedAcceptedSetupAuthority;
    ballotCandidateViewRoot: Uint8Array;
    evaluatorKeyStore: EvaluatorKeyStoreRangeSource;
    kernel: TranscriptCoreKernel;
    options?: BallotEvaluationWorkerOptions;
}): VerifiedBallotAggregationSession => {
    if (typeof globalThis.document !== 'undefined') {
        throw new CanonicalStreamInternalError(
            'Verified-ballot aggregation may only run inside the dedicated WASM worker.',
        );
    }
    if (
        typeof input.evaluatorKeyStore !== 'object' ||
        input.evaluatorKeyStore === null ||
        typeof input.evaluatorKeyStore.readExactRange !== 'function'
    ) {
        throw new CanonicalStreamRefusalError('wrongTypeOrLength');
    }
    if (input.options?.signal?.aborted === true) {
        throw new CanonicalStreamCancellationError();
    }
    const ballotCandidateViewRoot = copyFixedBytes(
        input.ballotCandidateViewRoot,
        hashByteLength,
    );
    const context = resolveCommonProofKernelContext(input.kernel);
    if (context === undefined) {
        ballotCandidateViewRoot.fill(0);
        throw new CanonicalStreamInternalError(
            'The loaded WASM kernel has no common-proof worker context.',
        );
    }
    try {
        requireReusableAggregationContext(context);
    } catch (error) {
        ballotCandidateViewRoot.fill(0);
        throw error;
    }
    if (activeAggregationContexts.has(context)) {
        ballotCandidateViewRoot.fill(0);
        throw new CanonicalStreamResourceError(
            'The WASM worker already retains a verified-ballot aggregation.',
        );
    }
    const acceptedSetupAuthority = (() => {
        try {
            return requireVerifiedAcceptedSetupAuthorityKernelOwner(
                input.acceptedSetupAuthority,
                input.kernel,
            );
        } catch (error) {
            ballotCandidateViewRoot.fill(0);
            throw error;
        }
    })();
    const kernel = requireBallotAggregationKernel(context);
    const memoryBoundary = new WasmMemoryBoundary({
        context,
        createInternalError: (message) =>
            new CanonicalStreamInternalError(message),
        createResourceError: (message) =>
            new CanonicalStreamResourceError(message),
        label: 'verified-ballot aggregation boundary',
    });
    const statusBoundary = createStatusBoundary();
    const statusPointer = memoryBoundary.allocateZeroedWords(1);
    let aggregationHandle = 0;
    try {
        aggregationHandle = context.runExclusive(
            'verified-ballot aggregation begin',
            () => kernel.begin(acceptedSetupAuthority.handle, statusPointer),
        );
        const [status] = memoryBoundary.readWords(statusPointer, 1);
        statusBoundary.throwIfError(status);
        requireLiveHandle(
            aggregationHandle,
            'The verified-ballot aggregation handle',
        );
    } catch (operationFailure) {
        ballotCandidateViewRoot.fill(0);
        if (aggregationHandle !== 0) {
            let cleanupFailure: unknown;
            try {
                const status = context.runExclusive(
                    'failed verified-ballot aggregation begin cleanup',
                    () => kernel.cancel(aggregationHandle),
                );
                statusBoundary.throwIfError(status);
            } catch (error) {
                cleanupFailure = error;
            }
            if (cleanupFailure !== undefined) {
                throw new CanonicalStreamCleanupError(
                    operationFailure,
                    cleanupFailure,
                );
            }
        }
        throw operationFailure;
    } finally {
        memoryBoundary.zeroAndDeallocate(statusPointer, wasm32WordByteLength);
    }

    const cancellationController = new AbortController();
    activeAggregationContexts.add(context);
    try {
        return createVerifiedBallotAggregationSession({
            ballotCandidateViewRoot,
            cancellationController,
            context,
            evaluatorKeyStore: input.evaluatorKeyStore,
            handle: aggregationHandle,
            kernel,
            operationInProgress: false,
            options: Object.freeze({
                observeEvaluatorKeyStoreRangeRead:
                    input.options?.observeEvaluatorKeyStoreRangeRead,
                signal: input.options?.signal,
                yieldControl: input.options?.yieldControl,
            }),
            rustStateLive: true,
            selectionEntries: [],
            selectionFrozen: false,
            transcriptCoreKernel: input.kernel,
        });
    } catch (operationFailure) {
        ballotCandidateViewRoot.fill(0);
        retireVerifiedBallotEvaluationWorkerLease(
            context,
            cancellationController,
        );
        let cleanupFailure: unknown;
        try {
            const status = context.runExclusive(
                'unwrapped verified-ballot aggregation cleanup',
                () => kernel.cancel(aggregationHandle),
            );
            statusBoundary.throwIfError(status);
        } catch (error) {
            cleanupFailure = error;
        }
        if (cleanupFailure !== undefined) {
            throw new CanonicalStreamCleanupError(
                operationFailure,
                cleanupFailure,
            );
        }
        throw operationFailure;
    }
};

/**
 * Authenticates a selection checkpoint, matches its supplied ballot-candidate
 * view root, positively rechecks the setup and selected ballots, then rebuilds
 * both product forests deterministically from ballot ordinal zero.
 */
export const resumeVerifiedBallotAggregationFromCheckpointInClosedWorker =
    async (input: {
        acceptedSetupSourceHash: Uint8Array;
        ballotCandidateViewRoot: Uint8Array;
        checkpointCustody: BallotAggregationCheckpointCustody;
        checkpointLineageIdentifier: Uint8Array;
        evaluatorKeyStore: EvaluatorKeyStoreRangeSource;
        expectedSelection: readonly BallotAggregationSelectionIdentity[];
        kernel: TranscriptCoreKernel;
        options?: BallotEvaluationWorkerOptions;
        replaySource: BallotAggregationCheckpointReplaySource;
    }): Promise<VerifiedBallotAggregationSession> => {
        if (typeof globalThis.document !== 'undefined') {
            throw new CanonicalStreamInternalError(
                'Verified-ballot aggregation may only resume inside the dedicated WASM worker.',
            );
        }
        if (
            typeof input.checkpointCustody !== 'object' ||
            input.checkpointCustody === null ||
            typeof input.checkpointCustody.resume !== 'function' ||
            typeof input.checkpointCustody.releaseOperationIdentity !==
                'function' ||
            typeof input.replaySource !== 'object' ||
            input.replaySource === null ||
            typeof input.replaySource.borrowPreflightAcceptedSetupSource !==
                'function' ||
            typeof input.replaySource.borrowPreflightSelectedBallot !==
                'function' ||
            typeof input.replaySource.reverifyAcceptedSetup !== 'function' ||
            typeof input.replaySource.reverifySelectedBallot !== 'function'
        ) {
            throw new CanonicalStreamRefusalError('wrongTypeOrLength');
        }
        if (input.options?.signal?.aborted === true) {
            throw new CanonicalStreamCancellationError();
        }
        const resumeContext = resolveCommonProofKernelContext(input.kernel);
        if (resumeContext === undefined) {
            throw new CanonicalStreamInternalError(
                'The loaded WASM kernel has no common-proof worker context.',
            );
        }
        requireReusableAggregationContext(resumeContext);

        const acceptedSetupSourceHash = copyFixedBytes(
            input.acceptedSetupSourceHash,
            hashByteLength,
        );
        const ballotCandidateViewRoot = copyFixedBytes(
            input.ballotCandidateViewRoot,
            hashByteLength,
        );
        const checkpointLineageIdentifier = copyFixedBytes(
            input.checkpointLineageIdentifier,
            checkpointLineageIdentifierByteLength,
        );
        const expectedSelection = copyOrderedSelection(input.expectedSelection);
        const resumeCancellationController = new AbortController();
        let resumedCheckpoint: ResumedBallotAggregationCheckpoint | undefined;
        let resumedOperationIdentity:
            | BallotAggregationCheckpointOperationIdentity
            | undefined;
        let operationIdentityReleaseStarted = false;
        let acceptedSetupAuthority: VerifiedAcceptedSetupAuthority | undefined;
        let aggregation: VerifiedBallotAggregationSession | undefined;
        let pendingVerifiedBallot: VerifiedBallotOutput | undefined;
        let operationFailure: unknown;
        let result: VerifiedBallotAggregationSession | undefined;
        try {
            throwIfCancelled(
                resumeCancellationController,
                input.options?.signal,
            );
            resumedCheckpoint = await awaitAbortableHostOperation(
                resumeCancellationController,
                input.options?.signal,
                resumeContext,
                (operationSignal) =>
                    input.checkpointCustody.resume({
                        checkpointLineageIdentifier,
                        expectedBoundary: selectionCheckpointBoundary({
                            acceptedSetupSourceHash,
                            ballotCandidateViewRoot,
                            selectionEntries: expectedSelection,
                        }),
                        signal: operationSignal,
                    }),
                async (lateCheckpoint) => {
                    try {
                        await input.checkpointCustody.releaseOperationIdentity(
                            lateCheckpoint.operationIdentity,
                        );
                    } finally {
                        lateCheckpoint.canonicalManifestBytes.fill(0);
                        lateCheckpoint.stateStreamDescriptorBytes.fill(0);
                    }
                },
            );
            if (
                typeof resumedCheckpoint !== 'object' ||
                resumedCheckpoint === null
            ) {
                throw new CanonicalStreamRefusalError('wrongTypeOrLength');
            }
            if (
                typeof resumedCheckpoint.operationIdentity !== 'object' ||
                resumedCheckpoint.operationIdentity === null
            ) {
                throw new CanonicalStreamRefusalError('wrongTypeOrLength');
            }
            resumedOperationIdentity = resumedCheckpoint.operationIdentity;
            if (
                typeof resumedCheckpoint.restoreState !== 'function' ||
                !isUint8Array(resumedCheckpoint.canonicalManifestBytes) ||
                resumedCheckpoint.canonicalManifestBytes.byteLength === 0 ||
                resumedCheckpoint.canonicalManifestBytes.byteLength >
                    foundationProfile.maximumCopiedBufferByteLength ||
                !isUint8Array(resumedCheckpoint.stateStreamDescriptorBytes) ||
                resumedCheckpoint.stateStreamDescriptorBytes.byteLength === 0 ||
                resumedCheckpoint.stateStreamDescriptorBytes.byteLength >
                    maximumBallotAggregationCheckpointStateByteLength
            ) {
                throw new CanonicalStreamRefusalError('wrongTypeOrLength');
            }
            const resumedLineageIdentifier = copyFixedBytes(
                resumedCheckpoint.operationIdentity.checkpointLineageIdentifier,
                checkpointLineageIdentifierByteLength,
            );
            try {
                if (
                    !bytesEqual(
                        resumedLineageIdentifier,
                        checkpointLineageIdentifier,
                    )
                ) {
                    throw new CanonicalStreamRefusalError('wrongContext');
                }
            } finally {
                resumedLineageIdentifier.fill(0);
            }
            const checkpointForRestore = resumedCheckpoint;
            const restoredChunks: Uint8Array<ArrayBuffer>[] = [];
            let restoredByteLength = 0;
            try {
                await awaitAbortableHostOperation(
                    resumeCancellationController,
                    input.options?.signal,
                    resumeContext,
                    (operationSignal) =>
                        checkpointForRestore.restoreState(
                            (chunkIndex, chunkBytes) => {
                                if (operationSignal.aborted) {
                                    if (isUint8Array(chunkBytes)) {
                                        chunkBytes.fill(0);
                                    }
                                    throw new CanonicalStreamCancellationError();
                                }
                                if (
                                    chunkIndex !== restoredChunks.length ||
                                    !isUint8Array(chunkBytes) ||
                                    chunkBytes.byteLength === 0 ||
                                    restoredByteLength + chunkBytes.byteLength >
                                        maximumBallotAggregationCheckpointStateByteLength
                                ) {
                                    if (isUint8Array(chunkBytes)) {
                                        chunkBytes.fill(0);
                                    }
                                    throw new CanonicalStreamRefusalError(
                                        'wrongTypeOrLength',
                                    );
                                }
                                const copiedChunk = Uint8Array.from(chunkBytes);
                                chunkBytes.fill(0);
                                restoredChunks.push(copiedChunk);
                                restoredByteLength += copiedChunk.byteLength;
                            },
                            operationSignal,
                        ),
                );
                if (restoredChunks.length === 0) {
                    throw new CanonicalStreamRefusalError('wrongTypeOrLength');
                }
                const restoredStateBytes = concatenateBytes(restoredChunks);
                try {
                    const decodedState =
                        decodeSelectionCheckpointState(restoredStateBytes);
                    try {
                        if (
                            !bytesEqual(
                                decodedState.acceptedSetupSourceHash,
                                acceptedSetupSourceHash,
                            ) ||
                            !bytesEqual(
                                decodedState.ballotCandidateViewRoot,
                                ballotCandidateViewRoot,
                            ) ||
                            decodedState.selectionEntries.length !==
                                expectedSelection.length ||
                            decodedState.selectionEntries.some(
                                (entry, index) =>
                                    !selectionIdentityMatches(
                                        entry,
                                        expectedSelection[index],
                                    ),
                            )
                        ) {
                            throw new CanonicalStreamRefusalError(
                                'wrongHashOrRoot',
                            );
                        }
                    } finally {
                        decodedState.acceptedSetupSourceHash.fill(0);
                        decodedState.ballotCandidateViewRoot.fill(0);
                        for (const entry of decodedState.selectionEntries) {
                            entry.ballotObjectHash.fill(0);
                        }
                    }
                } finally {
                    restoredStateBytes.fill(0);
                }
            } finally {
                for (const chunk of restoredChunks) {
                    chunk.fill(0);
                }
            }

            operationIdentityReleaseStarted = true;
            await releaseCheckpointOperationIdentity({
                cancellationController: resumeCancellationController,
                context: resumeContext,
                custody: input.checkpointCustody,
                identity: resumedOperationIdentity,
                signal: input.options?.signal,
            });

            throwIfCancelled(
                resumeCancellationController,
                input.options?.signal,
            );
            const preflightAcceptedSetupSourceHash =
                acceptedSetupSourceHash.slice();
            try {
                await awaitAbortableHostOperation(
                    resumeCancellationController,
                    input.options?.signal,
                    resumeContext,
                    (operationSignal) =>
                        input.replaySource.borrowPreflightAcceptedSetupSource(
                            preflightAcceptedSetupSourceHash,
                            operationSignal,
                        ),
                );
            } finally {
                preflightAcceptedSetupSourceHash.fill(0);
            }
            for (const selectionIdentity of expectedSelection) {
                const preflightIdentity =
                    copySelectionIdentity(selectionIdentity);
                try {
                    await awaitAbortableHostOperation(
                        resumeCancellationController,
                        input.options?.signal,
                        resumeContext,
                        (operationSignal) =>
                            input.replaySource.borrowPreflightSelectedBallot(
                                preflightIdentity,
                                operationSignal,
                            ),
                    );
                } finally {
                    preflightIdentity.ballotObjectHash.fill(0);
                }
            }

            acceptedSetupAuthority = await awaitAbortableHostOperation(
                resumeCancellationController,
                input.options?.signal,
                resumeContext,
                (operationSignal) =>
                    input.replaySource.reverifyAcceptedSetup(operationSignal),
                (lateAuthority) => lateAuthority.release(),
            );
            requireVerifiedAcceptedSetupAuthorityKernelOwner(
                acceptedSetupAuthority,
                input.kernel,
            );
            aggregation = openVerifiedBallotAggregationInClosedWorker({
                acceptedSetupAuthority,
                ballotCandidateViewRoot,
                evaluatorKeyStore: input.evaluatorKeyStore,
                kernel: input.kernel,
                options: input.options,
            });

            for (const selectionIdentity of expectedSelection) {
                const replayRequestIdentity =
                    copySelectionIdentity(selectionIdentity);
                try {
                    pendingVerifiedBallot = await awaitAbortableHostOperation(
                        resumeCancellationController,
                        input.options?.signal,
                        resumeContext,
                        (operationSignal) =>
                            input.replaySource.reverifySelectedBallot(
                                replayRequestIdentity,
                                operationSignal,
                            ),
                        (lateBallot) => lateBallot.release(),
                    );
                } finally {
                    replayRequestIdentity.ballotObjectHash.fill(0);
                }
                requireVerifiedBallotOutputKernelAuthority(
                    pendingVerifiedBallot,
                    input.kernel,
                );
                await aggregation.absorb({
                    verifiedBallot: pendingVerifiedBallot,
                });
                pendingVerifiedBallot = undefined;
                const replayedSelectionEntries =
                    requireLiveAggregationRecord(aggregation).selectionEntries;
                const replayedSelectionIdentity =
                    replayedSelectionEntries[
                        replayedSelectionEntries.length - 1
                    ];
                if (
                    replayedSelectionIdentity === undefined ||
                    !selectionIdentityMatches(
                        replayedSelectionIdentity,
                        selectionIdentity,
                    )
                ) {
                    throw new CanonicalStreamRefusalError('wrongContext');
                }
                if (acceptedSetupAuthority !== undefined) {
                    acceptedSetupAuthority.release();
                    acceptedSetupAuthority = undefined;
                }
            }
            const aggregationRecord = requireLiveAggregationRecord(aggregation);
            if (
                aggregationRecord.acceptedSetupSourceHash === undefined ||
                !bytesEqual(
                    aggregationRecord.acceptedSetupSourceHash,
                    acceptedSetupSourceHash,
                ) ||
                aggregationRecord.selectionEntries.length !==
                    expectedSelection.length ||
                aggregationRecord.selectionEntries.some(
                    (entry, index) =>
                        !selectionIdentityMatches(
                            entry,
                            expectedSelection[index],
                        ),
                )
            ) {
                throw new CanonicalStreamRefusalError('wrongContext');
            }
            aggregationRecord.selectionFrozen = true;
            result = aggregation;
            aggregation = undefined;
        } catch (error) {
            operationFailure = error;
        } finally {
            if (
                resumedOperationIdentity !== undefined &&
                !operationIdentityReleaseStarted
            ) {
                try {
                    await releaseCheckpointOperationIdentity({
                        cancellationController: resumeCancellationController,
                        context: resumeContext,
                        custody: input.checkpointCustody,
                        identity: resumedOperationIdentity,
                        signal: input.options?.signal,
                    });
                } catch (cleanupFailure) {
                    operationFailure =
                        operationFailure === undefined
                            ? cleanupFailure
                            : new CanonicalStreamCleanupError(
                                  operationFailure,
                                  cleanupFailure,
                              );
                }
            }
            resumeCancellationController.abort();
            if (pendingVerifiedBallot !== undefined) {
                try {
                    pendingVerifiedBallot.release();
                } catch (cleanupFailure) {
                    operationFailure =
                        operationFailure === undefined
                            ? cleanupFailure
                            : new CanonicalStreamCleanupError(
                                  operationFailure,
                                  cleanupFailure,
                              );
                }
            }
            if (aggregation !== undefined) {
                try {
                    aggregation.cancel();
                } catch (cleanupFailure) {
                    if (
                        !(cleanupFailure instanceof CanonicalStreamRefusalError)
                    ) {
                        operationFailure =
                            operationFailure === undefined
                                ? cleanupFailure
                                : new CanonicalStreamCleanupError(
                                      operationFailure,
                                      cleanupFailure,
                                  );
                    }
                }
            }
            if (acceptedSetupAuthority !== undefined) {
                try {
                    acceptedSetupAuthority.release();
                } catch (cleanupFailure) {
                    operationFailure =
                        operationFailure === undefined
                            ? cleanupFailure
                            : new CanonicalStreamCleanupError(
                                  operationFailure,
                                  cleanupFailure,
                              );
                }
            }
            acceptedSetupSourceHash.fill(0);
            ballotCandidateViewRoot.fill(0);
            checkpointLineageIdentifier.fill(0);
            for (const entry of expectedSelection) {
                entry.ballotObjectHash.fill(0);
            }
        }
        if (operationFailure !== undefined) {
            throw operationFailure instanceof Error
                ? operationFailure
                : new CanonicalStreamInternalError(
                      'The ballot-aggregation checkpoint resume failed with a non-error value.',
                      operationFailure,
                  );
        }
        if (result === undefined) {
            throw new CanonicalStreamInternalError(
                'The ballot-aggregation checkpoint resume returned no session.',
            );
        }
        return result;
    };
