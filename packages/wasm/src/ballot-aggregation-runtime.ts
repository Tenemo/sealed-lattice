import {
    markVerifiedBallotOutputConsumedAfterKernelSuccess,
    requireVerifiedBallotOutputKernelAuthority,
    type VerifiedBallotOutput,
} from './ballot-validity-runtime.js';
import {
    resolveVerifiedTranscriptObjectKernelAuthorization,
    type VerifiedTranscriptObject,
} from './canonical-board-runtime.js';
import {
    CanonicalStreamCleanupError,
    CanonicalStreamInternalError,
    CanonicalStreamRefusalError,
    CanonicalStreamResourceError,
} from './canonical-stream-runtime.js';
import { resolveCommonProofKernelContext } from './transcript-core-bridge/common-proof-kernel-context.js';
import type { TranscriptCoreKernelCommandRuntime } from './transcript-core-bridge/kernel-runtime.js';
import type { TranscriptCoreKernel } from './transcript-core-bridge/kernel-types.js';
import { WasmMemoryBoundary } from './wasm-memory-boundary.js';
import { WasmStatusBoundary } from './wasm-status-boundary.js';

const boardVerifierCapabilityByteLength = 32;
const maximumWasm32UnsignedInteger = 0xffff_ffff;
const wasm32WordByteLength = Uint32Array.BYTES_PER_ELEMENT;

type BallotAggregationKernel = Readonly<{
    absorb: NonNullable<
        TranscriptCoreKernelCommandRuntime['wasmExports']['sealed_lattice_ballot_aggregation_absorb']
    >;
    begin: NonNullable<
        TranscriptCoreKernelCommandRuntime['wasmExports']['sealed_lattice_ballot_aggregation_begin']
    >;
    cancel: NonNullable<
        TranscriptCoreKernelCommandRuntime['wasmExports']['sealed_lattice_ballot_aggregation_cancel']
    >;
    discardVerifiedAggregate: NonNullable<
        TranscriptCoreKernelCommandRuntime['wasmExports']['sealed_lattice_ballot_aggregation_discard_verified_aggregate']
    >;
    finish: NonNullable<
        TranscriptCoreKernelCommandRuntime['wasmExports']['sealed_lattice_ballot_aggregation_finish']
    >;
}>;

const verifiedBallotAggregationSessionBrand: unique symbol = Symbol(
    'sealed-lattice/verified-ballot-aggregation-session',
);
const verifiedEvaluatorAggregateAuthorityBrand: unique symbol = Symbol(
    'sealed-lattice/verified-evaluator-aggregate-authority',
);

/** Single-resident incremental aggregation in one dedicated WASM worker. */
export type VerifiedBallotAggregationSession = Readonly<{
    readonly [verifiedBallotAggregationSessionBrand]: true;
    absorb(verifiedBallot: VerifiedBallotOutput): void;
    cancel(): void;
    finish(
        verifiedAggregateObject: VerifiedTranscriptObject,
    ): VerifiedEvaluatorAggregateAuthority;
}>;

/** One verified aggregate retained exclusively inside its WASM worker. */
export type VerifiedEvaluatorAggregateAuthority = Readonly<{
    readonly [verifiedEvaluatorAggregateAuthorityBrand]: true;
    release(): void;
}>;

type VerifiedBallotAggregationSessionRecord = Readonly<{
    context: TranscriptCoreKernelCommandRuntime;
    handle: number;
    kernel: BallotAggregationKernel;
    transcriptCoreKernel: TranscriptCoreKernel;
}>;

type VerifiedEvaluatorAggregateAuthorityRecord = Readonly<{
    context: TranscriptCoreKernelCommandRuntime;
    handle: number;
    kernel: TranscriptCoreKernel;
}>;

export type VerifiedEvaluatorAggregateKernelAuthority = Readonly<{
    handle: number;
    kernel: TranscriptCoreKernel;
}>;

const verifiedBallotAggregationSessionRecords = new WeakMap<
    VerifiedBallotAggregationSession,
    VerifiedBallotAggregationSessionRecord
>();
const verifiedEvaluatorAggregateAuthorityRecords = new WeakMap<
    VerifiedEvaluatorAggregateAuthority,
    VerifiedEvaluatorAggregateAuthorityRecord
>();
const activeAggregationContexts = new WeakSet<object>();

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
        sealed_lattice_ballot_aggregation_begin: begin,
        sealed_lattice_ballot_aggregation_cancel: cancel,
        sealed_lattice_ballot_aggregation_discard_verified_aggregate:
            discardVerifiedAggregate,
        sealed_lattice_ballot_aggregation_finish: finish,
    } = context.wasmExports;
    if (
        typeof absorb !== 'function' ||
        typeof begin !== 'function' ||
        typeof cancel !== 'function' ||
        typeof discardVerifiedAggregate !== 'function' ||
        typeof finish !== 'function'
    ) {
        throw new CanonicalStreamInternalError(
            'The transcript-core kernel lacks the verified-ballot aggregation boundary.',
        );
    }
    return Object.freeze({
        absorb,
        begin,
        cancel,
        discardVerifiedAggregate,
        finish,
    });
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
    activeAggregationContexts.delete(record.context);
};

const cancelAggregationSession = (
    session: VerifiedBallotAggregationSession,
): void => {
    const record = requireLiveAggregationRecord(session);
    const statusBoundary = createStatusBoundary();
    let invocationEntered = false;
    let status: number;
    try {
        status = record.context.runExclusive(
            'verified-ballot aggregation cancellation',
            () => {
                invocationEntered = true;
                return record.kernel.cancel(record.handle);
            },
        );
    } finally {
        if (invocationEntered) {
            retireAggregationSession(session, record);
        }
    }
    statusBoundary.throwIfError(status);
};

const retireFailedAggregation = (
    session: VerifiedBallotAggregationSession,
    record: VerifiedBallotAggregationSessionRecord,
    operationFailure: unknown,
): never => {
    let cleanupFailure: unknown;
    try {
        const status = record.context.runExclusive(
            'failed verified-ballot aggregation cleanup',
            () => record.kernel.cancel(record.handle),
        );
        createStatusBoundary().throwIfError(status);
    } catch (error) {
        cleanupFailure = error;
    }
    retireAggregationSession(session, record);
    if (cleanupFailure !== undefined) {
        throw new CanonicalStreamCleanupError(operationFailure, cleanupFailure);
    }
    throw operationFailure;
};

const absorbVerifiedBallot = (
    session: VerifiedBallotAggregationSession,
    verifiedBallot: VerifiedBallotOutput,
): void => {
    const record = requireLiveAggregationRecord(session);
    const ballotAuthority = requireVerifiedBallotOutputKernelAuthority(
        verifiedBallot,
        record.transcriptCoreKernel,
    );
    const statusBoundary = createStatusBoundary();
    try {
        const status = record.context.runExclusive(
            'verified-ballot aggregation absorption',
            () => record.kernel.absorb(record.handle, ballotAuthority.handle),
        );
        statusBoundary.throwIfError(status);
        markVerifiedBallotOutputConsumedAfterKernelSuccess(
            verifiedBallot,
            record.transcriptCoreKernel,
        );
    } catch (operationFailure) {
        retireFailedAggregation(session, record, operationFailure);
    }
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
            const kernel = requireBallotAggregationKernel(liveRecord.context);
            const statusBoundary = createStatusBoundary();
            const status = liveRecord.context.runExclusive(
                'verified evaluator aggregate release',
                () => kernel.discardVerifiedAggregate(liveRecord.handle),
            );
            statusBoundary.throwIfError(status);
            verifiedEvaluatorAggregateAuthorityRecords.delete(authority);
        },
    });
    verifiedEvaluatorAggregateAuthorityRecords.set(authority, record);
    return authority;
};

const finishAggregationSession = (
    session: VerifiedBallotAggregationSession,
    verifiedAggregateObject: VerifiedTranscriptObject,
): VerifiedEvaluatorAggregateAuthority => {
    const record = requireLiveAggregationRecord(session);
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
        label: 'verified-ballot aggregate finalization boundary',
    });
    const statusBoundary = createStatusBoundary();
    const statusPointer = memoryBoundary.allocateZeroedWords(1);
    let invocationEntered = false;
    let verifiedAggregateHandle = 0;
    try {
        verifiedAggregateHandle = record.context.runExclusive(
            'verified-ballot aggregate finalization',
            () => {
                invocationEntered = true;
                return record.kernel.finish(
                    record.handle,
                    boardAuthorization.sessionHandle,
                    boardAuthorization.capabilityPointer,
                    boardVerifierCapabilityByteLength,
                    boardAuthorization.objectHandle,
                    statusPointer,
                );
            },
        );
        const [status] = memoryBoundary.readWords(statusPointer, 1);
        statusBoundary.throwIfError(status);
        requireLiveHandle(
            verifiedAggregateHandle,
            'The verified evaluator aggregate authority handle',
        );
    } finally {
        memoryBoundary.zeroAndDeallocate(statusPointer, wasm32WordByteLength);
        if (invocationEntered) {
            retireAggregationSession(session, record);
        }
    }

    try {
        return createVerifiedEvaluatorAggregateAuthority({
            context: record.context,
            handle: verifiedAggregateHandle,
            kernel: record.transcriptCoreKernel,
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

const createVerifiedBallotAggregationSession = (
    record: VerifiedBallotAggregationSessionRecord,
): VerifiedBallotAggregationSession => {
    const session: VerifiedBallotAggregationSession = Object.freeze({
        [verifiedBallotAggregationSessionBrand]: true as const,
        absorb: (verifiedBallot) =>
            absorbVerifiedBallot(session, verifiedBallot),
        cancel: () => cancelAggregationSession(session),
        finish: (verifiedAggregateObject) =>
            finishAggregationSession(session, verifiedAggregateObject),
    });
    verifiedBallotAggregationSessionRecords.set(session, record);
    return session;
};

/** Internal borrow used only by evaluator begin in the same worker. */
export const requireVerifiedEvaluatorAggregateKernelAuthority = (
    authority: VerifiedEvaluatorAggregateAuthority,
    kernel: TranscriptCoreKernel,
): VerifiedEvaluatorAggregateKernelAuthority => {
    const record = requireLiveAggregateRecord(authority);
    if (record.kernel !== kernel) {
        throw new CanonicalStreamRefusalError('wrongContext');
    }
    return Object.freeze({ handle: record.handle, kernel: record.kernel });
};

/**
 * Retires browser custody after evaluator begin entered Rust. The evaluator
 * registry takes the aggregate before any accepted-setup validation that may
 * refuse, so the wrapper must be retired even when that invocation returns a
 * nonzero status.
 */
export const markVerifiedEvaluatorAggregateConsumedAfterKernelInvocation = (
    authority: VerifiedEvaluatorAggregateAuthority,
    kernel: TranscriptCoreKernel,
): void => {
    const record = requireLiveAggregateRecord(authority);
    if (record.kernel !== kernel) {
        throw new CanonicalStreamRefusalError('wrongContext');
    }
    verifiedEvaluatorAggregateAuthorityRecords.delete(authority);
};

/**
 * Opens the sole incremental aggregate in one dedicated worker. Callers
 * verify and absorb one ballot at a time, matching the one-output ballot
 * verifier and retaining only Rust's running ciphertext sum.
 */
export const openVerifiedBallotAggregationInClosedWorker = (input: {
    kernel: TranscriptCoreKernel;
}): VerifiedBallotAggregationSession => {
    if (typeof globalThis.document !== 'undefined') {
        throw new CanonicalStreamInternalError(
            'Verified-ballot aggregation may only run inside the dedicated WASM worker.',
        );
    }
    const context = resolveCommonProofKernelContext(input.kernel);
    if (context === undefined) {
        throw new CanonicalStreamInternalError(
            'The loaded WASM kernel has no common-proof worker context.',
        );
    }
    if (activeAggregationContexts.has(context)) {
        throw new CanonicalStreamResourceError(
            'The WASM worker already retains a verified-ballot aggregation.',
        );
    }
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
            () => kernel.begin(statusPointer),
        );
        const [status] = memoryBoundary.readWords(statusPointer, 1);
        statusBoundary.throwIfError(status);
        requireLiveHandle(
            aggregationHandle,
            'The verified-ballot aggregation handle',
        );
    } catch (operationFailure) {
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

    activeAggregationContexts.add(context);
    return createVerifiedBallotAggregationSession({
        context,
        handle: aggregationHandle,
        kernel,
        transcriptCoreKernel: input.kernel,
    });
};
