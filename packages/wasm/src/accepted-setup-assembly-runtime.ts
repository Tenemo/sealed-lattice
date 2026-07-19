import { foundationProfile } from '@sealed-lattice/types';

import {
    createVerifiedAcceptedSetupAuthorityFromKernelHandle,
    type VerifiedAcceptedSetupAuthority,
} from './accepted-setup-verification-runtime.js';
import {
    markAggregateThresholdShareRecipientAuthorityConsumedAfterKernelSuccess,
    requireAggregateThresholdShareRecipientAuthorityKernelOwner,
    type AggregateThresholdShareRecipientAuthority,
} from './aggregate-threshold-share-authenticated-recipient.js';
import { isUint8Array } from './byte-array.js';
import {
    CanonicalStreamCleanupError,
    CanonicalStreamInternalError,
    CanonicalStreamRefusalError,
    CanonicalStreamResourceError,
} from './canonical-stream-runtime.js';
import {
    stateVerifierCapabilityByteLength,
    type VerifiedStateReservation,
} from './state-verifier-runtime/contracts.js';
import {
    prepareVerifiedStateReservationKernelTransaction,
    type PreparedVerifiedStateReservationKernelTransaction,
} from './state-verifier-runtime/runtime.js';
import { resolveCommonProofKernelContext } from './transcript-core-bridge/common-proof-kernel-context.js';
import type { TranscriptCoreKernelCommandRuntime } from './transcript-core-bridge/kernel-runtime.js';
import type {
    TranscriptCoreKernel,
    TranscriptCoreKernelExports,
} from './transcript-core-bridge/kernel-types.js';
import { WasmMemoryBoundary } from './wasm-memory-boundary.js';
import { WasmStatusBoundary } from './wasm-status-boundary.js';

const wasm32WordByteLength = 4;
const maximumWasm32UnsignedInteger = 0xffff_ffff;

type AcceptedSetupVerificationAssemblyExports = Required<
    Pick<
        TranscriptCoreKernelExports,
        | 'sealed_lattice_accepted_setup_authority_release'
        | 'sealed_lattice_accepted_setup_verification_cancel'
        | 'sealed_lattice_accepted_setup_verification_complete_evaluator_sources'
        | 'sealed_lattice_accepted_setup_verification_complete_public_proofs'
        | 'sealed_lattice_accepted_setup_verification_finalize'
    >
>;

type AcceptedSetupVerificationAssemblyContext =
    TranscriptCoreKernelCommandRuntime & {
        readonly wasmExports: TranscriptCoreKernelCommandRuntime['wasmExports'] &
            AcceptedSetupVerificationAssemblyExports;
    };

type AcceptedSetupEvaluatorSourceCatalogExports = Required<
    Pick<
        TranscriptCoreKernelExports,
        | 'sealed_lattice_accepted_setup_verification_transfer_prepackage_evaluator_sources'
        | 'sealed_lattice_prepackage_evaluator_generated_proofs_bind_package'
        | 'sealed_lattice_prepackage_evaluator_source_catalog_begin'
        | 'sealed_lattice_prepackage_evaluator_source_catalog_cancel'
        | 'sealed_lattice_prepackage_evaluator_source_catalog_complete'
    >
>;

type AcceptedSetupEvaluatorSourceCatalogContext =
    TranscriptCoreKernelCommandRuntime & {
        readonly wasmExports: TranscriptCoreKernelCommandRuntime['wasmExports'] &
            AcceptedSetupEvaluatorSourceCatalogExports;
    };

type AcceptedSetupVerificationAssemblyPhase =
    | 'collecting'
    | 'evaluatorSourcesComplete'
    | 'publicProofsComplete';

const acceptedSetupVerificationSessionBrand = Symbol(
    'accepted-setup verification session',
);
const acceptedSetupEvaluatorSourceCatalogSessionBrand = Symbol(
    'accepted-setup evaluator-source catalog session',
);
const acceptedSetupEvaluatorComponentBackingBrand = Symbol(
    'accepted-setup evaluator component backing',
);

/** Browser-worker custody of one exact accepted-setup verification assembly. */
export type AcceptedSetupVerificationSession = Readonly<{
    readonly [acceptedSetupVerificationSessionBrand]: true;
    cancel(): void;
    completeEvaluatorSources(): void;
    completePublicProofs(): void;
    finalize(input: {
        orderedCommitmentReservations: readonly VerifiedStateReservation[];
        terminalPackageReservations: readonly VerifiedStateReservation[];
    }): VerifiedAcceptedSetupAuthority;
}>;

/** Browser-worker custody of verified evaluator sources before package finalization. */
export type AcceptedSetupEvaluatorSourceCatalogSession = Readonly<{
    readonly [acceptedSetupEvaluatorSourceCatalogSessionBrand]: true;
    cancel(): void;
    complete(): void;
    transferTo(
        acceptedSetupVerification: AcceptedSetupVerificationSession,
    ): void;
}>;

/** Internal same-worker custody of one positively verified component carrier. */
export type AcceptedSetupEvaluatorComponentBacking = Readonly<{
    readonly [acceptedSetupEvaluatorComponentBackingBrand]: true;
}>;

type AcceptedSetupEvaluatorComponentBackingRecord = {
    readonly authenticatedByteLength: bigint;
    readonly fullObjectDigestHex: string;
    readonly kernel: TranscriptCoreKernel;
    readonly materialRootHex: string;
    readonly readExactRange: (
        sourceByteOffset: bigint,
        exactByteLength: number,
    ) => Promise<Uint8Array<ArrayBuffer>>;
    readonly release: () => void;
    retained: boolean;
    released: boolean;
};

type AcceptedSetupVerificationSessionRecord = {
    readonly context: AcceptedSetupVerificationAssemblyContext;
    evaluatorComponentBackings: Map<
        string,
        AcceptedSetupEvaluatorComponentBacking
    >;
    readonly handle: number;
    readonly kernel: TranscriptCoreKernel;
    readonly vssRecipientAuthority: AggregateThresholdShareRecipientAuthority;
    phase: AcceptedSetupVerificationAssemblyPhase;
};

type AcceptedSetupEvaluatorSourceCatalogSessionRecord = {
    readonly context: AcceptedSetupEvaluatorSourceCatalogContext;
    readonly handle: number;
    readonly kernel: TranscriptCoreKernel;
    readonly vssRecipientAuthority: AggregateThresholdShareRecipientAuthority;
    evaluatorComponentBackings: Map<
        string,
        AcceptedSetupEvaluatorComponentBacking
    >;
    phase: 'collecting' | 'complete';
};

const sessionRecords = new WeakMap<
    AcceptedSetupVerificationSession,
    AcceptedSetupVerificationSessionRecord
>();

const evaluatorSourceCatalogSessionRecords = new WeakMap<
    AcceptedSetupEvaluatorSourceCatalogSession,
    AcceptedSetupEvaluatorSourceCatalogSessionRecord
>();

const evaluatorComponentBackingRecords = new WeakMap<
    AcceptedSetupEvaluatorComponentBacking,
    AcceptedSetupEvaluatorComponentBackingRecord
>();

const fixedHashByteLength = 64;

const bytesToStableHex = (bytes: Uint8Array): string =>
    Array.from(bytes, (value) => value.toString(16).padStart(2, '0')).join('');

const requireFixedHashHex = (value: Uint8Array, label: string): string => {
    if (
        !isUint8Array(value) ||
        !(value.buffer instanceof ArrayBuffer) ||
        value.byteLength !== fixedHashByteLength
    ) {
        throw new TypeError(`${label} must contain exactly 64 owned bytes.`);
    }
    return bytesToStableHex(value);
};

const requireEvaluatorComponentBackingRecord = (
    backing: AcceptedSetupEvaluatorComponentBacking,
    kernel: TranscriptCoreKernel,
): AcceptedSetupEvaluatorComponentBackingRecord => {
    const record = evaluatorComponentBackingRecords.get(backing);
    if (record === undefined || record.kernel !== kernel || record.released) {
        throw new CanonicalStreamRefusalError('consumedState');
    }
    return record;
};

const releaseEvaluatorComponentBacking = (
    backing: AcceptedSetupEvaluatorComponentBacking,
): void => {
    const record = evaluatorComponentBackingRecords.get(backing);
    if (record === undefined || record.released) {
        return;
    }
    record.release();
    record.released = true;
    evaluatorComponentBackingRecords.delete(backing);
};

const releaseEvaluatorComponentBackingMap = (
    backings: Map<string, AcceptedSetupEvaluatorComponentBacking>,
): void => {
    let firstFailure: unknown;
    for (const backing of backings.values()) {
        try {
            releaseEvaluatorComponentBacking(backing);
        } catch (error) {
            firstFailure ??= error;
        }
    }
    backings.clear();
    if (firstFailure !== undefined) {
        throw firstFailure instanceof Error
            ? firstFailure
            : new CanonicalStreamInternalError(
                  'The evaluator component backing release failed.',
                  firstFailure,
              );
    }
};

export type AcceptedSetupVerificationAssemblyKernelOwner = Readonly<{
    handle: number;
    kernel: TranscriptCoreKernel;
}>;

export type AcceptedSetupEvaluatorSourceCatalogKernelOwner = Readonly<{
    handle: number;
    kernel: TranscriptCoreKernel;
}>;

const createStatusBoundary = (): WasmStatusBoundary =>
    new WasmStatusBoundary({
        createInternalError: (message) =>
            new CanonicalStreamInternalError(message),
        createRefusalError: (refusalReason) =>
            new CanonicalStreamRefusalError(refusalReason),
        createResourceError: () => new CanonicalStreamResourceError(),
        internalFailureMessage:
            'The accepted-setup verification assembly failed internally.',
        unknownStatusMessage:
            'The accepted-setup verification assembly returned an unknown status code.',
    });

const requireWasm32Handle = (value: number, label: string): number => {
    if (
        !Number.isSafeInteger(value) ||
        value <= 0 ||
        value > maximumWasm32UnsignedInteger
    ) {
        throw new CanonicalStreamInternalError(`${label} is invalid.`);
    }
    return value;
};

const requireAssemblyContext = (
    kernel: TranscriptCoreKernel,
): AcceptedSetupVerificationAssemblyContext => {
    const context = resolveCommonProofKernelContext(kernel);
    const wasmExports = context?.wasmExports;
    if (
        context === undefined ||
        wasmExports === undefined ||
        typeof wasmExports.sealed_lattice_accepted_setup_authority_release !==
            'function' ||
        typeof wasmExports.sealed_lattice_accepted_setup_verification_cancel !==
            'function' ||
        typeof wasmExports.sealed_lattice_accepted_setup_verification_complete_evaluator_sources !==
            'function' ||
        typeof wasmExports.sealed_lattice_accepted_setup_verification_complete_public_proofs !==
            'function' ||
        typeof wasmExports.sealed_lattice_accepted_setup_verification_finalize !==
            'function'
    ) {
        throw new CanonicalStreamInternalError(
            'The transcript-core kernel lacks the accepted-setup verification assembly boundary.',
        );
    }
    return context as AcceptedSetupVerificationAssemblyContext;
};

const requireEvaluatorSourceCatalogContext = (
    kernel: TranscriptCoreKernel,
): AcceptedSetupEvaluatorSourceCatalogContext => {
    const context = resolveCommonProofKernelContext(kernel);
    const wasmExports = context?.wasmExports;
    if (
        context === undefined ||
        wasmExports === undefined ||
        typeof wasmExports.sealed_lattice_prepackage_evaluator_source_catalog_begin !==
            'function' ||
        typeof wasmExports.sealed_lattice_prepackage_evaluator_source_catalog_complete !==
            'function' ||
        typeof wasmExports.sealed_lattice_prepackage_evaluator_source_catalog_cancel !==
            'function' ||
        typeof wasmExports.sealed_lattice_prepackage_evaluator_generated_proofs_bind_package !==
            'function' ||
        typeof wasmExports.sealed_lattice_accepted_setup_verification_transfer_prepackage_evaluator_sources !==
            'function'
    ) {
        throw new CanonicalStreamInternalError(
            'The transcript-core kernel lacks the prepackage evaluator-source catalog boundary.',
        );
    }
    return context as AcceptedSetupEvaluatorSourceCatalogContext;
};

const requireSessionRecord = (
    session: AcceptedSetupVerificationSession,
): AcceptedSetupVerificationSessionRecord => {
    if (
        (typeof session !== 'object' && typeof session !== 'function') ||
        session === null
    ) {
        throw new TypeError(
            'The accepted-setup verification session was not issued by this WASM runtime.',
        );
    }
    const record = sessionRecords.get(session);
    if (record === undefined) {
        throw new TypeError(
            'The accepted-setup verification session is unavailable or already consumed.',
        );
    }
    return record;
};

const requireEvaluatorSourceCatalogSessionRecord = (
    session: AcceptedSetupEvaluatorSourceCatalogSession,
): AcceptedSetupEvaluatorSourceCatalogSessionRecord => {
    if (
        (typeof session !== 'object' && typeof session !== 'function') ||
        session === null
    ) {
        throw new TypeError(
            'The evaluator-source catalog session was not issued by this WASM runtime.',
        );
    }
    const record = evaluatorSourceCatalogSessionRecords.get(session);
    if (record === undefined) {
        throw new TypeError(
            'The evaluator-source catalog session is unavailable or already consumed.',
        );
    }
    return record;
};

const requirePhase = (
    record: AcceptedSetupVerificationSessionRecord,
    expectedPhase: AcceptedSetupVerificationAssemblyPhase,
): void => {
    if (record.phase !== expectedPhase) {
        throw new CanonicalStreamRefusalError('consumedState');
    }
};

const encodeHandles = (handles: readonly number[]): Uint8Array<ArrayBuffer> => {
    const bytes = new Uint8Array(handles.length * wasm32WordByteLength);
    const view = new DataView(bytes.buffer);
    handles.forEach((handle, handleIndex) => {
        view.setUint32(
            handleIndex * wasm32WordByteLength,
            requireWasm32Handle(handle, 'A state reservation handle'),
            true,
        );
    });
    return bytes;
};

const cancelSession = (session: AcceptedSetupVerificationSession): void => {
    const record = requireSessionRecord(session);
    const statusBoundary = createStatusBoundary();
    const status = record.context.runExclusive(
        'accepted-setup verification assembly cancellation',
        () =>
            record.context.wasmExports.sealed_lattice_accepted_setup_verification_cancel(
                record.handle,
            ),
    );
    statusBoundary.throwIfError(status);
    sessionRecords.delete(session);
    releaseEvaluatorComponentBackingMap(record.evaluatorComponentBackings);
};

const cancelEvaluatorSourceCatalogSession = (
    session: AcceptedSetupEvaluatorSourceCatalogSession,
): void => {
    const record = requireEvaluatorSourceCatalogSessionRecord(session);
    const status = record.context.runExclusive(
        'prepackage evaluator-source catalog cancellation',
        () =>
            record.context.wasmExports.sealed_lattice_prepackage_evaluator_source_catalog_cancel(
                record.handle,
            ),
    );
    createStatusBoundary().throwIfError(status);
    evaluatorSourceCatalogSessionRecords.delete(session);
    releaseEvaluatorComponentBackingMap(record.evaluatorComponentBackings);
};

const completeEvaluatorSourceCatalogSession = (
    session: AcceptedSetupEvaluatorSourceCatalogSession,
): void => {
    const record = requireEvaluatorSourceCatalogSessionRecord(session);
    if (record.phase !== 'collecting') {
        throw new CanonicalStreamRefusalError('consumedState');
    }
    const status = record.context.runExclusive(
        'prepackage evaluator-source catalog completion',
        () =>
            record.context.wasmExports.sealed_lattice_prepackage_evaluator_source_catalog_complete(
                record.handle,
            ),
    );
    createStatusBoundary().throwIfError(status);
    record.phase = 'complete';
};

const transferEvaluatorSourceCatalogSession = (
    session: AcceptedSetupEvaluatorSourceCatalogSession,
    acceptedSetupVerification: AcceptedSetupVerificationSession,
): void => {
    const catalogRecord = requireEvaluatorSourceCatalogSessionRecord(session);
    if (catalogRecord.phase !== 'complete') {
        throw new CanonicalStreamRefusalError('consumedState');
    }
    const assemblyRecord = requireSessionRecord(acceptedSetupVerification);
    requirePhase(assemblyRecord, 'collecting');
    if (
        assemblyRecord.kernel !== catalogRecord.kernel ||
        assemblyRecord.vssRecipientAuthority !==
            catalogRecord.vssRecipientAuthority ||
        assemblyRecord.evaluatorComponentBackings.size !== 0
    ) {
        throw new CanonicalStreamRefusalError('wrongContext');
    }
    const status = catalogRecord.context.runExclusive(
        'prepackage evaluator-source catalog transfer',
        () =>
            catalogRecord.context.wasmExports.sealed_lattice_accepted_setup_verification_transfer_prepackage_evaluator_sources(
                assemblyRecord.handle,
                catalogRecord.handle,
            ),
    );
    createStatusBoundary().throwIfError(status);
    assemblyRecord.evaluatorComponentBackings =
        catalogRecord.evaluatorComponentBackings;
    catalogRecord.evaluatorComponentBackings = new Map();
    evaluatorSourceCatalogSessionRecords.delete(session);
};

/**
 * Atomically binds every generated evaluator-source proof to the canonical
 * package slots held by the exact accepted-setup assembly. A refusal consumes
 * neither session and remains retryable.
 */
export const bindAcceptedSetupEvaluatorGeneratedProofsToPackage = (input: {
    acceptedSetupVerification: AcceptedSetupVerificationSession;
    catalog: AcceptedSetupEvaluatorSourceCatalogSession;
    kernel: TranscriptCoreKernel;
}): void => {
    const catalogRecord = requireEvaluatorSourceCatalogSessionRecord(
        input.catalog,
    );
    const assemblyRecord = requireSessionRecord(
        input.acceptedSetupVerification,
    );
    if (
        catalogRecord.kernel !== input.kernel ||
        assemblyRecord.kernel !== input.kernel ||
        catalogRecord.phase !== 'collecting' ||
        assemblyRecord.phase !== 'collecting' ||
        catalogRecord.vssRecipientAuthority !==
            assemblyRecord.vssRecipientAuthority
    ) {
        throw new CanonicalStreamRefusalError('wrongContext');
    }
    const status = catalogRecord.context.runExclusive(
        'prepackage generated-proof package binding',
        () =>
            catalogRecord.context.wasmExports.sealed_lattice_prepackage_evaluator_generated_proofs_bind_package(
                assemblyRecord.handle,
                catalogRecord.handle,
            ),
    );
    createStatusBoundary().throwIfError(status);
};

const completeEvaluatorSources = (
    session: AcceptedSetupVerificationSession,
): void => {
    const record = requireSessionRecord(session);
    requirePhase(record, 'collecting');
    const status = record.context.runExclusive(
        'accepted-setup evaluator-source completion',
        () =>
            record.context.wasmExports.sealed_lattice_accepted_setup_verification_complete_evaluator_sources(
                record.handle,
            ),
    );
    createStatusBoundary().throwIfError(status);
    record.phase = 'evaluatorSourcesComplete';
};

const completePublicProofs = (
    session: AcceptedSetupVerificationSession,
): void => {
    const record = requireSessionRecord(session);
    requirePhase(record, 'evaluatorSourcesComplete');
    const status = record.context.runExclusive(
        'accepted-setup public-proof completion',
        () =>
            record.context.wasmExports.sealed_lattice_accepted_setup_verification_complete_public_proofs(
                record.handle,
            ),
    );
    createStatusBoundary().throwIfError(status);
    record.phase = 'publicProofsComplete';
};

const requireReservationCounts = (input: {
    orderedCommitmentReservations: readonly VerifiedStateReservation[];
    terminalPackageReservations: readonly VerifiedStateReservation[];
}): void => {
    if (
        !Array.isArray(input.orderedCommitmentReservations) ||
        input.orderedCommitmentReservations.length !==
            foundationProfile.participantCount ||
        !Array.isArray(input.terminalPackageReservations) ||
        input.terminalPackageReservations.length <
            foundationProfile.finalityQuorum ||
        input.terminalPackageReservations.length >
            foundationProfile.participantCount
    ) {
        throw new CanonicalStreamRefusalError('wrongTypeOrLength');
    }
};

const requireStateTransactionMemory = (
    record: AcceptedSetupVerificationSessionRecord,
    transaction: PreparedVerifiedStateReservationKernelTransaction,
): void => {
    if (
        transaction.capabilityMemory !== record.context.memory ||
        transaction.capabilityPointer <= 0 ||
        transaction.capabilityPointer + stateVerifierCapabilityByteLength >
            record.context.memory.buffer.byteLength
    ) {
        throw new CanonicalStreamRefusalError('wrongContext');
    }
};

const retireSuccessfulFinalizationSources = (input: {
    record: AcceptedSetupVerificationSessionRecord;
    session: AcceptedSetupVerificationSession;
    transaction: PreparedVerifiedStateReservationKernelTransaction;
}): void => {
    input.transaction.commitAfterKernelSuccess();
    markAggregateThresholdShareRecipientAuthorityConsumedAfterKernelSuccess(
        input.record.vssRecipientAuthority,
        input.record.kernel,
    );
    sessionRecords.delete(input.session);
};

const releaseUnwrappedAuthority = (
    record: AcceptedSetupVerificationSessionRecord,
    authorityHandle: number,
): void => {
    const status = record.context.runExclusive(
        'unwrapped accepted-setup authority release',
        () =>
            record.context.wasmExports.sealed_lattice_accepted_setup_authority_release(
                authorityHandle,
            ),
    );
    createStatusBoundary().throwIfError(status);
};

const finalizeSession = (
    session: AcceptedSetupVerificationSession,
    input: {
        orderedCommitmentReservations: readonly VerifiedStateReservation[];
        terminalPackageReservations: readonly VerifiedStateReservation[];
    },
): VerifiedAcceptedSetupAuthority => {
    const record = requireSessionRecord(session);
    requirePhase(record, 'publicProofsComplete');
    requireReservationCounts(input);
    requireAggregateThresholdShareRecipientAuthorityKernelOwner(
        record.vssRecipientAuthority,
        record.kernel,
    );

    const orderedReservations = [
        ...input.orderedCommitmentReservations,
        ...input.terminalPackageReservations,
    ];
    const transaction = prepareVerifiedStateReservationKernelTransaction({
        kernel: record.kernel,
        reservations: orderedReservations,
    });
    requireStateTransactionMemory(record, transaction);

    const commitmentHandleCount = input.orderedCommitmentReservations.length;
    const commitmentHandleBytes = encodeHandles(
        transaction.reservationHandles.slice(0, commitmentHandleCount),
    );
    const terminalPackageHandleBytes = encodeHandles(
        transaction.reservationHandles.slice(commitmentHandleCount),
    );
    const memoryBoundary = new WasmMemoryBoundary({
        context: record.context,
        createInternalError: (message) =>
            new CanonicalStreamInternalError(message),
        createResourceError: (message) =>
            new CanonicalStreamResourceError(message),
        label: 'accepted-setup finalization',
    });
    const statusBoundary = createStatusBoundary();
    let commitmentHandlesPointer = 0;
    let terminalPackageHandlesPointer = 0;
    let statusPointer = 0;
    let authorityHandle = 0;
    let kernelFinalizationSucceeded = false;
    try {
        commitmentHandlesPointer = memoryBoundary.copy(commitmentHandleBytes);
        terminalPackageHandlesPointer = memoryBoundary.copy(
            terminalPackageHandleBytes,
        );
        statusPointer = memoryBoundary.allocateZeroedWords(1);
        authorityHandle = record.context.runExclusive(
            'accepted-setup verification finalization',
            () =>
                record.context.wasmExports.sealed_lattice_accepted_setup_verification_finalize(
                    record.handle,
                    transaction.sessionHandle,
                    transaction.capabilityPointer,
                    stateVerifierCapabilityByteLength,
                    commitmentHandlesPointer,
                    commitmentHandleBytes.byteLength,
                    terminalPackageHandlesPointer,
                    terminalPackageHandleBytes.byteLength,
                    statusPointer,
                ),
        );
        const [status] = memoryBoundary.readWords(statusPointer, 1);
        statusBoundary.throwIfError(status);
        kernelFinalizationSucceeded = true;
        requireWasm32Handle(
            authorityHandle,
            'The verified accepted-setup authority handle',
        );
    } catch (operationFailure) {
        if (authorityHandle !== 0) {
            try {
                releaseUnwrappedAuthority(record, authorityHandle);
            } catch (cleanupFailure) {
                if (kernelFinalizationSucceeded) {
                    retireSuccessfulFinalizationSources({
                        record,
                        session,
                        transaction,
                    });
                }
                throw new CanonicalStreamCleanupError(
                    operationFailure,
                    cleanupFailure,
                );
            }
        }
        if (kernelFinalizationSucceeded) {
            retireSuccessfulFinalizationSources({
                record,
                session,
                transaction,
            });
        }
        throw operationFailure;
    } finally {
        memoryBoundary.zeroAndDeallocate(statusPointer, wasm32WordByteLength);
        memoryBoundary.zeroAndDeallocate(
            terminalPackageHandlesPointer,
            terminalPackageHandleBytes.byteLength,
        );
        memoryBoundary.zeroAndDeallocate(
            commitmentHandlesPointer,
            commitmentHandleBytes.byteLength,
        );
    }

    let authority: VerifiedAcceptedSetupAuthority;
    try {
        authority = createVerifiedAcceptedSetupAuthorityFromKernelHandle({
            handle: authorityHandle,
            kernel: record.kernel,
        });
    } catch (operationFailure) {
        let cleanupFailure: unknown;
        try {
            releaseUnwrappedAuthority(record, authorityHandle);
        } catch (error) {
            cleanupFailure = error;
        }
        retireSuccessfulFinalizationSources({
            record,
            session,
            transaction,
        });
        if (cleanupFailure !== undefined) {
            throw new CanonicalStreamCleanupError(
                operationFailure,
                cleanupFailure,
            );
        }
        throw operationFailure;
    }
    retireSuccessfulFinalizationSources({ record, session, transaction });
    return authority;
};

const createSession = (
    record: AcceptedSetupVerificationSessionRecord,
): AcceptedSetupVerificationSession => {
    const session: AcceptedSetupVerificationSession = Object.freeze({
        [acceptedSetupVerificationSessionBrand]: true as const,
        cancel: (): void => cancelSession(session),
        completeEvaluatorSources: (): void => completeEvaluatorSources(session),
        completePublicProofs: (): void => completePublicProofs(session),
        finalize: (input): VerifiedAcceptedSetupAuthority =>
            finalizeSession(session, input),
    });
    sessionRecords.set(session, record);
    return session;
};

const createEvaluatorSourceCatalogSession = (
    record: AcceptedSetupEvaluatorSourceCatalogSessionRecord,
): AcceptedSetupEvaluatorSourceCatalogSession => {
    const session: AcceptedSetupEvaluatorSourceCatalogSession = Object.freeze({
        [acceptedSetupEvaluatorSourceCatalogSessionBrand]: true as const,
        cancel: (): void => cancelEvaluatorSourceCatalogSession(session),
        complete: (): void => completeEvaluatorSourceCatalogSession(session),
        transferTo: (acceptedSetupVerification): void =>
            transferEvaluatorSourceCatalogSession(
                session,
                acceptedSetupVerification,
            ),
    });
    evaluatorSourceCatalogSessionRecords.set(session, record);
    return session;
};

/**
 * Adopts an assembly handle minted by another exact Rust-owned package ingress.
 * The handle remains opaque and the completed VSS authority stays bound to the
 * same worker for finalization.
 */
export const adoptAcceptedSetupVerificationAssemblyFromKernelHandle = (input: {
    assemblyHandle: number;
    kernel: TranscriptCoreKernel;
    vssRecipientAuthority: AggregateThresholdShareRecipientAuthority;
}): AcceptedSetupVerificationSession => {
    const context = requireAssemblyContext(input.kernel);
    requireAggregateThresholdShareRecipientAuthorityKernelOwner(
        input.vssRecipientAuthority,
        input.kernel,
    );
    return createSession({
        context,
        evaluatorComponentBackings: new Map(),
        handle: requireWasm32Handle(
            input.assemblyHandle,
            'The accepted-setup verification assembly handle',
        ),
        kernel: input.kernel,
        phase: 'collecting',
        vssRecipientAuthority: input.vssRecipientAuthority,
    });
};

/** Begins a non-serializable catalog from the completed VSS authority. */
export const beginAcceptedSetupEvaluatorSourceCatalog = (input: {
    kernel: TranscriptCoreKernel;
    vssRecipientAuthority: AggregateThresholdShareRecipientAuthority;
}): AcceptedSetupEvaluatorSourceCatalogSession => {
    const context = requireEvaluatorSourceCatalogContext(input.kernel);
    const vssAuthorityOwner =
        requireAggregateThresholdShareRecipientAuthorityKernelOwner(
            input.vssRecipientAuthority,
            input.kernel,
        );
    const memoryBoundary = new WasmMemoryBoundary({
        context,
        createInternalError: (message) =>
            new CanonicalStreamInternalError(message),
        createResourceError: (message) =>
            new CanonicalStreamResourceError(message),
        label: 'prepackage evaluator-source catalog',
    });
    const statusBoundary = createStatusBoundary();
    let statusPointer = 0;
    let catalogHandle = 0;
    try {
        statusPointer = memoryBoundary.allocateZeroedWords(1);
        catalogHandle = context.runExclusive(
            'prepackage evaluator-source catalog begin',
            () =>
                context.wasmExports.sealed_lattice_prepackage_evaluator_source_catalog_begin(
                    vssAuthorityOwner.handle,
                    statusPointer,
                ),
        );
        const [status] = memoryBoundary.readWords(statusPointer, 1);
        statusBoundary.throwIfError(status);
        requireWasm32Handle(
            catalogHandle,
            'The prepackage evaluator-source catalog handle',
        );
        const session = createEvaluatorSourceCatalogSession({
            context,
            evaluatorComponentBackings: new Map(),
            handle: catalogHandle,
            kernel: input.kernel,
            phase: 'collecting',
            vssRecipientAuthority: input.vssRecipientAuthority,
        });
        catalogHandle = 0;
        return session;
    } catch (operationFailure) {
        if (catalogHandle !== 0) {
            try {
                const cleanupStatus = context.runExclusive(
                    'unwrapped prepackage evaluator-source catalog cancellation',
                    () =>
                        context.wasmExports.sealed_lattice_prepackage_evaluator_source_catalog_cancel(
                            catalogHandle,
                        ),
                );
                statusBoundary.throwIfError(cleanupStatus);
            } catch (cleanupFailure) {
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
};

/** Internal same-worker borrow for one phase-specific family verifier. */
export const requireAcceptedSetupVerificationAssemblyKernelOwner = (
    session: AcceptedSetupVerificationSession,
    kernel: TranscriptCoreKernel,
    expectedPhase: AcceptedSetupVerificationAssemblyPhase,
): AcceptedSetupVerificationAssemblyKernelOwner => {
    const record = requireSessionRecord(session);
    if (record.kernel !== kernel) {
        throw new TypeError(
            'The accepted-setup verification session belongs to another WASM kernel.',
        );
    }
    requirePhase(record, expectedPhase);
    return Object.freeze({ handle: record.handle, kernel: record.kernel });
};

/** Internal same-worker borrow for one evaluator-source family verifier. */
export const requireAcceptedSetupEvaluatorSourceCatalogKernelOwner = (
    session: AcceptedSetupEvaluatorSourceCatalogSession,
    kernel: TranscriptCoreKernel,
    expectedPhase: 'collecting' | 'complete' = 'collecting',
): AcceptedSetupEvaluatorSourceCatalogKernelOwner => {
    const record = requireEvaluatorSourceCatalogSessionRecord(session);
    if (record.kernel !== kernel) {
        throw new TypeError(
            'The evaluator-source catalog session belongs to another WASM kernel.',
        );
    }
    if (record.phase !== expectedPhase) {
        throw new CanonicalStreamRefusalError('consumedState');
    }
    return Object.freeze({ handle: record.handle, kernel: record.kernel });
};

/**
 * Mints internal custody from Rust-authenticated component readback. Custody
 * does not accept the proof; only the later positive family terminal can do
 * that. This helper is not part of the package entry point and exposes no
 * component identity on the object.
 */
export const createAcceptedSetupEvaluatorComponentBacking = (input: {
    authenticatedByteLength: bigint;
    fullObjectDigest: Uint8Array;
    kernel: TranscriptCoreKernel;
    materialRoot: Uint8Array;
    readExactRange(
        sourceByteOffset: bigint,
        exactByteLength: number,
    ): Promise<Uint8Array<ArrayBuffer>>;
    release(): void;
}): AcceptedSetupEvaluatorComponentBacking => {
    if (
        typeof input.authenticatedByteLength !== 'bigint' ||
        input.authenticatedByteLength <= 0n ||
        typeof input.readExactRange !== 'function' ||
        typeof input.release !== 'function'
    ) {
        throw new TypeError(
            'The evaluator component backing has invalid authenticated ownership.',
        );
    }
    const record: AcceptedSetupEvaluatorComponentBackingRecord = {
        authenticatedByteLength: input.authenticatedByteLength,
        fullObjectDigestHex: requireFixedHashHex(
            input.fullObjectDigest,
            'The evaluator component stream digest',
        ),
        kernel: input.kernel,
        materialRootHex: requireFixedHashHex(
            input.materialRoot,
            'The evaluator component material root',
        ),
        readExactRange: (sourceByteOffset, exactByteLength) =>
            input.readExactRange(sourceByteOffset, exactByteLength),
        release: () => input.release(),
        retained: false,
        released: false,
    };
    const backing: AcceptedSetupEvaluatorComponentBacking = Object.freeze({
        [acceptedSetupEvaluatorComponentBackingBrand]: true as const,
    });
    evaluatorComponentBackingRecords.set(backing, record);
    return backing;
};

const prepareAcceptedSetupEvaluatorComponentBackingRetention = (input: {
    backings: readonly AcceptedSetupEvaluatorComponentBacking[];
    catalog: AcceptedSetupEvaluatorSourceCatalogSession;
    kernel: TranscriptCoreKernel;
}): Readonly<{
    catalogRecord: AcceptedSetupEvaluatorSourceCatalogSessionRecord;
    prepared: readonly Readonly<{
        backing: AcceptedSetupEvaluatorComponentBacking;
        materialRootHex: string;
    }>[];
}> => {
    const catalogRecord = requireEvaluatorSourceCatalogSessionRecord(
        input.catalog,
    );
    if (
        catalogRecord.kernel !== input.kernel ||
        catalogRecord.phase !== 'collecting'
    ) {
        throw new CanonicalStreamRefusalError('wrongContext');
    }
    if (input.backings.length === 0) {
        throw new CanonicalStreamRefusalError('wrongTypeOrLength');
    }
    const prepared = input.backings.map((backing) => {
        const record = requireEvaluatorComponentBackingRecord(
            backing,
            input.kernel,
        );
        if (
            record.retained ||
            catalogRecord.evaluatorComponentBackings.has(record.materialRootHex)
        ) {
            throw new CanonicalStreamRefusalError('wrongHashOrRoot');
        }
        return { backing, materialRootHex: record.materialRootHex };
    });
    const distinctRoots = new Set(
        prepared.map((entry) => entry.materialRootHex),
    );
    if (distinctRoots.size !== prepared.length) {
        throw new CanonicalStreamRefusalError('wrongHashOrRoot');
    }
    return Object.freeze({
        catalogRecord,
        prepared: Object.freeze(prepared),
    });
};

/** Rejects component-custody conflicts before consuming Rust proof authority. */
export const requireAcceptedSetupEvaluatorComponentBackingsRetainable =
    (input: {
        backings: readonly AcceptedSetupEvaluatorComponentBacking[];
        catalog: AcceptedSetupEvaluatorSourceCatalogSession;
        kernel: TranscriptCoreKernel;
    }): void => {
        prepareAcceptedSetupEvaluatorComponentBackingRetention(input);
    };

/** Gives the prepackage catalog custody of Rust-minted component carriers. */
export const retainAcceptedSetupEvaluatorComponentBackings = (input: {
    backings: readonly AcceptedSetupEvaluatorComponentBacking[];
    catalog: AcceptedSetupEvaluatorSourceCatalogSession;
    kernel: TranscriptCoreKernel;
}): void => {
    const { catalogRecord, prepared } =
        prepareAcceptedSetupEvaluatorComponentBackingRetention(input);
    for (const entry of prepared) {
        catalogRecord.evaluatorComponentBackings.set(
            entry.materialRootHex,
            entry.backing,
        );
        requireEvaluatorComponentBackingRecord(
            entry.backing,
            input.kernel,
        ).retained = true;
    }
};

/** Releases component carriers that were never transferred into a catalog. */
export const releaseUnretainedAcceptedSetupEvaluatorComponentBackings = (
    backings: readonly AcceptedSetupEvaluatorComponentBacking[],
    kernel: TranscriptCoreKernel,
): void => {
    let firstFailure: unknown;
    for (const backing of backings) {
        try {
            const record = requireEvaluatorComponentBackingRecord(
                backing,
                kernel,
            );
            if (record.retained) {
                throw new CanonicalStreamRefusalError('consumedState');
            }
            releaseEvaluatorComponentBacking(backing);
        } catch (error) {
            firstFailure ??= error;
        }
    }
    if (firstFailure !== undefined) {
        throw firstFailure instanceof Error
            ? firstFailure
            : new CanonicalStreamInternalError(
                  'The unretained evaluator component backing release failed.',
                  firstFailure,
              );
    }
};

const resolveEvaluatorComponentBacking = (input: {
    authenticatedByteLength: bigint;
    backings: Map<string, AcceptedSetupEvaluatorComponentBacking>;
    fullObjectDigest: Uint8Array;
    kernel: TranscriptCoreKernel;
    materialRoot: Uint8Array;
}): AcceptedSetupEvaluatorComponentBackingRecord => {
    const materialRootHex = requireFixedHashHex(
        input.materialRoot,
        'The requested evaluator component material root',
    );
    const backing = input.backings.get(materialRootHex);
    if (backing === undefined) {
        throw new CanonicalStreamRefusalError('missingPrerequisite');
    }
    const record = requireEvaluatorComponentBackingRecord(
        backing,
        input.kernel,
    );
    if (
        record.authenticatedByteLength !== input.authenticatedByteLength ||
        record.fullObjectDigestHex !==
            requireFixedHashHex(
                input.fullObjectDigest,
                'The requested evaluator component stream digest',
            )
    ) {
        throw new CanonicalStreamRefusalError('wrongHashOrRoot');
    }
    return record;
};

export const readAcceptedSetupPrepackageEvaluatorComponentExactRange =
    async (input: {
        authenticatedByteLength: bigint;
        catalog: AcceptedSetupEvaluatorSourceCatalogSession;
        exactByteLength: number;
        fullObjectDigest: Uint8Array;
        kernel: TranscriptCoreKernel;
        materialRoot: Uint8Array;
        sourceByteOffset: bigint;
    }): Promise<Uint8Array<ArrayBuffer>> => {
        const catalogRecord = requireEvaluatorSourceCatalogSessionRecord(
            input.catalog,
        );
        if (catalogRecord.kernel !== input.kernel) {
            throw new CanonicalStreamRefusalError('consumedState');
        }
        const backing = resolveEvaluatorComponentBacking({
            authenticatedByteLength: input.authenticatedByteLength,
            backings: catalogRecord.evaluatorComponentBackings,
            fullObjectDigest: input.fullObjectDigest,
            kernel: input.kernel,
            materialRoot: input.materialRoot,
        });
        return backing.readExactRange(
            input.sourceByteOffset,
            input.exactByteLength,
        );
    };

export const readAcceptedSetupVerificationEvaluatorComponentExactRange =
    async (input: {
        acceptedSetupVerification: AcceptedSetupVerificationSession;
        authenticatedByteLength: bigint;
        exactByteLength: number;
        fullObjectDigest: Uint8Array;
        kernel: TranscriptCoreKernel;
        materialRoot: Uint8Array;
        sourceByteOffset: bigint;
    }): Promise<Uint8Array<ArrayBuffer>> => {
        const assemblyRecord = requireSessionRecord(
            input.acceptedSetupVerification,
        );
        if (
            assemblyRecord.kernel !== input.kernel ||
            assemblyRecord.phase !== 'collecting'
        ) {
            throw new CanonicalStreamRefusalError('consumedState');
        }
        const backing = resolveEvaluatorComponentBacking({
            authenticatedByteLength: input.authenticatedByteLength,
            backings: assemblyRecord.evaluatorComponentBackings,
            fullObjectDigest: input.fullObjectDigest,
            kernel: input.kernel,
            materialRoot: input.materialRoot,
        });
        return backing.readExactRange(
            input.sourceByteOffset,
            input.exactByteLength,
        );
    };

/** Releases participant component carriers after the evaluator terminal. */
export const releaseAcceptedSetupVerificationEvaluatorComponentBackings = (
    acceptedSetupVerification: AcceptedSetupVerificationSession,
    kernel: TranscriptCoreKernel,
): void => {
    const assemblyRecord = requireSessionRecord(acceptedSetupVerification);
    if (
        assemblyRecord.kernel !== kernel ||
        assemblyRecord.phase !== 'collecting'
    ) {
        throw new CanonicalStreamRefusalError('consumedState');
    }
    releaseEvaluatorComponentBackingMap(
        assemblyRecord.evaluatorComponentBackings,
    );
};
