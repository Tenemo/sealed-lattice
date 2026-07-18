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
        | 'sealed_lattice_accepted_setup_verification_begin'
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
    ) => Promise<Uint8Array>;
    readonly release: () => void;
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
    if (
        record === undefined ||
        record.kernel !== kernel ||
        record.released
    ) {
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
        throw firstFailure;
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
        typeof wasmExports.sealed_lattice_accepted_setup_verification_begin !==
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
        typeof wasmExports.sealed_lattice_accepted_setup_verification_transfer_prepackage_evaluator_sources !==
            'function'
    ) {
        throw new CanonicalStreamInternalError(
            'The transcript-core kernel lacks the prepackage evaluator-source catalog boundary.',
        );
    }
    return context as AcceptedSetupEvaluatorSourceCatalogContext;
};

const requireCanonicalPackageBytes = (value: Uint8Array): Uint8Array => {
    if (!isUint8Array(value) || value.byteLength === 0) {
        throw new CanonicalStreamRefusalError('wrongTypeOrLength');
    }
    return value;
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
            catalogRecord.vssRecipientAuthority
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
    evaluatorSourceCatalogSessionRecords.delete(session);
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

/** Begins verification from one canonical package and the completed VSS source. */
export const beginAcceptedSetupVerification = (input: {
    canonicalPackageBytes: Uint8Array;
    kernel: TranscriptCoreKernel;
    vssRecipientAuthority: AggregateThresholdShareRecipientAuthority;
}): AcceptedSetupVerificationSession => {
    const context = requireAssemblyContext(input.kernel);
    const canonicalPackageBytes = requireCanonicalPackageBytes(
        input.canonicalPackageBytes,
    );
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
        label: 'accepted-setup canonical package',
    });
    const statusBoundary = createStatusBoundary();
    let packagePointer = 0;
    let statusPointer = 0;
    let assemblyHandle = 0;
    try {
        packagePointer = memoryBoundary.copy(canonicalPackageBytes);
        statusPointer = memoryBoundary.allocateZeroedWords(1);
        assemblyHandle = context.runExclusive(
            'accepted-setup verification assembly begin',
            () =>
                context.wasmExports.sealed_lattice_accepted_setup_verification_begin(
                    vssAuthorityOwner.handle,
                    packagePointer,
                    canonicalPackageBytes.byteLength,
                    statusPointer,
                ),
        );
        const [status] = memoryBoundary.readWords(statusPointer, 1);
        statusBoundary.throwIfError(status);
        requireWasm32Handle(
            assemblyHandle,
            'The accepted-setup verification assembly handle',
        );
        const session = createSession({
            context,
            handle: assemblyHandle,
            kernel: input.kernel,
            phase: 'collecting',
            vssRecipientAuthority: input.vssRecipientAuthority,
        });
        assemblyHandle = 0;
        return session;
    } catch (operationFailure) {
        if (assemblyHandle !== 0) {
            try {
                const cleanupStatus = context.runExclusive(
                    'unwrapped accepted-setup verification assembly cancellation',
                    () =>
                        context.wasmExports.sealed_lattice_accepted_setup_verification_cancel(
                            assemblyHandle,
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
        memoryBoundary.zeroAndDeallocate(
            packagePointer,
            canonicalPackageBytes.byteLength,
        );
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
): AcceptedSetupEvaluatorSourceCatalogKernelOwner => {
    const record = requireEvaluatorSourceCatalogSessionRecord(session);
    if (record.kernel !== kernel) {
        throw new TypeError(
            'The evaluator-source catalog session belongs to another WASM kernel.',
        );
    }
    if (record.phase !== 'collecting') {
        throw new CanonicalStreamRefusalError('consumedState');
    }
    return Object.freeze({ handle: record.handle, kernel: record.kernel });
};
