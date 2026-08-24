import {
    adoptAcceptedSetupVerificationAssemblyFromKernelHandle,
    type AcceptedSetupVerificationSession,
} from './accepted-setup-assembly-runtime.js';
import {
    requireAggregateThresholdShareRecipientAuthorityKernelOwner,
    type AggregateThresholdShareRecipientAuthority,
} from './aggregate-threshold-share-authenticated-recipient.js';
import { isUint8Array } from './byte-array.js';
import {
    resolveCanonicalBoardVerifierSessionKernelAuthorization,
    type CanonicalBoardVerifierSession,
} from './canonical-board-runtime.js';
import {
    CanonicalStreamCleanupError,
    CanonicalStreamInternalError,
    CanonicalStreamRefusalError,
    CanonicalStreamResourceError,
} from './canonical-stream-runtime.js';
import {
    applyClosedWorkerGeneratedCommonProofCapability,
    applyClosedWorkerVerifiedCommonProofCapability,
    type ClosedWorkerGeneratedCommonProofCapability,
    type VerifiedCommonProofCapability,
} from './common-proof-worker-runtime/runtime.js';
import { resolveCommonProofKernelContext } from './transcript-core-bridge/common-proof-kernel-context.js';
import type { TranscriptCoreKernelCommandRuntime } from './transcript-core-bridge/kernel-runtime.js';
import type {
    TranscriptCoreKernel,
    TranscriptCoreKernelExports,
} from './transcript-core-bridge/kernel-types.js';
import { WasmMemoryBoundary } from './wasm-memory-boundary.js';
import { WasmStatusBoundary } from './wasm-status-boundary.js';

const generatedProofSourceKind = 1;
const verifiedProofSourceKind = 2;
const wasm32WordByteLength = 4;
const maximumWasm32UnsignedInteger = 0xffff_ffff;

type AcceptedSetupPackageBuilderExports = Required<
    Pick<
        TranscriptCoreKernelExports,
        | 'sealed_lattice_accepted_setup_package_builder_add_proof_source'
        | 'sealed_lattice_accepted_setup_package_builder_begin'
        | 'sealed_lattice_accepted_setup_package_builder_cancel'
        | 'sealed_lattice_accepted_setup_package_builder_copy_bytes'
        | 'sealed_lattice_accepted_setup_package_builder_finish'
        | 'sealed_lattice_accepted_setup_verification_cancel'
        | 'sealed_lattice_accepted_setup_verification_begin_from_package_builder'
    >
>;

type AcceptedSetupPackageBuilderContext = TranscriptCoreKernelCommandRuntime & {
    readonly wasmExports: TranscriptCoreKernelCommandRuntime['wasmExports'] &
        AcceptedSetupPackageBuilderExports;
};

const acceptedSetupPackageBuilderBrand = Symbol(
    'accepted-setup package builder',
);

/** Opaque same-worker custody of the verifier-owned canonical package. */
export type AcceptedSetupPackageBuilder = Readonly<{
    readonly [acceptedSetupPackageBuilderBrand]: true;
    addGeneratedProof(input: {
        canonicalApplicationStatement: Uint8Array;
        proof: ClosedWorkerGeneratedCommonProofCapability;
    }): void;
    addVerifiedProof(input: {
        canonicalApplicationStatement: Uint8Array;
        proof: VerifiedCommonProofCapability;
    }): void;
    beginVerification(): AcceptedSetupVerificationSession;
    cancel(): void;
    finish(): Uint8Array<ArrayBuffer>;
}>;

type AcceptedSetupPackageBuilderPhase = 'collecting' | 'finished';

type AcceptedSetupPackageBuilderRecord = {
    readonly context: AcceptedSetupPackageBuilderContext;
    readonly handle: number;
    readonly kernel: TranscriptCoreKernel;
    packageByteLength: number;
    phase: AcceptedSetupPackageBuilderPhase;
    readonly boardVerifierSession: CanonicalBoardVerifierSession;
    readonly vssRecipientAuthority: AggregateThresholdShareRecipientAuthority;
};

const builderRecords = new WeakMap<
    AcceptedSetupPackageBuilder,
    AcceptedSetupPackageBuilderRecord
>();

const createStatusBoundary = (): WasmStatusBoundary =>
    new WasmStatusBoundary({
        createInternalError: (message) =>
            new CanonicalStreamInternalError(message),
        createRefusalError: (refusalReason) =>
            new CanonicalStreamRefusalError(refusalReason),
        createResourceError: () => new CanonicalStreamResourceError(),
        internalFailureMessage:
            'The accepted-setup package builder failed internally.',
        unknownStatusMessage:
            'The accepted-setup package builder returned an unknown status code.',
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

const requireBuilderContext = (
    kernel: TranscriptCoreKernel,
): AcceptedSetupPackageBuilderContext => {
    const context = resolveCommonProofKernelContext(kernel);
    const exports = context?.wasmExports as
        | Partial<AcceptedSetupPackageBuilderExports>
        | undefined;
    const requiredExportNames = [
        'sealed_lattice_accepted_setup_package_builder_add_proof_source',
        'sealed_lattice_accepted_setup_package_builder_begin',
        'sealed_lattice_accepted_setup_package_builder_cancel',
        'sealed_lattice_accepted_setup_package_builder_copy_bytes',
        'sealed_lattice_accepted_setup_package_builder_finish',
        'sealed_lattice_accepted_setup_verification_cancel',
        'sealed_lattice_accepted_setup_verification_begin_from_package_builder',
    ] as const;
    if (
        context === undefined ||
        exports === undefined ||
        requiredExportNames.some(
            (exportName) => typeof exports[exportName] !== 'function',
        )
    ) {
        throw new CanonicalStreamInternalError(
            'The transcript-core kernel lacks the accepted-setup package-builder boundary.',
        );
    }
    return context as AcceptedSetupPackageBuilderContext;
};

const createMemoryBoundary = (
    context: AcceptedSetupPackageBuilderContext,
): WasmMemoryBoundary =>
    new WasmMemoryBoundary({
        context,
        createInternalError: (message) =>
            new CanonicalStreamInternalError(message),
        createResourceError: (message) =>
            new CanonicalStreamResourceError(message),
        label: 'accepted-setup package builder',
    });

const requireBuilderRecord = (
    builder: AcceptedSetupPackageBuilder,
): AcceptedSetupPackageBuilderRecord => {
    const record =
        (typeof builder === 'object' || typeof builder === 'function') &&
        builder !== null
            ? builderRecords.get(builder)
            : undefined;
    if (record === undefined) {
        throw new CanonicalStreamRefusalError('consumedState');
    }
    return record;
};

const requirePhase = (
    record: AcceptedSetupPackageBuilderRecord,
    expectedPhase: AcceptedSetupPackageBuilderPhase,
): void => {
    if (record.phase !== expectedPhase) {
        throw new CanonicalStreamRefusalError('consumedState');
    }
};

const requireCanonicalApplicationStatement = (
    value: Uint8Array,
): Uint8Array => {
    if (!isUint8Array(value) || value.byteLength === 0) {
        throw new CanonicalStreamRefusalError('wrongTypeOrLength');
    }
    return value;
};

const addProofSource = (
    builder: AcceptedSetupPackageBuilder,
    proofSourceKind: number,
    proof:
        | ClosedWorkerGeneratedCommonProofCapability
        | VerifiedCommonProofCapability,
    canonicalApplicationStatementInput: Uint8Array,
): void => {
    const record = requireBuilderRecord(builder);
    requirePhase(record, 'collecting');
    const canonicalApplicationStatement = requireCanonicalApplicationStatement(
        canonicalApplicationStatementInput,
    );
    const memoryBoundary = createMemoryBoundary(record.context);
    const statusBoundary = createStatusBoundary();
    let statementPointer = 0;
    try {
        statementPointer = memoryBoundary.copy(canonicalApplicationStatement);
        const applyProof = (proofHandle: number): number =>
            record.context.runExclusive(
                'accepted-setup package proof-source intake',
                () =>
                    record.context.wasmExports.sealed_lattice_accepted_setup_package_builder_add_proof_source(
                        record.handle,
                        proofSourceKind,
                        proofHandle,
                        statementPointer,
                        canonicalApplicationStatement.byteLength,
                    ),
            );
        const status =
            proofSourceKind === generatedProofSourceKind
                ? applyClosedWorkerGeneratedCommonProofCapability(
                      proof as ClosedWorkerGeneratedCommonProofCapability,
                      record.context,
                      (proofHandle) =>
                          Object.freeze({
                              consumed: false,
                              result: applyProof(proofHandle),
                          }),
                  )
                : applyClosedWorkerVerifiedCommonProofCapability(
                      proof as VerifiedCommonProofCapability,
                      record.context,
                      (proofHandle) =>
                          Object.freeze({
                              consumed: false,
                              result: applyProof(proofHandle),
                          }),
                  );
        statusBoundary.throwIfError(status);
    } finally {
        memoryBoundary.zeroAndDeallocate(
            statementPointer,
            canonicalApplicationStatement.byteLength,
        );
    }
};

const finishBuilder = (
    builder: AcceptedSetupPackageBuilder,
): Uint8Array<ArrayBuffer> => {
    const record = requireBuilderRecord(builder);
    const memoryBoundary = createMemoryBoundary(record.context);
    const statusBoundary = createStatusBoundary();
    let statusPointer = 0;
    let outputPointer = 0;
    let outputByteLength = record.packageByteLength;
    try {
        if (record.phase === 'collecting') {
            statusPointer = memoryBoundary.allocateZeroedWords(1);
            outputByteLength = record.context.runExclusive(
                'accepted-setup package finish',
                () =>
                    record.context.wasmExports.sealed_lattice_accepted_setup_package_builder_finish(
                        record.handle,
                        statusPointer,
                    ),
            );
            const [status] = memoryBoundary.readWords(statusPointer, 1);
            statusBoundary.throwIfError(status);
            if (
                !Number.isSafeInteger(outputByteLength) ||
                outputByteLength <= 0
            ) {
                throw new CanonicalStreamInternalError(
                    'The accepted-setup package builder returned an invalid byte length.',
                );
            }
            record.packageByteLength = outputByteLength;
            record.phase = 'finished';
        } else {
            requirePhase(record, 'finished');
        }
        outputPointer = memoryBoundary.allocate(outputByteLength);
        const copyStatus = record.context.runExclusive(
            'accepted-setup package copy',
            () =>
                record.context.wasmExports.sealed_lattice_accepted_setup_package_builder_copy_bytes(
                    record.handle,
                    outputPointer,
                    outputByteLength,
                ),
        );
        statusBoundary.throwIfError(copyStatus);
        const packageBytes = Uint8Array.from(
            new Uint8Array(
                record.context.memory.buffer,
                outputPointer,
                outputByteLength,
            ),
        );
        return packageBytes;
    } finally {
        memoryBoundary.zeroAndDeallocate(statusPointer, wasm32WordByteLength);
        memoryBoundary.zeroAndDeallocate(outputPointer, outputByteLength);
    }
};

const cancelBuilder = (builder: AcceptedSetupPackageBuilder): void => {
    const record = requireBuilderRecord(builder);
    const status = record.context.runExclusive(
        'accepted-setup package builder cancellation',
        () =>
            record.context.wasmExports.sealed_lattice_accepted_setup_package_builder_cancel(
                record.handle,
            ),
    );
    createStatusBoundary().throwIfError(status);
    builderRecords.delete(builder);
};

const beginVerification = (
    builder: AcceptedSetupPackageBuilder,
): AcceptedSetupVerificationSession => {
    const record = requireBuilderRecord(builder);
    requirePhase(record, 'finished');
    requireAggregateThresholdShareRecipientAuthorityKernelOwner(
        record.vssRecipientAuthority,
        record.kernel,
    );
    const memoryBoundary = createMemoryBoundary(record.context);
    const statusBoundary = createStatusBoundary();
    let statusPointer = 0;
    let assemblyHandle = 0;
    try {
        statusPointer = memoryBoundary.allocateZeroedWords(1);
        assemblyHandle = record.context.runExclusive(
            'accepted-setup verification begin from package builder',
            () =>
                record.context.wasmExports.sealed_lattice_accepted_setup_verification_begin_from_package_builder(
                    record.handle,
                    statusPointer,
                ),
        );
        const [status] = memoryBoundary.readWords(statusPointer, 1);
        statusBoundary.throwIfError(status);
        requireLiveHandle(
            assemblyHandle,
            'The accepted-setup verification assembly handle',
        );
        const session = adoptAcceptedSetupVerificationAssemblyFromKernelHandle({
            assemblyHandle,
            kernel: record.kernel,
            vssRecipientAuthority: record.vssRecipientAuthority,
        });
        builderRecords.delete(builder);
        assemblyHandle = 0;
        return session;
    } catch (operationFailure) {
        if (assemblyHandle !== 0) {
            builderRecords.delete(builder);
            try {
                const cleanupStatus = record.context.runExclusive(
                    'unwrapped accepted-setup verification assembly cancellation',
                    () =>
                        record.context.wasmExports.sealed_lattice_accepted_setup_verification_cancel(
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
    }
};

const createBuilder = (
    record: AcceptedSetupPackageBuilderRecord,
): AcceptedSetupPackageBuilder => {
    const builder: AcceptedSetupPackageBuilder = Object.freeze({
        [acceptedSetupPackageBuilderBrand]: true as const,
        addGeneratedProof: (input): void =>
            addProofSource(
                builder,
                generatedProofSourceKind,
                input.proof,
                input.canonicalApplicationStatement,
            ),
        addVerifiedProof: (input): void =>
            addProofSource(
                builder,
                verifiedProofSourceKind,
                input.proof,
                input.canonicalApplicationStatement,
            ),
        beginVerification: (): AcceptedSetupVerificationSession =>
            beginVerification(builder),
        cancel: (): void => cancelBuilder(builder),
        finish: (): Uint8Array<ArrayBuffer> => finishBuilder(builder),
    });
    builderRecords.set(builder, record);
    return builder;
};

/** Begins exact package construction from completed VSS and board authorities. */
export const beginAcceptedSetupPackageBuilder = (input: {
    boardVerifierSession: CanonicalBoardVerifierSession;
    kernel: TranscriptCoreKernel;
    vssRecipientAuthority: AggregateThresholdShareRecipientAuthority;
}): AcceptedSetupPackageBuilder => {
    const context = requireBuilderContext(input.kernel);
    const vssOwner =
        requireAggregateThresholdShareRecipientAuthorityKernelOwner(
            input.vssRecipientAuthority,
            input.kernel,
        );
    const boardAuthorization =
        resolveCanonicalBoardVerifierSessionKernelAuthorization(
            input.boardVerifierSession,
            input.kernel,
        );
    if (boardAuthorization.capabilityMemory !== context.memory) {
        throw new CanonicalStreamRefusalError('wrongContext');
    }
    const memoryBoundary = createMemoryBoundary(context);
    const statusBoundary = createStatusBoundary();
    let statusPointer = 0;
    let builderHandle = 0;
    try {
        statusPointer = memoryBoundary.allocateZeroedWords(1);
        builderHandle = context.runExclusive(
            'accepted-setup package builder begin',
            () =>
                context.wasmExports.sealed_lattice_accepted_setup_package_builder_begin(
                    vssOwner.handle,
                    boardAuthorization.sessionHandle,
                    boardAuthorization.capabilityPointer,
                    boardAuthorization.capabilityByteLength,
                    statusPointer,
                ),
        );
        const [status] = memoryBoundary.readWords(statusPointer, 1);
        statusBoundary.throwIfError(status);
        requireLiveHandle(
            builderHandle,
            'The accepted-setup package builder handle',
        );
        const builder = createBuilder({
            context,
            handle: builderHandle,
            kernel: input.kernel,
            packageByteLength: 0,
            phase: 'collecting',
            boardVerifierSession: input.boardVerifierSession,
            vssRecipientAuthority: input.vssRecipientAuthority,
        });
        builderHandle = 0;
        return builder;
    } catch (operationFailure) {
        if (builderHandle !== 0) {
            try {
                const cleanupStatus = context.runExclusive(
                    'unwrapped accepted-setup package builder cancellation',
                    () =>
                        context.wasmExports.sealed_lattice_accepted_setup_package_builder_cancel(
                            builderHandle,
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

/** Internal same-worker borrow for a Rust-owned material source. */
export const requireAcceptedSetupPackageBuilderKernelOwner = (
    builder: AcceptedSetupPackageBuilder,
    kernel: TranscriptCoreKernel,
    expectedPhase: AcceptedSetupPackageBuilderPhase = 'collecting',
): Readonly<{
    context: AcceptedSetupPackageBuilderContext;
    handle: number;
    kernel: TranscriptCoreKernel;
}> => {
    const record = requireBuilderRecord(builder);
    if (record.kernel !== kernel) {
        throw new CanonicalStreamRefusalError('wrongContext');
    }
    requirePhase(record, expectedPhase);
    return Object.freeze({
        context: record.context,
        handle: record.handle,
        kernel: record.kernel,
    });
};
