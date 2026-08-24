import {
    refusalReasonCodes,
    type VerificationResult,
} from '@sealed-lattice/types';

import {
    requireAcceptedSetupVerificationAssemblyKernelOwner,
    type AcceptedSetupVerificationSession,
} from './accepted-setup-assembly-runtime.js';
import { isUint8Array } from './byte-array.js';
import {
    CanonicalStreamCancellationError,
    CanonicalStreamCleanupError,
    CanonicalStreamInternalError,
    CanonicalStreamRefusalError,
    CanonicalStreamResourceError,
} from './canonical-stream-runtime.js';
import {
    CommonProofVerificationKernelBoundary,
    yieldBrowserWorkerTurn,
} from './common-proof-worker-runtime/kernel-boundaries.js';
import {
    applyClosedWorkerGeneratedCommonProofCapability,
    applyClosedWorkerVerifiedCommonProofCapability,
    openClosedWorkerCommonProofVerificationFamilyAdapter,
    releaseClosedWorkerCommonProofVerificationFamilyAdapter,
    runClosedWorkerCommonProofVerificationFamilyAdapter,
    type AuthenticatedCommonProofInputStore,
    type AcceptedSetupCompactPublicKeyVerificationCheckpointCustody,
    type ClosedWorkerCommonProofVerificationFamilyAdapter,
    type ClosedWorkerGeneratedCommonProofCapability,
    type CommonProofVerificationWorkerOptions,
} from './common-proof-worker-runtime/runtime.js';
import { resolveCommonProofKernelContext } from './transcript-core-bridge/common-proof-kernel-context.js';
import type { TranscriptCoreKernelCommandRuntime } from './transcript-core-bridge/kernel-runtime.js';
import type {
    TranscriptCoreKernel,
    TranscriptCoreKernelExports,
} from './transcript-core-bridge/kernel-types.js';
import {
    consumeVerifiedVssLowDegreeEvidence,
    type VerifiedVssLowDegreeEvidence,
} from './vss-share-linkage-verification-runtime.js';
import { WasmMemoryBoundary } from './wasm-memory-boundary.js';
import { WasmStatusBoundary } from './wasm-status-boundary.js';

const wasm32WordByteLength = 4;
const maximumWasm32UnsignedInteger = 0xffff_ffff;

type AcceptedSetupProofFamily = 'publicKeyShare' | 'sameSecret';

type AcceptedSetupProofVerificationKernel = Readonly<{
    discardTerminalSource(terminalSourceHandle: number): number;
    finishGeneratedVerification(
        verifiedCommonProofHandle: number,
        terminalSourceHandle: number,
        generatedCommonProofHandle: number,
    ): number;
    finishVerification(
        verifiedCommonProofHandle: number,
        terminalSourceHandle: number,
    ): number;
    prepareVerification(
        selectedSuiteHandle: number,
        assemblyHandle: number,
        vssLowDegreeEvidenceHandle: number | undefined,
        canonicalApplicationStatementPointer: number,
        canonicalApplicationStatementByteLength: number,
        terminalSourceHandleOutputPointer: number,
        statusPointer: number,
    ): number;
    prepareGeneratedVerification(
        selectedSuiteHandle: number,
        assemblyHandle: number,
        generationStatementSourceHandle: number,
        terminalSourceHandleOutputPointer: number,
        statusPointer: number,
    ): number;
    releaseSelectedSuite(selectedSuiteHandle: number): number;
    selectSuite(
        canonicalSuiteRecordPointer: number,
        canonicalSuiteRecordByteLength: number,
        statusPointer: number,
    ): number;
}>;

export type AcceptedSetupProofVerificationInput = Readonly<{
    assembly: AcceptedSetupVerificationSession;
    canonicalApplicationStatementBytes: Uint8Array;
    canonicalSuiteRecordBytes: Uint8Array;
    inputStore: AuthenticatedCommonProofInputStore;
    kernel: TranscriptCoreKernel;
    options?: CommonProofVerificationWorkerOptions;
}>;

export type AcceptedSetupSameSecretProofVerificationInput =
    AcceptedSetupProofVerificationInput &
        Readonly<{
            vssLowDegreeEvidence: VerifiedVssLowDegreeEvidence;
        }>;

export type AcceptedSetupCompactPublicKeyVerificationInput = Readonly<{
    assembly: AcceptedSetupVerificationSession;
    canonicalApplicationStatementBytes: Uint8Array;
    canonicalProofBytes: Uint8Array;
    canonicalPublicInputBytes: Uint8Array;
    kernel: TranscriptCoreKernel;
    options?: AcceptedSetupCompactPublicKeyVerificationWorkerOptions;
}>;

export type AcceptedSetupCompactPublicKeyVerificationResume = Readonly<{
    checkpointCustody: AcceptedSetupCompactPublicKeyVerificationCheckpointCustody;
}>;

export type AcceptedSetupCompactPublicKeyVerificationCheckpointCustodyOpening =
    Readonly<{
        checkpointCustody: AcceptedSetupCompactPublicKeyVerificationCheckpointCustody;
        mode: 'fresh' | 'resumed';
    }>;

export type AcceptedSetupCompactPublicKeyVerificationCheckpointCustodyOpener = (
    orderedSourceDigests: readonly Uint8Array<ArrayBuffer>[],
) => Promise<AcceptedSetupCompactPublicKeyVerificationCheckpointCustodyOpening>;

type AcceptedSetupCompactPublicKeyVerificationSchedulingOptions = Readonly<{
    maximumWorkUnitCountPerPoll?: number;
    signal?: AbortSignal;
    yieldControl?: () => Promise<void>;
}>;

export type AcceptedSetupCompactPublicKeyVerificationWorkerOptions =
    AcceptedSetupCompactPublicKeyVerificationSchedulingOptions &
        (
            | Readonly<{
                  checkpointCustody?: AcceptedSetupCompactPublicKeyVerificationCheckpointCustody;
                  resume?: never;
              }>
            | Readonly<{
                  checkpointCustody?: never;
                  resume: AcceptedSetupCompactPublicKeyVerificationResume;
              }>
            | Readonly<{
                  checkpointCustody?: never;
                  openCheckpointCustody: AcceptedSetupCompactPublicKeyVerificationCheckpointCustodyOpener;
                  resume?: never;
              }>
        );

export type AcceptedSetupCompactPublicKeyVerificationCheckpointGeometry =
    Readonly<{
        checkpointByteLength: number;
        safeBoundaryCount: number;
    }>;

export const readAcceptedSetupCompactPublicKeyVerificationCheckpointGeometry = (
    kernel: TranscriptCoreKernel,
): AcceptedSetupCompactPublicKeyVerificationCheckpointGeometry => {
    const context = resolveCommonProofKernelContext(kernel);
    if (context === undefined) {
        throw new CanonicalStreamInternalError(
            'The loaded WASM kernel has no common-proof worker context.',
        );
    }
    const verificationKernel = new CommonProofVerificationKernelBoundary(
        context,
    );
    return Object.freeze({
        checkpointByteLength:
            verificationKernel.acceptedSetupCompactPublicKeyVerificationCheckpointByteLength(),
        safeBoundaryCount:
            verificationKernel.acceptedSetupCompactPublicKeyVerificationSafeBoundaryCount(),
    });
};

type AcceptedSetupProofVerificationCoreInput = Omit<
    AcceptedSetupProofVerificationInput,
    'canonicalApplicationStatementBytes'
>;

type AcceptedSetupProofVerificationSource =
    | Readonly<{
          canonicalApplicationStatementBytes: Uint8Array;
          kind: 'transported';
      }>
    | Readonly<{
          generatedCommonProofCapability: ClosedWorkerGeneratedCommonProofCapability;
          generationStatementSourceHandle: number;
          kind: 'generated';
      }>;

const createStatusBoundary = (
    family: AcceptedSetupProofFamily,
): WasmStatusBoundary =>
    new WasmStatusBoundary({
        createInternalError: (message) =>
            new CanonicalStreamInternalError(message),
        createRefusalError: (refusalReason) =>
            new CanonicalStreamRefusalError(refusalReason),
        createResourceError: () => new CanonicalStreamResourceError(),
        internalFailureMessage: `The accepted-setup ${family} verification failed internally.`,
        unknownStatusMessage: `The accepted-setup ${family} verification returned an unknown status code.`,
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

const requireCanonicalBytes = (value: Uint8Array): Uint8Array => {
    if (!isUint8Array(value) || value.byteLength === 0) {
        throw new CanonicalStreamRefusalError('wrongTypeOrLength');
    }
    return value;
};

const requireVerificationKernel = (
    context: TranscriptCoreKernelCommandRuntime,
    family: AcceptedSetupProofFamily,
): AcceptedSetupProofVerificationKernel => {
    const {
        sealed_lattice_common_proof_release_suite: releaseSelectedSuite,
        sealed_lattice_common_proof_select_suite: selectSuite,
    } = context.wasmExports;
    const rawPrepareVerification =
        family === 'sameSecret'
            ? context.wasmExports
                  .sealed_lattice_accepted_setup_same_secret_prepare_verification
            : context.wasmExports
                  .sealed_lattice_accepted_setup_public_key_share_prepare_verification;
    const rawPrepareGeneratedVerification =
        family === 'sameSecret'
            ? context.wasmExports
                  .sealed_lattice_accepted_setup_same_secret_prepare_generated_verification
            : context.wasmExports
                  .sealed_lattice_accepted_setup_public_key_share_prepare_generated_verification;
    const finishVerification =
        family === 'sameSecret'
            ? context.wasmExports
                  .sealed_lattice_accepted_setup_same_secret_finish_verification
            : context.wasmExports
                  .sealed_lattice_accepted_setup_public_key_share_finish_verification;
    const finishGeneratedVerification =
        family === 'sameSecret'
            ? context.wasmExports
                  .sealed_lattice_accepted_setup_same_secret_finish_generated_verification
            : context.wasmExports
                  .sealed_lattice_accepted_setup_public_key_share_finish_generated_verification;
    const discardTerminalSource =
        family === 'sameSecret'
            ? context.wasmExports
                  .sealed_lattice_accepted_setup_same_secret_discard_terminal_source
            : context.wasmExports
                  .sealed_lattice_accepted_setup_public_key_share_discard_terminal_source;
    if (
        typeof releaseSelectedSuite !== 'function' ||
        typeof selectSuite !== 'function' ||
        typeof rawPrepareVerification !== 'function' ||
        typeof rawPrepareGeneratedVerification !== 'function' ||
        typeof finishVerification !== 'function' ||
        typeof finishGeneratedVerification !== 'function' ||
        typeof discardTerminalSource !== 'function'
    ) {
        throw new CanonicalStreamInternalError(
            `The transcript-core kernel lacks the accepted-setup ${family} verification boundary.`,
        );
    }
    const prepareVerification: AcceptedSetupProofVerificationKernel['prepareVerification'] =
        family === 'sameSecret'
            ? (
                  selectedSuiteHandle,
                  assemblyHandle,
                  vssLowDegreeEvidenceHandle,
                  canonicalApplicationStatementPointer,
                  canonicalApplicationStatementByteLength,
                  terminalSourceHandleOutputPointer,
                  statusPointer,
              ) => {
                  if (vssLowDegreeEvidenceHandle === undefined) {
                      throw new CanonicalStreamInternalError(
                          'The same-secret verifier lacks its VSS low-degree evidence.',
                      );
                  }
                  return rawPrepareVerification(
                      selectedSuiteHandle,
                      assemblyHandle,
                      vssLowDegreeEvidenceHandle,
                      canonicalApplicationStatementPointer,
                      canonicalApplicationStatementByteLength,
                      terminalSourceHandleOutputPointer,
                      statusPointer,
                  );
              }
            : (
                  selectedSuiteHandle,
                  assemblyHandle,
                  _vssLowDegreeEvidenceHandle,
                  canonicalApplicationStatementPointer,
                  canonicalApplicationStatementByteLength,
                  terminalSourceHandleOutputPointer,
                  statusPointer,
              ) =>
                  (
                      rawPrepareVerification as NonNullable<
                          TranscriptCoreKernelExports['sealed_lattice_accepted_setup_public_key_share_prepare_verification']
                      >
                  )(
                      selectedSuiteHandle,
                      assemblyHandle,
                      canonicalApplicationStatementPointer,
                      canonicalApplicationStatementByteLength,
                      terminalSourceHandleOutputPointer,
                      statusPointer,
                  );
    const prepareGeneratedVerification: AcceptedSetupProofVerificationKernel['prepareGeneratedVerification'] =
        (
            selectedSuiteHandle,
            assemblyHandle,
            generationStatementSourceHandle,
            terminalSourceHandleOutputPointer,
            statusPointer,
        ) =>
            rawPrepareGeneratedVerification(
                selectedSuiteHandle,
                assemblyHandle,
                generationStatementSourceHandle,
                terminalSourceHandleOutputPointer,
                statusPointer,
            );
    return Object.freeze({
        discardTerminalSource,
        finishGeneratedVerification,
        finishVerification,
        prepareGeneratedVerification,
        prepareVerification,
        releaseSelectedSuite,
        selectSuite,
    });
};

const selectSuite = (input: {
    canonicalSuiteRecordBytes: Uint8Array;
    context: TranscriptCoreKernelCommandRuntime;
    kernel: AcceptedSetupProofVerificationKernel;
    memoryBoundary: WasmMemoryBoundary;
    statusBoundary: WasmStatusBoundary;
}): number => {
    const canonicalSuiteRecordBytes = requireCanonicalBytes(
        input.canonicalSuiteRecordBytes,
    );
    let suitePointer = 0;
    let statusPointer = 0;
    let selectedSuiteHandle = 0;
    try {
        suitePointer = input.memoryBoundary.copy(canonicalSuiteRecordBytes);
        statusPointer = input.memoryBoundary.allocateZeroedWords(1);
        selectedSuiteHandle = input.context.runExclusive(
            'accepted-setup selected-suite acquisition',
            () =>
                input.kernel.selectSuite(
                    suitePointer,
                    canonicalSuiteRecordBytes.byteLength,
                    statusPointer,
                ),
        );
        const [status] = input.memoryBoundary.readWords(statusPointer, 1);
        input.statusBoundary.throwIfError(status);
        return requireWasm32Handle(
            selectedSuiteHandle,
            'The selected-suite handle',
        );
    } catch (operationFailure) {
        if (selectedSuiteHandle !== 0) {
            try {
                const cleanupStatus = input.context.runExclusive(
                    'accepted-setup failed selected-suite acquisition cleanup',
                    () =>
                        input.kernel.releaseSelectedSuite(selectedSuiteHandle),
                );
                input.statusBoundary.throwIfError(cleanupStatus);
            } catch (cleanupFailure) {
                throw new CanonicalStreamCleanupError(
                    operationFailure,
                    cleanupFailure,
                );
            }
        }
        throw operationFailure;
    } finally {
        input.memoryBoundary.zeroAndDeallocate(
            statusPointer,
            wasm32WordByteLength,
        );
        input.memoryBoundary.zeroAndDeallocate(
            suitePointer,
            canonicalSuiteRecordBytes.byteLength,
        );
    }
};

const discardTerminalSource = (input: {
    context: TranscriptCoreKernelCommandRuntime;
    handle: number;
    kernel: AcceptedSetupProofVerificationKernel;
    statusBoundary: WasmStatusBoundary;
}): void => {
    const status = input.context.runExclusive(
        'accepted-setup verification terminal-source discard',
        () => input.kernel.discardTerminalSource(input.handle),
    );
    if (status >>> 0 === refusalReasonCodes.consumedState) {
        return;
    }
    input.statusBoundary.throwIfError(status);
};

const verifyAcceptedSetupProofInClosedWorker = async (
    family: AcceptedSetupProofFamily,
    input: AcceptedSetupProofVerificationCoreInput,
    source: AcceptedSetupProofVerificationSource,
    vssLowDegreeEvidence: VerifiedVssLowDegreeEvidence | undefined,
): Promise<void> => {
    if (typeof globalThis.document !== 'undefined') {
        throw new CanonicalStreamInternalError(
            'Accepted-setup proof verification may only run inside the dedicated WASM worker.',
        );
    }
    const context = resolveCommonProofKernelContext(input.kernel);
    if (context === undefined) {
        throw new CanonicalStreamInternalError(
            'The loaded WASM kernel has no common-proof worker context.',
        );
    }
    const assemblyOwner = requireAcceptedSetupVerificationAssemblyKernelOwner(
        input.assembly,
        input.kernel,
        'collecting',
    );
    const canonicalApplicationStatementBytes =
        source.kind === 'transported'
            ? requireCanonicalBytes(source.canonicalApplicationStatementBytes)
            : undefined;
    if (source.kind === 'generated') {
        requireWasm32Handle(
            source.generationStatementSourceHandle,
            'The generation statement-source handle',
        );
    }
    const kernel = requireVerificationKernel(context, family);
    const statusBoundary = createStatusBoundary(family);
    const memoryBoundary = new WasmMemoryBoundary({
        context,
        createInternalError: (message) =>
            new CanonicalStreamInternalError(message),
        createResourceError: (message) =>
            new CanonicalStreamResourceError(message),
        label: `accepted-setup ${family} verification`,
    });

    let familyAdapter:
        | ClosedWorkerCommonProofVerificationFamilyAdapter
        | undefined;
    let terminalSourceHandle = 0;
    let selectedSuiteHandle = selectSuite({
        canonicalSuiteRecordBytes: input.canonicalSuiteRecordBytes,
        context,
        kernel,
        memoryBoundary,
        statusBoundary,
    });
    let operationFailed = false;
    let operationFailure: unknown;
    try {
        const prepared = context.runExclusive(
            `accepted-setup ${family} verification preparation`,
            () => {
                const statementPointer =
                    canonicalApplicationStatementBytes === undefined
                        ? 0
                        : memoryBoundary.copy(
                              canonicalApplicationStatementBytes,
                          );
                const metadataPointer = memoryBoundary.allocateZeroedWords(2);
                try {
                    const statementByteLength =
                        canonicalApplicationStatementBytes?.byteLength ?? 0;
                    const prepareTransportedWithEvidenceHandle = (
                        vssLowDegreeEvidenceHandle: number | undefined,
                    ): number =>
                        kernel.prepareVerification(
                            selectedSuiteHandle,
                            assemblyOwner.handle,
                            vssLowDegreeEvidenceHandle,
                            statementPointer,
                            statementByteLength,
                            metadataPointer,
                            metadataPointer + wasm32WordByteLength,
                        );
                    const adapterHandle =
                        source.kind === 'generated'
                            ? kernel.prepareGeneratedVerification(
                                  selectedSuiteHandle,
                                  assemblyOwner.handle,
                                  source.generationStatementSourceHandle,
                                  metadataPointer,
                                  metadataPointer + wasm32WordByteLength,
                              )
                            : family === 'sameSecret'
                              ? consumeVerifiedVssLowDegreeEvidence({
                                    consume:
                                        prepareTransportedWithEvidenceHandle,
                                    context,
                                    evidence:
                                        vssLowDegreeEvidence ??
                                        (() => {
                                            throw new CanonicalStreamRefusalError(
                                                'wrongContext',
                                            );
                                        })(),
                                    kernel: input.kernel,
                                })
                              : prepareTransportedWithEvidenceHandle(undefined);
                    const [sourceHandle, status] = memoryBoundary.readWords(
                        metadataPointer,
                        2,
                    );
                    statusBoundary.throwIfError(status);
                    return Object.freeze({
                        adapterHandle: requireWasm32Handle(
                            adapterHandle,
                            'The common-proof verification adapter handle',
                        ),
                        terminalSourceHandle: requireWasm32Handle(
                            sourceHandle,
                            'The verification terminal-source handle',
                        ),
                    });
                } finally {
                    memoryBoundary.zeroAndDeallocate(
                        metadataPointer,
                        wasm32WordByteLength * 2,
                    );
                    memoryBoundary.zeroAndDeallocate(
                        statementPointer,
                        canonicalApplicationStatementBytes?.byteLength ?? 0,
                    );
                }
            },
        );
        terminalSourceHandle = prepared.terminalSourceHandle;
        familyAdapter = openClosedWorkerCommonProofVerificationFamilyAdapter(
            context,
            prepared.adapterHandle,
        );
        const releaseSuiteStatus = context.runExclusive(
            'accepted-setup selected-suite release',
            () => kernel.releaseSelectedSuite(selectedSuiteHandle),
        );
        selectedSuiteHandle = 0;
        statusBoundary.throwIfError(releaseSuiteStatus);

        const adapterForRun = familyAdapter;
        familyAdapter = undefined;
        const verifiedCommonProof =
            await runClosedWorkerCommonProofVerificationFamilyAdapter(
                adapterForRun,
                input.inputStore,
                input.options,
            );
        const finishStatus = (() => {
            try {
                return applyClosedWorkerVerifiedCommonProofCapability(
                    verifiedCommonProof,
                    context,
                    (verifiedCommonProofHandle) => {
                        const status =
                            source.kind === 'transported'
                                ? context.runExclusive(
                                      `accepted-setup ${family} verification finish`,
                                      () =>
                                          kernel.finishVerification(
                                              verifiedCommonProofHandle,
                                              terminalSourceHandle,
                                          ),
                                  )
                                : applyClosedWorkerGeneratedCommonProofCapability(
                                      source.generatedCommonProofCapability,
                                      context,
                                      (generatedCommonProofHandle) => {
                                          const generatedFinishStatus =
                                              context.runExclusive(
                                                  `accepted-setup ${family} generated-proof verification finish`,
                                                  () =>
                                                      kernel.finishGeneratedVerification(
                                                          verifiedCommonProofHandle,
                                                          terminalSourceHandle,
                                                          generatedCommonProofHandle,
                                                      ),
                                              );
                                          return Object.freeze({
                                              consumed:
                                                  generatedFinishStatus === 0,
                                              result: generatedFinishStatus,
                                          });
                                      },
                                  );
                        return Object.freeze({
                            consumed: status === 0,
                            result: status,
                        });
                    },
                );
            } catch (finishFailure) {
                try {
                    verifiedCommonProof.release();
                } catch (cleanupFailure) {
                    throw new CanonicalStreamInternalError(
                        'The failed accepted-setup proof handoff could not release its generic verifier authority.',
                        Object.freeze({ cleanupFailure, finishFailure }),
                    );
                }
                throw finishFailure;
            }
        })();
        if (finishStatus !== 0) {
            try {
                verifiedCommonProof.release();
            } catch (cleanupFailure) {
                throw new CanonicalStreamInternalError(
                    'The refused accepted-setup proof handoff could not release its generic verifier authority.',
                    Object.freeze({ cleanupFailure, finishStatus }),
                );
            }
            statusBoundary.throwIfError(finishStatus);
        }
        terminalSourceHandle = 0;
    } catch (error) {
        operationFailed = true;
        operationFailure = error;
    }

    const cleanupFailures: unknown[] = [];
    if (selectedSuiteHandle !== 0) {
        try {
            const status = context.runExclusive(
                'accepted-setup selected-suite failure release',
                () => kernel.releaseSelectedSuite(selectedSuiteHandle),
            );
            statusBoundary.throwIfError(status);
        } catch (cleanupFailure) {
            cleanupFailures.push(cleanupFailure);
        }
    }
    if (familyAdapter !== undefined) {
        try {
            releaseClosedWorkerCommonProofVerificationFamilyAdapter(
                familyAdapter,
            );
        } catch (cleanupFailure) {
            cleanupFailures.push(cleanupFailure);
        }
    }
    if (terminalSourceHandle !== 0) {
        try {
            discardTerminalSource({
                context,
                handle: terminalSourceHandle,
                kernel,
                statusBoundary,
            });
        } catch (cleanupFailure) {
            cleanupFailures.push(cleanupFailure);
        }
    }
    if (cleanupFailures.length > 0) {
        throw new CanonicalStreamInternalError(
            'Accepted-setup proof verification failed to retire all worker-owned authority.',
            Object.freeze({ cleanupFailures, operationFailure }),
        );
    }
    if (operationFailed) {
        throw operationFailure;
    }
};

const defaultCompactPublicKeyMaximumWorkUnitCountPerPoll = 4_096;

const throwIfCompactPublicKeyVerificationCancelled = (
    signal: AbortSignal | undefined,
): void => {
    if (signal?.aborted === true) {
        throw new CanonicalStreamCancellationError();
    }
};

const restoreCompactPublicKeyVerificationCheckpoint = async (
    kernel: CommonProofVerificationKernelBoundary,
    checkpointCustody: AcceptedSetupCompactPublicKeyVerificationCheckpointCustody,
): Promise<
    Readonly<{
        canonicalCheckpointBytes: Uint8Array<ArrayBuffer>;
        safeBoundaryOrdinal: number;
    }>
> => {
    let restoredCheckpoint: Readonly<{
        canonicalCheckpointBytes: Uint8Array;
        safeBoundaryOrdinal: number;
    }>;
    try {
        restoredCheckpoint =
            await checkpointCustody.restoreAuthenticatedCheckpoint();
    } catch (error) {
        throw new CanonicalStreamInternalError(
            'The browser store could not authenticate and restore the accepted-setup compact public-key checkpoint.',
            error,
        );
    }
    if (typeof restoredCheckpoint !== 'object' || restoredCheckpoint === null) {
        throw new CanonicalStreamInternalError(
            'The browser store returned a malformed accepted-setup compact public-key checkpoint record.',
        );
    }
    const canonicalCheckpointBytes =
        restoredCheckpoint.canonicalCheckpointBytes;
    const expectedByteLength =
        kernel.acceptedSetupCompactPublicKeyVerificationCheckpointByteLength();
    if (
        !(canonicalCheckpointBytes instanceof Uint8Array) ||
        !(canonicalCheckpointBytes.buffer instanceof ArrayBuffer) ||
        canonicalCheckpointBytes.byteOffset !== 0 ||
        canonicalCheckpointBytes.byteLength !== expectedByteLength ||
        canonicalCheckpointBytes.buffer.byteLength !== expectedByteLength
    ) {
        if (canonicalCheckpointBytes instanceof Uint8Array) {
            canonicalCheckpointBytes.fill(0);
        }
        throw new CanonicalStreamInternalError(
            'The browser store returned malformed accepted-setup compact public-key checkpoint bytes.',
        );
    }
    if (
        !Number.isSafeInteger(restoredCheckpoint.safeBoundaryOrdinal) ||
        restoredCheckpoint.safeBoundaryOrdinal < 0 ||
        restoredCheckpoint.safeBoundaryOrdinal >=
            kernel.acceptedSetupCompactPublicKeyVerificationSafeBoundaryCount()
    ) {
        canonicalCheckpointBytes.fill(0);
        throw new CanonicalStreamInternalError(
            'The browser store returned an unassigned accepted-setup compact public-key checkpoint boundary.',
        );
    }
    return Object.freeze({
        canonicalCheckpointBytes:
            canonicalCheckpointBytes as Uint8Array<ArrayBuffer>,
        safeBoundaryOrdinal: restoredCheckpoint.safeBoundaryOrdinal,
    });
};

const publishCompactPublicKeyVerificationCheckpoint = async (
    kernel: CommonProofVerificationKernelBoundary,
    operationHandle: number,
    checkpointCustody: AcceptedSetupCompactPublicKeyVerificationCheckpointCustody,
    safeBoundaryOrdinal: number,
): Promise<void> => {
    const canonicalCheckpointBytes =
        kernel.copyAcceptedSetupCompactPublicKeyVerificationCheckpoint(
            operationHandle,
        );
    try {
        try {
            await checkpointCustody.publishAuthenticatedCheckpoint(
                canonicalCheckpointBytes,
                safeBoundaryOrdinal,
            );
        } catch (error) {
            throw new CanonicalStreamInternalError(
                'The browser store could not atomically publish the accepted-setup compact public-key checkpoint.',
                error,
            );
        }
    } finally {
        canonicalCheckpointBytes.fill(0);
    }
};

/**
 * Verifies and inserts one compact public-key-share proof using only bindings
 * derived from the accepted package. The positive result is returned after
 * transport, CFW, both WHIR epochs, complete statement correspondence, and
 * one-shot terminal-slot commit all succeed.
 */
export const verifyAcceptedSetupCompactPublicKeyShareInClosedWorker = async (
    input: AcceptedSetupCompactPublicKeyVerificationInput,
): Promise<VerificationResult<undefined>> => {
    if (typeof globalThis.document !== 'undefined') {
        throw new CanonicalStreamInternalError(
            'Accepted-setup compact public-key verification may only run inside the dedicated WASM worker.',
        );
    }
    const context = resolveCommonProofKernelContext(input.kernel);
    if (context === undefined) {
        throw new CanonicalStreamInternalError(
            'The loaded WASM kernel has no common-proof worker context.',
        );
    }
    const assemblyOwner = requireAcceptedSetupVerificationAssemblyKernelOwner(
        input.assembly,
        input.kernel,
        'collecting',
    );
    const canonicalApplicationStatementBytes = requireCanonicalBytes(
        input.canonicalApplicationStatementBytes,
    );
    const canonicalProofBytes = requireCanonicalBytes(
        input.canonicalProofBytes,
    );
    const canonicalPublicInputBytes = requireCanonicalBytes(
        input.canonicalPublicInputBytes,
    );
    const options = input.options ?? {};
    const maximumWorkUnitCountPerPoll =
        options.maximumWorkUnitCountPerPoll ??
        defaultCompactPublicKeyMaximumWorkUnitCountPerPoll;
    if (
        !Number.isSafeInteger(maximumWorkUnitCountPerPoll) ||
        maximumWorkUnitCountPerPoll <= 0 ||
        maximumWorkUnitCountPerPoll > maximumWasm32UnsignedInteger
    ) {
        throw new CanonicalStreamResourceError(
            'The accepted-setup compact public-key work-unit bound must be a positive unsigned 32-bit integer.',
        );
    }
    const signal = options.signal;
    const yieldControl = options.yieldControl ?? yieldBrowserWorkerTurn;
    const runtimeCustodyOptions: Readonly<{
        checkpointCustody?: AcceptedSetupCompactPublicKeyVerificationCheckpointCustody;
        openCheckpointCustody?: AcceptedSetupCompactPublicKeyVerificationCheckpointCustodyOpener;
        resume?: AcceptedSetupCompactPublicKeyVerificationResume;
    }> = options;
    const directResume = runtimeCustodyOptions.resume;
    let checkpointCustody =
        runtimeCustodyOptions.checkpointCustody ??
        directResume?.checkpointCustody;
    const adoptedCheckpointCustodies =
        runtimeCustodyOptions.checkpointCustody === undefined
            ? directResume === undefined
                ? []
                : [directResume.checkpointCustody]
            : directResume === undefined ||
                directResume.checkpointCustody ===
                    runtimeCustodyOptions.checkpointCustody
              ? [runtimeCustodyOptions.checkpointCustody]
              : [
                    runtimeCustodyOptions.checkpointCustody,
                    directResume.checkpointCustody,
                ];
    const kernel = new CommonProofVerificationKernelBoundary(context);
    let preparedHandle = 0;
    let operationHandle = 0;
    let verifiedCapabilityHandle = 0;
    let resumed = directResume !== undefined;
    let deterministicReplayComplete = !resumed;
    let expectedResumeSafeBoundaryOrdinal: number | undefined;
    let operationResult: VerificationResult<undefined> | undefined;
    let operationFailure: unknown;

    try {
        if (
            Number(runtimeCustodyOptions.checkpointCustody !== undefined) +
                Number(directResume !== undefined) +
                Number(
                    runtimeCustodyOptions.openCheckpointCustody !== undefined,
                ) >
            1
        ) {
            throw new CanonicalStreamResourceError(
                'Accepted-setup compact public-key verification accepts exactly one direct fresh, direct resumed, or worker-opened checkpoint custody mode.',
            );
        }
        throwIfCompactPublicKeyVerificationCancelled(signal);
        const preparation =
            kernel.prepareAcceptedSetupCompactPublicKeyVerification(
                assemblyOwner.handle,
                canonicalApplicationStatementBytes,
            );
        if (preparation.kind === 'refused') {
            operationResult = Object.freeze({
                isValid: false,
                refusalReason: preparation.refusalReason,
            });
        } else {
            preparedHandle = preparation.preparedHandle;
            if (runtimeCustodyOptions.openCheckpointCustody !== undefined) {
                const orderedSourceDigests =
                    kernel.copyAcceptedSetupCompactPublicKeyVerificationCheckpointSourceDigests(
                        preparedHandle,
                    );
                let untrustedOpenedCustody: unknown;
                try {
                    untrustedOpenedCustody =
                        await runtimeCustodyOptions.openCheckpointCustody(
                            orderedSourceDigests,
                        );
                } finally {
                    for (const sourceDigest of orderedSourceDigests) {
                        sourceDigest.fill(0);
                    }
                }
                const openedCustodyCandidate =
                    typeof untrustedOpenedCustody === 'object' &&
                    untrustedOpenedCustody !== null
                        ? (untrustedOpenedCustody as {
                              checkpointCustody?: unknown;
                              mode?: unknown;
                          })
                        : undefined;
                const checkpointCustodyCandidate =
                    typeof openedCustodyCandidate?.checkpointCustody ===
                        'object' &&
                    openedCustodyCandidate.checkpointCustody !== null
                        ? (openedCustodyCandidate.checkpointCustody as {
                              publishAuthenticatedCheckpoint?: unknown;
                              release?: unknown;
                              restoreAuthenticatedCheckpoint?: unknown;
                          })
                        : undefined;
                if (typeof checkpointCustodyCandidate?.release === 'function') {
                    adoptedCheckpointCustodies.push(
                        checkpointCustodyCandidate as AcceptedSetupCompactPublicKeyVerificationCheckpointCustody,
                    );
                }
                if (
                    (openedCustodyCandidate?.mode !== 'fresh' &&
                        openedCustodyCandidate?.mode !== 'resumed') ||
                    checkpointCustodyCandidate === undefined ||
                    typeof checkpointCustodyCandidate.publishAuthenticatedCheckpoint !==
                        'function' ||
                    typeof checkpointCustodyCandidate.release !== 'function' ||
                    typeof checkpointCustodyCandidate.restoreAuthenticatedCheckpoint !==
                        'function'
                ) {
                    throw new CanonicalStreamInternalError(
                        'The worker checkpoint-custody opener returned a malformed accepted-setup compact public-key custody.',
                    );
                }
                checkpointCustody =
                    checkpointCustodyCandidate as AcceptedSetupCompactPublicKeyVerificationCheckpointCustody;
                resumed = openedCustodyCandidate.mode === 'resumed';
                deterministicReplayComplete = !resumed;
            }
            const begin = !resumed
                ? kernel.beginAcceptedSetupCompactPublicKeyVerification(
                      preparedHandle,
                      canonicalProofBytes,
                      canonicalPublicInputBytes,
                  )
                : await (async () => {
                      if (checkpointCustody === undefined) {
                          throw new CanonicalStreamInternalError(
                              'Accepted-setup compact public-key verification resume has no checkpoint custody.',
                          );
                      }
                      const restoredCheckpoint =
                          await restoreCompactPublicKeyVerificationCheckpoint(
                              kernel,
                              checkpointCustody,
                          );
                      expectedResumeSafeBoundaryOrdinal =
                          restoredCheckpoint.safeBoundaryOrdinal;
                      try {
                          throwIfCompactPublicKeyVerificationCancelled(signal);
                          return kernel.resumeAcceptedSetupCompactPublicKeyVerification(
                              preparedHandle,
                              canonicalProofBytes,
                              canonicalPublicInputBytes,
                              restoredCheckpoint.canonicalCheckpointBytes,
                          );
                      } finally {
                          restoredCheckpoint.canonicalCheckpointBytes.fill(0);
                      }
                  })();
            if (begin.kind === 'refused') {
                operationResult = Object.freeze({
                    isValid: false,
                    refusalReason: begin.refusalReason,
                });
            } else {
                preparedHandle = 0;
                operationHandle = begin.operationHandle;
                for (;;) {
                    throwIfCompactPublicKeyVerificationCancelled(signal);
                    const poll =
                        kernel.pollAcceptedSetupCompactPublicKeyVerification(
                            operationHandle,
                            maximumWorkUnitCountPerPoll,
                        );
                    switch (poll.kind) {
                        case 'progress':
                            if (
                                deterministicReplayComplete &&
                                checkpointCustody !== undefined &&
                                poll.checkpointSafeBoundaryOrdinal !== undefined
                            ) {
                                await publishCompactPublicKeyVerificationCheckpoint(
                                    kernel,
                                    operationHandle,
                                    checkpointCustody,
                                    poll.checkpointSafeBoundaryOrdinal,
                                );
                            }
                            await yieldControl();
                            break;
                        case 'resume-complete':
                            if (
                                !resumed ||
                                deterministicReplayComplete ||
                                poll.checkpointSafeBoundaryOrdinal !==
                                    expectedResumeSafeBoundaryOrdinal
                            ) {
                                throw new CanonicalStreamInternalError(
                                    'The accepted-setup compact verifier replayed a different checkpoint boundary than authenticated custody restored.',
                                );
                            }
                            deterministicReplayComplete = true;
                            await yieldControl();
                            break;
                        case 'refused':
                            operationHandle = 0;
                            operationResult = Object.freeze({
                                isValid: false,
                                refusalReason: poll.refusalReason,
                            });
                            break;
                        case 'complete': {
                            if (!deterministicReplayComplete) {
                                throw new CanonicalStreamInternalError(
                                    'The accepted-setup compact verifier completed before deterministic checkpoint replay.',
                                );
                            }
                            operationHandle = 0;
                            verifiedCapabilityHandle =
                                poll.verifiedCapabilityHandle;
                            const refusalReason =
                                kernel.finishAcceptedSetupCompactPublicKeyVerification(
                                    verifiedCapabilityHandle,
                                );
                            if (refusalReason === undefined) {
                                verifiedCapabilityHandle = 0;
                                operationResult = Object.freeze({
                                    isValid: true,
                                    value: undefined,
                                });
                            } else {
                                operationResult = Object.freeze({
                                    isValid: false,
                                    refusalReason,
                                });
                            }
                            break;
                        }
                    }
                    if (operationResult !== undefined) {
                        break;
                    }
                }
            }
        }
    } catch (error) {
        operationFailure = error;
    }

    const cleanupFailures: unknown[] = [];
    if (verifiedCapabilityHandle !== 0) {
        try {
            kernel.discardAcceptedSetupCompactPublicKeyCapability(
                verifiedCapabilityHandle,
            );
        } catch (cleanupFailure) {
            cleanupFailures.push(cleanupFailure);
        }
    }
    if (operationHandle !== 0) {
        try {
            kernel.cancelAcceptedSetupCompactPublicKeyVerification(
                operationHandle,
            );
        } catch (cleanupFailure) {
            cleanupFailures.push(cleanupFailure);
        }
    }
    if (preparedHandle !== 0) {
        try {
            kernel.discardAcceptedSetupCompactPublicKeyPreparedVerification(
                preparedHandle,
            );
        } catch (cleanupFailure) {
            cleanupFailures.push(cleanupFailure);
        }
    }
    for (const adoptedCheckpointCustody of new Set(
        adoptedCheckpointCustodies,
    )) {
        try {
            await adoptedCheckpointCustody.release();
        } catch (cleanupFailure) {
            cleanupFailures.push(cleanupFailure);
        }
    }
    if (cleanupFailures.length > 0) {
        throw new CanonicalStreamInternalError(
            'Accepted-setup compact public-key verification failed to retire all worker-owned authority.',
            Object.freeze({ cleanupFailures, operationFailure }),
        );
    }
    if (operationFailure !== undefined) {
        if (operationFailure instanceof Error) {
            throw operationFailure;
        }
        throw new CanonicalStreamInternalError(
            'Accepted-setup compact public-key verification failed with a non-error value.',
            operationFailure,
        );
    }
    if (operationResult === undefined) {
        throw new CanonicalStreamInternalError(
            'The accepted-setup compact public-key verifier returned no terminal result.',
        );
    }
    return operationResult;
};

/** Verifies and inserts one selected same-secret proof into its exact slot. */
export const verifyAcceptedSetupSameSecretInClosedWorker = (
    input: AcceptedSetupSameSecretProofVerificationInput,
): Promise<void> =>
    verifyAcceptedSetupProofInClosedWorker(
        'sameSecret',
        input,
        {
            canonicalApplicationStatementBytes:
                input.canonicalApplicationStatementBytes,
            kind: 'transported',
        },
        input.vssLowDegreeEvidence,
    );

/** Verifies and inserts one selected public-key-share proof into its exact slot. */
export const verifyAcceptedSetupPublicKeyShareInClosedWorker = (
    input: AcceptedSetupProofVerificationInput,
): Promise<void> =>
    verifyAcceptedSetupProofInClosedWorker(
        'publicKeyShare',
        input,
        {
            canonicalApplicationStatementBytes:
                input.canonicalApplicationStatementBytes,
            kind: 'transported',
        },
        undefined,
    );

/**
 * Internal same-worker handoff that requires a locally generated same-secret
 * proof to match the positive accepted-package verifier terminal exactly.
 */
export const verifyGeneratedAcceptedSetupSameSecretCapabilityInClosedWorker = (
    input: AcceptedSetupProofVerificationCoreInput,
    generatedCommonProofCapability: ClosedWorkerGeneratedCommonProofCapability,
    generationStatementSourceHandle: number,
): Promise<void> =>
    verifyAcceptedSetupProofInClosedWorker(
        'sameSecret',
        input,
        {
            generatedCommonProofCapability,
            generationStatementSourceHandle,
            kind: 'generated',
        },
        undefined,
    );

/**
 * Internal same-worker handoff that requires a locally generated public-key-
 * share proof to match the positive accepted-package verifier terminal exactly.
 */
export const verifyGeneratedAcceptedSetupPublicKeyShareCapabilityInClosedWorker =
    (
        input: AcceptedSetupProofVerificationCoreInput,
        generatedCommonProofCapability: ClosedWorkerGeneratedCommonProofCapability,
        generationStatementSourceHandle: number,
    ): Promise<void> =>
        verifyAcceptedSetupProofInClosedWorker(
            'publicKeyShare',
            input,
            {
                generatedCommonProofCapability,
                generationStatementSourceHandle,
                kind: 'generated',
            },
            undefined,
        );
