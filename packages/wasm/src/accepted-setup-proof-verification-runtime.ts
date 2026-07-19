import { refusalReasonCodes } from '@sealed-lattice/types';

import {
    requireAcceptedSetupVerificationAssemblyKernelOwner,
    type AcceptedSetupVerificationSession,
} from './accepted-setup-assembly-runtime.js';
import { isUint8Array } from './byte-array.js';
import {
    CanonicalStreamCleanupError,
    CanonicalStreamInternalError,
    CanonicalStreamRefusalError,
    CanonicalStreamResourceError,
} from './canonical-stream-runtime.js';
import {
    applyClosedWorkerGeneratedCommonProofCapability,
    applyClosedWorkerVerifiedCommonProofCapability,
    openClosedWorkerCommonProofVerificationFamilyAdapter,
    releaseClosedWorkerCommonProofVerificationFamilyAdapter,
    runClosedWorkerCommonProofVerificationFamilyAdapter,
    type AuthenticatedCommonProofInputStore,
    type ClosedWorkerCommonProofVerificationFamilyAdapter,
    type ClosedWorkerGeneratedCommonProofCapability,
    type CommonProofVerificationWorkerOptions,
} from './common-proof-worker-runtime/runtime.js';
import { resolveCommonProofKernelContext } from './transcript-core-bridge/common-proof-kernel-context.js';
import type { TranscriptCoreKernelCommandRuntime } from './transcript-core-bridge/kernel-runtime.js';
import type { TranscriptCoreKernel } from './transcript-core-bridge/kernel-types.js';
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
    const prepareVerification =
        family === 'sameSecret'
            ? context.wasmExports
                  .sealed_lattice_accepted_setup_same_secret_prepare_verification
            : context.wasmExports
                  .sealed_lattice_accepted_setup_public_key_share_prepare_verification;
    const prepareGeneratedVerification =
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
        typeof prepareVerification !== 'function' ||
        typeof prepareGeneratedVerification !== 'function' ||
        typeof finishVerification !== 'function' ||
        typeof finishGeneratedVerification !== 'function' ||
        typeof discardTerminalSource !== 'function'
    ) {
        throw new CanonicalStreamInternalError(
            `The transcript-core kernel lacks the accepted-setup ${family} verification boundary.`,
        );
    }
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
                    const adapterHandle =
                        source.kind === 'generated'
                            ? kernel.prepareGeneratedVerification(
                                  selectedSuiteHandle,
                                  assemblyOwner.handle,
                                  source.generationStatementSourceHandle,
                                  metadataPointer,
                                  metadataPointer + wasm32WordByteLength,
                              )
                            : kernel.prepareVerification(
                                  selectedSuiteHandle,
                                  assemblyOwner.handle,
                                  statementPointer,
                                  statementByteLength,
                                  metadataPointer,
                                  metadataPointer + wasm32WordByteLength,
                              );
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

/** Verifies and inserts one selected same-secret proof into its exact slot. */
export const verifyAcceptedSetupSameSecretInClosedWorker = (
    input: AcceptedSetupProofVerificationInput,
): Promise<void> =>
    verifyAcceptedSetupProofInClosedWorker('sameSecret', input, {
        canonicalApplicationStatementBytes:
            input.canonicalApplicationStatementBytes,
        kind: 'transported',
    });

/** Verifies and inserts one selected public-key-share proof into its exact slot. */
export const verifyAcceptedSetupPublicKeyShareInClosedWorker = (
    input: AcceptedSetupProofVerificationInput,
): Promise<void> =>
    verifyAcceptedSetupProofInClosedWorker('publicKeyShare', input, {
        canonicalApplicationStatementBytes:
            input.canonicalApplicationStatementBytes,
        kind: 'transported',
    });

/**
 * Internal same-worker handoff that requires a locally generated same-secret
 * proof to match the positive accepted-package verifier terminal exactly.
 */
export const verifyGeneratedAcceptedSetupSameSecretCapabilityInClosedWorker = (
    input: AcceptedSetupProofVerificationCoreInput,
    generatedCommonProofCapability: ClosedWorkerGeneratedCommonProofCapability,
    generationStatementSourceHandle: number,
): Promise<void> =>
    verifyAcceptedSetupProofInClosedWorker('sameSecret', input, {
        generatedCommonProofCapability,
        generationStatementSourceHandle,
        kind: 'generated',
    });

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
        verifyAcceptedSetupProofInClosedWorker('publicKeyShare', input, {
            generatedCommonProofCapability,
            generationStatementSourceHandle,
            kind: 'generated',
        });
