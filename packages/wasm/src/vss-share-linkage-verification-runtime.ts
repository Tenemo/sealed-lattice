import { foundationProfile, refusalReasonCodes } from '@sealed-lattice/types';

import { isUint8Array } from './byte-array.js';
import {
    resolveVerifiedTranscriptObjectKernelAuthorization,
    type VerifiedTranscriptObject,
} from './canonical-board-runtime.js';
import {
    CanonicalStreamInternalError,
    CanonicalStreamRefusalError,
    CanonicalStreamResourceError,
} from './canonical-stream-runtime.js';
import {
    applyClosedWorkerVerifiedCommonProofCapability,
    openClosedWorkerCommonProofVerificationFamilyAdapter,
    releaseClosedWorkerCommonProofVerificationFamilyAdapter,
    runClosedWorkerCommonProofVerificationFamilyAdapter,
    type AuthenticatedCommonProofInputStore,
    type ClosedWorkerCommonProofVerificationFamilyAdapter,
    type CommonProofVerificationWorkerOptions,
} from './common-proof-worker-runtime/runtime.js';
import { resolveCommonProofKernelContext } from './transcript-core-bridge/common-proof-kernel-context.js';
import type { TranscriptCoreKernelCommandRuntime } from './transcript-core-bridge/kernel-runtime.js';
import type { TranscriptCoreKernel } from './transcript-core-bridge/kernel-types.js';
import { WasmMemoryBoundary } from './wasm-memory-boundary.js';
import { WasmStatusBoundary } from './wasm-status-boundary.js';

const boardVerifierCapabilityByteLength = 32;
const wasm32HandleByteLength = Uint32Array.BYTES_PER_ELEMENT;
const maximumWasm32UnsignedInteger = 0xffff_ffff;

const verifiedVssShareLinkageTerminalBrand: unique symbol = Symbol(
    'sealed-lattice/verified-vss-share-linkage-terminal',
);
const verifiedVssLowDegreeEvidenceBrand: unique symbol = Symbol(
    'sealed-lattice/verified-vss-low-degree-evidence',
);

/** One positive VSS relation result retained by the exact WASM worker. */
export type VerifiedVssShareLinkageTerminal = Readonly<{
    readonly [verifiedVssShareLinkageTerminalBrand]: true;
    release(): void;
}>;

/** One-shot VSS low-degree authority for the exact same-secret construction. */
export type VerifiedVssLowDegreeEvidence = Readonly<{
    readonly [verifiedVssLowDegreeEvidenceBrand]: true;
    release(): void;
}>;

type VerifiedVssShareLinkageTerminalRecord = Readonly<{
    context: TranscriptCoreKernelCommandRuntime;
    handle: number;
    kernel: TranscriptCoreKernel;
}>;

const verifiedVssShareLinkageTerminalRecords = new WeakMap<
    VerifiedVssShareLinkageTerminal,
    VerifiedVssShareLinkageTerminalRecord
>();
const verifiedVssLowDegreeEvidenceRecords = new WeakMap<
    VerifiedVssLowDegreeEvidence,
    VerifiedVssShareLinkageTerminalRecord
>();

type VssVerificationKernel = Readonly<{
    boardObjectHandleCatalogByteLength(): number;
    discardTerminalSource(terminalSourceHandle: number): number;
    discardVerifiedTerminal(terminalHandle: number): number;
    discardLowDegreeEvidence(evidenceHandle: number): number;
    finishVerification(
        verifiedCommonProofHandle: number,
        terminalSourceHandle: number,
        statusPointer: number,
    ): number;
    finishLowDegreeEvidence(
        verifiedCommonProofHandle: number,
        terminalSourceHandle: number,
        statusPointer: number,
    ): number;
    prepareVerification(
        selectedSuiteHandle: number,
        boardVerifierSessionHandle: number,
        boardVerifierSessionCapabilityPointer: number,
        boardVerifierSessionCapabilityByteLength: number,
        orderedObjectHandleBytesPointer: number,
        orderedObjectHandleBytesByteLength: number,
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

export type OrderedVerifiedBoardObjectAuthorization = Readonly<{
    capabilityPointer: number;
    handleBytes: Uint8Array<ArrayBuffer>;
    sessionHandle: number;
}>;

const createStatusBoundary = (): WasmStatusBoundary =>
    new WasmStatusBoundary({
        createInternalError: (message) =>
            new CanonicalStreamInternalError(message),
        createRefusalError: (refusalReason) =>
            new CanonicalStreamRefusalError(refusalReason),
        createResourceError: () => new CanonicalStreamResourceError(),
        internalFailureMessage:
            'The VSS relation kernel session failed internally.',
        unknownStatusMessage:
            'The VSS relation kernel returned an unknown status code.',
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

const requireCanonicalSuiteRecordBytes = (value: Uint8Array): Uint8Array => {
    if (!isUint8Array(value) || value.byteLength === 0) {
        throw new CanonicalStreamRefusalError('wrongTypeOrLength');
    }
    return value;
};

const requireVssVerificationKernel = (
    context: TranscriptCoreKernelCommandRuntime,
): VssVerificationKernel => {
    const {
        sealed_lattice_common_proof_release_suite: releaseSelectedSuite,
        sealed_lattice_common_proof_select_suite: selectSuite,
        sealed_lattice_vss_share_linkage_board_object_handle_catalog_byte_length:
            boardObjectHandleCatalogByteLength,
        sealed_lattice_vss_share_linkage_discard_verification_terminal_source:
            discardTerminalSource,
        sealed_lattice_vss_share_linkage_discard_verified_terminal:
            discardVerifiedTerminal,
        sealed_lattice_vss_share_linkage_discard_low_degree_evidence:
            discardLowDegreeEvidence,
        sealed_lattice_vss_share_linkage_finish_verification:
            finishVerification,
        sealed_lattice_vss_share_linkage_finish_low_degree_evidence:
            finishLowDegreeEvidence,
        sealed_lattice_vss_share_linkage_prepare_verification:
            prepareVerification,
    } = context.wasmExports;
    if (
        typeof releaseSelectedSuite !== 'function' ||
        typeof selectSuite !== 'function' ||
        typeof boardObjectHandleCatalogByteLength !== 'function' ||
        typeof discardTerminalSource !== 'function' ||
        typeof discardVerifiedTerminal !== 'function' ||
        typeof discardLowDegreeEvidence !== 'function' ||
        typeof finishVerification !== 'function' ||
        typeof finishLowDegreeEvidence !== 'function' ||
        typeof prepareVerification !== 'function'
    ) {
        throw new CanonicalStreamInternalError(
            'The transcript-core kernel lacks the VSS verification boundary.',
        );
    }
    return Object.freeze({
        boardObjectHandleCatalogByteLength,
        discardTerminalSource,
        discardVerifiedTerminal,
        discardLowDegreeEvidence,
        finishLowDegreeEvidence,
        finishVerification,
        prepareVerification,
        releaseSelectedSuite,
        selectSuite,
    });
};

export const resolveOrderedVerifiedBoardObjectAuthorization = (input: {
    context: TranscriptCoreKernelCommandRuntime;
    expectedObjectCount: number;
    kernel: TranscriptCoreKernel;
    objects: readonly VerifiedTranscriptObject[];
}): OrderedVerifiedBoardObjectAuthorization => {
    if (
        input.objects.length !== input.expectedObjectCount ||
        input.objects.length === 0
    ) {
        throw new CanonicalStreamRefusalError('wrongTypeOrLength');
    }
    const authorizations = input.objects.map((object) =>
        resolveVerifiedTranscriptObjectKernelAuthorization(
            object,
            input.kernel,
        ),
    );
    const firstAuthorization = authorizations[0];
    if (
        firstAuthorization.capabilityMemory !== input.context.memory ||
        firstAuthorization.capabilityPointer <= 0 ||
        firstAuthorization.capabilityPointer +
            boardVerifierCapabilityByteLength >
            input.context.memory.buffer.byteLength
    ) {
        throw new CanonicalStreamInternalError(
            'The canonical-board authority does not belong to the common-proof WASM worker.',
        );
    }
    const handleBytes = new Uint8Array(
        input.expectedObjectCount * wasm32HandleByteLength,
    );
    const handleView = new DataView(handleBytes.buffer);
    authorizations.forEach((authorization, objectIndex) => {
        if (
            authorization.capabilityMemory !==
                firstAuthorization.capabilityMemory ||
            authorization.capabilityPointer !==
                firstAuthorization.capabilityPointer ||
            authorization.sessionHandle !== firstAuthorization.sessionHandle
        ) {
            throw new CanonicalStreamRefusalError('wrongContext');
        }
        handleView.setUint32(
            objectIndex * wasm32HandleByteLength,
            requireLiveHandle(
                authorization.objectHandle,
                'A canonical-board object handle',
            ),
            true,
        );
    });
    return Object.freeze({
        capabilityPointer: firstAuthorization.capabilityPointer,
        handleBytes,
        sessionHandle: requireLiveHandle(
            firstAuthorization.sessionHandle,
            'The canonical-board verifier session handle',
        ),
    });
};

export const resolveAggregatePublicRandomnessBoardAuthorization = (input: {
    context: TranscriptCoreKernelCommandRuntime;
    kernel: TranscriptCoreKernel;
    orderedCommitmentObjects: readonly VerifiedTranscriptObject[];
    orderedRevealObjects: readonly VerifiedTranscriptObject[];
    orderedSetupIntentObjects: readonly VerifiedTranscriptObject[];
}): OrderedVerifiedBoardObjectAuthorization =>
    resolveOrderedVerifiedBoardObjectAuthorization({
        context: input.context,
        expectedObjectCount: foundationProfile.participantCount * 3,
        kernel: input.kernel,
        objects: [
            ...input.orderedSetupIntentObjects,
            ...input.orderedCommitmentObjects,
            ...input.orderedRevealObjects,
        ],
    });

const discardHandle = (input: {
    context: TranscriptCoreKernelCommandRuntime;
    discard(handle: number): number;
    handle: number;
    operationName: string;
    statusBoundary: WasmStatusBoundary;
}): void => {
    const status = input.context.runExclusive(input.operationName, () =>
        input.discard(input.handle),
    );
    if (status >>> 0 === refusalReasonCodes.consumedState) {
        return;
    }
    input.statusBoundary.throwIfError(status);
};

const releaseTerminal = (terminal: VerifiedVssShareLinkageTerminal): void => {
    const record = verifiedVssShareLinkageTerminalRecords.get(terminal);
    if (record === undefined) {
        throw new CanonicalStreamRefusalError('consumedState');
    }
    verifiedVssShareLinkageTerminalRecords.delete(terminal);
    const kernel = requireVssVerificationKernel(record.context);
    discardHandle({
        context: record.context,
        discard: kernel.discardVerifiedTerminal,
        handle: record.handle,
        operationName: 'VSS verified-terminal release',
        statusBoundary: createStatusBoundary(),
    });
};

const createVerifiedTerminal = (
    record: VerifiedVssShareLinkageTerminalRecord,
): VerifiedVssShareLinkageTerminal => {
    const terminal: VerifiedVssShareLinkageTerminal = Object.freeze({
        [verifiedVssShareLinkageTerminalBrand]: true as const,
        release: () => releaseTerminal(terminal),
    });
    verifiedVssShareLinkageTerminalRecords.set(terminal, record);
    return terminal;
};

const releaseLowDegreeEvidence = (
    evidence: VerifiedVssLowDegreeEvidence,
): void => {
    const record = verifiedVssLowDegreeEvidenceRecords.get(evidence);
    if (record === undefined) {
        throw new CanonicalStreamRefusalError('consumedState');
    }
    verifiedVssLowDegreeEvidenceRecords.delete(evidence);
    const kernel = requireVssVerificationKernel(record.context);
    discardHandle({
        context: record.context,
        discard: kernel.discardLowDegreeEvidence,
        handle: record.handle,
        operationName: 'VSS low-degree evidence release',
        statusBoundary: createStatusBoundary(),
    });
};

const createVerifiedLowDegreeEvidence = (
    record: VerifiedVssShareLinkageTerminalRecord,
): VerifiedVssLowDegreeEvidence => {
    const evidence: VerifiedVssLowDegreeEvidence = Object.freeze({
        [verifiedVssLowDegreeEvidenceBrand]: true as const,
        release: () => releaseLowDegreeEvidence(evidence),
    });
    verifiedVssLowDegreeEvidenceRecords.set(evidence, record);
    return evidence;
};

/** Internal one-shot ownership transfer into same-secret generation or verification. */
export const consumeVerifiedVssLowDegreeEvidence = <Result>(input: {
    consume(evidenceHandle: number): Result;
    context: TranscriptCoreKernelCommandRuntime;
    evidence: VerifiedVssLowDegreeEvidence;
    kernel: TranscriptCoreKernel;
}): Result => {
    const record = verifiedVssLowDegreeEvidenceRecords.get(input.evidence);
    if (
        record === undefined ||
        record.context !== input.context ||
        record.kernel !== input.kernel
    ) {
        throw new CanonicalStreamRefusalError('wrongContext');
    }
    verifiedVssLowDegreeEvidenceRecords.delete(input.evidence);
    try {
        return input.consume(record.handle);
    } catch (operationFailure) {
        try {
            discardHandle({
                context: input.context,
                discard: requireVssVerificationKernel(input.context)
                    .discardLowDegreeEvidence,
                handle: record.handle,
                operationName:
                    'VSS uncertain low-degree evidence transfer cleanup',
                statusBoundary: createStatusBoundary(),
            });
        } catch (cleanupFailure) {
            throw new CanonicalStreamInternalError(
                'The VSS low-degree evidence transfer failed and its token could not be retired.',
                Object.freeze({ cleanupFailure, operationFailure }),
            );
        }
        throw operationFailure;
    }
};

/**
 * Internal atomic ownership transfer into the aggregate recipient authority.
 * Entering the callback poisons every wrapper because Rust may have consumed
 * any or all terminal handles before a trapping or otherwise uncertain return.
 */
export const consumeOrderedVerifiedVssShareLinkageTerminals = <Result>(input: {
    consume(orderedTerminalHandles: readonly number[]): Result;
    context: TranscriptCoreKernelCommandRuntime;
    kernel: TranscriptCoreKernel;
    orderedTerminals: readonly VerifiedVssShareLinkageTerminal[];
}): Result => {
    if (input.orderedTerminals.length !== foundationProfile.participantCount) {
        throw new CanonicalStreamRefusalError('wrongTypeOrLength');
    }
    const records = input.orderedTerminals.map((terminal) => {
        const record = verifiedVssShareLinkageTerminalRecords.get(terminal);
        if (
            record === undefined ||
            record.context !== input.context ||
            record.kernel !== input.kernel
        ) {
            throw new CanonicalStreamRefusalError('wrongContext');
        }
        return record;
    });
    for (const terminal of input.orderedTerminals) {
        verifiedVssShareLinkageTerminalRecords.delete(terminal);
    }
    try {
        return input.consume(records.map((record) => record.handle));
    } catch (operationFailure) {
        const cleanupFailures: unknown[] = [];
        const statusBoundary = createStatusBoundary();
        const kernel = requireVssVerificationKernel(input.context);
        for (const record of records) {
            try {
                discardHandle({
                    context: input.context,
                    discard: kernel.discardVerifiedTerminal,
                    handle: record.handle,
                    operationName:
                        'VSS uncertain aggregate-authority transfer cleanup',
                    statusBoundary,
                });
            } catch (cleanupFailure) {
                cleanupFailures.push(cleanupFailure);
            }
        }
        if (cleanupFailures.length > 0) {
            throw new CanonicalStreamInternalError(
                'The aggregate recipient-authority transfer failed and its VSS terminals could not all be retired.',
                Object.freeze({ cleanupFailures, operationFailure }),
            );
        }
        throw operationFailure;
    }
};

const selectSuite = (input: {
    canonicalSuiteRecordBytes: Uint8Array;
    context: TranscriptCoreKernelCommandRuntime;
    kernel: VssVerificationKernel;
    memoryBoundary: WasmMemoryBoundary;
    statusBoundary: WasmStatusBoundary;
}): number =>
    input.context.runExclusive('VSS selected-suite acquisition', () => {
        const suiteBytes = requireCanonicalSuiteRecordBytes(
            input.canonicalSuiteRecordBytes,
        );
        const suitePointer = input.memoryBoundary.copy(suiteBytes);
        const statusPointer = input.memoryBoundary.allocateZeroedWords(1);
        let selectedSuiteHandle = 0;
        try {
            selectedSuiteHandle = input.kernel.selectSuite(
                suitePointer,
                suiteBytes.byteLength,
                statusPointer,
            );
            const [status] = input.memoryBoundary.readWords(statusPointer, 1);
            input.statusBoundary.throwIfError(status);
            return requireLiveHandle(
                selectedSuiteHandle,
                'The selected-suite handle',
            );
        } catch (error) {
            if (selectedSuiteHandle !== 0) {
                input.kernel.releaseSelectedSuite(selectedSuiteHandle);
            }
            throw error;
        } finally {
            input.memoryBoundary.zeroAndDeallocate(
                statusPointer,
                wasm32HandleByteLength,
            );
            input.memoryBoundary.zeroAndDeallocate(
                suitePointer,
                suiteBytes.byteLength,
            );
        }
    });

const discardTerminalSource = (input: {
    context: TranscriptCoreKernelCommandRuntime;
    handle: number;
    kernel: VssVerificationKernel;
    statusBoundary: WasmStatusBoundary;
}): void =>
    discardHandle({
        context: input.context,
        discard: input.kernel.discardTerminalSource,
        handle: input.handle,
        operationName: 'VSS verification terminal-source discard',
        statusBoundary: input.statusBoundary,
    });

type VssShareLinkageVerificationOutput =
    | VerifiedVssLowDegreeEvidence
    | VerifiedVssShareLinkageTerminal;

const verifyVssShareLinkageOutputInClosedWorker = async (
    input: {
        canonicalSuiteRecordBytes: Uint8Array;
        dealerRecordObject: VerifiedTranscriptObject;
        inputStore: AuthenticatedCommonProofInputStore;
        kernel: TranscriptCoreKernel;
        options?: CommonProofVerificationWorkerOptions;
        orderedCommitmentObjects: readonly VerifiedTranscriptObject[];
        orderedRevealObjects: readonly VerifiedTranscriptObject[];
        orderedSetupIntentObjects: readonly VerifiedTranscriptObject[];
    },
    outputKind: 'lowDegreeEvidence' | 'terminal',
): Promise<VssShareLinkageVerificationOutput> => {
    if (typeof globalThis.document !== 'undefined') {
        throw new CanonicalStreamInternalError(
            'VSS proof verification may only run inside the dedicated WASM worker.',
        );
    }
    const context = resolveCommonProofKernelContext(input.kernel);
    if (context === undefined) {
        throw new CanonicalStreamInternalError(
            'The loaded WASM kernel has no common-proof worker context.',
        );
    }
    const kernel = requireVssVerificationKernel(context);
    const statusBoundary = createStatusBoundary();
    const memoryBoundary = new WasmMemoryBoundary({
        context,
        createInternalError: (message) =>
            new CanonicalStreamInternalError(message),
        createResourceError: (message) =>
            new CanonicalStreamResourceError(message),
        label: 'VSS verification boundary',
    });
    const orderedAuthorization = resolveOrderedVerifiedBoardObjectAuthorization(
        {
            context,
            expectedObjectCount: foundationProfile.participantCount * 3 + 1,
            kernel: input.kernel,
            objects: [
                ...input.orderedSetupIntentObjects,
                ...input.orderedCommitmentObjects,
                ...input.orderedRevealObjects,
                input.dealerRecordObject,
            ],
        },
    );
    const expectedCatalogByteLength = context.runExclusive(
        'VSS board-object catalog length',
        () => kernel.boardObjectHandleCatalogByteLength(),
    );
    if (
        expectedCatalogByteLength !==
        orderedAuthorization.handleBytes.byteLength
    ) {
        throw new CanonicalStreamInternalError(
            'The VSS verifier and browser adapter disagree on the exact board-object catalog length.',
        );
    }

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
    let verifiedOutput: VssShareLinkageVerificationOutput | undefined;
    try {
        const prepared = context.runExclusive(
            'VSS verification preparation',
            () => {
                const catalogPointer = memoryBoundary.copy(
                    orderedAuthorization.handleBytes,
                );
                const metadataPointer = memoryBoundary.allocateZeroedWords(2);
                try {
                    const adapterHandle = kernel.prepareVerification(
                        selectedSuiteHandle,
                        orderedAuthorization.sessionHandle,
                        orderedAuthorization.capabilityPointer,
                        boardVerifierCapabilityByteLength,
                        catalogPointer,
                        orderedAuthorization.handleBytes.byteLength,
                        metadataPointer,
                        metadataPointer + wasm32HandleByteLength,
                    );
                    const [sourceHandle, status] = memoryBoundary.readWords(
                        metadataPointer,
                        2,
                    );
                    statusBoundary.throwIfError(status);
                    return Object.freeze({
                        adapterHandle: requireLiveHandle(
                            adapterHandle,
                            'The VSS common-proof verification adapter handle',
                        ),
                        terminalSourceHandle: requireLiveHandle(
                            sourceHandle,
                            'The VSS verification terminal-source handle',
                        ),
                    });
                } finally {
                    memoryBoundary.zeroAndDeallocate(
                        metadataPointer,
                        wasm32HandleByteLength * 2,
                    );
                    memoryBoundary.zeroAndDeallocate(
                        catalogPointer,
                        orderedAuthorization.handleBytes.byteLength,
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
            'VSS selected-suite release',
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
        const verificationFinish = (() => {
            try {
                return applyClosedWorkerVerifiedCommonProofCapability(
                    verifiedCommonProof,
                    context,
                    (verifiedCommonProofHandle) =>
                        context.runExclusive('VSS verification finish', () => {
                            const statusPointer =
                                memoryBoundary.allocateZeroedWords(1);
                            try {
                                const handle =
                                    outputKind === 'lowDegreeEvidence'
                                        ? kernel.finishLowDegreeEvidence(
                                              verifiedCommonProofHandle,
                                              terminalSourceHandle,
                                              statusPointer,
                                          )
                                        : kernel.finishVerification(
                                              verifiedCommonProofHandle,
                                              terminalSourceHandle,
                                              statusPointer,
                                          );
                                const [status] = memoryBoundary.readWords(
                                    statusPointer,
                                    1,
                                );
                                return Object.freeze({
                                    consumed: status === 0,
                                    result: Object.freeze({ handle, status }),
                                });
                            } finally {
                                memoryBoundary.zeroAndDeallocate(
                                    statusPointer,
                                    wasm32HandleByteLength,
                                );
                            }
                        }),
                );
            } catch (handoffFailure) {
                try {
                    verifiedCommonProof.release();
                } catch (cleanupFailure) {
                    throw new CanonicalStreamInternalError(
                        'The failed VSS proof handoff could not release its generic verifier authority.',
                        Object.freeze({ cleanupFailure, handoffFailure }),
                    );
                }
                throw handoffFailure;
            }
        })();
        if (verificationFinish.status !== 0) {
            try {
                verifiedCommonProof.release();
            } catch (cleanupFailure) {
                throw new CanonicalStreamInternalError(
                    'The refused VSS proof handoff could not release its generic verifier authority.',
                    Object.freeze({
                        cleanupFailure,
                        status: verificationFinish.status,
                    }),
                );
            }
            statusBoundary.throwIfError(verificationFinish.status);
        }
        const outputHandle = requireLiveHandle(
            verificationFinish.handle,
            outputKind === 'lowDegreeEvidence'
                ? 'The verified VSS low-degree evidence handle'
                : 'The verified VSS relation terminal handle',
        );
        terminalSourceHandle = 0;
        try {
            const outputRecord = {
                context,
                handle: outputHandle,
                kernel: input.kernel,
            };
            verifiedOutput =
                outputKind === 'lowDegreeEvidence'
                    ? createVerifiedLowDegreeEvidence(outputRecord)
                    : createVerifiedTerminal(outputRecord);
        } catch (terminalAdoptionFailure) {
            try {
                discardHandle({
                    context,
                    discard:
                        outputKind === 'lowDegreeEvidence'
                            ? kernel.discardLowDegreeEvidence
                            : kernel.discardVerifiedTerminal,
                    handle: outputHandle,
                    operationName:
                        outputKind === 'lowDegreeEvidence'
                            ? 'VSS low-degree evidence adoption discard'
                            : 'VSS verified-terminal adoption discard',
                    statusBoundary,
                });
            } catch (cleanupFailure) {
                throw new CanonicalStreamInternalError(
                    'The verified VSS output could not be adopted or retired.',
                    Object.freeze({
                        cleanupFailure,
                        operationFailure: terminalAdoptionFailure,
                    }),
                );
            }
            throw terminalAdoptionFailure;
        }
    } catch (error) {
        operationFailed = true;
        operationFailure = error;
    }

    const cleanupFailures: unknown[] = [];
    if (selectedSuiteHandle !== 0) {
        try {
            const status = context.runExclusive(
                'VSS selected-suite failure release',
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
            'VSS verification failed to retire all worker-owned authority.',
            Object.freeze({ cleanupFailures, operationFailure }),
        );
    }
    if (operationFailed) {
        throw operationFailure;
    }
    if (verifiedOutput === undefined) {
        throw new CanonicalStreamInternalError(
            'VSS verification completed without its requested output.',
        );
    }
    return verifiedOutput;
};

/** Verifies VSS and returns the broad one-shot family terminal. */
export const verifyVssShareLinkageInClosedWorker = async (
    input: Parameters<typeof verifyVssShareLinkageOutputInClosedWorker>[0],
): Promise<VerifiedVssShareLinkageTerminal> =>
    (await verifyVssShareLinkageOutputInClosedWorker(
        input,
        'terminal',
    )) as VerifiedVssShareLinkageTerminal;

/** Verifies VSS and returns only the one-shot same-secret low-degree authority. */
export const verifyVssLowDegreeEvidenceInClosedWorker = async (
    input: Parameters<typeof verifyVssShareLinkageOutputInClosedWorker>[0],
): Promise<VerifiedVssLowDegreeEvidence> =>
    (await verifyVssShareLinkageOutputInClosedWorker(
        input,
        'lowDegreeEvidence',
    )) as VerifiedVssLowDegreeEvidence;
