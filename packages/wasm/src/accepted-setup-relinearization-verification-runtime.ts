import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { foundationProfile, refusalReasonCodes } from '@sealed-lattice/types';

import {
    readAcceptedSetupPrepackageEvaluatorComponentExactRange,
    requireAcceptedSetupEvaluatorSourceCatalogKernelOwner,
    requireAcceptedSetupVerificationAssemblyKernelOwner,
    type AcceptedSetupEvaluatorSourceCatalogSession,
    type AcceptedSetupVerificationSession,
} from './accepted-setup-assembly-runtime.js';
import { isUint8Array } from './byte-array.js';
import {
    CanonicalStreamInternalError,
    CanonicalStreamRefusalError,
    CanonicalStreamResourceError,
    deriveCanonicalStreamChunkCount,
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
import type {
    TranscriptCoreKernel,
    TranscriptCoreKernelExports,
} from './transcript-core-bridge/kernel-types.js';
import { WasmMemoryBoundary } from './wasm-memory-boundary.js';
import { WasmStatusBoundary } from './wasm-status-boundary.js';

const materialRootByteLength = 64;
const wasm32WordByteLength = Uint32Array.BYTES_PER_ELEMENT;
const maximumWasm32UnsignedInteger = 0xffff_ffff;

type AcceptedSetupRelinearizationProofFamily =
    | 'roundOne'
    | 'roundOneAggregate'
    | 'roundTwo';

/** Canonical public bindings needed to replay one relinearization component. */
export type AcceptedSetupRelinearizationComponentDescription = Readonly<{
    materialRoot: Uint8Array<ArrayBuffer>;
    streamDescriptorBytes: Uint8Array<ArrayBuffer>;
}>;

/** Browser-worker inputs for one exact accepted-setup relinearization proof. */
export type AcceptedSetupRelinearizationVerificationInput = Readonly<{
    acceptedSetupVerification: AcceptedSetupVerificationSession;
    canonicalApplicationStatementBytes: Uint8Array;
    canonicalSuiteRecordBytes: Uint8Array;
    components: readonly AcceptedSetupRelinearizationComponentDescription[];
    evaluatorSourceCatalog: AcceptedSetupEvaluatorSourceCatalogSession;
    inputStore: AuthenticatedCommonProofInputStore;
    kernel: TranscriptCoreKernel;
    options?: CommonProofVerificationWorkerOptions;
}>;

type RelinearizationVerificationKernel = Readonly<{
    absorbComponentChunk: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_relinearization_verification_component_absorb_chunk']
    >;
    beginComponent: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_relinearization_verification_component_begin']
    >;
    beginVerificationIngress(
        selectedSuiteHandle: number,
        verificationAssemblyHandle: number,
        prepackageCatalogHandle: number,
        canonicalApplicationStatementPointer: number,
        canonicalApplicationStatementByteLength: number,
        statusPointer: number,
    ): number;
    discardVerificationIngress: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_relinearization_discard_verification_ingress']
    >;
    discardVerificationTerminalSource(terminalSourceHandle: number): number;
    finishComponent: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_relinearization_verification_component_finish']
    >;
    finishVerification(
        verifiedCommonProofHandle: number,
        terminalSourceHandle: number,
    ): number;
    prepareVerification: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_relinearization_prepare_verification']
    >;
    releaseSelectedSuite: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_common_proof_release_suite']
    >;
    selectSuite: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_common_proof_select_suite']
    >;
}>;

type DecodedComponentDescription = Readonly<{
    chunkByteLengths: readonly number[];
    fullObjectDigest: Uint8Array<ArrayBuffer>;
    totalByteLength: number;
}>;

type OwnedComponentDescription = Readonly<{
    decoded: DecodedComponentDescription;
    materialRoot: Uint8Array<ArrayBuffer>;
    streamDescriptorBytes: Uint8Array<ArrayBuffer>;
}>;

const expectedComponentCounts: Readonly<
    Record<AcceptedSetupRelinearizationProofFamily, number>
> = Object.freeze({
    roundOne: 2,
    roundOneAggregate: 2,
    roundTwo: 1,
});

const familyLabels: Readonly<
    Record<AcceptedSetupRelinearizationProofFamily, string>
> = Object.freeze({
    roundOne: 'round-one relinearization share',
    roundOneAggregate: 'round-one relinearization aggregate',
    roundTwo: 'round-two relinearization share',
});

const createStatusBoundary = (
    family: AcceptedSetupRelinearizationProofFamily,
): WasmStatusBoundary =>
    new WasmStatusBoundary({
        createInternalError: (message) =>
            new CanonicalStreamInternalError(message),
        createRefusalError: (refusalReason) =>
            new CanonicalStreamRefusalError(refusalReason),
        createResourceError: () => new CanonicalStreamResourceError(),
        internalFailureMessage: `The accepted-setup ${familyLabels[family]} verification failed internally.`,
        unknownStatusMessage: `The accepted-setup ${familyLabels[family]} verification returned an unknown status code.`,
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

const requireCanonicalBytes = (value: unknown): Uint8Array<ArrayBuffer> => {
    if (!isUint8Array(value) || value.byteLength === 0) {
        throw new CanonicalStreamRefusalError('wrongTypeOrLength');
    }
    return value.slice();
};

const requireFixedOwnedBytes = (
    value: unknown,
    expectedByteLength: number,
): Uint8Array<ArrayBuffer> => {
    if (!isUint8Array(value) || value.byteLength !== expectedByteLength) {
        throw new CanonicalStreamRefusalError('wrongTypeOrLength');
    }
    return value.slice();
};

const requireRelinearizationVerificationKernel = (
    context: TranscriptCoreKernelCommandRuntime,
    family: AcceptedSetupRelinearizationProofFamily,
): RelinearizationVerificationKernel => {
    const wasmExports = context.wasmExports;
    const beginVerificationIngress =
        family === 'roundOne'
            ? wasmExports.sealed_lattice_relinearization_round_one_verification_ingress_begin
            : family === 'roundOneAggregate'
              ? wasmExports.sealed_lattice_relinearization_round_one_aggregate_verification_ingress_begin
              : wasmExports.sealed_lattice_relinearization_round_two_verification_ingress_begin;
    const finishVerification =
        family === 'roundOne'
            ? wasmExports.sealed_lattice_relinearization_round_one_finish_verification
            : family === 'roundOneAggregate'
              ? wasmExports.sealed_lattice_relinearization_round_one_aggregate_finish_verification
              : wasmExports.sealed_lattice_relinearization_round_two_finish_verification;
    const discardVerificationTerminalSource =
        family === 'roundOne'
            ? wasmExports.sealed_lattice_relinearization_round_one_discard_verification_terminal_source
            : family === 'roundOneAggregate'
              ? wasmExports.sealed_lattice_relinearization_round_one_aggregate_discard_verification_terminal_source
              : wasmExports.sealed_lattice_relinearization_round_two_discard_verification_terminal_source;
    const kernel: Partial<RelinearizationVerificationKernel> = {
        absorbComponentChunk:
            wasmExports.sealed_lattice_relinearization_verification_component_absorb_chunk,
        beginComponent:
            wasmExports.sealed_lattice_relinearization_verification_component_begin,
        beginVerificationIngress,
        discardVerificationIngress:
            wasmExports.sealed_lattice_relinearization_discard_verification_ingress,
        discardVerificationTerminalSource,
        finishComponent:
            wasmExports.sealed_lattice_relinearization_verification_component_finish,
        finishVerification,
        prepareVerification:
            wasmExports.sealed_lattice_relinearization_prepare_verification,
        releaseSelectedSuite:
            wasmExports.sealed_lattice_common_proof_release_suite,
        selectSuite: wasmExports.sealed_lattice_common_proof_select_suite,
    };
    if (
        Object.values(kernel).some((boundary) => typeof boundary !== 'function')
    ) {
        throw new CanonicalStreamInternalError(
            `The transcript-core kernel lacks the accepted-setup ${familyLabels[family]} verification boundary.`,
        );
    }
    return Object.freeze(kernel as RelinearizationVerificationKernel);
};

const decodeComponentDescription = (input: {
    kernel: TranscriptCoreKernel;
    streamDescriptorBytes: Uint8Array<ArrayBuffer>;
}): DecodedComponentDescription => {
    let decoded;
    try {
        decoded = input.kernel.decodeStreamDescriptor({
            canonicalBytesHex: bytesToHex(input.streamDescriptorBytes),
        }).value;
    } catch {
        throw new CanonicalStreamRefusalError('malformedEncoding');
    }
    const totalByteLength = Number(decoded.totalByteLength);
    if (
        !Number.isSafeInteger(totalByteLength) ||
        totalByteLength <= 0 ||
        totalByteLength > foundationProfile.maximumCanonicalStreamByteLength
    ) {
        throw new CanonicalStreamInternalError(
            'The relinearization component stream length is outside the canonical runtime bounds.',
        );
    }
    const chunkCount = deriveCanonicalStreamChunkCount(totalByteLength);
    if (decoded.orderedChunkDigests.length !== chunkCount) {
        throw new CanonicalStreamInternalError(
            'The relinearization component descriptor has the wrong canonical chunk count.',
        );
    }
    const fullObjectDigest = Uint8Array.from(
        hexToBytes(decoded.fullObjectDigest),
    );
    if (fullObjectDigest.byteLength !== materialRootByteLength) {
        throw new CanonicalStreamInternalError(
            'The relinearization component descriptor has the wrong stream-digest length.',
        );
    }
    const chunkByteLengths = Array.from({ length: chunkCount }, (_, index) =>
        Math.min(
            foundationProfile.streamChunkByteLength,
            totalByteLength - index * foundationProfile.streamChunkByteLength,
        ),
    );
    return Object.freeze({
        chunkByteLengths: Object.freeze(chunkByteLengths),
        fullObjectDigest,
        totalByteLength,
    });
};

const requireComponentDescriptions = (input: {
    components: readonly AcceptedSetupRelinearizationComponentDescription[];
    expectedCount: number;
    kernel: TranscriptCoreKernel;
}): readonly OwnedComponentDescription[] => {
    const components: unknown = input.components;
    if (
        !Array.isArray(components) ||
        components.length !== input.expectedCount
    ) {
        throw new CanonicalStreamRefusalError('wrongTypeOrLength');
    }
    return Object.freeze(
        components.map((component: unknown) => {
            if (
                typeof component !== 'object' ||
                component === null ||
                !('streamDescriptorBytes' in component) ||
                !('materialRoot' in component)
            ) {
                throw new CanonicalStreamRefusalError('wrongTypeOrLength');
            }
            const streamDescriptorBytes = requireCanonicalBytes(
                component.streamDescriptorBytes,
            );
            return Object.freeze({
                decoded: decodeComponentDescription({
                    kernel: input.kernel,
                    streamDescriptorBytes,
                }),
                materialRoot: requireFixedOwnedBytes(
                    component.materialRoot,
                    materialRootByteLength,
                ),
                streamDescriptorBytes,
            });
        }),
    );
};

const selectSuite = (input: {
    canonicalSuiteRecordBytes: Uint8Array;
    context: TranscriptCoreKernelCommandRuntime;
    kernel: RelinearizationVerificationKernel;
    memoryBoundary: WasmMemoryBoundary;
    statusBoundary: WasmStatusBoundary;
}): number =>
    input.context.runExclusive(
        'accepted-setup relinearization selected-suite acquisition',
        () => {
            const canonicalSuiteRecordBytes = requireCanonicalBytes(
                input.canonicalSuiteRecordBytes,
            );
            const suitePointer = input.memoryBoundary.copy(
                canonicalSuiteRecordBytes,
            );
            const statusPointer = input.memoryBoundary.allocateZeroedWords(1);
            let selectedSuiteHandle = 0;
            try {
                selectedSuiteHandle = input.kernel.selectSuite(
                    suitePointer,
                    canonicalSuiteRecordBytes.byteLength,
                    statusPointer,
                );
                const [status] = input.memoryBoundary.readWords(
                    statusPointer,
                    1,
                );
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
                canonicalSuiteRecordBytes.fill(0);
                input.memoryBoundary.zeroAndDeallocate(
                    statusPointer,
                    wasm32WordByteLength,
                );
                input.memoryBoundary.zeroAndDeallocate(
                    suitePointer,
                    canonicalSuiteRecordBytes.byteLength,
                );
            }
        },
    );

const releaseSelectedSuite = (input: {
    context: TranscriptCoreKernelCommandRuntime;
    handle: number;
    kernel: RelinearizationVerificationKernel;
    operationName: string;
    statusBoundary: WasmStatusBoundary;
}): void => {
    const status = input.context.runExclusive(input.operationName, () =>
        input.kernel.releaseSelectedSuite(input.handle),
    );
    input.statusBoundary.throwIfError(status);
};

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

const zeroComponentDescriptions = (
    components: readonly OwnedComponentDescription[],
): void => {
    for (const component of components) {
        component.decoded.fullObjectDigest.fill(0);
        component.materialRoot.fill(0);
        component.streamDescriptorBytes.fill(0);
    }
};

const verifyAcceptedSetupRelinearizationInClosedWorker = async (
    family: AcceptedSetupRelinearizationProofFamily,
    input: AcceptedSetupRelinearizationVerificationInput,
): Promise<void> => {
    if (typeof globalThis.document !== 'undefined') {
        throw new CanonicalStreamInternalError(
            'Accepted-setup relinearization verification may only run inside the dedicated WASM worker.',
        );
    }
    const context = resolveCommonProofKernelContext(input.kernel);
    if (context === undefined) {
        throw new CanonicalStreamInternalError(
            'The loaded WASM kernel has no common-proof worker context.',
        );
    }
    const kernel = requireRelinearizationVerificationKernel(context, family);
    const assemblyOwner = requireAcceptedSetupVerificationAssemblyKernelOwner(
        input.acceptedSetupVerification,
        input.kernel,
        'collecting',
    );
    const catalogOwner = requireAcceptedSetupEvaluatorSourceCatalogKernelOwner(
        input.evaluatorSourceCatalog,
        input.kernel,
        'collecting',
    );
    const components = requireComponentDescriptions({
        components: input.components,
        expectedCount: expectedComponentCounts[family],
        kernel: input.kernel,
    });
    const canonicalApplicationStatementBytes = requireCanonicalBytes(
        input.canonicalApplicationStatementBytes,
    );
    const statusBoundary = createStatusBoundary(family);
    const memoryBoundary = new WasmMemoryBoundary({
        context,
        createInternalError: (message) =>
            new CanonicalStreamInternalError(message),
        createResourceError: (message) =>
            new CanonicalStreamResourceError(message),
        label: `Accepted-setup ${familyLabels[family]} verification`,
    });
    let selectedSuiteHandle = selectSuite({
        canonicalSuiteRecordBytes: input.canonicalSuiteRecordBytes,
        context,
        kernel,
        memoryBoundary,
        statusBoundary,
    });
    let ingressHandle = 0;
    let terminalSourceHandle = 0;
    let familyAdapter:
        | ClosedWorkerCommonProofVerificationFamilyAdapter
        | undefined;
    let operationFailure: unknown;
    try {
        ingressHandle = context.runExclusive(
            'accepted-setup relinearization verification ingress begin',
            () => {
                const statementPointer = memoryBoundary.copy(
                    canonicalApplicationStatementBytes,
                );
                const statusPointer = memoryBoundary.allocateZeroedWords(1);
                try {
                    const handle = kernel.beginVerificationIngress(
                        selectedSuiteHandle,
                        assemblyOwner.handle,
                        catalogOwner.handle,
                        statementPointer,
                        canonicalApplicationStatementBytes.byteLength,
                        statusPointer,
                    );
                    const [status] = memoryBoundary.readWords(statusPointer, 1);
                    statusBoundary.throwIfError(status);
                    return requireLiveHandle(
                        handle,
                        'The relinearization verification ingress handle',
                    );
                } finally {
                    memoryBoundary.zeroAndDeallocate(
                        statusPointer,
                        wasm32WordByteLength,
                    );
                    memoryBoundary.zeroAndDeallocate(
                        statementPointer,
                        canonicalApplicationStatementBytes.byteLength,
                    );
                }
            },
        );
        for (
            let componentOrdinal = 0;
            componentOrdinal < components.length;
            componentOrdinal += 1
        ) {
            const component = components[componentOrdinal];
            const descriptorPointer = memoryBoundary.copy(
                component.streamDescriptorBytes,
            );
            try {
                const beginStatus = context.runExclusive(
                    'accepted-setup relinearization verification component begin',
                    () =>
                        kernel.beginComponent(
                            ingressHandle,
                            componentOrdinal,
                            descriptorPointer,
                            component.streamDescriptorBytes.byteLength,
                        ),
                );
                statusBoundary.throwIfError(beginStatus);
            } finally {
                memoryBoundary.zeroAndDeallocate(
                    descriptorPointer,
                    component.streamDescriptorBytes.byteLength,
                );
            }
            let sourceByteOffset = 0n;
            for (
                let chunkIndex = 0;
                chunkIndex < component.decoded.chunkByteLengths.length;
                chunkIndex += 1
            ) {
                const exactByteLength =
                    component.decoded.chunkByteLengths[chunkIndex];
                const chunk =
                    await readAcceptedSetupPrepackageEvaluatorComponentExactRange(
                        {
                            authenticatedByteLength: BigInt(
                                component.decoded.totalByteLength,
                            ),
                            catalog: input.evaluatorSourceCatalog,
                            exactByteLength,
                            fullObjectDigest:
                                component.decoded.fullObjectDigest,
                            kernel: input.kernel,
                            materialRoot: component.materialRoot,
                            sourceByteOffset,
                        },
                    );
                if (
                    !isUint8Array(chunk) ||
                    chunk.byteLength !== exactByteLength
                ) {
                    throw new CanonicalStreamInternalError(
                        'The evaluator-source catalog returned a malformed relinearization component range.',
                    );
                }
                const chunkPointer = memoryBoundary.copy(chunk);
                try {
                    const absorbStatus = context.runExclusive(
                        'accepted-setup relinearization verification component chunk absorb',
                        () =>
                            kernel.absorbComponentChunk(
                                ingressHandle,
                                componentOrdinal,
                                chunkIndex,
                                chunkPointer,
                                chunk.byteLength,
                            ),
                    );
                    statusBoundary.throwIfError(absorbStatus);
                } finally {
                    chunk.fill(0);
                    memoryBoundary.zeroAndDeallocate(
                        chunkPointer,
                        exactByteLength,
                    );
                }
                sourceByteOffset += BigInt(exactByteLength);
            }
            const finishStatus = context.runExclusive(
                'accepted-setup relinearization verification component finish',
                () => kernel.finishComponent(ingressHandle, componentOrdinal),
            );
            statusBoundary.throwIfError(finishStatus);
        }
        const prepared = context.runExclusive(
            'accepted-setup relinearization common-proof verification preparation',
            () => {
                const metadataPointer = memoryBoundary.allocateZeroedWords(2);
                try {
                    const adapterHandle = kernel.prepareVerification(
                        ingressHandle,
                        metadataPointer,
                        metadataPointer + wasm32WordByteLength,
                    );
                    const [sourceHandle, status] = memoryBoundary.readWords(
                        metadataPointer,
                        2,
                    );
                    statusBoundary.throwIfError(status);
                    return Object.freeze({
                        adapterHandle: requireLiveHandle(
                            adapterHandle,
                            'The relinearization verification family-adapter handle',
                        ),
                        terminalSourceHandle: requireLiveHandle(
                            sourceHandle,
                            'The relinearization verification terminal-source handle',
                        ),
                    });
                } finally {
                    memoryBoundary.zeroAndDeallocate(
                        metadataPointer,
                        wasm32WordByteLength * 2,
                    );
                }
            },
        );
        ingressHandle = 0;
        terminalSourceHandle = prepared.terminalSourceHandle;
        familyAdapter = openClosedWorkerCommonProofVerificationFamilyAdapter(
            context,
            prepared.adapterHandle,
        );
        releaseSelectedSuite({
            context,
            handle: selectedSuiteHandle,
            kernel,
            operationName:
                'accepted-setup relinearization verification selected-suite release',
            statusBoundary,
        });
        selectedSuiteHandle = 0;
        const adapterForRun = familyAdapter;
        familyAdapter = undefined;
        const verifiedCommonProof =
            await runClosedWorkerCommonProofVerificationFamilyAdapter(
                adapterForRun,
                input.inputStore,
                input.options,
            );
        let finishStatus: number;
        try {
            finishStatus = applyClosedWorkerVerifiedCommonProofCapability(
                verifiedCommonProof,
                context,
                (verifiedCommonProofHandle) => {
                    const status = context.runExclusive(
                        'accepted-setup relinearization verification finish',
                        () =>
                            kernel.finishVerification(
                                verifiedCommonProofHandle,
                                terminalSourceHandle,
                            ),
                    );
                    return Object.freeze({
                        consumed: status === 0,
                        result: status,
                    });
                },
            );
        } catch (handoffFailure) {
            try {
                verifiedCommonProof.release();
            } catch (cleanupFailure) {
                throw new CanonicalStreamInternalError(
                    'The failed relinearization proof handoff could not release its generic verifier authority.',
                    Object.freeze({ cleanupFailure, handoffFailure }),
                );
            }
            throw handoffFailure;
        }
        if (finishStatus !== 0) {
            try {
                verifiedCommonProof.release();
            } catch (cleanupFailure) {
                throw new CanonicalStreamInternalError(
                    'The refused relinearization proof handoff could not release its generic verifier authority.',
                    Object.freeze({ cleanupFailure, finishStatus }),
                );
            }
            statusBoundary.throwIfError(finishStatus);
        }
        terminalSourceHandle = 0;
        canonicalApplicationStatementBytes.fill(0);
        zeroComponentDescriptions(components);
        return;
    } catch (error) {
        operationFailure = error;
    }

    const cleanupFailures: unknown[] = [];
    if (selectedSuiteHandle !== 0) {
        try {
            releaseSelectedSuite({
                context,
                handle: selectedSuiteHandle,
                kernel,
                operationName:
                    'accepted-setup relinearization verification failed selected-suite release',
                statusBoundary,
            });
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
    if (ingressHandle !== 0) {
        try {
            discardHandle({
                context,
                discard: kernel.discardVerificationIngress,
                handle: ingressHandle,
                operationName:
                    'accepted-setup relinearization verification ingress discard',
                statusBoundary,
            });
        } catch (cleanupFailure) {
            cleanupFailures.push(cleanupFailure);
        }
    }
    if (terminalSourceHandle !== 0) {
        try {
            discardHandle({
                context,
                discard: kernel.discardVerificationTerminalSource,
                handle: terminalSourceHandle,
                operationName:
                    'accepted-setup relinearization verification terminal-source discard',
                statusBoundary,
            });
        } catch (cleanupFailure) {
            cleanupFailures.push(cleanupFailure);
        }
    }
    canonicalApplicationStatementBytes.fill(0);
    zeroComponentDescriptions(components);
    if (cleanupFailures.length > 0) {
        throw new CanonicalStreamInternalError(
            'Relinearization verification failed to retire all worker-owned authority.',
            Object.freeze({ cleanupFailures, operationFailure }),
        );
    }
    throw operationFailure;
};

/** Verifies one exact roster member's `0x1214` proof and retains its source. */
export const verifyAcceptedSetupRelinearizationRoundOneInClosedWorker = (
    input: AcceptedSetupRelinearizationVerificationInput,
): Promise<void> =>
    verifyAcceptedSetupRelinearizationInClosedWorker('roundOne', input);

/** Verifies the sole roster-ordered `0x1215` aggregate proof. */
export const verifyAcceptedSetupRelinearizationRoundOneAggregateInClosedWorker =
    (input: AcceptedSetupRelinearizationVerificationInput): Promise<void> =>
        verifyAcceptedSetupRelinearizationInClosedWorker(
            'roundOneAggregate',
            input,
        );

/** Verifies one exact roster member's `0x1216` proof against the frozen aggregate. */
export const verifyAcceptedSetupRelinearizationRoundTwoInClosedWorker = (
    input: AcceptedSetupRelinearizationVerificationInput,
): Promise<void> =>
    verifyAcceptedSetupRelinearizationInClosedWorker('roundTwo', input);
