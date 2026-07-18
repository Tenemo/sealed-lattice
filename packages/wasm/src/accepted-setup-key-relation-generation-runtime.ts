import { refusalReasonCodes } from '@sealed-lattice/types';

import {
    resolveActionRandomnessKernelAuthorization,
    type ActionRandomnessSession,
} from './action-randomness-runtime.js';
import {
    verifyGeneratedAcceptedSetupPublicKeyShareCapabilityInClosedWorker,
    verifyGeneratedAcceptedSetupSameSecretCapabilityInClosedWorker,
    type AcceptedSetupProofVerificationInput,
} from './accepted-setup-proof-verification-runtime.js';
import { isUint8Array } from './byte-array.js';
import type { VerifiedTranscriptObject } from './canonical-board-runtime.js';
import {
    canonicalStreamDomains,
    CanonicalStreamCleanupError,
    CanonicalStreamInternalError,
    CanonicalStreamRefusalError,
    CanonicalStreamResourceError,
} from './canonical-stream-runtime.js';
import {
    openClosedWorkerCommonProofGenerationFamilyAdapter,
    releaseClosedWorkerCommonProofGenerationFamilyAdapter,
    runClosedWorkerCommonProofGenerationFamilyAdapterRetainingGeneratedCapability,
    type CommonProofCanonicalOutputStore,
    type CommonProofExternalMemoryTransactionExecutor,
    type CommonProofGenerationWorkerOptions,
    type ClosedWorkerCommonProofGenerationFamilyAdapter,
    type ClosedWorkerGeneratedCommonProofCapability,
} from './common-proof-worker-runtime/runtime.js';
import {
    deriveGeneratedCommonProofDescriptor,
    trackCanonicalCommonProofOutputChunks,
} from './generated-common-proof-output-runtime.js';
import {
    resolveSetupGenerationAuthorityKernelAuthorization,
    type BrowserOwnedSetupGenerationAuthority,
} from './setup-generation-recipient-payload.js';
import {
    resolveVerifiedStateReservationKernelAuthorization,
    type VerifiedStateReservation,
} from './state-verifier-runtime.js';
import { resolveCommonProofKernelContext } from './transcript-core-bridge/common-proof-kernel-context.js';
import type { TranscriptCoreKernelCommandRuntime } from './transcript-core-bridge/kernel-runtime.js';
import type {
    TranscriptCoreKernel,
    TranscriptCoreKernelExports,
} from './transcript-core-bridge/kernel-types.js';
import { resolveOrderedVerifiedBoardObjectAuthorization } from './vss-share-linkage-verification-runtime.js';
import { WasmMemoryBoundary } from './wasm-memory-boundary.js';
import { WasmStatusBoundary } from './wasm-status-boundary.js';

const verifierCapabilityByteLength = 32;
const checkpointLineageIdentifierByteLength = 32;
const wasm32WordByteLength = Uint32Array.BYTES_PER_ELEMENT;
const maximumWasm32UnsignedInteger = 0xffff_ffff;

type AcceptedSetupKeyRelationProofFamily = 'publicKeyShare' | 'sameSecret';

export type AcceptedSetupKeyRelationGenerationMode = 'fresh' | 'resumed';

const generatedAcceptedSetupKeyRelationProofBrand = Symbol(
    'generated accepted-setup key-relation proof',
);

/** Same-worker custody of one generated proof until positive package verification. */
export type GeneratedAcceptedSetupKeyRelationProof = Readonly<{
    readonly [generatedAcceptedSetupKeyRelationProofBrand]: true;
    copyCanonicalApplicationStatementBytes(): Uint8Array<ArrayBuffer>;
    copyProofDescriptorBytes(): Uint8Array<ArrayBuffer>;
    release(): void;
}>;

type GeneratedAcceptedSetupKeyRelationProofRecord = Readonly<{
    canonicalApplicationStatementBytes: Uint8Array<ArrayBuffer>;
    capability: ClosedWorkerGeneratedCommonProofCapability;
    context: TranscriptCoreKernelCommandRuntime;
    family: AcceptedSetupKeyRelationProofFamily;
    kernel: TranscriptCoreKernel;
    proofDescriptorBytes: Uint8Array<ArrayBuffer>;
}>;

const generatedProofRecords = new WeakMap<
    GeneratedAcceptedSetupKeyRelationProof,
    GeneratedAcceptedSetupKeyRelationProofRecord
>();

export type AcceptedSetupKeyRelationGenerationInput = Readonly<{
    actionRandomnessSession: ActionRandomnessSession;
    canonicalSuiteRecordBytes: Uint8Array;
    checkpointLineageIdentifier: Uint8Array;
    externalMemory: CommonProofExternalMemoryTransactionExecutor;
    generationMode: AcceptedSetupKeyRelationGenerationMode;
    generationOptions?: CommonProofGenerationWorkerOptions;
    kernel: TranscriptCoreKernel;
    outputStore: CommonProofCanonicalOutputStore;
    setupGenerationAuthority: BrowserOwnedSetupGenerationAuthority;
    setupIntentObject: VerifiedTranscriptObject;
    verifiedReservation: VerifiedStateReservation;
}>;

export type GeneratedAcceptedSetupKeyRelationProofVerificationInput = Omit<
    AcceptedSetupProofVerificationInput,
    'canonicalApplicationStatementBytes'
> &
    Readonly<{
        generatedProof: GeneratedAcceptedSetupKeyRelationProof;
    }>;

type SetupKeyRelationGenerationKernel = Readonly<{
    copyAndReleaseStatementSource: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_setup_key_relation_generation_statement_copy_and_release']
    >;
    discardStatementSource: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_setup_key_relation_generation_statement_discard']
    >;
    prepareGeneration: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_same_secret_prepare_generation']
    >;
    prepareResumedGeneration: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_same_secret_prepare_resumed_generation']
    >;
    releaseSelectedSuite: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_common_proof_release_suite']
    >;
    selectSuite: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_common_proof_select_suite']
    >;
    statementSourceByteLength: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_setup_key_relation_generation_statement_byte_length']
    >;
}>;

const createStatusBoundary = (
    family: AcceptedSetupKeyRelationProofFamily,
): WasmStatusBoundary =>
    new WasmStatusBoundary({
        createInternalError: (message) =>
            new CanonicalStreamInternalError(message),
        createRefusalError: (refusalReason) =>
            new CanonicalStreamRefusalError(refusalReason),
        createResourceError: () => new CanonicalStreamResourceError(),
        internalFailureMessage: `The accepted-setup ${family} generator failed internally.`,
        unknownStatusMessage: `The accepted-setup ${family} generator returned an unknown status code.`,
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

const requireOwnedFixedBytes = (
    value: Uint8Array,
    expectedByteLength: number,
): Uint8Array<ArrayBuffer> => {
    if (
        !isUint8Array(value) ||
        !(value.buffer instanceof ArrayBuffer) ||
        value.byteLength !== expectedByteLength
    ) {
        throw new CanonicalStreamRefusalError('wrongTypeOrLength');
    }
    return value.slice();
};

const requireCanonicalSuiteRecordBytes = (
    value: Uint8Array,
): Uint8Array<ArrayBuffer> => {
    if (!isUint8Array(value) || value.byteLength === 0) {
        throw new CanonicalStreamRefusalError('wrongTypeOrLength');
    }
    return value.slice();
};

const requireGenerationKernel = (
    context: TranscriptCoreKernelCommandRuntime,
    family: AcceptedSetupKeyRelationProofFamily,
): SetupKeyRelationGenerationKernel => {
    const {
        sealed_lattice_common_proof_release_suite: releaseSelectedSuite,
        sealed_lattice_common_proof_select_suite: selectSuite,
        sealed_lattice_setup_key_relation_generation_statement_byte_length:
            statementSourceByteLength,
        sealed_lattice_setup_key_relation_generation_statement_copy_and_release:
            copyAndReleaseStatementSource,
        sealed_lattice_setup_key_relation_generation_statement_discard:
            discardStatementSource,
    } = context.wasmExports;
    const prepareGeneration =
        family === 'sameSecret'
            ? context.wasmExports.sealed_lattice_same_secret_prepare_generation
            : context.wasmExports
                  .sealed_lattice_public_key_share_prepare_generation;
    const prepareResumedGeneration =
        family === 'sameSecret'
            ? context.wasmExports
                  .sealed_lattice_same_secret_prepare_resumed_generation
            : context.wasmExports
                  .sealed_lattice_public_key_share_prepare_resumed_generation;
    if (
        typeof releaseSelectedSuite !== 'function' ||
        typeof selectSuite !== 'function' ||
        typeof statementSourceByteLength !== 'function' ||
        typeof copyAndReleaseStatementSource !== 'function' ||
        typeof discardStatementSource !== 'function' ||
        typeof prepareGeneration !== 'function' ||
        typeof prepareResumedGeneration !== 'function'
    ) {
        throw new CanonicalStreamInternalError(
            `The transcript-core kernel lacks the accepted-setup ${family} generation boundary.`,
        );
    }
    return Object.freeze({
        copyAndReleaseStatementSource,
        discardStatementSource,
        prepareGeneration,
        prepareResumedGeneration,
        releaseSelectedSuite,
        selectSuite,
        statementSourceByteLength,
    });
};

const selectSuite = (input: {
    canonicalSuiteRecordBytes: Uint8Array;
    context: TranscriptCoreKernelCommandRuntime;
    kernel: SetupKeyRelationGenerationKernel;
    memoryBoundary: WasmMemoryBoundary;
    statusBoundary: WasmStatusBoundary;
}): number =>
    input.context.runExclusive(
        'accepted-setup key-relation selected-suite acquisition',
        () => {
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
                suiteBytes.fill(0);
                input.memoryBoundary.zeroAndDeallocate(
                    statusPointer,
                    wasm32WordByteLength,
                );
                input.memoryBoundary.zeroAndDeallocate(
                    suitePointer,
                    suiteBytes.byteLength,
                );
            }
        },
    );

const releaseSelectedSuite = (input: {
    context: TranscriptCoreKernelCommandRuntime;
    handle: number;
    kernel: SetupKeyRelationGenerationKernel;
    operationName: string;
    statusBoundary: WasmStatusBoundary;
}): void => {
    const status = input.context.runExclusive(input.operationName, () =>
        input.kernel.releaseSelectedSuite(input.handle),
    );
    input.statusBoundary.throwIfError(status);
};

const discardStatementSource = (input: {
    context: TranscriptCoreKernelCommandRuntime;
    handle: number;
    kernel: SetupKeyRelationGenerationKernel;
    statusBoundary: WasmStatusBoundary;
}): void => {
    const status = input.context.runExclusive(
        'accepted-setup key-relation statement-source discard',
        () => input.kernel.discardStatementSource(input.handle),
    );
    if (status >>> 0 === refusalReasonCodes.consumedState) {
        return;
    }
    input.statusBoundary.throwIfError(status);
};

const copyAndReleaseStatementSource = (input: {
    context: TranscriptCoreKernelCommandRuntime;
    handle: number;
    kernel: SetupKeyRelationGenerationKernel;
    memoryBoundary: WasmMemoryBoundary;
    statusBoundary: WasmStatusBoundary;
}): Uint8Array<ArrayBuffer> =>
    input.context.runExclusive(
        'accepted-setup key-relation statement-source readback',
        () => {
            const statusPointer = input.memoryBoundary.allocateZeroedWords(1);
            let outputPointer = 0;
            let outputByteLength = 0;
            try {
                outputByteLength = input.kernel.statementSourceByteLength(
                    input.handle,
                    statusPointer,
                );
                const [lengthStatus] = input.memoryBoundary.readWords(
                    statusPointer,
                    1,
                );
                input.statusBoundary.throwIfError(lengthStatus);
                input.memoryBoundary.validateAllocationByteLength(
                    outputByteLength,
                );
                outputPointer = input.memoryBoundary.allocate(outputByteLength);
                const copyStatus = input.kernel.copyAndReleaseStatementSource(
                    input.handle,
                    outputPointer,
                    outputByteLength,
                );
                input.statusBoundary.throwIfError(copyStatus);
                return new Uint8Array(
                    input.context.memory.buffer,
                    outputPointer,
                    outputByteLength,
                ).slice();
            } finally {
                input.memoryBoundary.zeroAndDeallocate(
                    outputPointer,
                    outputByteLength,
                );
                input.memoryBoundary.zeroAndDeallocate(
                    statusPointer,
                    wasm32WordByteLength,
                );
            }
        },
    );

const requireGeneratedProofRecord = (
    proof: GeneratedAcceptedSetupKeyRelationProof,
): GeneratedAcceptedSetupKeyRelationProofRecord => {
    const record =
        typeof proof === 'object' && proof !== null
            ? generatedProofRecords.get(proof)
            : undefined;
    if (record === undefined) {
        throw new CanonicalStreamRefusalError('consumedState');
    }
    return record;
};

const retireConsumedGeneratedProof = (
    proof: GeneratedAcceptedSetupKeyRelationProof,
    record: GeneratedAcceptedSetupKeyRelationProofRecord,
): void => {
    record.canonicalApplicationStatementBytes.fill(0);
    record.proofDescriptorBytes.fill(0);
    generatedProofRecords.delete(proof);
};

const createGeneratedProof = (
    record: GeneratedAcceptedSetupKeyRelationProofRecord,
): GeneratedAcceptedSetupKeyRelationProof => {
    let proof: GeneratedAcceptedSetupKeyRelationProof;
    proof = Object.freeze({
        [generatedAcceptedSetupKeyRelationProofBrand]: true as const,
        copyCanonicalApplicationStatementBytes: () =>
            requireGeneratedProofRecord(
                proof,
            ).canonicalApplicationStatementBytes.slice(),
        copyProofDescriptorBytes: () =>
            requireGeneratedProofRecord(proof).proofDescriptorBytes.slice(),
        release: (): void => {
            const activeRecord = requireGeneratedProofRecord(proof);
            activeRecord.capability.release();
            retireConsumedGeneratedProof(proof, activeRecord);
        },
    });
    generatedProofRecords.set(proof, record);
    return proof;
};

const generateAcceptedSetupKeyRelationInClosedWorker = async (
    family: AcceptedSetupKeyRelationProofFamily,
    input: AcceptedSetupKeyRelationGenerationInput,
): Promise<GeneratedAcceptedSetupKeyRelationProof> => {
    if (typeof globalThis.document !== 'undefined') {
        throw new CanonicalStreamInternalError(
            'Accepted-setup key-relation generation may only run inside the dedicated WASM worker.',
        );
    }
    if (
        (input.generationMode !== 'fresh' &&
            input.generationMode !== 'resumed') ||
        (input.generationMode === 'resumed') !==
            (input.generationOptions?.resume !== undefined)
    ) {
        throw new CanonicalStreamRefusalError('wrongContext');
    }
    const context = resolveCommonProofKernelContext(input.kernel);
    if (context === undefined) {
        throw new CanonicalStreamInternalError(
            'The loaded WASM kernel has no common-proof worker context.',
        );
    }
    const kernel = requireGenerationKernel(context, family);
    const statusBoundary = createStatusBoundary(family);
    const memoryBoundary = new WasmMemoryBoundary({
        context,
        createInternalError: (message) =>
            new CanonicalStreamInternalError(message),
        createResourceError: (message) =>
            new CanonicalStreamResourceError(message),
        label: `accepted-setup ${family} generation`,
    });
    const checkpointLineageIdentifier = requireOwnedFixedBytes(
        input.checkpointLineageIdentifier,
        checkpointLineageIdentifierByteLength,
    );
    const actionRandomnessAuthorization =
        resolveActionRandomnessKernelAuthorization(
            input.actionRandomnessSession,
            input.kernel,
        );
    const setupGenerationAuthorization =
        resolveSetupGenerationAuthorityKernelAuthorization(
            input.setupGenerationAuthority,
            context,
        );
    const stateAuthorization =
        resolveVerifiedStateReservationKernelAuthorization(
            input.verifiedReservation,
            input.kernel,
        );
    const setupIntentAuthorization =
        resolveOrderedVerifiedBoardObjectAuthorization({
            context,
            expectedObjectCount: 1,
            kernel: input.kernel,
            objects: [input.setupIntentObject],
        });
    if (
        actionRandomnessAuthorization.context.memory !== context.memory ||
        stateAuthorization.capabilityMemory !== context.memory ||
        stateAuthorization.capabilityPointer <= 0 ||
        stateAuthorization.capabilityPointer + verifierCapabilityByteLength >
            context.memory.buffer.byteLength ||
        setupIntentAuthorization.handleBytes.byteLength !== wasm32WordByteLength
    ) {
        throw new CanonicalStreamInternalError(
            'The accepted-setup key-relation generation authorities do not belong to one WASM worker.',
        );
    }

    let selectedSuiteHandle = 0;
    let statementSourceHandle = 0;
    let familyAdapter:
        | ClosedWorkerCommonProofGenerationFamilyAdapter
        | undefined;
    let generatedCapability:
        | ClosedWorkerGeneratedCommonProofCapability
        | undefined;
    let canonicalApplicationStatementBytes:
        | Uint8Array<ArrayBuffer>
        | undefined;
    let proofDescriptorBytes: Uint8Array<ArrayBuffer> | undefined;
    let result: GeneratedAcceptedSetupKeyRelationProof | undefined;
    let operationFailure: unknown;
    let operationFailed = false;
    try {
        selectedSuiteHandle = selectSuite({
            canonicalSuiteRecordBytes: input.canonicalSuiteRecordBytes,
            context,
            kernel,
            memoryBoundary,
            statusBoundary,
        });
        const prepared = context.runExclusive(
            `accepted-setup ${family} generation preparation`,
            () => {
                const checkpointPointer = memoryBoundary.copy(
                    checkpointLineageIdentifier,
                );
                const metadataPointer = memoryBoundary.allocateZeroedWords(2);
                try {
                    const prepare =
                        input.generationMode === 'fresh'
                            ? kernel.prepareGeneration
                            : kernel.prepareResumedGeneration;
                    const adapterHandle = prepare(
                        selectedSuiteHandle,
                        setupGenerationAuthorization.handle,
                        actionRandomnessAuthorization.handle,
                        stateAuthorization.sessionHandle,
                        stateAuthorization.capabilityPointer,
                        verifierCapabilityByteLength,
                        stateAuthorization.reservationHandle,
                        setupIntentAuthorization.sessionHandle,
                        setupIntentAuthorization.capabilityPointer,
                        verifierCapabilityByteLength,
                        new DataView(
                            setupIntentAuthorization.handleBytes.buffer,
                            setupIntentAuthorization.handleBytes.byteOffset,
                            setupIntentAuthorization.handleBytes.byteLength,
                        ).getUint32(0, true),
                        checkpointPointer,
                        checkpointLineageIdentifier.byteLength,
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
                            `The accepted-setup ${family} generation family-adapter handle`,
                        ),
                        statementSourceHandle: requireLiveHandle(
                            sourceHandle,
                            `The accepted-setup ${family} statement-source handle`,
                        ),
                    });
                } finally {
                    memoryBoundary.zeroAndDeallocate(
                        metadataPointer,
                        wasm32WordByteLength * 2,
                    );
                    memoryBoundary.zeroAndDeallocate(
                        checkpointPointer,
                        checkpointLineageIdentifier.byteLength,
                    );
                }
            },
        );
        statementSourceHandle = prepared.statementSourceHandle;
        familyAdapter = openClosedWorkerCommonProofGenerationFamilyAdapter(
            context,
            prepared.adapterHandle,
        );
        canonicalApplicationStatementBytes = copyAndReleaseStatementSource({
            context,
            handle: statementSourceHandle,
            kernel,
            memoryBoundary,
            statusBoundary,
        });
        statementSourceHandle = 0;
        releaseSelectedSuite({
            context,
            handle: selectedSuiteHandle,
            kernel,
            operationName: `accepted-setup ${family} generation selected-suite release`,
            statusBoundary,
        });
        selectedSuiteHandle = 0;

        const adapterForRun = familyAdapter;
        familyAdapter = undefined;
        const trackedOutput = trackCanonicalCommonProofOutputChunks(
            input.outputStore,
        );
        generatedCapability =
            await runClosedWorkerCommonProofGenerationFamilyAdapterRetainingGeneratedCapability(
                adapterForRun,
                input.externalMemory,
                trackedOutput.outputStore,
                input.generationOptions,
            );
        proofDescriptorBytes = await deriveGeneratedCommonProofDescriptor({
            kernel: input.kernel,
            outputChunkByteLengths: trackedOutput.outputChunkByteLengths,
            outputStore: input.outputStore,
            proofFamilyLabel:
                family === 'sameSecret'
                    ? 'same-secret'
                    : 'public-key-share',
            streamDomain:
                family === 'sameSecret'
                    ? canonicalStreamDomains.sameSecretProof
                    : canonicalStreamDomains.publicKeyShareProof,
        });
        result = createGeneratedProof(
            Object.freeze({
                canonicalApplicationStatementBytes,
                capability: generatedCapability,
                context,
                family,
                kernel: input.kernel,
                proofDescriptorBytes,
            }),
        );
        generatedCapability = undefined;
    } catch (error) {
        operationFailed = true;
        operationFailure = error;
    } finally {
        checkpointLineageIdentifier.fill(0);
    }

    const cleanupFailures: unknown[] = [];
    if (selectedSuiteHandle !== 0) {
        try {
            releaseSelectedSuite({
                context,
                handle: selectedSuiteHandle,
                kernel,
                operationName: `accepted-setup ${family} selected-suite failure release`,
                statusBoundary,
            });
        } catch (cleanupFailure) {
            cleanupFailures.push(cleanupFailure);
        }
    }
    if (familyAdapter !== undefined) {
        try {
            releaseClosedWorkerCommonProofGenerationFamilyAdapter(
                familyAdapter,
            );
        } catch (cleanupFailure) {
            cleanupFailures.push(cleanupFailure);
        }
    }
    if (generatedCapability !== undefined) {
        try {
            generatedCapability.release();
        } catch (cleanupFailure) {
            cleanupFailures.push(cleanupFailure);
        }
    }
    if (statementSourceHandle !== 0) {
        try {
            discardStatementSource({
                context,
                handle: statementSourceHandle,
                kernel,
                statusBoundary,
            });
        } catch (cleanupFailure) {
            cleanupFailures.push(cleanupFailure);
        }
    }
    if (cleanupFailures.length > 0) {
        throw new CanonicalStreamCleanupError(
            operationFailure,
            new CanonicalStreamInternalError(
                'Accepted-setup key-relation generation failed to retire all worker-owned authority.',
                Object.freeze({ cleanupFailures }),
            ),
        );
    }
    if (operationFailed) {
        throw operationFailure;
    }
    if (result === undefined) {
        throw new CanonicalStreamInternalError(
            'Accepted-setup key-relation generation completed without its proof authority.',
        );
    }
    return result;
};

/** Generates one same-secret proof for later positive package verification. */
export const generateAcceptedSetupSameSecretInClosedWorker = (
    input: AcceptedSetupKeyRelationGenerationInput,
): Promise<GeneratedAcceptedSetupKeyRelationProof> =>
    generateAcceptedSetupKeyRelationInClosedWorker(
        'sameSecret',
        input,
    );

/**
 * Generates one public-key-share proof for later positive package verification.
 */
export const generateAcceptedSetupPublicKeyShareInClosedWorker = (
    input: AcceptedSetupKeyRelationGenerationInput,
): Promise<GeneratedAcceptedSetupKeyRelationProof> =>
    generateAcceptedSetupKeyRelationInClosedWorker(
        'publicKeyShare',
        input,
    );

const verifyGeneratedAcceptedSetupKeyRelationInClosedWorker = async (
    family: AcceptedSetupKeyRelationProofFamily,
    input: GeneratedAcceptedSetupKeyRelationProofVerificationInput,
): Promise<void> => {
    const record = requireGeneratedProofRecord(input.generatedProof);
    const context = resolveCommonProofKernelContext(input.kernel);
    if (
        context === undefined ||
        record.family !== family ||
        record.kernel !== input.kernel ||
        record.context !== context
    ) {
        throw new CanonicalStreamRefusalError('wrongContext');
    }
    const verificationInput: AcceptedSetupProofVerificationInput =
        Object.freeze({
            assembly: input.assembly,
            canonicalApplicationStatementBytes:
                record.canonicalApplicationStatementBytes,
            canonicalSuiteRecordBytes: input.canonicalSuiteRecordBytes,
            inputStore: input.inputStore,
            kernel: input.kernel,
            options: input.options,
        });
    if (family === 'sameSecret') {
        await verifyGeneratedAcceptedSetupSameSecretCapabilityInClosedWorker(
            verificationInput,
            record.capability,
        );
    } else {
        await verifyGeneratedAcceptedSetupPublicKeyShareCapabilityInClosedWorker(
            verificationInput,
            record.capability,
        );
    }
    retireConsumedGeneratedProof(input.generatedProof, record);
};

/** Positively verifies one generated same-secret proof from its exact package. */
export const verifyGeneratedAcceptedSetupSameSecretInClosedWorker = (
    input: GeneratedAcceptedSetupKeyRelationProofVerificationInput,
): Promise<void> =>
    verifyGeneratedAcceptedSetupKeyRelationInClosedWorker(
        'sameSecret',
        input,
    );

/**
 * Positively verifies one generated public-key-share proof from its exact
 * package.
 */
export const verifyGeneratedAcceptedSetupPublicKeyShareInClosedWorker = (
    input: GeneratedAcceptedSetupKeyRelationProofVerificationInput,
): Promise<void> =>
    verifyGeneratedAcceptedSetupKeyRelationInClosedWorker(
        'publicKeyShare',
        input,
    );
