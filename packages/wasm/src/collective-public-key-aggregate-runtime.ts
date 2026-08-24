import {
    foundationProfile,
    type BrowserActionStorageWorkerKernel,
} from '@sealed-lattice/types';

import {
    requireAcceptedSetupVerificationAssemblyKernelOwner,
    type AcceptedSetupVerificationSession,
} from './accepted-setup-assembly-runtime.js';
import type { AcceptedSetupPackageBuilder } from './accepted-setup-package-builder-runtime.js';
import { requireAcceptedSetupPackageBuilderKernelOwner } from './accepted-setup-package-builder-runtime.js';
import {
    requireAggregateThresholdShareRecipientAuthorityKernelOwner,
    type AggregateThresholdShareRecipientAuthority,
} from './aggregate-threshold-share-authenticated-recipient.js';
import { byteArraysEqual, isUint8Array } from './byte-array.js';
import {
    canonicalStreamDomains,
    CanonicalStreamCleanupError,
    CanonicalStreamInternalError,
    CanonicalStreamRefusalError,
    CanonicalStreamResourceError,
} from './canonical-stream-runtime.js';
import {
    yieldBrowserWorkerTurn,
    type CommonProofAuthenticatedSourceRangeRequest,
} from './common-proof-worker-runtime/kernel-boundaries.js';
import {
    applyClosedWorkerGeneratedCommonProofCapability,
    applyClosedWorkerVerifiedCommonProofCapability,
    openClosedWorkerCommonProofGenerationFamilyAdapter,
    openClosedWorkerCommonProofVerificationFamilyAdapter,
    releaseClosedWorkerCommonProofGenerationFamilyAdapter,
    releaseClosedWorkerCommonProofVerificationFamilyAdapter,
    runClosedWorkerCommonProofGenerationFamilyAdapterWithExecutionOpener,
    runClosedWorkerCommonProofVerificationFamilyAdapter,
    type AuthenticatedCommonProofInputStore,
    type ClosedWorkerCommonProofGenerationFamilyAdapter,
    type ClosedWorkerCommonProofVerificationFamilyAdapter,
    type ClosedWorkerGeneratedCommonProofCapability,
    type CommonProofGenerationExecutionOpener,
    type CommonProofVerificationWorkerOptions,
    type VerifiedCommonProofCapability,
} from './common-proof-worker-runtime/runtime.js';
import { deriveGeneratedCommonProofDescriptor } from './generated-common-proof-output-runtime.js';
import type { ClosedWorkerProductionOperationIdentifiers } from './local-storage-root-worker-kernel/authorities.js';
import { withClosedWorkerProductionOperationAuthority } from './local-storage-root-worker-kernel/worker-kernel.js';
import {
    requireSelectedSuiteRecordSourceKernelOwner,
    type SelectedSuiteRecordSource,
} from './selected-suite-record-source.js';
import { stateVerifierCapabilityByteLength } from './state-verifier-runtime/contracts.js';
import { resolveCommonProofKernelContext } from './transcript-core-bridge/common-proof-kernel-context.js';
import type { TranscriptCoreKernelCommandRuntime } from './transcript-core-bridge/kernel-runtime.js';
import type {
    TranscriptCoreKernel,
    TranscriptCoreKernelExports,
} from './transcript-core-bridge/kernel-types.js';
import { WasmMemoryBoundary } from './wasm-memory-boundary.js';
import { WasmStatusBoundary } from './wasm-status-boundary.js';

const attemptIdentifierByteLength = 32;
const fixedHashByteLength = 64;
const participantSourceDescriptionByteLength = 136;
const streamDescriptionByteLength = 72;
const wasm32WordByteLength = 4;
const maximumWasm32UnsignedInteger = 0xffff_ffff;

type CollectivePublicKeyAggregateExports = Required<
    Pick<
        TranscriptCoreKernelExports,
        | 'sealed_lattice_collective_public_key_aggregate_absorb_participant_chunk'
        | 'sealed_lattice_collective_public_key_aggregate_begin'
        | 'sealed_lattice_collective_public_key_aggregate_begin_participant'
        | 'sealed_lattice_collective_public_key_aggregate_commit_generated_proof'
        | 'sealed_lattice_collective_public_key_aggregate_copy_participant_source_description'
        | 'sealed_lattice_collective_public_key_aggregate_copy_statement'
        | 'sealed_lattice_collective_public_key_aggregate_copy_stream_range'
        | 'sealed_lattice_collective_public_key_aggregate_contribute_package'
        | 'sealed_lattice_collective_public_key_aggregate_describe_stream'
        | 'sealed_lattice_collective_public_key_aggregate_discard_session'
        | 'sealed_lattice_collective_public_key_aggregate_discard_verification_terminal_source'
        | 'sealed_lattice_collective_public_key_aggregate_finish_participant'
        | 'sealed_lattice_collective_public_key_aggregate_finish_roster'
        | 'sealed_lattice_collective_public_key_aggregate_finish_verification'
        | 'sealed_lattice_collective_public_key_aggregate_participant_body_byte_length'
        | 'sealed_lattice_collective_public_key_aggregate_prepare_generation'
        | 'sealed_lattice_collective_public_key_aggregate_prepare_resumed_generation'
        | 'sealed_lattice_collective_public_key_aggregate_prepare_verification'
        | 'sealed_lattice_collective_public_key_aggregate_statement_byte_length'
    >
>;

type CollectivePublicKeyAggregateContext =
    TranscriptCoreKernelCommandRuntime & {
        readonly wasmExports: TranscriptCoreKernelCommandRuntime['wasmExports'] &
            CollectivePublicKeyAggregateExports;
    };

export type CollectivePublicKeyDescription = Readonly<{
    fullObjectDigest: Uint8Array<ArrayBuffer>;
    totalByteLength: bigint;
}>;

export type CollectivePublicKeyGenerationMode = 'fresh' | 'resumed';

export type CollectivePublicKeyParticipantSource = Readonly<{
    descriptorBytes: Uint8Array;
    inputStore: AuthenticatedCommonProofInputStore;
}>;

const collectivePublicKeyAggregateBrand = Symbol(
    'collective public-key aggregate',
);

/** Opaque same-worker custody of slot 20 production and verification. */
export type CollectivePublicKeyAggregate = Readonly<{
    readonly [collectivePublicKeyAggregateBrand]: true;
    cancel(): void;
    contributeToPackage(builder: AcceptedSetupPackageBuilder): void;
    copyCanonicalApplicationStatement(): Uint8Array<ArrayBuffer>;
    describeCollectivePublicKey(): CollectivePublicKeyDescription;
    generate(input: {
        checkpointLineageIdentifier: Uint8Array;
        generationMode: CollectivePublicKeyGenerationMode;
        openProofGenerationExecution: CommonProofGenerationExecutionOpener;
        productionOperationIdentifiers: ClosedWorkerProductionOperationIdentifiers;
        workerKernel: BrowserActionStorageWorkerKernel;
    }): Promise<Uint8Array<ArrayBuffer>>;
    readCollectivePublicKeyRange(
        sourceByteOffset: bigint,
        exactByteLength: number,
    ): Uint8Array<ArrayBuffer>;
    verify(input: {
        acceptedSetupVerification: AcceptedSetupVerificationSession;
        options?: CommonProofVerificationWorkerOptions;
        proofInputStore: AuthenticatedCommonProofInputStore;
        selectedSuiteRecordSource: SelectedSuiteRecordSource;
    }): Promise<void>;
}>;

type CollectivePublicKeyAggregatePhase =
    | 'prepared'
    | 'generating'
    | 'generated'
    | 'packageContributed'
    | 'verifying';

type CollectivePublicKeyAggregateRecord = {
    readonly canonicalApplicationStatement: Uint8Array<ArrayBuffer>;
    readonly collectivePublicKeyDescription: CollectivePublicKeyDescription;
    readonly context: CollectivePublicKeyAggregateContext;
    generatedProof: ClosedWorkerGeneratedCommonProofCapability | undefined;
    readonly kernel: TranscriptCoreKernel;
    readonly participantBodyByteLength: number;
    readonly participantSources: readonly ParticipantSourceRecord[];
    phase: CollectivePublicKeyAggregatePhase;
    readonly sessionHandle: number;
};

type ParticipantSourceRecord = Readonly<{
    carrierBinding: Uint8Array<ArrayBuffer>;
    inputStore: AuthenticatedCommonProofInputStore;
    streamDigest: Uint8Array<ArrayBuffer>;
    totalByteLength: bigint;
}>;

type PreparedParticipantSource = Readonly<{
    descriptorBytes: Uint8Array<ArrayBuffer>;
    inputStore: AuthenticatedCommonProofInputStore;
}>;

const aggregateRecords = new WeakMap<
    CollectivePublicKeyAggregate,
    CollectivePublicKeyAggregateRecord
>();

const createStatusBoundary = (): WasmStatusBoundary =>
    new WasmStatusBoundary({
        createInternalError: (message) =>
            new CanonicalStreamInternalError(message),
        createRefusalError: (refusalReason) =>
            new CanonicalStreamRefusalError(refusalReason),
        createResourceError: () => new CanonicalStreamResourceError(),
        internalFailureMessage:
            'The collective public-key aggregate failed internally.',
        unknownStatusMessage:
            'The collective public-key aggregate returned an unknown status code.',
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

const requireContext = (
    kernel: TranscriptCoreKernel,
): CollectivePublicKeyAggregateContext => {
    const context = resolveCommonProofKernelContext(kernel);
    const exports = context?.wasmExports as
        | Partial<CollectivePublicKeyAggregateExports>
        | undefined;
    const requiredExportNames = [
        'sealed_lattice_collective_public_key_aggregate_absorb_participant_chunk',
        'sealed_lattice_collective_public_key_aggregate_begin',
        'sealed_lattice_collective_public_key_aggregate_begin_participant',
        'sealed_lattice_collective_public_key_aggregate_commit_generated_proof',
        'sealed_lattice_collective_public_key_aggregate_copy_participant_source_description',
        'sealed_lattice_collective_public_key_aggregate_copy_statement',
        'sealed_lattice_collective_public_key_aggregate_copy_stream_range',
        'sealed_lattice_collective_public_key_aggregate_contribute_package',
        'sealed_lattice_collective_public_key_aggregate_describe_stream',
        'sealed_lattice_collective_public_key_aggregate_discard_session',
        'sealed_lattice_collective_public_key_aggregate_discard_verification_terminal_source',
        'sealed_lattice_collective_public_key_aggregate_finish_participant',
        'sealed_lattice_collective_public_key_aggregate_finish_roster',
        'sealed_lattice_collective_public_key_aggregate_finish_verification',
        'sealed_lattice_collective_public_key_aggregate_participant_body_byte_length',
        'sealed_lattice_collective_public_key_aggregate_prepare_generation',
        'sealed_lattice_collective_public_key_aggregate_prepare_resumed_generation',
        'sealed_lattice_collective_public_key_aggregate_prepare_verification',
        'sealed_lattice_collective_public_key_aggregate_statement_byte_length',
    ] as const;
    if (
        context === undefined ||
        exports === undefined ||
        requiredExportNames.some(
            (exportName) => typeof exports[exportName] !== 'function',
        )
    ) {
        throw new CanonicalStreamInternalError(
            'The transcript-core kernel lacks the collective public-key aggregate boundary.',
        );
    }
    return context as CollectivePublicKeyAggregateContext;
};

const createMemoryBoundary = (
    context: CollectivePublicKeyAggregateContext,
): WasmMemoryBoundary =>
    new WasmMemoryBoundary({
        context,
        createInternalError: (message) =>
            new CanonicalStreamInternalError(message),
        createResourceError: (message) =>
            new CanonicalStreamResourceError(message),
        label: 'collective public-key aggregate',
    });

const requireRecord = (
    aggregate: CollectivePublicKeyAggregate,
): CollectivePublicKeyAggregateRecord => {
    const record =
        (typeof aggregate === 'object' || typeof aggregate === 'function') &&
        aggregate !== null
            ? aggregateRecords.get(aggregate)
            : undefined;
    if (record === undefined) {
        throw new CanonicalStreamRefusalError('consumedState');
    }
    return record;
};

const requirePhase = (
    record: CollectivePublicKeyAggregateRecord,
    expectedPhase: CollectivePublicKeyAggregatePhase,
): void => {
    if (record.phase !== expectedPhase) {
        throw new CanonicalStreamRefusalError('consumedState');
    }
};

const requireFixedOwnedBytes = (
    value: Uint8Array,
    exactByteLength: number,
): Uint8Array<ArrayBuffer> => {
    if (
        !isUint8Array(value) ||
        !(value.buffer instanceof ArrayBuffer) ||
        value.byteLength !== exactByteLength
    ) {
        throw new CanonicalStreamRefusalError('wrongTypeOrLength');
    }
    return Uint8Array.from(value);
};

const requireParticipantSources = (
    value: readonly CollectivePublicKeyParticipantSource[],
    participantBodyByteLength: number,
): readonly PreparedParticipantSource[] => {
    if (
        !Array.isArray(value) ||
        value.length !== foundationProfile.participantCount
    ) {
        throw new CanonicalStreamRefusalError('wrongTypeOrLength');
    }
    const participantSources: readonly CollectivePublicKeyParticipantSource[] =
        value;
    return Object.freeze(
        participantSources.map((source) => {
            if (
                typeof source !== 'object' ||
                source === null ||
                !isUint8Array(source.descriptorBytes) ||
                source.descriptorBytes.byteLength === 0 ||
                source.descriptorBytes.byteLength >
                    foundationProfile.maximumCopiedBufferByteLength ||
                typeof source.inputStore !== 'object' ||
                source.inputStore === null ||
                source.inputStore.declaredByteLength !==
                    participantBodyByteLength ||
                typeof source.inputStore.readCommittedChunk !== 'function'
            ) {
                throw new CanonicalStreamRefusalError('wrongTypeOrLength');
            }
            return Object.freeze({
                descriptorBytes: Uint8Array.from(source.descriptorBytes),
                inputStore: source.inputStore,
            });
        }),
    );
};

const requireParticipantBodyByteLength = (
    context: CollectivePublicKeyAggregateContext,
): number => {
    const reportedByteLength = context.runExclusive(
        'collective public-key participant body byte length',
        () =>
            context.wasmExports.sealed_lattice_collective_public_key_aggregate_participant_body_byte_length(),
    );
    if (
        reportedByteLength <= 0n ||
        reportedByteLength > BigInt(Number.MAX_SAFE_INTEGER) ||
        reportedByteLength >
            BigInt(foundationProfile.maximumCanonicalStreamByteLength)
    ) {
        throw new CanonicalStreamResourceError(
            'The collective public-key participant body exceeds the canonical-stream safety bound.',
        );
    }
    return Number(reportedByteLength);
};

const requireFreshOwnedStoreChunk = async (input: {
    chunkIndex: number;
    exactByteLength: number;
    inputStore: AuthenticatedCommonProofInputStore;
}): Promise<Uint8Array<ArrayBuffer>> => {
    const bytes = await input.inputStore.readCommittedChunk(
        input.chunkIndex,
        input.exactByteLength,
    );
    if (
        !isUint8Array(bytes) ||
        !(bytes.buffer instanceof ArrayBuffer) ||
        bytes.byteOffset !== 0 ||
        bytes.byteLength !== input.exactByteLength ||
        bytes.buffer.byteLength !== input.exactByteLength
    ) {
        throw new CanonicalStreamInternalError(
            'The public-key-share store did not return a fresh owned canonical chunk.',
        );
    }
    return bytes as Uint8Array<ArrayBuffer>;
};

const copyParticipantSourceDescription = (input: {
    bodyByteLength: number;
    context: CollectivePublicKeyAggregateContext;
    inputStore: AuthenticatedCommonProofInputStore;
    rosterPosition: number;
    sessionHandle: number;
}): ParticipantSourceRecord => {
    const memoryBoundary = createMemoryBoundary(input.context);
    let outputPointer = 0;
    try {
        outputPointer = memoryBoundary.allocate(
            participantSourceDescriptionByteLength,
        );
        const status = input.context.runExclusive(
            'collective public-key participant source description copy',
            () =>
                input.context.wasmExports.sealed_lattice_collective_public_key_aggregate_copy_participant_source_description(
                    input.sessionHandle,
                    input.rosterPosition,
                    outputPointer,
                    participantSourceDescriptionByteLength,
                ),
        );
        createStatusBoundary().throwIfError(status);
        const description = Uint8Array.from(
            new Uint8Array(
                input.context.memory.buffer,
                outputPointer,
                participantSourceDescriptionByteLength,
            ),
        );
        const totalByteLength = new DataView(description.buffer).getBigUint64(
            fixedHashByteLength * 2,
            true,
        );
        if (totalByteLength !== BigInt(input.bodyByteLength)) {
            description.fill(0);
            throw new CanonicalStreamInternalError(
                'The collective public-key participant source description has the wrong length.',
            );
        }
        return Object.freeze({
            carrierBinding: description.slice(0, fixedHashByteLength),
            inputStore: input.inputStore,
            streamDigest: description.slice(
                fixedHashByteLength,
                fixedHashByteLength * 2,
            ),
            totalByteLength,
        });
    } finally {
        memoryBoundary.zeroAndDeallocate(
            outputPointer,
            participantSourceDescriptionByteLength,
        );
    }
};

const ingestParticipantSource = async (input: {
    bodyByteLength: number;
    context: CollectivePublicKeyAggregateContext;
    participantSource: PreparedParticipantSource;
    rosterPosition: number;
    sessionHandle: number;
}): Promise<ParticipantSourceRecord> => {
    const memoryBoundary = createMemoryBoundary(input.context);
    const statusBoundary = createStatusBoundary();
    let descriptorPointer = 0;
    try {
        descriptorPointer = memoryBoundary.copy(
            input.participantSource.descriptorBytes,
        );
        const status = input.context.runExclusive(
            'collective public-key participant begin',
            () =>
                input.context.wasmExports.sealed_lattice_collective_public_key_aggregate_begin_participant(
                    input.sessionHandle,
                    input.rosterPosition,
                    descriptorPointer,
                    input.participantSource.descriptorBytes.byteLength,
                ),
        );
        statusBoundary.throwIfError(status);
    } finally {
        memoryBoundary.zeroAndDeallocate(
            descriptorPointer,
            input.participantSource.descriptorBytes.byteLength,
        );
        input.participantSource.descriptorBytes.fill(0);
    }

    const chunkCount = Math.ceil(
        input.bodyByteLength / foundationProfile.streamChunkByteLength,
    );
    for (let chunkIndex = 0; chunkIndex < chunkCount; chunkIndex += 1) {
        const sourceByteOffset =
            chunkIndex * foundationProfile.streamChunkByteLength;
        const exactByteLength = Math.min(
            foundationProfile.streamChunkByteLength,
            input.bodyByteLength - sourceByteOffset,
        );
        let chunkBytes: Uint8Array<ArrayBuffer> | undefined;
        let chunkPointer = 0;
        try {
            chunkBytes = await requireFreshOwnedStoreChunk({
                chunkIndex,
                exactByteLength,
                inputStore: input.participantSource.inputStore,
            });
            chunkPointer = memoryBoundary.copy(chunkBytes);
            const status = input.context.runExclusive(
                'collective public-key participant chunk absorption',
                () =>
                    input.context.wasmExports.sealed_lattice_collective_public_key_aggregate_absorb_participant_chunk(
                        input.sessionHandle,
                        input.rosterPosition,
                        chunkIndex,
                        chunkPointer,
                        exactByteLength,
                    ),
            );
            statusBoundary.throwIfError(status);
        } finally {
            memoryBoundary.zeroAndDeallocate(chunkPointer, exactByteLength);
            chunkBytes?.fill(0);
        }
        await yieldBrowserWorkerTurn();
    }
    const finishStatus = input.context.runExclusive(
        'collective public-key participant finish',
        () =>
            input.context.wasmExports.sealed_lattice_collective_public_key_aggregate_finish_participant(
                input.sessionHandle,
                input.rosterPosition,
            ),
    );
    statusBoundary.throwIfError(finishStatus);
    return copyParticipantSourceDescription({
        bodyByteLength: input.bodyByteLength,
        context: input.context,
        inputStore: input.participantSource.inputStore,
        rosterPosition: input.rosterPosition,
        sessionHandle: input.sessionHandle,
    });
};

const readAuthenticatedParticipantSourceRange = async (
    record: CollectivePublicKeyAggregateRecord,
    request: CommonProofAuthenticatedSourceRangeRequest,
): Promise<Uint8Array<ArrayBuffer>> => {
    const expectedTotalByteLength = BigInt(record.participantBodyByteLength);
    const chunkByteLength = BigInt(foundationProfile.streamChunkByteLength);
    const expectedChunkIndex = Number(
        request.sourceStreamByteOffset / chunkByteLength,
    );
    const expectedSourceByteOffset =
        BigInt(expectedChunkIndex) * chunkByteLength;
    const expectedByteLength = Number(
        expectedTotalByteLength - expectedSourceByteOffset < chunkByteLength
            ? expectedTotalByteLength - expectedSourceByteOffset
            : chunkByteLength,
    );
    if (
        !Number.isSafeInteger(expectedChunkIndex) ||
        expectedChunkIndex < 0 ||
        request.sourceStreamTotalByteLength !== expectedTotalByteLength ||
        request.storageByteOffset !== request.sourceStreamByteOffset ||
        request.sourceStreamByteOffset !== expectedSourceByteOffset ||
        request.authenticationChunkIndex !== expectedChunkIndex ||
        request.exactByteLength !== expectedByteLength
    ) {
        throw new CanonicalStreamRefusalError('wrongContext');
    }
    const matchingSources = record.participantSources.filter(
        (source) =>
            source.totalByteLength === request.sourceStreamTotalByteLength &&
            byteArraysEqual(
                source.carrierBinding,
                request.sourceMaterialRoot,
            ) &&
            byteArraysEqual(source.streamDigest, request.sourceStreamDigest),
    );
    if (matchingSources.length !== 1) {
        throw new CanonicalStreamRefusalError('wrongContext');
    }
    const [matchingSource] = matchingSources;
    if (
        matchingSource.inputStore.declaredByteLength !==
        record.participantBodyByteLength
    ) {
        throw new CanonicalStreamRefusalError('wrongContext');
    }
    return requireFreshOwnedStoreChunk({
        chunkIndex: expectedChunkIndex,
        exactByteLength: expectedByteLength,
        inputStore: matchingSource.inputStore,
    });
};

const clearParticipantSourceRecords = (
    records: readonly ParticipantSourceRecord[],
): void => {
    for (const record of records) {
        record.carrierBinding.fill(0);
        record.streamDigest.fill(0);
    }
};

const copyCanonicalApplicationStatement = (input: {
    context: CollectivePublicKeyAggregateContext;
    sessionHandle: number;
}): Uint8Array<ArrayBuffer> => {
    const memoryBoundary = createMemoryBoundary(input.context);
    const statusBoundary = createStatusBoundary();
    let statusPointer = 0;
    let outputPointer = 0;
    let outputByteLength = 0;
    try {
        statusPointer = memoryBoundary.allocateZeroedWords(1);
        const returnedByteLength = input.context.runExclusive(
            'collective public-key application-statement length',
            () =>
                input.context.wasmExports.sealed_lattice_collective_public_key_aggregate_statement_byte_length(
                    input.sessionHandle,
                    statusPointer,
                ),
        );
        const [status] = memoryBoundary.readWords(statusPointer, 1);
        statusBoundary.throwIfError(status);
        if (
            returnedByteLength <= 0n ||
            returnedByteLength >
                BigInt(foundationProfile.maximumCopiedBufferByteLength)
        ) {
            throw new CanonicalStreamResourceError(
                'The collective public-key application statement exceeds the absolute copy bound.',
            );
        }
        outputByteLength = Number(returnedByteLength);
        outputPointer = memoryBoundary.allocate(outputByteLength);
        const copyStatus = input.context.runExclusive(
            'collective public-key application-statement copy',
            () =>
                input.context.wasmExports.sealed_lattice_collective_public_key_aggregate_copy_statement(
                    input.sessionHandle,
                    outputPointer,
                    outputByteLength,
                ),
        );
        statusBoundary.throwIfError(copyStatus);
        return Uint8Array.from(
            new Uint8Array(
                input.context.memory.buffer,
                outputPointer,
                outputByteLength,
            ),
        );
    } finally {
        memoryBoundary.zeroAndDeallocate(statusPointer, wasm32WordByteLength);
        memoryBoundary.zeroAndDeallocate(outputPointer, outputByteLength);
    }
};

const describeCollectivePublicKey = (input: {
    context: CollectivePublicKeyAggregateContext;
    sessionHandle: number;
}): CollectivePublicKeyDescription => {
    const memoryBoundary = createMemoryBoundary(input.context);
    const statusBoundary = createStatusBoundary();
    let descriptionPointer = 0;
    try {
        descriptionPointer = memoryBoundary.allocate(
            streamDescriptionByteLength,
        );
        const status = input.context.runExclusive(
            'collective public-key stream description',
            () =>
                input.context.wasmExports.sealed_lattice_collective_public_key_aggregate_describe_stream(
                    input.sessionHandle,
                    descriptionPointer,
                    streamDescriptionByteLength,
                ),
        );
        statusBoundary.throwIfError(status);
        const description = Uint8Array.from(
            new Uint8Array(
                input.context.memory.buffer,
                descriptionPointer,
                streamDescriptionByteLength,
            ),
        );
        const totalByteLength = new DataView(description.buffer).getBigUint64(
            0,
            true,
        );
        if (
            totalByteLength <= 0n ||
            totalByteLength >
                BigInt(foundationProfile.maximumCanonicalStreamByteLength)
        ) {
            throw new CanonicalStreamInternalError(
                'The collective public-key stream description exceeds its absolute bound.',
            );
        }
        return Object.freeze({
            fullObjectDigest: description.slice(8),
            totalByteLength,
        });
    } finally {
        memoryBoundary.zeroAndDeallocate(
            descriptionPointer,
            streamDescriptionByteLength,
        );
    }
};

const readCollectivePublicKeyRange = (
    aggregate: CollectivePublicKeyAggregate,
    sourceByteOffset: bigint,
    exactByteLength: number,
): Uint8Array<ArrayBuffer> => {
    const record = requireRecord(aggregate);
    if (
        typeof sourceByteOffset !== 'bigint' ||
        sourceByteOffset < 0n ||
        !Number.isSafeInteger(exactByteLength) ||
        exactByteLength <= 0 ||
        exactByteLength > foundationProfile.streamChunkByteLength ||
        sourceByteOffset + BigInt(exactByteLength) >
            record.collectivePublicKeyDescription.totalByteLength
    ) {
        throw new CanonicalStreamRefusalError('wrongTypeOrLength');
    }
    const memoryBoundary = createMemoryBoundary(record.context);
    let outputPointer = 0;
    try {
        outputPointer = memoryBoundary.allocate(exactByteLength);
        const status = record.context.runExclusive(
            'collective public-key stream range copy',
            () =>
                record.context.wasmExports.sealed_lattice_collective_public_key_aggregate_copy_stream_range(
                    record.sessionHandle,
                    sourceByteOffset,
                    outputPointer,
                    exactByteLength,
                ),
        );
        createStatusBoundary().throwIfError(status);
        return Uint8Array.from(
            new Uint8Array(
                record.context.memory.buffer,
                outputPointer,
                exactByteLength,
            ),
        );
    } finally {
        memoryBoundary.zeroAndDeallocate(outputPointer, exactByteLength);
    }
};

const discardKernelSession = (
    record: CollectivePublicKeyAggregateRecord,
): void => {
    const status = record.context.runExclusive(
        'collective public-key aggregate session discard',
        () =>
            record.context.wasmExports.sealed_lattice_collective_public_key_aggregate_discard_session(
                record.sessionHandle,
            ),
    );
    createStatusBoundary().throwIfError(status);
};

const cancelAggregate = (aggregate: CollectivePublicKeyAggregate): void => {
    const record = requireRecord(aggregate);
    let operationFailure: unknown;
    try {
        record.generatedProof?.release();
        record.generatedProof = undefined;
    } catch (error) {
        operationFailure = error;
    }
    let cleanupFailure: unknown;
    try {
        discardKernelSession(record);
    } catch (error) {
        cleanupFailure = error;
    } finally {
        clearParticipantSourceRecords(record.participantSources);
        aggregateRecords.delete(aggregate);
    }
    if (cleanupFailure !== undefined) {
        throw operationFailure === undefined
            ? cleanupFailure instanceof Error
                ? cleanupFailure
                : new CanonicalStreamInternalError(
                      'The collective public-key aggregate cleanup failed.',
                      cleanupFailure,
                  )
            : new CanonicalStreamCleanupError(operationFailure, cleanupFailure);
    }
    if (operationFailure !== undefined) {
        throw operationFailure instanceof Error
            ? operationFailure
            : new CanonicalStreamInternalError(
                  'The collective public-key aggregate cancellation failed.',
                  operationFailure,
              );
    }
};

const generate = async (
    aggregate: CollectivePublicKeyAggregate,
    input: Parameters<CollectivePublicKeyAggregate['generate']>[0],
): Promise<Uint8Array<ArrayBuffer>> => {
    const record = requireRecord(aggregate);
    requirePhase(record, 'prepared');
    const checkpointLineageIdentifier = requireFixedOwnedBytes(
        input.checkpointLineageIdentifier,
        attemptIdentifierByteLength,
    );
    const memoryBoundary = createMemoryBoundary(record.context);
    const statusBoundary = createStatusBoundary();
    let familyAdapter:
        | ClosedWorkerCommonProofGenerationFamilyAdapter
        | undefined;
    let generatedProof: ClosedWorkerGeneratedCommonProofCapability | undefined;
    record.phase = 'generating';
    try {
        let adapterHandle: number | undefined;
        await withClosedWorkerProductionOperationAuthority(
            input.workerKernel,
            input.productionOperationIdentifiers,
            (productionOperationAuthority) =>
                productionOperationAuthority.withExactKernelAuthorization(
                    (authorization) => {
                        if (
                            authorization.kernel !== record.kernel ||
                            authorization.actionRandomnessContext.memory !==
                                record.context.memory ||
                            authorization.stateReservationCapabilityMemory !==
                                record.context.memory ||
                            authorization.stateReservationCapabilityPointer <=
                                0 ||
                            authorization.stateReservationCapabilityPointer +
                                stateVerifierCapabilityByteLength >
                                record.context.memory.buffer.byteLength
                        ) {
                            throw new CanonicalStreamRefusalError(
                                'wrongContext',
                            );
                        }
                        adapterHandle = record.context.runExclusive(
                            'collective public-key proof generation preparation',
                            () => {
                                const checkpointPointer = memoryBoundary.copy(
                                    checkpointLineageIdentifier,
                                );
                                const statusPointer =
                                    memoryBoundary.allocateZeroedWords(1);
                                try {
                                    const prepare =
                                        input.generationMode === 'fresh'
                                            ? record.context.wasmExports
                                                  .sealed_lattice_collective_public_key_aggregate_prepare_generation
                                            : record.context.wasmExports
                                                  .sealed_lattice_collective_public_key_aggregate_prepare_resumed_generation;
                                    const handle = prepare(
                                        record.sessionHandle,
                                        authorization.actionRandomnessHandle,
                                        authorization.stateVerifierSessionHandle,
                                        authorization.stateReservationCapabilityPointer,
                                        stateVerifierCapabilityByteLength,
                                        authorization.stateReservationHandle,
                                        checkpointPointer,
                                        checkpointLineageIdentifier.byteLength,
                                        statusPointer,
                                    );
                                    const [status] = memoryBoundary.readWords(
                                        statusPointer,
                                        1,
                                    );
                                    statusBoundary.throwIfError(status);
                                    return requireLiveHandle(
                                        handle,
                                        'The collective public-key generation adapter handle',
                                    );
                                } finally {
                                    memoryBoundary.zeroAndDeallocate(
                                        statusPointer,
                                        wasm32WordByteLength,
                                    );
                                    memoryBoundary.zeroAndDeallocate(
                                        checkpointPointer,
                                        checkpointLineageIdentifier.byteLength,
                                    );
                                }
                            },
                        );
                    },
                ),
        );
        if (adapterHandle === undefined) {
            throw new CanonicalStreamInternalError(
                'The production operation completed without a collective public-key adapter.',
            );
        }
        familyAdapter = openClosedWorkerCommonProofGenerationFamilyAdapter(
            record.context,
            adapterHandle,
        );
        const adapterForRun = familyAdapter;
        familyAdapter = undefined;
        const execution =
            await runClosedWorkerCommonProofGenerationFamilyAdapterWithExecutionOpener(
                adapterForRun,
                async (description) => {
                    const opened =
                        await input.openProofGenerationExecution(description);
                    return Object.freeze({
                        externalMemory: opened.externalMemory,
                        options: Object.freeze({
                            ...opened.options,
                            authenticatedSourceRangeReader: Object.freeze({
                                readExactRange: (
                                    request: CommonProofAuthenticatedSourceRangeRequest,
                                ) =>
                                    readAuthenticatedParticipantSourceRange(
                                        record,
                                        request,
                                    ),
                            }),
                        }),
                        outputStore: opened.outputStore,
                    });
                },
            );
        generatedProof = execution.generatedCapability;
        const proofDescriptor = await deriveGeneratedCommonProofDescriptor({
            kernel: record.kernel,
            outputChunkByteLengths: execution.outputChunkByteLengths,
            outputStore: execution.outputStore,
            proofFamilyLabel: 'collective public-key aggregate',
            streamDomain:
                canonicalStreamDomains.collectivePublicKeyAggregateProof,
        });
        const commitStatus = applyClosedWorkerGeneratedCommonProofCapability(
            generatedProof,
            record.context,
            (generatedProofHandle) =>
                Object.freeze({
                    consumed: false,
                    result: record.context.runExclusive(
                        'collective public-key generated-proof commit',
                        () =>
                            record.context.wasmExports.sealed_lattice_collective_public_key_aggregate_commit_generated_proof(
                                record.sessionHandle,
                                generatedProofHandle,
                            ),
                    ),
                }),
        );
        statusBoundary.throwIfError(commitStatus);
        record.generatedProof = generatedProof;
        generatedProof = undefined;
        record.phase = 'generated';
        return proofDescriptor;
    } catch (operationFailure) {
        const cleanupFailures: unknown[] = [];
        if (familyAdapter !== undefined) {
            try {
                releaseClosedWorkerCommonProofGenerationFamilyAdapter(
                    familyAdapter,
                );
            } catch (error) {
                cleanupFailures.push(error);
            }
        }
        if (generatedProof !== undefined) {
            try {
                generatedProof.release();
            } catch (error) {
                cleanupFailures.push(error);
            }
        }
        try {
            discardKernelSession(record);
        } catch (error) {
            cleanupFailures.push(error);
        } finally {
            clearParticipantSourceRecords(record.participantSources);
            aggregateRecords.delete(aggregate);
        }
        if (cleanupFailures.length > 0) {
            throw new CanonicalStreamInternalError(
                'Collective public-key proof generation failed to retire all worker-owned authority.',
                Object.freeze({ cleanupFailures, operationFailure }),
            );
        }
        throw operationFailure;
    } finally {
        checkpointLineageIdentifier.fill(0);
    }
};

const contributeToPackage = (
    aggregate: CollectivePublicKeyAggregate,
    builder: AcceptedSetupPackageBuilder,
): void => {
    const record = requireRecord(aggregate);
    requirePhase(record, 'generated');
    const generatedProof = record.generatedProof;
    if (generatedProof === undefined) {
        throw new CanonicalStreamInternalError(
            'The collective public-key generated proof is unavailable.',
        );
    }
    const builderOwner = requireAcceptedSetupPackageBuilderKernelOwner(
        builder,
        record.kernel,
        'collecting',
    );
    const memoryBoundary = createMemoryBoundary(record.context);
    let statementPointer = 0;
    try {
        statementPointer = memoryBoundary.copy(
            record.canonicalApplicationStatement,
        );
        const status = applyClosedWorkerGeneratedCommonProofCapability(
            generatedProof,
            record.context,
            (generatedProofHandle) =>
                Object.freeze({
                    consumed: false,
                    result: record.context.runExclusive(
                        'collective public-key package contribution',
                        () =>
                            record.context.wasmExports.sealed_lattice_collective_public_key_aggregate_contribute_package(
                                record.sessionHandle,
                                builderOwner.handle,
                                generatedProofHandle,
                                statementPointer,
                                record.canonicalApplicationStatement.byteLength,
                            ),
                    ),
                }),
        );
        createStatusBoundary().throwIfError(status);
        record.phase = 'packageContributed';
    } finally {
        memoryBoundary.zeroAndDeallocate(
            statementPointer,
            record.canonicalApplicationStatement.byteLength,
        );
    }
};

const verify = async (
    aggregate: CollectivePublicKeyAggregate,
    input: Parameters<CollectivePublicKeyAggregate['verify']>[0],
): Promise<void> => {
    const record = requireRecord(aggregate);
    requirePhase(record, 'packageContributed');
    const generatedProof = record.generatedProof;
    if (generatedProof === undefined) {
        throw new CanonicalStreamInternalError(
            'The collective public-key generated proof is unavailable.',
        );
    }
    const selectedSuiteOwner = requireSelectedSuiteRecordSourceKernelOwner({
        kernel: record.kernel,
        source: input.selectedSuiteRecordSource,
    });
    const assemblyOwner = requireAcceptedSetupVerificationAssemblyKernelOwner(
        input.acceptedSetupVerification,
        record.kernel,
        'collecting',
    );
    const memoryBoundary = createMemoryBoundary(record.context);
    const statusBoundary = createStatusBoundary();
    let terminalSourceHandle = 0;
    let familyAdapter:
        | ClosedWorkerCommonProofVerificationFamilyAdapter
        | undefined;
    let verifiedProof: VerifiedCommonProofCapability | undefined;
    record.phase = 'verifying';
    try {
        const adapterHandle = record.context.runExclusive(
            'collective public-key proof verification preparation',
            () => {
                const terminalPointer = memoryBoundary.allocateZeroedWords(1);
                const statusPointer = memoryBoundary.allocateZeroedWords(1);
                try {
                    const handle =
                        record.context.wasmExports.sealed_lattice_collective_public_key_aggregate_prepare_verification(
                            selectedSuiteOwner.handle,
                            record.sessionHandle,
                            assemblyOwner.handle,
                            terminalPointer,
                            statusPointer,
                        );
                    const [status] = memoryBoundary.readWords(statusPointer, 1);
                    statusBoundary.throwIfError(status);
                    [terminalSourceHandle] = memoryBoundary.readWords(
                        terminalPointer,
                        1,
                    );
                    requireLiveHandle(
                        terminalSourceHandle,
                        'The collective public-key terminal-source handle',
                    );
                    return requireLiveHandle(
                        handle,
                        'The collective public-key verification adapter handle',
                    );
                } finally {
                    memoryBoundary.zeroAndDeallocate(
                        terminalPointer,
                        wasm32WordByteLength,
                    );
                    memoryBoundary.zeroAndDeallocate(
                        statusPointer,
                        wasm32WordByteLength,
                    );
                }
            },
        );
        familyAdapter = openClosedWorkerCommonProofVerificationFamilyAdapter(
            record.context,
            adapterHandle,
        );
        const adapterForRun = familyAdapter;
        familyAdapter = undefined;
        verifiedProof =
            await runClosedWorkerCommonProofVerificationFamilyAdapter(
                adapterForRun,
                input.proofInputStore,
                input.options,
            );
        requireAcceptedSetupVerificationAssemblyKernelOwner(
            input.acceptedSetupVerification,
            record.kernel,
            'collecting',
        );
        const finishStatus = applyClosedWorkerVerifiedCommonProofCapability(
            verifiedProof,
            record.context,
            (verifiedProofHandle) => {
                const status = applyClosedWorkerGeneratedCommonProofCapability(
                    generatedProof,
                    record.context,
                    (generatedProofHandle) => {
                        const result = record.context.runExclusive(
                            'collective public-key verification finish',
                            () =>
                                record.context.wasmExports.sealed_lattice_collective_public_key_aggregate_finish_verification(
                                    verifiedProofHandle,
                                    terminalSourceHandle,
                                    generatedProofHandle,
                                ),
                        );
                        return Object.freeze({
                            consumed: result === 0,
                            result,
                        });
                    },
                );
                return Object.freeze({
                    consumed: status === 0,
                    result: status,
                });
            },
        );
        statusBoundary.throwIfError(finishStatus);
        verifiedProof = undefined;
        record.generatedProof = undefined;
        terminalSourceHandle = 0;
        try {
            discardKernelSession(record);
        } finally {
            clearParticipantSourceRecords(record.participantSources);
            aggregateRecords.delete(aggregate);
        }
    } catch (operationFailure) {
        const cleanupFailures: unknown[] = [];
        if (familyAdapter !== undefined) {
            try {
                releaseClosedWorkerCommonProofVerificationFamilyAdapter(
                    familyAdapter,
                );
            } catch (error) {
                cleanupFailures.push(error);
            }
        }
        if (verifiedProof !== undefined) {
            try {
                verifiedProof.release();
            } catch (error) {
                cleanupFailures.push(error);
            }
        }
        if (terminalSourceHandle !== 0) {
            try {
                const cleanupStatus = record.context.runExclusive(
                    'collective public-key terminal-source discard',
                    () =>
                        record.context.wasmExports.sealed_lattice_collective_public_key_aggregate_discard_verification_terminal_source(
                            terminalSourceHandle,
                        ),
                );
                statusBoundary.throwIfError(cleanupStatus);
            } catch (error) {
                cleanupFailures.push(error);
            }
        }
        if (aggregateRecords.has(aggregate)) {
            record.phase = 'packageContributed';
        }
        if (cleanupFailures.length > 0) {
            throw new CanonicalStreamInternalError(
                'Collective public-key verification failed to retire all temporary worker-owned authority.',
                Object.freeze({ cleanupFailures, operationFailure }),
            );
        }
        throw operationFailure;
    }
};

const createAggregate = (
    record: CollectivePublicKeyAggregateRecord,
): CollectivePublicKeyAggregate => {
    const aggregate: CollectivePublicKeyAggregate = Object.freeze({
        [collectivePublicKeyAggregateBrand]: true as const,
        cancel: (): void => cancelAggregate(aggregate),
        contributeToPackage: (builder): void =>
            contributeToPackage(aggregate, builder),
        copyCanonicalApplicationStatement: (): Uint8Array<ArrayBuffer> =>
            requireRecord(aggregate).canonicalApplicationStatement.slice(),
        describeCollectivePublicKey: (): CollectivePublicKeyDescription => {
            const description =
                requireRecord(aggregate).collectivePublicKeyDescription;
            return Object.freeze({
                fullObjectDigest: description.fullObjectDigest.slice(),
                totalByteLength: description.totalByteLength,
            });
        },
        generate: (input): Promise<Uint8Array<ArrayBuffer>> =>
            generate(aggregate, input),
        readCollectivePublicKeyRange: (
            sourceByteOffset,
            exactByteLength,
        ): Uint8Array<ArrayBuffer> =>
            readCollectivePublicKeyRange(
                aggregate,
                sourceByteOffset,
                exactByteLength,
            ),
        verify: (input): Promise<void> => verify(aggregate, input),
    });
    aggregateRecords.set(aggregate, record);
    return aggregate;
};

/**
 * Derives slot 20 from roster-ordered authenticated public-key-share bodies
 * and the completed VSS authority. Rust recomputes every participant root and
 * the aggregate; no participant-supplied aggregate or claimed root is admitted.
 */
export const beginCollectivePublicKeyAggregate = async (input: {
    kernel: TranscriptCoreKernel;
    participantSources: readonly CollectivePublicKeyParticipantSource[];
    vssRecipientAuthority: AggregateThresholdShareRecipientAuthority;
}): Promise<CollectivePublicKeyAggregate> => {
    const context = requireContext(input.kernel);
    const vssOwner =
        requireAggregateThresholdShareRecipientAuthorityKernelOwner(
            input.vssRecipientAuthority,
            input.kernel,
        );
    const bodyByteLength = requireParticipantBodyByteLength(context);
    const participantSources = requireParticipantSources(
        input.participantSources,
        bodyByteLength,
    );
    const memoryBoundary = createMemoryBoundary(context);
    const statusBoundary = createStatusBoundary();
    const participantSourceRecords: ParticipantSourceRecord[] = [];
    let statusPointer = 0;
    let sessionHandle = 0;
    try {
        statusPointer = memoryBoundary.allocateZeroedWords(1);
        sessionHandle = context.runExclusive(
            'collective public-key aggregate begin',
            () =>
                context.wasmExports.sealed_lattice_collective_public_key_aggregate_begin(
                    vssOwner.handle,
                    statusPointer,
                ),
        );
        const [status] = memoryBoundary.readWords(statusPointer, 1);
        statusBoundary.throwIfError(status);
        requireLiveHandle(
            sessionHandle,
            'The collective public-key aggregate session handle',
        );
        for (
            let rosterPosition = 0;
            rosterPosition < participantSources.length;
            rosterPosition += 1
        ) {
            participantSourceRecords.push(
                await ingestParticipantSource({
                    bodyByteLength,
                    context,
                    participantSource: participantSources[rosterPosition],
                    rosterPosition,
                    sessionHandle,
                }),
            );
        }
        const finishRosterStatus = context.runExclusive(
            'collective public-key roster finish',
            () =>
                context.wasmExports.sealed_lattice_collective_public_key_aggregate_finish_roster(
                    sessionHandle,
                ),
        );
        statusBoundary.throwIfError(finishRosterStatus);
        const canonicalApplicationStatement = copyCanonicalApplicationStatement(
            { context, sessionHandle },
        );
        const collectivePublicKeyDescription = describeCollectivePublicKey({
            context,
            sessionHandle,
        });
        const aggregate = createAggregate({
            canonicalApplicationStatement,
            collectivePublicKeyDescription,
            context,
            generatedProof: undefined,
            kernel: input.kernel,
            participantBodyByteLength: bodyByteLength,
            participantSources: Object.freeze([...participantSourceRecords]),
            phase: 'prepared',
            sessionHandle,
        });
        sessionHandle = 0;
        return aggregate;
    } catch (operationFailure) {
        clearParticipantSourceRecords(participantSourceRecords);
        for (const participantSource of participantSources) {
            participantSource.descriptorBytes.fill(0);
        }
        if (sessionHandle !== 0) {
            try {
                const cleanupStatus = context.runExclusive(
                    'unwrapped collective public-key session discard',
                    () =>
                        context.wasmExports.sealed_lattice_collective_public_key_aggregate_discard_session(
                            sessionHandle,
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
