import {
    BrowserActionStorageCustodyError,
    foundationProfile,
    type BrowserActionStorageWorkerKernel,
} from '@sealed-lattice/types';

import type { VerifiedTranscriptObject } from './canonical-board-runtime.js';
import {
    CanonicalStreamCleanupError,
    CanonicalStreamInternalError,
    CanonicalStreamRefusalError,
    CanonicalStreamResourceError,
    type CanonicalStreamKernelContext,
} from './canonical-stream-runtime.js';
import type { ClosedWorkerProductionOperationIdentifiers } from './local-storage-root-worker-kernel/authorities.js';
import { withClosedWorkerProductionOperationAuthority } from './local-storage-root-worker-kernel/worker-kernel.js';
import {
    activateSelectedSuiteRecordSource,
    releaseSelectedSuiteRecordSource,
    requireSelectedSuiteRecordSourceKernelOwner,
    type SelectedSuiteRecordSource,
} from './selected-suite-record-source.js';
import { resolveCommonProofKernelContext } from './transcript-core-bridge/common-proof-kernel-context.js';
import type { TranscriptCoreKernelCommandRuntime } from './transcript-core-bridge/kernel-runtime.js';
import type { TranscriptCoreKernel } from './transcript-core-bridge/kernel-types.js';
import { resolveAggregatePublicRandomnessBoardAuthorization } from './vss-share-linkage-verification-runtime.js';
import { WasmMemoryBoundary } from './wasm-memory-boundary.js';
import { WasmStatusBoundary } from './wasm-status-boundary.js';

const verifierCapabilityByteLength = 32;
const wasm32MaximumUnsignedInteger = 0xffff_ffff;
export const selectedSetupGenerationPublicKeyShareBodyByteLength = 13_631_488;

type SetupGenerationKernelContext = CanonicalStreamKernelContext &
    Required<
        Pick<
            CanonicalStreamKernelContext,
            | 'setupGenerationAuthorityBegin'
            | 'setupGenerationAuthorityRelease'
            | 'setupGenerationPublicKeyShareBodyByteLength'
            | 'setupGenerationPublicKeyShareBodyCancel'
            | 'setupGenerationPublicKeyShareBodyOpen'
            | 'setupGenerationPublicKeyShareBodyRead'
            | 'setupGenerationPublicKeyShareSourceByteLength'
            | 'setupGenerationRecipientVssPayloadByteLength'
            | 'setupGenerationRecipientVssPayloadCancel'
            | 'setupGenerationRecipientVssPayloadOpen'
            | 'setupGenerationRecipientVssPayloadRead'
            | 'setupGenerationRecipientVssPayloadSourceByteLength'
            | 'setupGenerationRecipientVssPayloadSourceRecipientRosterPosition'
        >
    >;

const setupGenerationAuthorityBrand: unique symbol = Symbol(
    'sealed-lattice/setup-generation-authority',
);
const setupGenerationRecipientPayloadSourceBrand: unique symbol = Symbol(
    'sealed-lattice/setup-generation-recipient-payload-source',
);
const setupGenerationPublicKeyShareBodySourceBrand: unique symbol = Symbol(
    'sealed-lattice/setup-generation-public-key-share-body-source',
);

export type BrowserOwnedSetupGenerationAuthority = Readonly<{
    readonly [setupGenerationAuthorityBrand]: true;
    publicKeyShareBodyByteLength(): number;
    openPublicKeyShareBody(): SetupGenerationPublicKeyShareBodySource;
    payloadByteLength(recipientRosterPosition: number): number;
    openRecipientPayload(
        recipientRosterPosition: number,
    ): SetupGenerationRecipientPayloadSource;
    release(): void;
}>;

export type SetupGenerationPublicKeyShareBodySource = Readonly<{
    readonly [setupGenerationPublicKeyShareBodySourceBrand]: true;
    readonly byteLength: number;
    cancel(): void;
    read(input: {
        readonly expectedOffset: number;
        readonly requestedByteLength: number;
    }): Uint8Array<ArrayBuffer>;
}>;

export type SetupGenerationRecipientPayloadSource = Readonly<{
    readonly [setupGenerationRecipientPayloadSourceBrand]: true;
    readonly byteLength: number;
    readonly recipientRosterPosition: number;
    cancel(): void;
    read(input: {
        readonly expectedOffset: number;
        readonly requestedByteLength: number;
    }): Uint8Array<ArrayBuffer>;
}>;

type AuthorityRecord = {
    readonly context: SetupGenerationKernelContext;
    readonly handle: number;
    readonly memoryBoundary: WasmMemoryBoundary;
    readonly publicKeyShareSources: Set<SetupGenerationPublicKeyShareBodySource>;
    readonly recipientPayloadSources: Set<SetupGenerationRecipientPayloadSource>;
    readonly statusBoundary: WasmStatusBoundary;
    released: boolean;
};

type SourceRecord = {
    readonly authority: BrowserOwnedSetupGenerationAuthority;
    readonly byteLength: number;
    readonly handle: number;
    readonly recipientRosterPosition: number;
    closed: boolean;
    nextOffset: number;
};

type PublicKeyShareSourceRecord = {
    readonly authority: BrowserOwnedSetupGenerationAuthority;
    readonly byteLength: number;
    readonly handle: number;
    closed: boolean;
    nextOffset: number;
};

const authorityRecords = new WeakMap<
    BrowserOwnedSetupGenerationAuthority,
    AuthorityRecord
>();
const sourceRecords = new WeakMap<
    SetupGenerationRecipientPayloadSource,
    SourceRecord
>();
const publicKeyShareSourceRecords = new WeakMap<
    SetupGenerationPublicKeyShareBodySource,
    PublicKeyShareSourceRecord
>();

export type SetupGenerationAuthorityKernelAuthorization = Readonly<{
    handle: number;
}>;

/**
 * Internal same-worker handoff for proof-family adapters. The setup authority
 * is accepted only when its allocation, exclusivity, and memory boundaries
 * are the exact boundaries of the requesting transcript-core runtime.
 */
export const resolveSetupGenerationAuthorityKernelAuthorization = (
    authority: BrowserOwnedSetupGenerationAuthority,
    context: TranscriptCoreKernelCommandRuntime,
): SetupGenerationAuthorityKernelAuthorization => {
    const record = requireAuthorityRecord(authority);
    if (
        record.context.memory !== context.memory ||
        record.context.allocate !== context.allocate ||
        record.context.deallocate !== context.deallocate ||
        record.context.runExclusive !== context.runExclusive
    ) {
        throw new CanonicalStreamInternalError(
            'The setup-generation authority belongs to another WASM worker.',
        );
    }
    return Object.freeze({ handle: record.handle });
};

const requireKernelContext = (
    context: CanonicalStreamKernelContext,
): SetupGenerationKernelContext => {
    const requiredFunctions = [
        context.setupGenerationAuthorityBegin,
        context.setupGenerationAuthorityRelease,
        context.setupGenerationPublicKeyShareBodyByteLength,
        context.setupGenerationPublicKeyShareBodyCancel,
        context.setupGenerationPublicKeyShareBodyOpen,
        context.setupGenerationPublicKeyShareBodyRead,
        context.setupGenerationPublicKeyShareSourceByteLength,
        context.setupGenerationRecipientVssPayloadByteLength,
        context.setupGenerationRecipientVssPayloadCancel,
        context.setupGenerationRecipientVssPayloadOpen,
        context.setupGenerationRecipientVssPayloadRead,
        context.setupGenerationRecipientVssPayloadSourceByteLength,
        context.setupGenerationRecipientVssPayloadSourceRecipientRosterPosition,
    ];
    if (requiredFunctions.some((value) => typeof value !== 'function')) {
        throw new CanonicalStreamInternalError(
            'The transcript-core kernel lacks the setup-generation custody boundary.',
        );
    }
    return context as SetupGenerationKernelContext;
};

const requireWasm32Handle = (value: number, label: string): number => {
    if (
        !Number.isSafeInteger(value) ||
        value <= 0 ||
        value > wasm32MaximumUnsignedInteger
    ) {
        throw new CanonicalStreamInternalError(`${label} is invalid.`);
    }
    return value;
};

const requireRecipientRosterPosition = (value: number): number => {
    if (
        !Number.isSafeInteger(value) ||
        value < 0 ||
        value >= foundationProfile.participantCount
    ) {
        throw new CanonicalStreamRefusalError('wrongTypeOrLength');
    }
    return value;
};

const requireCapabilityPointer = (
    context: CanonicalStreamKernelContext,
    pointer: number,
    label: string,
): number => {
    if (
        !Number.isSafeInteger(pointer) ||
        pointer <= 0 ||
        pointer + verifierCapabilityByteLength >
            context.memory.buffer.byteLength
    ) {
        throw new CanonicalStreamInternalError(`${label} is invalid.`);
    }
    return pointer;
};

const requireExactByteLength = (value: bigint, label: string): number => {
    if (
        value <= 0n ||
        value > BigInt(Number.MAX_SAFE_INTEGER) ||
        value > BigInt(foundationProfile.maximumCanonicalStreamByteLength)
    ) {
        throw new CanonicalStreamResourceError(
            `${label} exceeds the canonical-stream safety bound.`,
        );
    }
    return Number(value);
};

const requireAuthorityRecord = (
    authority: BrowserOwnedSetupGenerationAuthority,
): AuthorityRecord => {
    const record = authorityRecords.get(authority);
    if (record === undefined || record.released) {
        throw new CanonicalStreamInternalError(
            'The setup-generation authority is unavailable.',
        );
    }
    return record;
};

const requireSourceRecord = (
    source: SetupGenerationRecipientPayloadSource,
): SourceRecord => {
    const record = sourceRecords.get(source);
    if (record === undefined || record.closed) {
        throw new CanonicalStreamInternalError(
            'The setup-generation recipient source is unavailable.',
        );
    }
    requireAuthorityRecord(record.authority);
    return record;
};

const requirePublicKeyShareSourceRecord = (
    source: SetupGenerationPublicKeyShareBodySource,
): PublicKeyShareSourceRecord => {
    const record = publicKeyShareSourceRecords.get(source);
    if (record === undefined || record.closed) {
        throw new CanonicalStreamInternalError(
            'The setup-generation public-key-share source is unavailable.',
        );
    }
    requireAuthorityRecord(record.authority);
    return record;
};

const encodeOrderedHandles = (
    handles: readonly number[],
): Uint8Array<ArrayBuffer> => {
    const expectedHandleCount = foundationProfile.participantCount * 3;
    if (handles.length !== expectedHandleCount) {
        throw new CanonicalStreamRefusalError('wrongTypeOrLength');
    }
    const bytes = new Uint8Array(
        expectedHandleCount * Uint32Array.BYTES_PER_ELEMENT,
    );
    const view = new DataView(bytes.buffer);
    handles.forEach((handle, handleIndex) => {
        view.setUint32(
            handleIndex * Uint32Array.BYTES_PER_ELEMENT,
            requireWasm32Handle(
                handle,
                'A setup-generation canonical-board object handle',
            ),
            true,
        );
    });
    return bytes;
};

const createStatusBoundary = (): WasmStatusBoundary =>
    new WasmStatusBoundary({
        createInternalError: (message) =>
            new CanonicalStreamInternalError(message),
        createRefusalError: (refusalReason) =>
            new CanonicalStreamRefusalError(refusalReason),
        createResourceError: () => new CanonicalStreamResourceError(),
        internalFailureMessage:
            'The setup-generation kernel session failed internally.',
        unknownStatusMessage:
            'The setup-generation kernel returned an unknown status code.',
    });

const readStatus = (
    memoryBoundary: WasmMemoryBoundary,
    statusBoundary: WasmStatusBoundary,
    statusPointer: number,
): void => {
    const [status] = memoryBoundary.readWords(statusPointer, 1);
    statusBoundary.throwIfError(status);
};

const publicKeyShareBodyByteLength = (
    authority: BrowserOwnedSetupGenerationAuthority,
): number => {
    const record = requireAuthorityRecord(authority);
    return record.context.runExclusive(
        'setup-generation public-key-share body byte length',
        () => {
            const statusPointer = record.memoryBoundary.allocateZeroedWords(1);
            try {
                const byteLength =
                    record.context.setupGenerationPublicKeyShareBodyByteLength(
                        record.handle,
                        statusPointer,
                    );
                readStatus(
                    record.memoryBoundary,
                    record.statusBoundary,
                    statusPointer,
                );
                const exactByteLength = requireExactByteLength(
                    byteLength,
                    'The setup-generation public-key-share body',
                );
                if (
                    exactByteLength !==
                    selectedSetupGenerationPublicKeyShareBodyByteLength
                ) {
                    throw new CanonicalStreamInternalError(
                        'The setup-generation public-key-share body has the wrong selected-suite length.',
                    );
                }
                return exactByteLength;
            } finally {
                record.memoryBoundary.zeroAndDeallocate(
                    statusPointer,
                    Uint32Array.BYTES_PER_ELEMENT,
                );
            }
        },
    );
};

const cancelPublicKeyShareSource = (
    source: SetupGenerationPublicKeyShareBodySource,
): void => {
    const sourceRecord = requirePublicKeyShareSourceRecord(source);
    const authorityRecord = requireAuthorityRecord(sourceRecord.authority);
    const status = authorityRecord.context.runExclusive(
        'setup-generation public-key-share body cancellation',
        () =>
            authorityRecord.context.setupGenerationPublicKeyShareBodyCancel(
                sourceRecord.handle,
            ),
    );
    authorityRecord.statusBoundary.throwIfError(status);
    sourceRecord.closed = true;
    authorityRecord.publicKeyShareSources.delete(source);
    publicKeyShareSourceRecords.delete(source);
};

const cancelUnactivatedPublicKeyShareSource = (
    authorityRecord: AuthorityRecord,
    sourceHandle: number,
    operationFailure: unknown,
): never => {
    try {
        const cancellationStatus =
            authorityRecord.context.setupGenerationPublicKeyShareBodyCancel(
                sourceHandle,
            );
        authorityRecord.statusBoundary.throwIfError(cancellationStatus);
    } catch (cleanupFailure) {
        throw new CanonicalStreamCleanupError(operationFailure, cleanupFailure);
    }
    throw operationFailure;
};

const readPublicKeyShareSource = (
    source: SetupGenerationPublicKeyShareBodySource,
    input: {
        readonly expectedOffset: number;
        readonly requestedByteLength: number;
    },
): Uint8Array<ArrayBuffer> => {
    const sourceRecord = requirePublicKeyShareSourceRecord(source);
    const authorityRecord = requireAuthorityRecord(sourceRecord.authority);
    if (
        !Number.isSafeInteger(input.expectedOffset) ||
        input.expectedOffset !== sourceRecord.nextOffset
    ) {
        throw new CanonicalStreamRefusalError('wrongContext');
    }
    const remainingByteLength =
        sourceRecord.byteLength - sourceRecord.nextOffset;
    if (
        !Number.isSafeInteger(input.requestedByteLength) ||
        input.requestedByteLength <= 0 ||
        input.requestedByteLength > foundationProfile.streamChunkByteLength ||
        input.requestedByteLength > remainingByteLength
    ) {
        throw new CanonicalStreamRefusalError('wrongTypeOrLength');
    }
    authorityRecord.memoryBoundary.validateAllocationByteLength(
        input.requestedByteLength,
    );
    return authorityRecord.context.runExclusive(
        'setup-generation public-key-share body read',
        () => {
            const outputPointer = authorityRecord.memoryBoundary.allocate(
                input.requestedByteLength,
            );
            try {
                const status =
                    authorityRecord.context.setupGenerationPublicKeyShareBodyRead(
                        sourceRecord.handle,
                        BigInt(sourceRecord.nextOffset),
                        outputPointer,
                        input.requestedByteLength,
                    );
                authorityRecord.statusBoundary.throwIfError(status);
                const output = new Uint8Array(
                    authorityRecord.context.memory.buffer,
                    outputPointer,
                    input.requestedByteLength,
                ).slice();
                sourceRecord.nextOffset += input.requestedByteLength;
                if (sourceRecord.nextOffset === sourceRecord.byteLength) {
                    sourceRecord.closed = true;
                    authorityRecord.publicKeyShareSources.delete(source);
                    publicKeyShareSourceRecords.delete(source);
                }
                return output;
            } finally {
                authorityRecord.memoryBoundary.zeroAndDeallocate(
                    outputPointer,
                    input.requestedByteLength,
                );
            }
        },
    );
};

const openPublicKeyShareBody = (
    authority: BrowserOwnedSetupGenerationAuthority,
): SetupGenerationPublicKeyShareBodySource => {
    const authorityRecord = requireAuthorityRecord(authority);
    const expectedByteLength = publicKeyShareBodyByteLength(authority);
    return authorityRecord.context.runExclusive(
        'setup-generation public-key-share body open',
        () => {
            const statusPointer =
                authorityRecord.memoryBoundary.allocateZeroedWords(1);
            let sourceHandle = 0;
            try {
                try {
                    sourceHandle =
                        authorityRecord.context.setupGenerationPublicKeyShareBodyOpen(
                            authorityRecord.handle,
                            statusPointer,
                        );
                    readStatus(
                        authorityRecord.memoryBoundary,
                        authorityRecord.statusBoundary,
                        statusPointer,
                    );
                    requireWasm32Handle(
                        sourceHandle,
                        'The setup-generation public-key-share source handle',
                    );
                    const sourceByteLengthValue =
                        authorityRecord.context.setupGenerationPublicKeyShareSourceByteLength(
                            sourceHandle,
                            statusPointer,
                        );
                    readStatus(
                        authorityRecord.memoryBoundary,
                        authorityRecord.statusBoundary,
                        statusPointer,
                    );
                    const sourceByteLength = requireExactByteLength(
                        sourceByteLengthValue,
                        'The opened setup-generation public-key-share body',
                    );
                    if (sourceByteLength !== expectedByteLength) {
                        throw new CanonicalStreamInternalError(
                            'The opened setup-generation public-key-share source has the wrong binding.',
                        );
                    }
                    const source: SetupGenerationPublicKeyShareBodySource =
                        Object.freeze({
                            [setupGenerationPublicKeyShareBodySourceBrand]:
                                true as const,
                            byteLength: sourceByteLength,
                            cancel: () => cancelPublicKeyShareSource(source),
                            read: (readInput) =>
                                readPublicKeyShareSource(source, readInput),
                        });
                    publicKeyShareSourceRecords.set(source, {
                        authority,
                        byteLength: sourceByteLength,
                        closed: false,
                        handle: sourceHandle,
                        nextOffset: 0,
                    });
                    authorityRecord.publicKeyShareSources.add(source);
                    sourceHandle = 0;
                    return source;
                } catch (operationFailure) {
                    if (sourceHandle !== 0) {
                        return cancelUnactivatedPublicKeyShareSource(
                            authorityRecord,
                            sourceHandle,
                            operationFailure,
                        );
                    }
                    throw operationFailure;
                }
            } finally {
                authorityRecord.memoryBoundary.zeroAndDeallocate(
                    statusPointer,
                    Uint32Array.BYTES_PER_ELEMENT,
                );
            }
        },
    );
};

const payloadByteLength = (
    authority: BrowserOwnedSetupGenerationAuthority,
    recipientRosterPosition: number,
): number => {
    const record = requireAuthorityRecord(authority);
    const position = requireRecipientRosterPosition(recipientRosterPosition);
    return record.context.runExclusive(
        'setup-generation recipient payload byte length',
        () => {
            const statusPointer = record.memoryBoundary.allocateZeroedWords(1);
            try {
                const byteLength =
                    record.context.setupGenerationRecipientVssPayloadByteLength(
                        record.handle,
                        position,
                        statusPointer,
                    );
                readStatus(
                    record.memoryBoundary,
                    record.statusBoundary,
                    statusPointer,
                );
                return requireExactByteLength(
                    byteLength,
                    'The setup-generation recipient payload',
                );
            } finally {
                record.memoryBoundary.zeroAndDeallocate(
                    statusPointer,
                    Uint32Array.BYTES_PER_ELEMENT,
                );
            }
        },
    );
};

const cancelSource = (source: SetupGenerationRecipientPayloadSource): void => {
    const sourceRecord = requireSourceRecord(source);
    const authorityRecord = requireAuthorityRecord(sourceRecord.authority);
    const status = authorityRecord.context.runExclusive(
        'setup-generation recipient payload cancellation',
        () =>
            authorityRecord.context.setupGenerationRecipientVssPayloadCancel(
                sourceRecord.handle,
            ),
    );
    authorityRecord.statusBoundary.throwIfError(status);
    sourceRecord.closed = true;
    authorityRecord.recipientPayloadSources.delete(source);
    sourceRecords.delete(source);
};

const cancelUnactivatedSource = (
    authorityRecord: AuthorityRecord,
    sourceHandle: number,
    operationFailure: unknown,
): never => {
    try {
        const cancellationStatus =
            authorityRecord.context.setupGenerationRecipientVssPayloadCancel(
                sourceHandle,
            );
        authorityRecord.statusBoundary.throwIfError(cancellationStatus);
    } catch (cleanupFailure) {
        throw new CanonicalStreamCleanupError(operationFailure, cleanupFailure);
    }
    throw operationFailure;
};

const readSource = (
    source: SetupGenerationRecipientPayloadSource,
    input: {
        readonly expectedOffset: number;
        readonly requestedByteLength: number;
    },
): Uint8Array<ArrayBuffer> => {
    const sourceRecord = requireSourceRecord(source);
    const authorityRecord = requireAuthorityRecord(sourceRecord.authority);
    if (
        !Number.isSafeInteger(input.expectedOffset) ||
        input.expectedOffset !== sourceRecord.nextOffset
    ) {
        throw new CanonicalStreamRefusalError('wrongContext');
    }
    const remainingByteLength =
        sourceRecord.byteLength - sourceRecord.nextOffset;
    if (
        !Number.isSafeInteger(input.requestedByteLength) ||
        input.requestedByteLength <= 0 ||
        input.requestedByteLength > remainingByteLength
    ) {
        throw new CanonicalStreamRefusalError('wrongTypeOrLength');
    }
    authorityRecord.memoryBoundary.validateAllocationByteLength(
        input.requestedByteLength,
    );
    return authorityRecord.context.runExclusive(
        'setup-generation recipient payload read',
        () => {
            const outputPointer = authorityRecord.memoryBoundary.allocate(
                input.requestedByteLength,
            );
            try {
                const status =
                    authorityRecord.context.setupGenerationRecipientVssPayloadRead(
                        sourceRecord.handle,
                        BigInt(sourceRecord.nextOffset),
                        outputPointer,
                        input.requestedByteLength,
                    );
                authorityRecord.statusBoundary.throwIfError(status);
                const output = new Uint8Array(
                    authorityRecord.context.memory.buffer,
                    outputPointer,
                    input.requestedByteLength,
                ).slice();
                sourceRecord.nextOffset += input.requestedByteLength;
                if (sourceRecord.nextOffset === sourceRecord.byteLength) {
                    sourceRecord.closed = true;
                    authorityRecord.recipientPayloadSources.delete(source);
                    sourceRecords.delete(source);
                }
                return output;
            } finally {
                authorityRecord.memoryBoundary.zeroAndDeallocate(
                    outputPointer,
                    input.requestedByteLength,
                );
            }
        },
    );
};

const openRecipientPayload = (
    authority: BrowserOwnedSetupGenerationAuthority,
    recipientRosterPosition: number,
): SetupGenerationRecipientPayloadSource => {
    const authorityRecord = requireAuthorityRecord(authority);
    const position = requireRecipientRosterPosition(recipientRosterPosition);
    const expectedByteLength = payloadByteLength(authority, position);
    return authorityRecord.context.runExclusive(
        'setup-generation recipient payload open',
        () => {
            const statusPointer =
                authorityRecord.memoryBoundary.allocateZeroedWords(1);
            let sourceHandle = 0;
            try {
                try {
                    sourceHandle =
                        authorityRecord.context.setupGenerationRecipientVssPayloadOpen(
                            authorityRecord.handle,
                            position,
                            statusPointer,
                        );
                    readStatus(
                        authorityRecord.memoryBoundary,
                        authorityRecord.statusBoundary,
                        statusPointer,
                    );
                    requireWasm32Handle(
                        sourceHandle,
                        'The setup-generation recipient source handle',
                    );
                    const sourceByteLengthValue =
                        authorityRecord.context.setupGenerationRecipientVssPayloadSourceByteLength(
                            sourceHandle,
                            statusPointer,
                        );
                    readStatus(
                        authorityRecord.memoryBoundary,
                        authorityRecord.statusBoundary,
                        statusPointer,
                    );
                    const sourceByteLength = requireExactByteLength(
                        sourceByteLengthValue,
                        'The opened setup-generation recipient payload',
                    );
                    const boundRecipientRosterPosition =
                        authorityRecord.context.setupGenerationRecipientVssPayloadSourceRecipientRosterPosition(
                            sourceHandle,
                            statusPointer,
                        );
                    readStatus(
                        authorityRecord.memoryBoundary,
                        authorityRecord.statusBoundary,
                        statusPointer,
                    );
                    if (
                        sourceByteLength !== expectedByteLength ||
                        boundRecipientRosterPosition !== position
                    ) {
                        throw new CanonicalStreamInternalError(
                            'The opened setup-generation recipient source has the wrong binding.',
                        );
                    }
                    const source: SetupGenerationRecipientPayloadSource =
                        Object.freeze({
                            [setupGenerationRecipientPayloadSourceBrand]:
                                true as const,
                            byteLength: sourceByteLength,
                            recipientRosterPosition: position,
                            cancel: () => cancelSource(source),
                            read: (readInput) => readSource(source, readInput),
                        });
                    sourceRecords.set(source, {
                        authority,
                        byteLength: sourceByteLength,
                        closed: false,
                        handle: sourceHandle,
                        nextOffset: 0,
                        recipientRosterPosition: position,
                    });
                    authorityRecord.recipientPayloadSources.add(source);
                    sourceHandle = 0;
                    return source;
                } catch (operationFailure) {
                    if (sourceHandle !== 0) {
                        return cancelUnactivatedSource(
                            authorityRecord,
                            sourceHandle,
                            operationFailure,
                        );
                    }
                    throw operationFailure;
                }
            } finally {
                authorityRecord.memoryBoundary.zeroAndDeallocate(
                    statusPointer,
                    Uint32Array.BYTES_PER_ELEMENT,
                );
            }
        },
    );
};

const releaseAuthority = (
    authority: BrowserOwnedSetupGenerationAuthority,
): void => {
    const record = requireAuthorityRecord(authority);
    const status = record.context.runExclusive(
        'setup-generation authority release',
        () => record.context.setupGenerationAuthorityRelease(record.handle),
    );
    record.statusBoundary.throwIfError(status);
    record.released = true;
    for (const source of record.publicKeyShareSources) {
        const sourceRecord = publicKeyShareSourceRecords.get(source);
        if (sourceRecord !== undefined) {
            sourceRecord.closed = true;
            publicKeyShareSourceRecords.delete(source);
        }
    }
    record.publicKeyShareSources.clear();
    for (const source of record.recipientPayloadSources) {
        const sourceRecord = sourceRecords.get(source);
        if (sourceRecord !== undefined) {
            sourceRecord.closed = true;
            sourceRecords.delete(source);
        }
    }
    record.recipientPayloadSources.clear();
    authorityRecords.delete(authority);
};

/** Module-private FFI step after every branded same-worker capability resolves. */
const retainSetupGenerationAuthorityFromResolvedCapabilities = (input: {
    readonly actionRandomnessHandle: number;
    readonly boardVerifierSessionCapabilityPointer: number;
    readonly boardVerifierSessionHandle: number;
    readonly context: CanonicalStreamKernelContext;
    readonly orderedPublicRandomnessObjectHandles: readonly number[];
    readonly selectedSuiteHandle: number;
    readonly stateVerifierSessionCapabilityPointer: number;
    readonly stateVerifierSessionHandle: number;
    readonly verifiedReservationHandle: number;
}): BrowserOwnedSetupGenerationAuthority => {
    const context = requireKernelContext(input.context);
    const orderedHandleBytes = encodeOrderedHandles(
        input.orderedPublicRandomnessObjectHandles,
    );
    const memoryBoundary = new WasmMemoryBoundary({
        context,
        createInternalError: (message) =>
            new CanonicalStreamInternalError(message),
        createResourceError: (message) =>
            new CanonicalStreamResourceError(message),
        label: 'setup-generation boundary',
    });
    const statusBoundary = createStatusBoundary();
    const selectedSuiteHandle = requireWasm32Handle(
        input.selectedSuiteHandle,
        'The selected-suite handle',
    );
    const boardVerifierSessionHandle = requireWasm32Handle(
        input.boardVerifierSessionHandle,
        'The canonical-board verifier session handle',
    );
    const actionRandomnessHandle = requireWasm32Handle(
        input.actionRandomnessHandle,
        'The action-randomness handle',
    );
    const stateVerifierSessionHandle = requireWasm32Handle(
        input.stateVerifierSessionHandle,
        'The state-verifier session handle',
    );
    const verifiedReservationHandle = requireWasm32Handle(
        input.verifiedReservationHandle,
        'The verified state-reservation handle',
    );
    const boardVerifierSessionCapabilityPointer = requireCapabilityPointer(
        context,
        input.boardVerifierSessionCapabilityPointer,
        'The canonical-board verifier capability',
    );
    const stateVerifierSessionCapabilityPointer = requireCapabilityPointer(
        context,
        input.stateVerifierSessionCapabilityPointer,
        'The state-verifier capability',
    );

    try {
        return context.runExclusive('setup-generation authority begin', () => {
            let orderedHandleBytesPointer = 0;
            let statusPointer = 0;
            let authorityHandle = 0;
            try {
                orderedHandleBytesPointer =
                    memoryBoundary.copy(orderedHandleBytes);
                statusPointer = memoryBoundary.allocateZeroedWords(1);
                try {
                    authorityHandle = context.setupGenerationAuthorityBegin(
                        selectedSuiteHandle,
                        boardVerifierSessionHandle,
                        boardVerifierSessionCapabilityPointer,
                        verifierCapabilityByteLength,
                        orderedHandleBytesPointer,
                        orderedHandleBytes.byteLength,
                        actionRandomnessHandle,
                        stateVerifierSessionHandle,
                        stateVerifierSessionCapabilityPointer,
                        verifierCapabilityByteLength,
                        verifiedReservationHandle,
                        statusPointer,
                    );
                    readStatus(memoryBoundary, statusBoundary, statusPointer);
                    requireWasm32Handle(
                        authorityHandle,
                        'The setup-generation authority handle',
                    );
                    const authority: BrowserOwnedSetupGenerationAuthority =
                        Object.freeze({
                            [setupGenerationAuthorityBrand]: true as const,
                            openPublicKeyShareBody: () =>
                                openPublicKeyShareBody(authority),
                            openRecipientPayload: (recipientRosterPosition) =>
                                openRecipientPayload(
                                    authority,
                                    recipientRosterPosition,
                                ),
                            payloadByteLength: (recipientRosterPosition) =>
                                payloadByteLength(
                                    authority,
                                    recipientRosterPosition,
                                ),
                            publicKeyShareBodyByteLength: () =>
                                publicKeyShareBodyByteLength(authority),
                            release: () => releaseAuthority(authority),
                        });
                    authorityRecords.set(authority, {
                        context,
                        handle: authorityHandle,
                        memoryBoundary,
                        released: false,
                        publicKeyShareSources: new Set(),
                        recipientPayloadSources: new Set(),
                        statusBoundary,
                    });
                    authorityHandle = 0;
                    return authority;
                } catch (operationFailure) {
                    if (authorityHandle !== 0) {
                        try {
                            const cleanupStatus =
                                context.setupGenerationAuthorityRelease(
                                    authorityHandle,
                                );
                            statusBoundary.throwIfError(cleanupStatus);
                        } catch (cleanupFailure) {
                            let retryFailure: unknown;
                            try {
                                const retryStatus =
                                    context.setupGenerationAuthorityRelease(
                                        authorityHandle,
                                    );
                                statusBoundary.throwIfError(retryStatus);
                            } catch (error) {
                                retryFailure = error;
                            }
                            throw new CanonicalStreamCleanupError(
                                operationFailure,
                                retryFailure === undefined
                                    ? cleanupFailure
                                    : Object.freeze([
                                          cleanupFailure,
                                          retryFailure,
                                      ]),
                            );
                        }
                    }
                    throw operationFailure;
                }
            } finally {
                if (statusPointer !== 0) {
                    memoryBoundary.zeroAndDeallocate(
                        statusPointer,
                        Uint32Array.BYTES_PER_ELEMENT,
                    );
                }
                if (orderedHandleBytesPointer !== 0) {
                    memoryBoundary.zeroAndDeallocate(
                        orderedHandleBytesPointer,
                        orderedHandleBytes.byteLength,
                    );
                }
            }
        });
    } finally {
        orderedHandleBytes.fill(0);
    }
};

export type BrowserOwnedSetupGenerationAuthorityInput = Readonly<{
    canonicalSuiteRecordBytes: Uint8Array;
    kernel: TranscriptCoreKernel;
    orderedPublicRandomnessCommitmentObjects: readonly VerifiedTranscriptObject[];
    orderedPublicRandomnessRevealObjects: readonly VerifiedTranscriptObject[];
    orderedSetupIntentObjects: readonly VerifiedTranscriptObject[];
    productionOperationIdentifiers: ClosedWorkerProductionOperationIdentifiers;
    workerKernel: BrowserActionStorageWorkerKernel;
}>;

const decodeOrderedPublicRandomnessObjectHandles = (
    handleBytes: Uint8Array<ArrayBuffer>,
): readonly number[] => {
    const expectedHandleCount = foundationProfile.participantCount * 3;
    if (
        handleBytes.byteLength !==
        expectedHandleCount * Uint32Array.BYTES_PER_ELEMENT
    ) {
        throw new CanonicalStreamInternalError(
            'The canonical-board verifier returned a malformed setup-generation handle catalog.',
        );
    }
    const handleView = new DataView(
        handleBytes.buffer,
        handleBytes.byteOffset,
        handleBytes.byteLength,
    );
    return Object.freeze(
        Array.from({ length: expectedHandleCount }, (_, handleIndex) =>
            requireWasm32Handle(
                handleView.getUint32(
                    handleIndex * Uint32Array.BYTES_PER_ELEMENT,
                    true,
                ),
                'A setup-generation canonical-board object handle',
            ),
        ),
    );
};

const requireExactPublicRandomnessObjectFamilies = (
    input: BrowserOwnedSetupGenerationAuthorityInput,
): void => {
    for (const objectFamily of [
        input.orderedSetupIntentObjects,
        input.orderedPublicRandomnessCommitmentObjects,
        input.orderedPublicRandomnessRevealObjects,
    ]) {
        if (
            !Array.isArray(objectFamily) ||
            objectFamily.length !== foundationProfile.participantCount
        ) {
            throw new CanonicalStreamRefusalError('wrongTypeOrLength');
        }
    }
};

const combineCleanupFailures = (
    cleanupFailures: readonly unknown[],
): unknown =>
    cleanupFailures.length === 1
        ? cleanupFailures[0]
        : Object.freeze([...cleanupFailures]);

/**
 * Retains the one opaque setup-generation authority from positively verified
 * same-worker capabilities. Temporary suite and worker borrows are released
 * before this promise resolves, so proof execution cannot deadlock on worker
 * storage and no raw handle or private byte string crosses the WASM boundary.
 */
export const openBrowserOwnedSetupGenerationAuthorityInClosedWorker = async (
    input: BrowserOwnedSetupGenerationAuthorityInput,
): Promise<BrowserOwnedSetupGenerationAuthority> => {
    if (typeof globalThis.document !== 'undefined') {
        throw new BrowserActionStorageCustodyError(
            'Unavailable',
            'Setup-generation authority may only be opened inside the dedicated custody worker.',
        );
    }
    requireExactPublicRandomnessObjectFamilies(input);
    const context = resolveCommonProofKernelContext(input.kernel);
    if (context === undefined) {
        throw new CanonicalStreamInternalError(
            'The loaded WASM kernel has no setup-generation context.',
        );
    }
    const setupGenerationContext =
        context as unknown as CanonicalStreamKernelContext;
    const boardAuthorization =
        resolveAggregatePublicRandomnessBoardAuthorization({
            context,
            kernel: input.kernel,
            orderedCommitmentObjects:
                input.orderedPublicRandomnessCommitmentObjects,
            orderedRevealObjects: input.orderedPublicRandomnessRevealObjects,
            orderedSetupIntentObjects: input.orderedSetupIntentObjects,
        });
    let selectedSuiteSource: SelectedSuiteRecordSource | undefined;
    let setupGenerationAuthority:
        | BrowserOwnedSetupGenerationAuthority
        | undefined;
    try {
        const orderedPublicRandomnessObjectHandles =
            decodeOrderedPublicRandomnessObjectHandles(
                boardAuthorization.handleBytes,
            );
        selectedSuiteSource = activateSelectedSuiteRecordSource({
            canonicalSuiteRecordBytes: input.canonicalSuiteRecordBytes,
            kernel: input.kernel,
        });
        const selectedSuite = requireSelectedSuiteRecordSourceKernelOwner({
            kernel: input.kernel,
            source: selectedSuiteSource,
        });
        await withClosedWorkerProductionOperationAuthority(
            input.workerKernel,
            input.productionOperationIdentifiers,
            (productionOperationAuthority) =>
                productionOperationAuthority.withExactKernelAuthorization(
                    (authorization) => {
                        if (authorization.kernel !== input.kernel) {
                            throw new CanonicalStreamInternalError(
                                'The setup-generation production operation belongs to another WASM worker.',
                            );
                        }
                        if (
                            authorization.actionRandomnessContext.memory !==
                                context.memory ||
                            authorization.stateReservationCapabilityMemory !==
                                context.memory
                        ) {
                            throw new CanonicalStreamInternalError(
                                'The setup-generation private authorities belong to another WASM worker.',
                            );
                        }
                        if (setupGenerationAuthority !== undefined) {
                            throw new CanonicalStreamInternalError(
                                'The setup-generation production operation was invoked more than once.',
                            );
                        }
                        setupGenerationAuthority =
                            retainSetupGenerationAuthorityFromResolvedCapabilities(
                                {
                                    actionRandomnessHandle:
                                        authorization.actionRandomnessHandle,
                                    boardVerifierSessionCapabilityPointer:
                                        boardAuthorization.capabilityPointer,
                                    boardVerifierSessionHandle:
                                        boardAuthorization.sessionHandle,
                                    context: setupGenerationContext,
                                    orderedPublicRandomnessObjectHandles,
                                    selectedSuiteHandle: selectedSuite.handle,
                                    stateVerifierSessionCapabilityPointer:
                                        authorization.stateReservationCapabilityPointer,
                                    stateVerifierSessionHandle:
                                        authorization.stateVerifierSessionHandle,
                                    verifiedReservationHandle:
                                        authorization.stateReservationHandle,
                                },
                            );
                    },
                ),
        );
        if (setupGenerationAuthority === undefined) {
            throw new CanonicalStreamInternalError(
                'The production operation completed without a setup-generation authority.',
            );
        }
        releaseSelectedSuiteRecordSource({
            kernel: input.kernel,
            source: selectedSuiteSource,
        });
        selectedSuiteSource = undefined;
        return setupGenerationAuthority;
    } catch (operationFailure) {
        const cleanupFailures: unknown[] = [];
        if (setupGenerationAuthority !== undefined) {
            try {
                setupGenerationAuthority.release();
            } catch (cleanupFailure) {
                let retryFailure: unknown;
                try {
                    setupGenerationAuthority.release();
                } catch (error) {
                    retryFailure = error;
                }
                cleanupFailures.push(
                    retryFailure === undefined
                        ? cleanupFailure
                        : new CanonicalStreamCleanupError(
                              cleanupFailure,
                              retryFailure,
                          ),
                );
            }
        }
        if (selectedSuiteSource !== undefined) {
            try {
                releaseSelectedSuiteRecordSource({
                    kernel: input.kernel,
                    source: selectedSuiteSource,
                });
            } catch (cleanupFailure) {
                let retryFailure: unknown;
                try {
                    releaseSelectedSuiteRecordSource({
                        kernel: input.kernel,
                        source: selectedSuiteSource,
                    });
                } catch (error) {
                    retryFailure = error;
                }
                cleanupFailures.push(
                    retryFailure === undefined
                        ? cleanupFailure
                        : new CanonicalStreamCleanupError(
                              cleanupFailure,
                              retryFailure,
                          ),
                );
            }
        }
        if (cleanupFailures.length > 0) {
            throw new CanonicalStreamCleanupError(
                operationFailure,
                combineCleanupFailures(cleanupFailures),
            );
        }
        throw operationFailure;
    } finally {
        boardAuthorization.handleBytes.fill(0);
    }
};
