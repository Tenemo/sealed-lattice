import { foundationProfile } from '@sealed-lattice/types';

import {
    CanonicalStreamCleanupError,
    CanonicalStreamInternalError,
    CanonicalStreamRefusalError,
    CanonicalStreamResourceError,
    type CanonicalStreamKernelContext,
} from './canonical-stream-runtime.js';
import type { TranscriptCoreKernelCommandRuntime } from './transcript-core-bridge/kernel-runtime.js';
import { WasmMemoryBoundary } from './wasm-memory-boundary.js';
import { WasmStatusBoundary } from './wasm-status-boundary.js';

const verifierCapabilityByteLength = 32;
const wasm32MaximumUnsignedInteger = 0xffff_ffff;

type SetupGenerationKernelContext = CanonicalStreamKernelContext &
    Required<
        Pick<
            CanonicalStreamKernelContext,
            | 'setupGenerationAuthorityBegin'
            | 'setupGenerationAuthorityRelease'
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

export type BrowserOwnedSetupGenerationAuthority = Readonly<{
    readonly [setupGenerationAuthorityBrand]: true;
    payloadByteLength(recipientRosterPosition: number): number;
    openRecipientPayload(
        recipientRosterPosition: number,
    ): SetupGenerationRecipientPayloadSource;
    release(): void;
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
    readonly sources: Set<SetupGenerationRecipientPayloadSource>;
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

const authorityRecords = new WeakMap<
    BrowserOwnedSetupGenerationAuthority,
    AuthorityRecord
>();
const sourceRecords = new WeakMap<
    SetupGenerationRecipientPayloadSource,
    SourceRecord
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
    authorityRecord.sources.delete(source);
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
                    authorityRecord.sources.delete(source);
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
                    authorityRecord.sources.add(source);
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
    for (const source of record.sources) {
        const sourceRecord = sourceRecords.get(source);
        if (sourceRecord !== undefined) {
            sourceRecord.closed = true;
            sourceRecords.delete(source);
        }
    }
    record.sources.clear();
    authorityRecords.delete(authority);
};

/**
 * Internal same-worker factory. All numeric handles and capability pointers
 * must come from live runtime authorities in this exact WASM instance.
 */
export const beginBrowserOwnedSetupGenerationAuthority = (input: {
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

    return context.runExclusive('setup-generation authority begin', () => {
        const orderedHandleBytesPointer =
            memoryBoundary.copy(orderedHandleBytes);
        const statusPointer = memoryBoundary.allocateZeroedWords(1);
        let authorityHandle = 0;
        try {
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
                        release: () => releaseAuthority(authority),
                    });
                authorityRecords.set(authority, {
                    context,
                    handle: authorityHandle,
                    memoryBoundary,
                    released: false,
                    sources: new Set(),
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
                        throw new CanonicalStreamCleanupError(
                            operationFailure,
                            cleanupFailure,
                        );
                    }
                }
                throw operationFailure;
            }
        } finally {
            memoryBoundary.zeroAndDeallocate(
                statusPointer,
                Uint32Array.BYTES_PER_ELEMENT,
            );
            memoryBoundary.zeroAndDeallocate(
                orderedHandleBytesPointer,
                orderedHandleBytes.byteLength,
            );
            orderedHandleBytes.fill(0);
        }
    });
};
