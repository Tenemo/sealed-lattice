import { foundationProfile, refusalReasonCodes } from '@sealed-lattice/types';

import { isUint8Array } from './byte-array.js';
import type { VerifiedTranscriptObject } from './canonical-board-runtime.js';
import {
    canonicalStreamKernelContext,
    CanonicalStreamInternalError,
    CanonicalStreamRefusalError,
    CanonicalStreamResourceError,
    type CanonicalStreamKernelContext,
} from './canonical-stream-runtime.js';
import {
    consumeAuthenticatedMailboxPlaintextCapability,
    type AuthenticatedMailboxPlaintextCapability,
} from './mailbox-gcm-runtime.js';
import { resolveCommonProofKernelContext } from './transcript-core-bridge/common-proof-kernel-context.js';
import type { TranscriptCoreKernel } from './transcript-core-bridge/kernel-types.js';
import {
    consumeOrderedVerifiedVssShareLinkageTerminals,
    resolveAggregatePublicRandomnessBoardAuthorization,
    type VerifiedVssShareLinkageTerminal,
} from './vss-share-linkage-verification-runtime.js';
import { WasmMemoryBoundary } from './wasm-memory-boundary.js';
import { WasmStatusBoundary } from './wasm-status-boundary.js';

const boardVerifierCapabilityByteLength = 32;
const wasm32HandleByteLength = Uint32Array.BYTES_PER_ELEMENT;
const maximumWasm32UnsignedInteger = 0xffff_ffff;

type AggregateThresholdShareRecipientKernelContext =
    CanonicalStreamKernelContext &
        Required<
            Pick<
                CanonicalStreamKernelContext,
                | 'aggregateThresholdShareAbsorbAuthenticatedRecipientPayload'
                | 'aggregateThresholdShareBeginRecipientAuthority'
                | 'aggregateThresholdShareDiscardRecipientAuthority'
            >
        >;

const aggregateThresholdShareRecipientAuthorityBrand: unique symbol = Symbol(
    'sealed-lattice/aggregate-threshold-share-recipient-authority',
);

/** Rust-owned aggregate recipient state. Numeric handles never leave WASM. */
export type AggregateThresholdShareRecipientAuthority = Readonly<{
    readonly [aggregateThresholdShareRecipientAuthorityBrand]: true;
    release(): void;
}>;

export type AggregateThresholdShareRecipientAuthorityInput = Readonly<{
    localRecipientRosterPosition: number;
    orderedCommitmentObjects: readonly VerifiedTranscriptObject[];
    orderedDealerVssTerminals: readonly VerifiedVssShareLinkageTerminal[];
    orderedRevealObjects: readonly VerifiedTranscriptObject[];
    orderedSetupIntentObjects: readonly VerifiedTranscriptObject[];
}>;

export type ClosedWorkerAggregateThresholdShareRecipientAuthorityInput =
    AggregateThresholdShareRecipientAuthorityInput &
        Readonly<{
            actionRandomnessSessionIdentifier: string;
        }>;

export type AggregateThresholdShareAuthenticatedRecipientConsumer = Readonly<{
    consumeAuthenticatedPlaintext(input: {
        authenticatedPlaintextCapability: AuthenticatedMailboxPlaintextCapability;
        canonicalPlaintextBytes: Uint8Array;
        canonicalSignedEnvelopeBytes: Uint8Array;
    }): Promise<void>;
    retireAfterUncertainConsumption(failure: unknown): Promise<void>;
}>;

type AggregateThresholdShareRecipientAuthorityRecord = Readonly<{
    context: AggregateThresholdShareRecipientKernelContext;
    handle: number;
    kernel: TranscriptCoreKernel;
}>;

const authorityRecords = new WeakMap<
    AggregateThresholdShareRecipientAuthority,
    AggregateThresholdShareRecipientAuthorityRecord
>();

const requireKernelContext = (
    context: CanonicalStreamKernelContext | undefined,
): AggregateThresholdShareRecipientKernelContext => {
    if (
        context === undefined ||
        typeof context.aggregateThresholdShareBeginRecipientAuthority !==
            'function' ||
        typeof context.aggregateThresholdShareAbsorbAuthenticatedRecipientPayload !==
            'function' ||
        typeof context.aggregateThresholdShareDiscardRecipientAuthority !==
            'function'
    ) {
        throw new CanonicalStreamInternalError(
            'The transcript-core kernel lacks the aggregate recipient-authority boundary.',
        );
    }
    return context as AggregateThresholdShareRecipientKernelContext;
};

const createStatusBoundary = (): WasmStatusBoundary =>
    new WasmStatusBoundary({
        createInternalError: (message) =>
            new CanonicalStreamInternalError(message),
        createRefusalError: (refusalReason) =>
            new CanonicalStreamRefusalError(refusalReason),
        createResourceError: () => new CanonicalStreamResourceError(),
        internalFailureMessage:
            'The aggregate recipient-authority kernel session failed internally.',
        unknownStatusMessage:
            'The aggregate recipient-authority kernel returned an unknown status code.',
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

const requireCanonicalBytes = (value: Uint8Array): Uint8Array => {
    if (!isUint8Array(value) || value.byteLength === 0) {
        throw new CanonicalStreamRefusalError('wrongTypeOrLength');
    }
    return value;
};

const encodeOrderedHandles = (
    handles: readonly number[],
): Uint8Array<ArrayBuffer> => {
    if (handles.length !== foundationProfile.participantCount) {
        throw new CanonicalStreamRefusalError('wrongTypeOrLength');
    }
    const bytes = new Uint8Array(handles.length * wasm32HandleByteLength);
    const view = new DataView(bytes.buffer);
    handles.forEach((handle, handleIndex) => {
        view.setUint32(
            handleIndex * wasm32HandleByteLength,
            requireLiveHandle(handle, 'A verified VSS terminal handle'),
            true,
        );
    });
    return bytes;
};

const requireAuthorityRecord = (
    authority: AggregateThresholdShareRecipientAuthority,
): AggregateThresholdShareRecipientAuthorityRecord => {
    const record = authorityRecords.get(authority);
    if (record === undefined) {
        throw new CanonicalStreamRefusalError('consumedState');
    }
    return record;
};

type AggregateThresholdShareRecipientAuthorityKernelOwner = Readonly<{
    handle: number;
    kernel: TranscriptCoreKernel;
}>;

/** Internal same-worker borrow used by accepted-setup verification. */
export const requireAggregateThresholdShareRecipientAuthorityKernelOwner = (
    authority: AggregateThresholdShareRecipientAuthority,
    kernel: TranscriptCoreKernel,
): AggregateThresholdShareRecipientAuthorityKernelOwner => {
    const record = requireAuthorityRecord(authority);
    if (record.kernel !== kernel) {
        throw new TypeError(
            'The aggregate recipient authority belongs to another WASM kernel.',
        );
    }
    return Object.freeze({ handle: record.handle, kernel: record.kernel });
};

/**
 * Retires browser custody only after Rust atomically consumed the complete VSS
 * qualification during accepted-setup finalization.
 */
export const markAggregateThresholdShareRecipientAuthorityConsumedAfterKernelSuccess =
    (
        authority: AggregateThresholdShareRecipientAuthority,
        kernel: TranscriptCoreKernel,
    ): void => {
        requireAggregateThresholdShareRecipientAuthorityKernelOwner(
            authority,
            kernel,
        );
        authorityRecords.delete(authority);
    };

const discardAuthorityRecord = (input: {
    record: AggregateThresholdShareRecipientAuthorityRecord;
    tolerateConsumedState: boolean;
}): void => {
    const statusBoundary = createStatusBoundary();
    const status = input.record.context.runExclusive(
        'aggregate recipient-authority discard',
        () =>
            input.record.context.aggregateThresholdShareDiscardRecipientAuthority(
                input.record.handle,
            ),
    );
    if (
        input.tolerateConsumedState &&
        status >>> 0 === refusalReasonCodes.consumedState
    ) {
        return;
    }
    statusBoundary.throwIfError(status);
};

const releaseAuthority = (
    authority: AggregateThresholdShareRecipientAuthority,
): void => {
    const record = requireAuthorityRecord(authority);
    authorityRecords.delete(authority);
    discardAuthorityRecord({ record, tolerateConsumedState: false });
};

const retireAuthorityAfterFailure = (
    authority: AggregateThresholdShareRecipientAuthority,
    operationFailure: unknown,
): never => {
    const record = authorityRecords.get(authority);
    authorityRecords.delete(authority);
    if (record !== undefined) {
        try {
            discardAuthorityRecord({
                record,
                tolerateConsumedState: true,
            });
        } catch (cleanupFailure) {
            throw new CanonicalStreamInternalError(
                'The aggregate recipient operation failed and its authority could not be retired.',
                Object.freeze({ cleanupFailure, operationFailure }),
            );
        }
    }
    throw operationFailure;
};

const retireAuthorityIfLive = (
    authority: AggregateThresholdShareRecipientAuthority,
    operationFailure: unknown,
): void => {
    const record = authorityRecords.get(authority);
    authorityRecords.delete(authority);
    if (record === undefined) {
        return;
    }
    try {
        discardAuthorityRecord({ record, tolerateConsumedState: true });
    } catch (cleanupFailure) {
        throw new CanonicalStreamInternalError(
            'The uncertain aggregate recipient operation could not retire its authority.',
            Object.freeze({ cleanupFailure, operationFailure }),
        );
    }
};

const consumeAuthenticatedRecipientPlaintext = (input: {
    authenticatedPlaintextCapability: AuthenticatedMailboxPlaintextCapability;
    authority: AggregateThresholdShareRecipientAuthority;
    canonicalPlaintextBytes: Uint8Array;
    canonicalSignedEnvelopeBytes: Uint8Array;
}): void => {
    let record: AggregateThresholdShareRecipientAuthorityRecord;
    try {
        record = requireAuthorityRecord(input.authority);
    } catch (operationFailure) {
        try {
            input.authenticatedPlaintextCapability.release();
        } catch (cleanupFailure) {
            throw new CanonicalStreamInternalError(
                'The aggregate recipient authority and authenticated plaintext capability were both unavailable.',
                Object.freeze({ cleanupFailure, operationFailure }),
            );
        }
        throw operationFailure;
    }
    try {
        consumeAuthenticatedMailboxPlaintextCapability({
            capability: input.authenticatedPlaintextCapability,
            consume: (authenticatedPlaintextCapabilityHandle) => {
                const canonicalSignedEnvelopeBytes = requireCanonicalBytes(
                    input.canonicalSignedEnvelopeBytes,
                );
                const canonicalPlaintextBytes = requireCanonicalBytes(
                    input.canonicalPlaintextBytes,
                );
                const memoryBoundary = new WasmMemoryBoundary({
                    context: record.context,
                    createInternalError: (message) =>
                        new CanonicalStreamInternalError(message),
                    createResourceError: (message) =>
                        new CanonicalStreamResourceError(message),
                    label: 'authenticated recipient VSS payload',
                });
                const statusBoundary = createStatusBoundary();
                let canonicalSignedEnvelopePointer = 0;
                let canonicalPlaintextPointer = 0;
                try {
                    canonicalSignedEnvelopePointer = memoryBoundary.copy(
                        canonicalSignedEnvelopeBytes,
                    );
                    canonicalPlaintextPointer = memoryBoundary.copy(
                        canonicalPlaintextBytes,
                    );
                    const status = record.context.runExclusive(
                        'aggregate authenticated recipient-payload absorption',
                        () =>
                            record.context.aggregateThresholdShareAbsorbAuthenticatedRecipientPayload(
                                record.handle,
                                authenticatedPlaintextCapabilityHandle,
                                canonicalSignedEnvelopePointer,
                                canonicalSignedEnvelopeBytes.byteLength,
                                canonicalPlaintextPointer,
                                canonicalPlaintextBytes.byteLength,
                            ),
                    );
                    statusBoundary.throwIfError(status);
                } finally {
                    memoryBoundary.zeroAndDeallocate(
                        canonicalPlaintextPointer,
                        canonicalPlaintextBytes.byteLength,
                    );
                    memoryBoundary.zeroAndDeallocate(
                        canonicalSignedEnvelopePointer,
                        canonicalSignedEnvelopeBytes.byteLength,
                    );
                }
            },
            context: record.context,
        });
    } catch (operationFailure) {
        retireAuthorityAfterFailure(input.authority, operationFailure);
    }
};

/**
 * Internal factory used only by the action-randomness custody worker. The raw
 * action handle and the consumed VSS terminal handles never become page data.
 */
export const beginAggregateThresholdShareRecipientAuthorityFromRetainedActionRandomness =
    (
        input: AggregateThresholdShareRecipientAuthorityInput &
            Readonly<{
                actionRandomnessHandle: number;
                kernel: TranscriptCoreKernel;
            }>,
    ): AggregateThresholdShareRecipientAuthority => {
        const commonProofContext = resolveCommonProofKernelContext(
            input.kernel,
        );
        if (commonProofContext === undefined) {
            throw new CanonicalStreamInternalError(
                'The loaded WASM kernel has no common-proof worker context.',
            );
        }
        const context = requireKernelContext(
            canonicalStreamKernelContext(input.kernel),
        );
        if (context.memory !== commonProofContext.memory) {
            throw new CanonicalStreamInternalError(
                'The aggregate recipient and common-proof authorities belong to different WASM workers.',
            );
        }
        const actionRandomnessHandle = requireLiveHandle(
            input.actionRandomnessHandle,
            'The retained action-randomness handle',
        );
        const localRecipientRosterPosition = requireRecipientRosterPosition(
            input.localRecipientRosterPosition,
        );
        const boardAuthorization =
            resolveAggregatePublicRandomnessBoardAuthorization({
                context: commonProofContext,
                kernel: input.kernel,
                orderedCommitmentObjects: input.orderedCommitmentObjects,
                orderedRevealObjects: input.orderedRevealObjects,
                orderedSetupIntentObjects: input.orderedSetupIntentObjects,
            });
        const memoryBoundary = new WasmMemoryBoundary({
            context,
            createInternalError: (message) =>
                new CanonicalStreamInternalError(message),
            createResourceError: (message) =>
                new CanonicalStreamResourceError(message),
            label: 'aggregate recipient-authority boundary',
        });
        const statusBoundary = createStatusBoundary();

        const recipientAuthorityHandle =
            consumeOrderedVerifiedVssShareLinkageTerminals({
                consume: (orderedTerminalHandles) => {
                    const terminalHandleBytes = encodeOrderedHandles(
                        orderedTerminalHandles,
                    );
                    return context.runExclusive(
                        'aggregate recipient-authority begin',
                        () => {
                            const publicRandomnessHandleBytesPointer =
                                memoryBoundary.copy(
                                    boardAuthorization.handleBytes,
                                );
                            const terminalHandleBytesPointer =
                                memoryBoundary.copy(terminalHandleBytes);
                            const statusPointer =
                                memoryBoundary.allocateZeroedWords(1);
                            let authorityHandle = 0;
                            try {
                                authorityHandle =
                                    context.aggregateThresholdShareBeginRecipientAuthority(
                                        actionRandomnessHandle,
                                        localRecipientRosterPosition,
                                        boardAuthorization.sessionHandle,
                                        boardAuthorization.capabilityPointer,
                                        boardVerifierCapabilityByteLength,
                                        publicRandomnessHandleBytesPointer,
                                        boardAuthorization.handleBytes
                                            .byteLength,
                                        terminalHandleBytesPointer,
                                        terminalHandleBytes.byteLength,
                                        statusPointer,
                                    );
                                const [status] = memoryBoundary.readWords(
                                    statusPointer,
                                    1,
                                );
                                statusBoundary.throwIfError(status);
                                return requireLiveHandle(
                                    authorityHandle,
                                    'The aggregate recipient-authority handle',
                                );
                            } catch (operationFailure) {
                                if (authorityHandle !== 0) {
                                    try {
                                        const discardStatus =
                                            context.aggregateThresholdShareDiscardRecipientAuthority(
                                                authorityHandle,
                                            );
                                        if (
                                            discardStatus >>> 0 !==
                                            refusalReasonCodes.consumedState
                                        ) {
                                            statusBoundary.throwIfError(
                                                discardStatus,
                                            );
                                        }
                                    } catch (cleanupFailure) {
                                        throw new CanonicalStreamInternalError(
                                            'The aggregate recipient-authority begin failed after returning an authority that could not be retired.',
                                            Object.freeze({
                                                cleanupFailure,
                                                operationFailure,
                                            }),
                                        );
                                    }
                                }
                                throw operationFailure;
                            } finally {
                                memoryBoundary.zeroAndDeallocate(
                                    statusPointer,
                                    wasm32HandleByteLength,
                                );
                                memoryBoundary.zeroAndDeallocate(
                                    terminalHandleBytesPointer,
                                    terminalHandleBytes.byteLength,
                                );
                                memoryBoundary.zeroAndDeallocate(
                                    publicRandomnessHandleBytesPointer,
                                    boardAuthorization.handleBytes.byteLength,
                                );
                            }
                        },
                    );
                },
                context: commonProofContext,
                kernel: input.kernel,
                orderedTerminals: input.orderedDealerVssTerminals,
            });
        let authority: AggregateThresholdShareRecipientAuthority | undefined;
        try {
            authority = Object.freeze({
                [aggregateThresholdShareRecipientAuthorityBrand]: true as const,
                release: () => releaseAuthority(authority!),
            });
            authorityRecords.set(authority, {
                context,
                handle: recipientAuthorityHandle,
                kernel: input.kernel,
            });
            return authority;
        } catch (operationFailure) {
            const record = Object.freeze({
                context,
                handle: recipientAuthorityHandle,
                kernel: input.kernel,
            });
            try {
                discardAuthorityRecord({
                    record,
                    tolerateConsumedState: true,
                });
            } catch (cleanupFailure) {
                throw new CanonicalStreamInternalError(
                    'The aggregate recipient authority could not be adopted or retired.',
                    Object.freeze({ cleanupFailure, operationFailure }),
                );
            }
            throw operationFailure;
        }
    };

/** Root-protected recipient sinks use this same-worker binding directly. */
export const resolveAggregateThresholdShareAuthenticatedRecipientConsumer = (
    authority: AggregateThresholdShareRecipientAuthority,
): AggregateThresholdShareAuthenticatedRecipientConsumer => {
    requireAuthorityRecord(authority);
    return Object.freeze({
        consumeAuthenticatedPlaintext: (input) =>
            Promise.resolve().then(() =>
                consumeAuthenticatedRecipientPlaintext({
                    ...input,
                    authority,
                }),
            ),
        retireAfterUncertainConsumption: (failure) =>
            Promise.resolve().then(() =>
                retireAuthorityIfLive(authority, failure),
            ),
    });
};
