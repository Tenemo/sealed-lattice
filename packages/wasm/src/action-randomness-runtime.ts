import { hexToBytes } from '@noble/hashes/utils.js';
import { refusalReasonCodes, type ProtocolHash } from '@sealed-lattice/types';

import {
    resolveVerifiedStateReservationKernelAuthorization,
    type VerifiedStateReservation,
} from './state-verifier-runtime.js';
import {
    resolveActionRandomnessKernelContext,
    type ActionRandomnessKernelContext,
} from './transcript-core-bridge/action-randomness-kernel-context.js';
import type { TranscriptCoreKernel } from './transcript-core-bridge/kernel-types.js';
import { bytesToHex } from './transcript-core-bridge/kernel-wasm-hash.js';

const actionRandomnessRootByteLength = 64;
const attemptIdentifierByteLength = 32;
const stateVerifierCapabilityByteLength = 32;
const foundationHashByteLength = 64;
const handleByteLength = 4;
const maximumCommandByteLength = 512;
const wasm32WordByteLength = 4;

const actionRandomnessCommands = Object.freeze({
    close: 2,
    freshBallotAttempt: 8,
    open: 1,
    ordinaryProofAttempt: 6,
    persistentProofAttempt: 5,
    targetReleaseAttempt: 7,
} as const);

const actionRandomnessStatuses = Object.freeze({
    resourceLimit: 0x0001_0000,
    staleHandle: 0x0001_0001,
} as const);

type ResetSafeProofFamilyWithoutSchedule =
    | 0x1211
    | 0x1212
    | 0x1621
    | 0x2110
    | 0x2111;
type ResetSafeProofFamilyWithSchedule = 0x1214 | 0x1216 | 0x1217;

export type ActionRandomnessScope = Readonly<{
    readonly actionContextHash: ProtocolHash;
    readonly ceremonyContextHash: ProtocolHash;
    readonly participantId: string;
    readonly suiteId: ProtocolHash;
}>;

type PersistentProofAttemptInput =
    | Readonly<{
          readonly applicationStatementHash: ProtocolHash;
          readonly rosterPosition: number;
          readonly statementSchemaIdentifier: ResetSafeProofFamilyWithoutSchedule;
      }>
    | Readonly<{
          readonly applicationStatementHash: ProtocolHash;
          readonly rosterPosition: number;
          readonly schedulePosition: number;
          readonly statementSchemaIdentifier: ResetSafeProofFamilyWithSchedule;
      }>;

type ProofAttemptBinding = Readonly<{
    readonly applicationSlotHash: ProtocolHash;
    readonly attemptIdentifier: Uint8Array<ArrayBuffer>;
}>;

type OrdinaryProofAttemptBinding = ProofAttemptBinding &
    Readonly<{
        readonly ordinaryProofAttemptNonce: Uint8Array<ArrayBuffer>;
    }>;

type OrdinaryProofAttemptInput = Readonly<{
    readonly applicationStatementHash: ProtocolHash;
    readonly producerSequence: bigint;
    readonly rosterPosition: number;
}>;

type ReservedPersistentProofAttemptInput = PersistentProofAttemptInput &
    Readonly<{ verifiedReservation: VerifiedStateReservation }>;

type TargetReleaseAttemptInput = Readonly<{
    readonly rosterPosition: number;
    readonly verifiedReservation: VerifiedStateReservation;
}>;

const actionRandomnessSessionBrand: unique symbol = Symbol(
    'sealed-lattice/action-randomness-session',
);

type ActionRandomnessSession = Readonly<{
    readonly [actionRandomnessSessionBrand]: true;
    readonly actionRandomnessCommitment: ProtocolHash;
    readonly scope: ActionRandomnessScope;
    beginFreshBallotAttempt(): Uint8Array<ArrayBuffer>;
    beginOrdinaryProofAttempt(
        input: OrdinaryProofAttemptInput,
    ): OrdinaryProofAttemptBinding;
    close(): void;
    derivePersistentProofAttempt(
        input: ReservedPersistentProofAttemptInput,
    ): ProofAttemptBinding;
    deriveTargetReleaseAttempt(
        input: TargetReleaseAttemptInput,
    ): ProofAttemptBinding;
}>;

type ActionRandomnessRuntimeFailureCode =
    | 'EntropyUnavailable'
    | 'InvalidInput'
    | 'InvalidState'
    | 'KernelUnavailable'
    | 'WrongContext';

export class ActionRandomnessRuntimeError extends Error {
    public readonly code: ActionRandomnessRuntimeFailureCode;
    public readonly failureCause: unknown;

    public constructor(
        code: ActionRandomnessRuntimeFailureCode,
        message: string,
        failureCause?: unknown,
    ) {
        super(message);
        this.name = 'ActionRandomnessRuntimeError';
        this.code = code;
        this.failureCause = failureCause;
    }
}

type SessionState = {
    readonly context: ActionRandomnessKernelContext;
    readonly cryptoProvider: Crypto;
    readonly handle: number;
    readonly kernel: TranscriptCoreKernel;
    readonly scope: ActionRandomnessScope;
    closed: boolean;
};

const sessionStates = new WeakMap<ActionRandomnessSession, SessionState>();

const bytesEqual = (left: Uint8Array, right: Uint8Array): boolean => {
    if (left.byteLength !== right.byteLength) {
        return false;
    }
    let difference = 0;
    for (let byteIndex = 0; byteIndex < left.byteLength; byteIndex += 1) {
        difference |= left[byteIndex] ^ right[byteIndex];
    }
    return difference === 0;
};

const requireHash = (value: unknown, label: string): ProtocolHash => {
    if (
        typeof value !== 'string' ||
        value.length !== foundationHashByteLength * 2 ||
        !/^[0-9a-f]+$/u.test(value)
    ) {
        throw new ActionRandomnessRuntimeError(
            'InvalidInput',
            `${label} must be exactly 64 bytes of lowercase hexadecimal.`,
        );
    }
    return value;
};

const requireUnsigned16 = (value: number, label: string): number => {
    if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff) {
        throw new ActionRandomnessRuntimeError(
            'InvalidInput',
            `${label} must be an unsigned 16-bit integer.`,
        );
    }
    return value;
};

const requireUnsigned32 = (value: number, label: string): number => {
    if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff_ffff) {
        throw new ActionRandomnessRuntimeError(
            'InvalidInput',
            `${label} must be an unsigned 32-bit integer.`,
        );
    }
    return value;
};

const requireUnsigned64 = (value: bigint, label: string): bigint => {
    if (
        typeof value !== 'bigint' ||
        value < 0n ||
        value > 0xffff_ffff_ffff_ffffn
    ) {
        throw new ActionRandomnessRuntimeError(
            'InvalidInput',
            `${label} must be an unsigned 64-bit integer.`,
        );
    }
    return value;
};

const encodeUnsigned16 = (value: number): Uint8Array<ArrayBuffer> => {
    const output = new Uint8Array(2);
    new DataView(output.buffer).setUint16(0, value, true);
    return output;
};

const encodeUnsigned32 = (value: number): Uint8Array<ArrayBuffer> => {
    const output = new Uint8Array(4);
    new DataView(output.buffer).setUint32(0, value, true);
    return output;
};

const encodeUnsigned64 = (value: bigint): Uint8Array<ArrayBuffer> => {
    const output = new Uint8Array(8);
    new DataView(output.buffer).setBigUint64(0, value, true);
    return output;
};

const concatenateBytes = (
    ...values: readonly Uint8Array[]
): Uint8Array<ArrayBuffer> => {
    const byteLength = values.reduce(
        (totalByteLength, value) => totalByteLength + value.byteLength,
        0,
    );
    if (byteLength > maximumCommandByteLength) {
        throw new ActionRandomnessRuntimeError(
            'InvalidInput',
            'The action-randomness command exceeds its byte limit.',
        );
    }
    const output = new Uint8Array(byteLength);
    let offset = 0;
    for (const value of values) {
        output.set(value, offset);
        offset += value.byteLength;
    }
    return output;
};

const wipeWasmAllocation = (
    context: ActionRandomnessKernelContext,
    pointer: number,
    byteLength: number,
): void => {
    if (
        pointer === 0 ||
        byteLength === 0 ||
        pointer + byteLength > context.memory.buffer.byteLength
    ) {
        return;
    }
    new Uint8Array(context.memory.buffer, pointer, byteLength).fill(0);
};

const command = (
    state: Pick<SessionState, 'context'>,
    commandCode: number,
    input: Uint8Array<ArrayBuffer>,
    operationName: string,
): Uint8Array<ArrayBuffer> =>
    state.context.runExclusive(`action randomness: ${operationName}`, () => {
        let inputPointer = 0;
        let metadataPointer = 0;
        let outputPointer = 0;
        let outputByteLength = 0;
        let outputAllocationIsOwned = false;
        try {
            if (input.byteLength > maximumCommandByteLength) {
                throw new ActionRandomnessRuntimeError(
                    'InvalidInput',
                    'The action-randomness command exceeds its byte limit.',
                );
            }
            if (input.byteLength > 0) {
                inputPointer = state.context.allocate(input.byteLength) >>> 0;
                if (inputPointer === 0) {
                    throw new ActionRandomnessRuntimeError(
                        'KernelUnavailable',
                        'WASM could not allocate action-randomness input.',
                    );
                }
                new Uint8Array(
                    state.context.memory.buffer,
                    inputPointer,
                    input.byteLength,
                ).set(input);
            }
            metadataPointer =
                state.context.allocate(wasm32WordByteLength * 2) >>> 0;
            if (metadataPointer === 0) {
                throw new ActionRandomnessRuntimeError(
                    'KernelUnavailable',
                    'WASM could not allocate action-randomness metadata.',
                );
            }
            outputPointer =
                state.context.command(
                    commandCode,
                    inputPointer,
                    input.byteLength,
                    metadataPointer,
                    metadataPointer + wasm32WordByteLength,
                ) >>> 0;
            const metadata = new DataView(
                state.context.memory.buffer,
                metadataPointer,
                wasm32WordByteLength * 2,
            );
            const status = metadata.getUint32(0, true);
            outputByteLength = metadata.getUint32(wasm32WordByteLength, true);
            if (status !== 0) {
                if (outputPointer !== 0 || outputByteLength !== 0) {
                    throw new ActionRandomnessRuntimeError(
                        'KernelUnavailable',
                        'The action-randomness kernel returned output with an error status.',
                    );
                }
                throwStatus(status);
            }
            if (
                outputByteLength > maximumCommandByteLength ||
                (outputPointer === 0) !== (outputByteLength === 0) ||
                outputPointer + outputByteLength >
                    state.context.memory.buffer.byteLength
            ) {
                throw new ActionRandomnessRuntimeError(
                    'KernelUnavailable',
                    'The action-randomness kernel returned invalid output metadata.',
                );
            }
            outputAllocationIsOwned = outputPointer !== 0;
            return outputByteLength === 0
                ? new Uint8Array(0)
                : new Uint8Array(
                      state.context.memory.buffer,
                      outputPointer,
                      outputByteLength,
                  ).slice();
        } catch (error) {
            throw error instanceof ActionRandomnessRuntimeError
                ? error
                : new ActionRandomnessRuntimeError(
                      'KernelUnavailable',
                      `The WASM kernel failed to ${operationName}.`,
                      error,
                  );
        } finally {
            input.fill(0);
            if (outputAllocationIsOwned) {
                wipeWasmAllocation(
                    state.context,
                    outputPointer,
                    outputByteLength,
                );
                state.context.deallocate(outputPointer, outputByteLength);
            }
            if (metadataPointer !== 0) {
                wipeWasmAllocation(
                    state.context,
                    metadataPointer,
                    wasm32WordByteLength * 2,
                );
                state.context.deallocate(
                    metadataPointer,
                    wasm32WordByteLength * 2,
                );
            }
            if (inputPointer !== 0) {
                wipeWasmAllocation(
                    state.context,
                    inputPointer,
                    input.byteLength,
                );
                state.context.deallocate(inputPointer, input.byteLength);
            }
        }
    });

const throwStatus = (status: number): never => {
    if (
        status === refusalReasonCodes.wrongContext ||
        status === refusalReasonCodes.wrongHashOrRoot
    ) {
        throw new ActionRandomnessRuntimeError(
            'WrongContext',
            'The action-randomness operation does not match its session binding.',
        );
    }
    if (
        status === refusalReasonCodes.malformedEncoding ||
        status === refusalReasonCodes.unsupportedVersionOrSuite ||
        status === refusalReasonCodes.outsideSupportedProfile ||
        status === refusalReasonCodes.wrongTypeOrLength
    ) {
        throw new ActionRandomnessRuntimeError(
            'InvalidInput',
            'The action-randomness operation has malformed or unsupported input.',
        );
    }
    if (
        status === refusalReasonCodes.consumedState ||
        status === actionRandomnessStatuses.resourceLimit ||
        status === actionRandomnessStatuses.staleHandle
    ) {
        throw new ActionRandomnessRuntimeError(
            'InvalidState',
            'The action-randomness session is unavailable or consumed.',
        );
    }
    throw new ActionRandomnessRuntimeError(
        'KernelUnavailable',
        `The action-randomness kernel returned unknown status ${String(status)}.`,
    );
};

const resolveCryptoProvider = (cryptoProvider: Crypto | undefined): Crypto => {
    const resolved = cryptoProvider ?? globalThis.crypto;
    if (
        resolved === undefined ||
        typeof resolved.getRandomValues !== 'function'
    ) {
        throw new ActionRandomnessRuntimeError(
            'EntropyUnavailable',
            'Web Crypto getRandomValues is required for action randomness.',
        );
    }
    return resolved;
};

const fillEntropy = (
    cryptoProvider: Crypto,
    output: Uint8Array<ArrayBuffer>,
    label: string,
): void => {
    try {
        cryptoProvider.getRandomValues(output);
    } catch (error) {
        output.fill(0);
        throw new ActionRandomnessRuntimeError(
            'EntropyUnavailable',
            `Secure randomness is unavailable for the ${label}.`,
            error,
        );
    }
};

const requireState = (session: ActionRandomnessSession): SessionState => {
    const state = sessionStates.get(session);
    if (state === undefined || state.closed) {
        throw new ActionRandomnessRuntimeError(
            'InvalidState',
            'The action-randomness session is closed or unavailable.',
        );
    }
    return state;
};

const handleBytes = (state: SessionState): Uint8Array<ArrayBuffer> =>
    encodeUnsigned32(state.handle);

const reservationAuthorizationBytes = (
    state: SessionState,
    reservation: VerifiedStateReservation,
): Uint8Array<ArrayBuffer> => {
    let authorization;
    try {
        authorization = resolveVerifiedStateReservationKernelAuthorization(
            reservation,
            state.kernel,
        );
    } catch (error) {
        throw new ActionRandomnessRuntimeError(
            'WrongContext',
            'The proof attempt requires an active verified state reservation from this WASM kernel.',
            error,
        );
    }
    if (
        authorization.capabilityMemory !== state.context.memory ||
        authorization.capabilityPointer <= 0 ||
        authorization.capabilityPointer + stateVerifierCapabilityByteLength >
            authorization.capabilityMemory.buffer.byteLength
    ) {
        throw new ActionRandomnessRuntimeError(
            'KernelUnavailable',
            'The state verifier returned malformed reservation authorization.',
        );
    }
    const bytes = new Uint8Array(
        handleByteLength + stateVerifierCapabilityByteLength + handleByteLength,
    );
    const view = new DataView(bytes.buffer);
    view.setUint32(0, authorization.sessionHandle, true);
    bytes.set(
        new Uint8Array(
            authorization.capabilityMemory.buffer,
            authorization.capabilityPointer,
            stateVerifierCapabilityByteLength,
        ),
        handleByteLength,
    );
    view.setUint32(
        handleByteLength + stateVerifierCapabilityByteLength,
        authorization.reservationHandle,
        true,
    );
    return bytes;
};

const parseProofAttemptBinding = (
    output: Uint8Array<ArrayBuffer>,
): ProofAttemptBinding => {
    try {
        if (
            output.byteLength !==
            foundationHashByteLength + attemptIdentifierByteLength
        ) {
            throw new ActionRandomnessRuntimeError(
                'KernelUnavailable',
                'The action-randomness kernel returned malformed proof-attempt metadata.',
            );
        }
        return Object.freeze({
            applicationSlotHash: bytesToHex(
                output.subarray(0, foundationHashByteLength),
            ),
            attemptIdentifier: output.slice(foundationHashByteLength),
        });
    } finally {
        output.fill(0);
    }
};

const derivePersistentProofAttempt = (
    session: ActionRandomnessSession,
    input: ReservedPersistentProofAttemptInput,
): ProofAttemptBinding => {
    const state = requireState(session);
    const statementSchemaIdentifier = requireUnsigned16(
        input.statementSchemaIdentifier,
        'statementSchemaIdentifier',
    );
    const rosterPosition = requireUnsigned16(
        input.rosterPosition,
        'rosterPosition',
    );
    const schedulePosition =
        'schedulePosition' in input
            ? requireUnsigned32(input.schedulePosition, 'schedulePosition')
            : undefined;
    const reservationAuthorization = reservationAuthorizationBytes(
        state,
        input.verifiedReservation,
    );
    try {
        const commandInput = concatenateBytes(
            handleBytes(state),
            reservationAuthorization,
            encodeUnsigned16(statementSchemaIdentifier),
            encodeUnsigned16(rosterPosition),
            new Uint8Array([schedulePosition === undefined ? 0 : 1]),
            ...(schedulePosition === undefined
                ? []
                : [encodeUnsigned32(schedulePosition)]),
            hexToBytes(
                requireHash(
                    input.applicationStatementHash,
                    'applicationStatementHash',
                ),
            ),
        );
        return parseProofAttemptBinding(
            command(
                state,
                actionRandomnessCommands.persistentProofAttempt,
                commandInput,
                'derive a persistent proof attempt',
            ),
        );
    } finally {
        reservationAuthorization.fill(0);
    }
};

const beginOrdinaryProofAttempt = (
    session: ActionRandomnessSession,
    input: OrdinaryProofAttemptInput,
): OrdinaryProofAttemptBinding => {
    const state = requireState(session);
    const nonce = new Uint8Array(attemptIdentifierByteLength);
    fillEntropy(state.cryptoProvider, nonce, 'ordinary proof attempt');
    const commandInput = concatenateBytes(
        handleBytes(state),
        encodeUnsigned16(
            requireUnsigned16(input.rosterPosition, 'rosterPosition'),
        ),
        encodeUnsigned64(
            requireUnsigned64(input.producerSequence, 'producerSequence'),
        ),
        hexToBytes(
            requireHash(
                input.applicationStatementHash,
                'applicationStatementHash',
            ),
        ),
        nonce,
    );
    let output: Uint8Array<ArrayBuffer> | undefined;
    try {
        output = command(
            state,
            actionRandomnessCommands.ordinaryProofAttempt,
            commandInput,
            'begin an ordinary proof attempt',
        );
        const expectedOutputByteLength =
            foundationHashByteLength + attemptIdentifierByteLength * 2;
        if (output.byteLength !== expectedOutputByteLength) {
            throw new ActionRandomnessRuntimeError(
                'KernelUnavailable',
                'The action-randomness kernel returned malformed ordinary-proof metadata.',
            );
        }
        const nonceOffset =
            foundationHashByteLength + attemptIdentifierByteLength;
        if (!bytesEqual(output.subarray(nonceOffset), nonce)) {
            throw new ActionRandomnessRuntimeError(
                'KernelUnavailable',
                'The action-randomness kernel did not return the exact injected proof nonce.',
            );
        }
        return Object.freeze({
            applicationSlotHash: bytesToHex(
                output.subarray(0, foundationHashByteLength),
            ),
            attemptIdentifier: output.slice(
                foundationHashByteLength,
                nonceOffset,
            ),
            ordinaryProofAttemptNonce: output.slice(nonceOffset),
        });
    } finally {
        nonce.fill(0);
        output?.fill(0);
    }
};

const deriveTargetReleaseAttempt = (
    session: ActionRandomnessSession,
    input: TargetReleaseAttemptInput,
): ProofAttemptBinding => {
    const state = requireState(session);
    const reservationAuthorization = reservationAuthorizationBytes(
        state,
        input.verifiedReservation,
    );
    try {
        return parseProofAttemptBinding(
            command(
                state,
                actionRandomnessCommands.targetReleaseAttempt,
                concatenateBytes(
                    handleBytes(state),
                    reservationAuthorization,
                    encodeUnsigned16(
                        requireUnsigned16(
                            input.rosterPosition,
                            'rosterPosition',
                        ),
                    ),
                ),
                'derive a target-release attempt',
            ),
        );
    } finally {
        reservationAuthorization.fill(0);
    }
};

const beginFreshBallotAttempt = (
    session: ActionRandomnessSession,
): Uint8Array<ArrayBuffer> => {
    const state = requireState(session);
    const attemptIdentifier = new Uint8Array(attemptIdentifierByteLength);
    fillEntropy(
        state.cryptoProvider,
        attemptIdentifier,
        'fresh ballot attempt',
    );
    let output: Uint8Array<ArrayBuffer> | undefined;
    try {
        output = command(
            state,
            actionRandomnessCommands.freshBallotAttempt,
            concatenateBytes(handleBytes(state), attemptIdentifier),
            'begin a fresh ballot attempt',
        );
        if (
            output.byteLength !== attemptIdentifierByteLength ||
            !bytesEqual(output, attemptIdentifier)
        ) {
            throw new ActionRandomnessRuntimeError(
                'KernelUnavailable',
                'The action-randomness kernel did not return the exact fresh ballot identifier.',
            );
        }
        return output.slice();
    } finally {
        attemptIdentifier.fill(0);
        output?.fill(0);
    }
};

const close = (session: ActionRandomnessSession): void => {
    const state = sessionStates.get(session);
    if (state === undefined) {
        throw new ActionRandomnessRuntimeError(
            'InvalidState',
            'The action-randomness session is unavailable.',
        );
    }
    if (state.closed) {
        return;
    }
    try {
        const output = command(
            state,
            actionRandomnessCommands.close,
            handleBytes(state),
            'close the session',
        );
        try {
            if (output.byteLength !== 0) {
                throw new ActionRandomnessRuntimeError(
                    'KernelUnavailable',
                    'The action-randomness close command returned unexpected output.',
                );
            }
        } finally {
            output.fill(0);
        }
    } finally {
        state.closed = true;
    }
};

export const openActionRandomnessSession = (input: {
    readonly cryptoProvider?: Crypto;
    readonly kernel: TranscriptCoreKernel;
    readonly scope: ActionRandomnessScope;
}): ActionRandomnessSession => {
    const context = resolveActionRandomnessKernelContext(input.kernel);
    if (context === undefined) {
        throw new ActionRandomnessRuntimeError(
            'KernelUnavailable',
            'The loaded WASM kernel does not expose action-randomness custody.',
        );
    }
    const scope = Object.freeze({
        actionContextHash: requireHash(
            input.scope.actionContextHash,
            'scope.actionContextHash',
        ),
        ceremonyContextHash: requireHash(
            input.scope.ceremonyContextHash,
            'scope.ceremonyContextHash',
        ),
        participantId: requireHash(
            input.scope.participantId,
            'scope.participantId',
        ),
        suiteId: requireHash(input.scope.suiteId, 'scope.suiteId'),
    });
    const cryptoProvider = resolveCryptoProvider(input.cryptoProvider);
    const commandInput = new Uint8Array(
        actionRandomnessRootByteLength + foundationHashByteLength * 4,
    );
    fillEntropy(
        cryptoProvider,
        commandInput.subarray(0, actionRandomnessRootByteLength),
        'action-randomness root',
    );
    let offset = actionRandomnessRootByteLength;
    for (const value of [
        scope.suiteId,
        scope.ceremonyContextHash,
        scope.actionContextHash,
        scope.participantId,
    ]) {
        commandInput.set(hexToBytes(value), offset);
        offset += foundationHashByteLength;
    }
    const output = command(
        { context },
        actionRandomnessCommands.open,
        commandInput,
        'open a session',
    );
    try {
        if (output.byteLength !== handleByteLength + foundationHashByteLength) {
            throw new ActionRandomnessRuntimeError(
                'KernelUnavailable',
                'The action-randomness kernel returned malformed session metadata.',
            );
        }
        const handle = new DataView(
            output.buffer,
            output.byteOffset,
            handleByteLength,
        ).getUint32(0, true);
        if (handle === 0) {
            throw new ActionRandomnessRuntimeError(
                'KernelUnavailable',
                'The action-randomness kernel returned a zero session handle.',
            );
        }
        const session: ActionRandomnessSession = Object.freeze({
            [actionRandomnessSessionBrand]: true as const,
            actionRandomnessCommitment: bytesToHex(
                output.subarray(handleByteLength),
            ),
            scope,
            beginFreshBallotAttempt: () => beginFreshBallotAttempt(session),
            beginOrdinaryProofAttempt: (
                attemptInput: OrdinaryProofAttemptInput,
            ) => beginOrdinaryProofAttempt(session, attemptInput),
            close: () => close(session),
            derivePersistentProofAttempt: (
                attemptInput: ReservedPersistentProofAttemptInput,
            ) => derivePersistentProofAttempt(session, attemptInput),
            deriveTargetReleaseAttempt: (
                attemptInput: TargetReleaseAttemptInput,
            ) => deriveTargetReleaseAttempt(session, attemptInput),
        });
        sessionStates.set(session, {
            closed: false,
            context,
            cryptoProvider,
            handle,
            kernel: input.kernel,
            scope,
        });
        return session;
    } finally {
        output.fill(0);
    }
};
