import { shake256 } from '@noble/hashes/sha3.js';
import {
    canonicalJson,
    signStateWitnessVoteMessage,
    type BrowserLocalSigningCapability,
} from '@sealed-lattice/crypto';
import type { VerificationResult } from '@sealed-lattice/types';
import {
    copyVerifiedStateDurableBinding,
    stateWitnessVoteKinds,
    type PreparedStateWitnessVote,
    type StateDurableBindingDescription,
    type StateVerifierSession,
    type VerifiedStateDurableBinding,
    type VerifiedStateIntent,
} from '@sealed-lattice/wasm';

import {
    AuthenticatedRuntimeRecordError,
    type AuthenticatedRuntimeRecordErrorCode,
    bytesEqual,
    bytesToHex,
    copyBoundedBytes,
    createRuntimeRecordProtection,
    mapStorageError,
    readRuntimeRecord,
    sampleRuntimeIdentifier,
    stageRuntimeRecordWrite,
    type RuntimeStorageAuthorityContext,
} from './authenticated-runtime-record.js';
import type {
    UntrustedStorageTransaction,
    UntrustedStorageTransactionStore,
} from './untrusted-storage-transaction-store.js';

const durableStateRecordVersion = 1;
const hashByteLength = 64;
const participantIdentityByteLength = 64;
const maximumUnsigned64 = 0xffff_ffff_ffff_ffffn;
const stateRecordOperationDomain =
    'sealed-lattice/runtime/state-witness-record/v1';
const exactOutputRecordOperationDomain =
    'sealed-lattice/runtime/state-exact-output-record/v1';
const stateExactOutputHashDomain = 'sealed-lattice/state/exact-output/v1';
const exactOutputRecordHeaderByteLength = 204;
const textEncoder = new TextEncoder();

type StoredStateVote = {
    intentObjectHash: string;
    journalIdentifier: string;
    signedCarrier?: string;
    voteKind: number;
    witnessVoteSequence: string;
};

type StoredStateRecord = {
    capabilityKind: number;
    currentEpoch: string;
    currentPredecessorTransitionHash?: string;
    exactOutputByteLength?: string;
    exactOutputHash?: string;
    outputIntentObjectHash?: string;
    recordVersion: number;
    reservationIntentObjectHash?: string;
    stateKey: string;
    subjectParticipantIdentity: string;
    votes: StoredStateVote[];
};

type OpenedExactOutputRecord = {
    capabilityKind: number;
    exactOutputBytes: Uint8Array;
    exactOutputHash: Uint8Array;
    outputIntentObjectHash: Uint8Array;
    stateKey: Uint8Array;
};

export type DurableStateWitnessServiceLimits = Readonly<{
    maximumCachedVoteCount: number;
    maximumExactOutputByteLength: number;
    maximumRecordSealingCount: number;
    maximumSignedCarrierByteLength: number;
    transactionLifetimeMilliseconds: number;
}>;

export type DurableStateWitnessService = Readonly<{
    cacheExactOutput(input: {
        exactOutputBytes: Uint8Array;
        verifiedOutputBinding: VerifiedStateDurableBinding;
    }): Promise<void>;
    readExactOutput(input: {
        verifiedOutputBinding: VerifiedStateDurableBinding;
    }): Promise<Uint8Array>;
    signOrReplayBrowserLocalVote(input: {
        voteIssuer: BrowserLocalStateWitnessVoteIssuer;
    }): Promise<Uint8Array>;
}>;

declare const browserLocalStateWitnessVoteIssuerBrand: unique symbol;

export type BrowserLocalStateWitnessVoteIssuer = Readonly<{
    readonly [browserLocalStateWitnessVoteIssuerBrand]: true;
}>;

type BrowserLocalStateWitnessVoteIssuerState = Readonly<{
    issue(): Promise<Uint8Array>;
    verifiedIntentBinding: VerifiedStateDurableBinding;
}>;

const browserLocalStateWitnessVoteIssuerStates = new WeakMap<
    object,
    BrowserLocalStateWitnessVoteIssuerState
>();
const stateVoteOperationTailsByStore = new WeakMap<
    UntrustedStorageTransactionStore,
    Map<string, Promise<void>>
>();

const runSerializedStateVoteOperation = async <Value>(input: {
    logicalRecordKey: string;
    operation(): Promise<Value>;
    store: UntrustedStorageTransactionStore;
}): Promise<Value> => {
    let operationTails = stateVoteOperationTailsByStore.get(input.store);
    if (operationTails === undefined) {
        operationTails = new Map();
        stateVoteOperationTailsByStore.set(input.store, operationTails);
    }
    const previousTail =
        operationTails.get(input.logicalRecordKey) ?? Promise.resolve();
    const operationResult = previousTail.then(() => input.operation());
    const currentTail = operationResult.then(
        () => undefined,
        () => undefined,
    );
    operationTails.set(input.logicalRecordKey, currentTail);
    try {
        return await operationResult;
    } finally {
        if (operationTails.get(input.logicalRecordKey) === currentTail) {
            operationTails.delete(input.logicalRecordKey);
            if (operationTails.size === 0) {
                stateVoteOperationTailsByStore.delete(input.store);
            }
        }
    }
};

const requirePreparedVoteValue = <Value>(
    result: VerificationResult<Value>,
    operation: string,
): Value => {
    if (!result.isValid) {
        throw new AuthenticatedRuntimeRecordError(
            'InvalidInput',
            `${operation} refused at the state-verifier boundary: ${result.refusalReason}.`,
        );
    }
    return result.value;
};

export const createBrowserLocalStateWitnessVoteIssuer = (input: {
    session: StateVerifierSession;
    signingCapability: BrowserLocalSigningCapability;
    verifiedIntent: VerifiedStateIntent;
    witnessParticipantIdentity: Uint8Array;
}): BrowserLocalStateWitnessVoteIssuer => {
    const verifiedIntentBinding = requirePreparedVoteValue(
        input.session.durableBindingFor(input.verifiedIntent),
        'State witness binding derivation',
    );
    const witnessParticipantIdentity = copyBoundedBytes(
        input.witnessParticipantIdentity,
        participantIdentityByteLength,
        'witnessParticipantIdentity',
    );
    let issuedCarrier: Promise<Uint8Array> | undefined;
    const issue = (): Promise<Uint8Array> => {
        issuedCarrier ??= Promise.resolve().then((): Uint8Array => {
            const preparedVote =
                requirePreparedVoteValue<PreparedStateWitnessVote>(
                    input.session.prepareWitnessVote({
                        verifiedIntent: input.verifiedIntent,
                        witnessParticipantIdentity,
                    }),
                    'State witness vote preparation',
                );
            let signatureMessage: Uint8Array | undefined;
            let signature: Uint8Array | undefined;
            try {
                signatureMessage = requirePreparedVoteValue(
                    preparedVote.copySignatureMessage(),
                    'State witness signature-message copy',
                );
                signature = signStateWitnessVoteMessage({
                    capability: input.signingCapability,
                    signatureMessage,
                });
                return requirePreparedVoteValue(
                    preparedVote.finish(signature),
                    'State witness vote finish',
                );
            } catch (error) {
                preparedVote.cancel();
                throw error;
            } finally {
                signatureMessage?.fill(0);
                signature?.fill(0);
            }
        });
        return issuedCarrier.then((carrier) => carrier.slice());
    };
    const issuer = Object.freeze(
        Object.create(null) as object,
    ) as BrowserLocalStateWitnessVoteIssuer;
    browserLocalStateWitnessVoteIssuerStates.set(
        issuer,
        Object.freeze({ issue, verifiedIntentBinding }),
    );
    return issuer;
};

const isPlainRecord = (value: unknown): value is Record<string, unknown> =>
    typeof value === 'object' &&
    value !== null &&
    !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype;

const requireSafePositiveInteger = (value: number, label: string): void => {
    if (!Number.isSafeInteger(value) || value <= 0) {
        throw new AuthenticatedRuntimeRecordError(
            'InvalidConfiguration',
            `${label} must be a positive safe integer.`,
        );
    }
};

const closeTransactionAfterFailure = async (
    transaction: UntrustedStorageTransaction,
    operationFailure: unknown,
): Promise<AuthenticatedRuntimeRecordError> => {
    const mappedOperationFailure = mapStorageError(operationFailure);
    try {
        await transaction.closeAfterFailure();
    } catch (closeFailure) {
        throw new AuthenticatedRuntimeRecordError(
            'CleanupFailed',
            'A durable state transaction failed and could not release its transaction ownership.',
            [mappedOperationFailure, mapStorageError(closeFailure)],
        );
    }
    return mappedOperationFailure;
};

const requireUnsigned64Decimal = (value: unknown, label: string): bigint => {
    if (typeof value !== 'string' || !/^(?:0|[1-9][0-9]*)$/u.test(value)) {
        throw new AuthenticatedRuntimeRecordError(
            'AuthenticationFailed',
            `${label} is not a canonical unsigned-64 decimal string.`,
        );
    }
    const parsed = BigInt(value);
    if (parsed > maximumUnsigned64) {
        throw new AuthenticatedRuntimeRecordError(
            'AuthenticationFailed',
            `${label} exceeds the unsigned-64 range.`,
        );
    }
    return parsed;
};

const hexToBytes = (
    value: unknown,
    expectedByteLength: number,
    label: string,
): Uint8Array => {
    if (
        typeof value !== 'string' ||
        value.length !== expectedByteLength * 2 ||
        !/^[0-9a-f]+$/u.test(value)
    ) {
        throw new AuthenticatedRuntimeRecordError(
            'AuthenticationFailed',
            `${label} is not canonical lowercase hexadecimal.`,
        );
    }
    const bytes = new Uint8Array(expectedByteLength);
    for (let byteIndex = 0; byteIndex < bytes.byteLength; byteIndex += 1) {
        bytes[byteIndex] = Number.parseInt(
            value.slice(byteIndex * 2, byteIndex * 2 + 2),
            16,
        );
    }
    return bytes;
};

const variableHexToBytes = (
    value: unknown,
    maximumByteLength: number,
    label: string,
): Uint8Array => {
    if (
        typeof value !== 'string' ||
        value.length % 2 !== 0 ||
        value.length > maximumByteLength * 2 ||
        !/^(?:[0-9a-f]{2})*$/u.test(value)
    ) {
        throw new AuthenticatedRuntimeRecordError(
            'AuthenticationFailed',
            `${label} is not bounded canonical hexadecimal.`,
        );
    }
    return hexToBytes(value, value.length / 2, label);
};

const optionalHash = (value: unknown, label: string): string | undefined => {
    if (value === undefined) {
        return undefined;
    }
    return bytesToHex(hexToBytes(value, hashByteLength, label));
};

const requireExactKeys = (
    value: Record<string, unknown>,
    requiredKeys: readonly string[],
    optionalKeys: readonly string[],
    label: string,
): void => {
    const acceptedKeys = new Set([...requiredKeys, ...optionalKeys]);
    if (
        requiredKeys.some((key) => !(key in value)) ||
        Object.keys(value).some((key) => !acceptedKeys.has(key))
    ) {
        throw new AuthenticatedRuntimeRecordError(
            'AuthenticationFailed',
            `${label} has the wrong fields.`,
        );
    }
};

const encodeCanonicalRecord = (value: unknown): Uint8Array =>
    textEncoder.encode(canonicalJson(value));

const parseCanonicalJson = (
    bytes: Uint8Array,
    label: string,
): Record<string, unknown> => {
    let parsed: unknown;
    try {
        parsed = JSON.parse(
            new TextDecoder('utf-8', { fatal: true }).decode(bytes),
        );
    } catch (error) {
        throw new AuthenticatedRuntimeRecordError(
            'AuthenticationFailed',
            `${label} is not valid UTF-8 canonical JSON.`,
            error,
        );
    }
    if (
        !isPlainRecord(parsed) ||
        !bytesEqual(bytes, encodeCanonicalRecord(parsed))
    ) {
        throw new AuthenticatedRuntimeRecordError(
            'AuthenticationFailed',
            `${label} is not canonical JSON.`,
        );
    }
    return parsed;
};

const decodeStateRecord = (
    bytes: Uint8Array,
    limits: DurableStateWitnessServiceLimits,
): StoredStateRecord => {
    const value = parseCanonicalJson(bytes, 'durable state record');
    requireExactKeys(
        value,
        [
            'capabilityKind',
            'currentEpoch',
            'recordVersion',
            'stateKey',
            'subjectParticipantIdentity',
            'votes',
        ],
        [
            'currentPredecessorTransitionHash',
            'exactOutputByteLength',
            'exactOutputHash',
            'outputIntentObjectHash',
            'reservationIntentObjectHash',
        ],
        'durable state record',
    );
    if (
        value.recordVersion !== durableStateRecordVersion ||
        !Number.isInteger(value.capabilityKind) ||
        !Array.isArray(value.votes) ||
        value.votes.length > limits.maximumCachedVoteCount
    ) {
        throw new AuthenticatedRuntimeRecordError(
            'AuthenticationFailed',
            'Durable state record has invalid fixed fields.',
        );
    }
    const stateKey = bytesToHex(
        hexToBytes(value.stateKey, hashByteLength, 'stateKey'),
    );
    const subjectParticipantIdentity = bytesToHex(
        hexToBytes(
            value.subjectParticipantIdentity,
            participantIdentityByteLength,
            'subjectParticipantIdentity',
        ),
    );
    const currentEpoch = requireUnsigned64Decimal(
        value.currentEpoch,
        'currentEpoch',
    ).toString();
    const votes: StoredStateVote[] = [];
    let previousSequence = -1n;
    for (const [voteIndex, untrustedVote] of value.votes.entries()) {
        if (!isPlainRecord(untrustedVote)) {
            throw new AuthenticatedRuntimeRecordError(
                'AuthenticationFailed',
                `votes[${voteIndex}] is not a record.`,
            );
        }
        requireExactKeys(
            untrustedVote,
            [
                'intentObjectHash',
                'journalIdentifier',
                'voteKind',
                'witnessVoteSequence',
            ],
            ['signedCarrier'],
            `votes[${voteIndex}]`,
        );
        const witnessVoteSequence = requireUnsigned64Decimal(
            untrustedVote.witnessVoteSequence,
            `votes[${voteIndex}].witnessVoteSequence`,
        );
        if (
            witnessVoteSequence <= previousSequence ||
            (untrustedVote.voteKind !== stateWitnessVoteKinds.reservation &&
                untrustedVote.voteKind !== stateWitnessVoteKinds.output &&
                untrustedVote.voteKind !== stateWitnessVoteKinds.recovery)
        ) {
            throw new AuthenticatedRuntimeRecordError(
                'AuthenticationFailed',
                'Durable state votes are not strictly sequence ordered.',
            );
        }
        previousSequence = witnessVoteSequence;
        votes.push({
            intentObjectHash: bytesToHex(
                hexToBytes(
                    untrustedVote.intentObjectHash,
                    hashByteLength,
                    `votes[${voteIndex}].intentObjectHash`,
                ),
            ),
            journalIdentifier: bytesToHex(
                hexToBytes(
                    untrustedVote.journalIdentifier,
                    32,
                    `votes[${voteIndex}].journalIdentifier`,
                ),
            ),
            ...(untrustedVote.signedCarrier === undefined
                ? {}
                : {
                      signedCarrier: bytesToHex(
                          variableHexToBytes(
                              untrustedVote.signedCarrier,
                              limits.maximumSignedCarrierByteLength,
                              `votes[${voteIndex}].signedCarrier`,
                          ),
                      ),
                  }),
            voteKind: untrustedVote.voteKind,
            witnessVoteSequence: witnessVoteSequence.toString(),
        });
    }
    const reservationIntentObjectHash = optionalHash(
        value.reservationIntentObjectHash,
        'reservationIntentObjectHash',
    );
    const outputIntentObjectHash = optionalHash(
        value.outputIntentObjectHash,
        'outputIntentObjectHash',
    );
    const exactOutputHash = optionalHash(
        value.exactOutputHash,
        'exactOutputHash',
    );
    const exactOutputByteLength =
        value.exactOutputByteLength === undefined
            ? undefined
            : requireUnsigned64Decimal(
                  value.exactOutputByteLength,
                  'exactOutputByteLength',
              ).toString();
    if (
        (outputIntentObjectHash !== undefined &&
            reservationIntentObjectHash === undefined) ||
        (exactOutputHash === undefined) !==
            (exactOutputByteLength === undefined) ||
        (exactOutputHash !== undefined && outputIntentObjectHash === undefined)
    ) {
        throw new AuthenticatedRuntimeRecordError(
            'AuthenticationFailed',
            'Durable state lock fields are inconsistent.',
        );
    }
    return {
        capabilityKind: value.capabilityKind as number,
        currentEpoch,
        ...(value.currentPredecessorTransitionHash === undefined
            ? {}
            : {
                  currentPredecessorTransitionHash: optionalHash(
                      value.currentPredecessorTransitionHash,
                      'currentPredecessorTransitionHash',
                  ),
              }),
        ...(exactOutputByteLength === undefined
            ? {}
            : { exactOutputByteLength }),
        ...(exactOutputHash === undefined ? {} : { exactOutputHash }),
        ...(outputIntentObjectHash === undefined
            ? {}
            : { outputIntentObjectHash }),
        recordVersion: durableStateRecordVersion,
        ...(reservationIntentObjectHash === undefined
            ? {}
            : { reservationIntentObjectHash }),
        stateKey,
        subjectParticipantIdentity,
        votes,
    };
};

const encodeExactOutputRecord = (
    binding: StateDurableBindingDescription,
    exactOutputBytes: Uint8Array,
): Uint8Array => {
    if (
        binding.outputIntentObjectHash === undefined ||
        binding.exactOutputHash === undefined
    ) {
        throw new AuthenticatedRuntimeRecordError(
            'InvalidInput',
            'Exact-output record encoding requires an output binding.',
        );
    }
    const bytes = new Uint8Array(
        exactOutputRecordHeaderByteLength + exactOutputBytes.byteLength,
    );
    const view = new DataView(bytes.buffer);
    view.setUint16(0, durableStateRecordVersion, true);
    view.setUint16(2, binding.capabilityKind, true);
    bytes.set(binding.stateKey, 4);
    bytes.set(binding.outputIntentObjectHash, 68);
    bytes.set(binding.exactOutputHash, 132);
    view.setBigUint64(196, BigInt(exactOutputBytes.byteLength), true);
    bytes.set(exactOutputBytes, exactOutputRecordHeaderByteLength);
    return bytes;
};

const decodeExactOutputRecord = (
    bytes: Uint8Array,
    limits: DurableStateWitnessServiceLimits,
): OpenedExactOutputRecord => {
    if (bytes.byteLength < exactOutputRecordHeaderByteLength) {
        throw new AuthenticatedRuntimeRecordError(
            'AuthenticationFailed',
            'Exact-output cache record is truncated.',
        );
    }
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const exactOutputByteLength = view.getBigUint64(196, true);
    if (
        view.getUint16(0, true) !== durableStateRecordVersion ||
        exactOutputByteLength > BigInt(limits.maximumExactOutputByteLength) ||
        exactOutputByteLength !==
            BigInt(bytes.byteLength - exactOutputRecordHeaderByteLength)
    ) {
        throw new AuthenticatedRuntimeRecordError(
            'AuthenticationFailed',
            'Exact-output cache record has noncanonical framing.',
        );
    }
    return {
        capabilityKind: view.getUint16(2, true),
        exactOutputBytes: bytes.slice(exactOutputRecordHeaderByteLength),
        exactOutputHash: bytes.slice(132, 196),
        outputIntentObjectHash: bytes.slice(68, 132),
        stateKey: bytes.slice(4, 68),
    };
};

const destroyOpenedExactOutputRecord = (
    record: OpenedExactOutputRecord,
): void => {
    record.exactOutputBytes.fill(0);
    record.exactOutputHash.fill(0);
    record.outputIntentObjectHash.fill(0);
    record.stateKey.fill(0);
};

const updateUnsigned16 = (
    hash: ReturnType<typeof shake256.create>,
    value: number,
): void => {
    const bytes = new Uint8Array(2);
    new DataView(bytes.buffer).setUint16(0, value, true);
    hash.update(bytes);
};

const updateUnsigned32 = (
    hash: ReturnType<typeof shake256.create>,
    value: number,
): void => {
    const bytes = new Uint8Array(4);
    new DataView(bytes.buffer).setUint32(0, value, true);
    hash.update(bytes);
};

const updateUnsigned64 = (
    hash: ReturnType<typeof shake256.create>,
    value: bigint,
): void => {
    const bytes = new Uint8Array(8);
    new DataView(bytes.buffer).setBigUint64(0, value, true);
    hash.update(bytes);
};

const updateAsciiCanonicalItem = (
    hash: ReturnType<typeof shake256.create>,
    value: string,
): void => {
    const bytes = textEncoder.encode(value);
    updateUnsigned16(hash, 0x02);
    updateUnsigned32(hash, bytes.byteLength + 4);
    updateUnsigned32(hash, bytes.byteLength);
    hash.update(bytes);
};

const deriveStateExactOutputHash = (
    capabilityKind: number,
    exactOutputBytes: Uint8Array,
): Uint8Array => {
    const hash = shake256.create({ dkLen: hashByteLength });
    try {
        updateUnsigned16(hash, 0x0001);
        updateUnsigned16(hash, 1);
        updateUnsigned32(hash, 4);
        updateAsciiCanonicalItem(hash, stateExactOutputHashDomain);
        updateUnsigned16(hash, 0x03);
        updateUnsigned32(hash, 2);
        updateUnsigned16(hash, capabilityKind);
        updateUnsigned16(hash, 0x05);
        updateUnsigned32(hash, 8);
        updateUnsigned64(hash, BigInt(exactOutputBytes.byteLength));
        updateUnsigned16(hash, 0x01);
        updateUnsigned32(hash, exactOutputBytes.byteLength + 4);
        updateUnsigned32(hash, exactOutputBytes.byteLength);
        hash.update(exactOutputBytes);
        return hash.digest();
    } finally {
        hash.destroy();
    }
};

const stateRecordKey = (binding: StateDurableBindingDescription): string =>
    `state-witness/${bytesToHex(binding.stateKey)}`;

const exactOutputRecordKey = (
    binding: StateDurableBindingDescription,
): string => `state-exact-output/${bytesToHex(binding.stateKey)}`;

const optionalHashHex = (value: Uint8Array | undefined): string | undefined =>
    value === undefined ? undefined : bytesToHex(value);

const sameOptionalHash = (
    left: string | undefined,
    right: Uint8Array | undefined,
): boolean => left === optionalHashHex(right);

const requireBindingContext = (
    binding: StateDurableBindingDescription,
    authorityContext: RuntimeStorageAuthorityContext,
): void => {
    if (
        !bytesEqual(
            binding.suiteIdentifier,
            authorityContext.suiteIdentifier,
        ) ||
        !bytesEqual(
            binding.ceremonyContextHash,
            authorityContext.ceremonyContextHash,
        ) ||
        !bytesEqual(
            binding.actionContextHash,
            authorityContext.actionContextHash,
        )
    ) {
        throw new AuthenticatedRuntimeRecordError(
            'InvalidInput',
            'The verified state binding belongs to another runtime context.',
        );
    }
};

const copyVerifiedBinding = (
    binding: VerifiedStateDurableBinding,
    authorityContext: RuntimeStorageAuthorityContext,
): StateDurableBindingDescription => {
    let description: StateDurableBindingDescription;
    try {
        description = copyVerifiedStateDurableBinding(binding);
    } catch (error) {
        throw new AuthenticatedRuntimeRecordError(
            'InvalidInput',
            'The state binding was not issued by the WASM verifier.',
            error,
        );
    }
    requireBindingContext(description, authorityContext);
    return description;
};

const freshStateRecord = (
    binding: StateDurableBindingDescription,
): StoredStateRecord => ({
    capabilityKind: binding.capabilityKind,
    currentEpoch: '0',
    recordVersion: durableStateRecordVersion,
    stateKey: bytesToHex(binding.stateKey),
    subjectParticipantIdentity: bytesToHex(binding.subjectParticipantIdentity),
    votes: [],
});

const requireRecordIdentity = (
    record: StoredStateRecord,
    binding: StateDurableBindingDescription,
): void => {
    if (
        record.capabilityKind !== binding.capabilityKind ||
        record.stateKey !== bytesToHex(binding.stateKey) ||
        record.subjectParticipantIdentity !==
            bytesToHex(binding.subjectParticipantIdentity)
    ) {
        throw new AuthenticatedRuntimeRecordError(
            'AuthenticationFailed',
            'Durable state record does not match its verifier-derived state key.',
        );
    }
};

const findVote = (
    record: StoredStateRecord,
    binding: StateDurableBindingDescription,
): StoredStateVote | undefined =>
    record.votes.find(
        (vote) =>
            BigInt(vote.witnessVoteSequence) === binding.witnessVoteSequence,
    );

const applyIntentLock = (
    record: StoredStateRecord,
    binding: StateDurableBindingDescription,
): void => {
    requireRecordIdentity(record, binding);
    const currentEpoch = BigInt(record.currentEpoch);
    const currentPredecessorTransitionHash =
        record.currentPredecessorTransitionHash;
    switch (binding.voteKind) {
        case stateWitnessVoteKinds.reservation: {
            if (
                binding.subjectEpoch !== currentEpoch ||
                !sameOptionalHash(
                    currentPredecessorTransitionHash,
                    binding.predecessorTransitionHash,
                ) ||
                (record.reservationIntentObjectHash !== undefined &&
                    record.reservationIntentObjectHash !==
                        bytesToHex(binding.intentObjectHash))
            ) {
                throw new AuthenticatedRuntimeRecordError(
                    'Conflict',
                    'The reservation conflicts with the durable state lock.',
                );
            }
            record.reservationIntentObjectHash = bytesToHex(
                binding.intentObjectHash,
            );
            break;
        }
        case stateWitnessVoteKinds.output: {
            if (
                binding.subjectEpoch !== currentEpoch ||
                !sameOptionalHash(
                    currentPredecessorTransitionHash,
                    binding.predecessorTransitionHash,
                ) ||
                binding.reservationIntentObjectHash === undefined ||
                binding.outputIntentObjectHash === undefined ||
                binding.exactOutputHash === undefined ||
                binding.exactOutputByteLength === undefined ||
                record.reservationIntentObjectHash !==
                    bytesToHex(binding.reservationIntentObjectHash) ||
                (record.outputIntentObjectHash !== undefined &&
                    record.outputIntentObjectHash !==
                        bytesToHex(binding.outputIntentObjectHash))
            ) {
                throw new AuthenticatedRuntimeRecordError(
                    'Conflict',
                    'The output conflicts with the durable reservation lock.',
                );
            }
            record.outputIntentObjectHash = bytesToHex(
                binding.outputIntentObjectHash,
            );
            record.exactOutputHash = bytesToHex(binding.exactOutputHash);
            record.exactOutputByteLength =
                binding.exactOutputByteLength.toString();
            break;
        }
        case stateWitnessVoteKinds.recovery: {
            const preservedReservationIntent = optionalHashHex(
                binding.reservationIntentObjectHash,
            );
            const preservedOutputIntent = optionalHashHex(
                binding.outputIntentObjectHash,
            );
            const firstObservedRecovery =
                record.votes.length === 0 &&
                record.reservationIntentObjectHash === undefined &&
                record.outputIntentObjectHash === undefined;
            if (
                (!firstObservedRecovery &&
                    binding.subjectEpoch !== currentEpoch + 1n) ||
                binding.subjectEpoch === 0n ||
                (!firstObservedRecovery &&
                    !sameOptionalHash(
                        currentPredecessorTransitionHash,
                        binding.predecessorTransitionHash,
                    )) ||
                (record.reservationIntentObjectHash !== undefined &&
                    record.reservationIntentObjectHash !==
                        preservedReservationIntent) ||
                (record.outputIntentObjectHash !== undefined &&
                    record.outputIntentObjectHash !== preservedOutputIntent)
            ) {
                throw new AuthenticatedRuntimeRecordError(
                    'Conflict',
                    'The recovery transition does not preserve the durable state lock.',
                );
            }
            if (preservedReservationIntent === undefined) {
                delete record.reservationIntentObjectHash;
            } else {
                record.reservationIntentObjectHash = preservedReservationIntent;
            }
            if (preservedOutputIntent === undefined) {
                delete record.outputIntentObjectHash;
            } else {
                record.outputIntentObjectHash = preservedOutputIntent;
            }
            record.currentEpoch = binding.subjectEpoch.toString();
            record.currentPredecessorTransitionHash = bytesToHex(
                binding.intentObjectHash,
            );
            break;
        }
    }
};

const requireExactOutputCacheMatches = async (input: {
    binding: StateDurableBindingDescription;
    limits: DurableStateWitnessServiceLimits;
    protection: ReturnType<typeof createRuntimeRecordProtection>;
    store: UntrustedStorageTransactionStore;
}): Promise<OpenedExactOutputRecord> => {
    if (
        input.binding.voteKind !== stateWitnessVoteKinds.output ||
        input.binding.outputIntentObjectHash === undefined ||
        input.binding.exactOutputHash === undefined ||
        input.binding.exactOutputByteLength === undefined
    ) {
        throw new AuthenticatedRuntimeRecordError(
            'InvalidInput',
            'An exact-output cache operation requires a verified output binding.',
        );
    }
    const logicalRecordKey = exactOutputRecordKey(input.binding);
    const opened = await readRuntimeRecord({
        logicalRecordKey,
        operationDomain: exactOutputRecordOperationDomain,
        protection: input.protection,
        store: input.store,
    });
    if (opened === undefined) {
        throw new AuthenticatedRuntimeRecordError(
            'MissingRecord',
            'The exact output named by the verified output intent is unavailable.',
        );
    }
    const record = decodeExactOutputRecord(opened.plaintext, input.limits);
    opened.plaintext.fill(0);
    if (
        record.capabilityKind !== input.binding.capabilityKind ||
        !bytesEqual(record.stateKey, input.binding.stateKey) ||
        !bytesEqual(
            record.outputIntentObjectHash,
            input.binding.outputIntentObjectHash,
        ) ||
        !bytesEqual(record.exactOutputHash, input.binding.exactOutputHash) ||
        BigInt(record.exactOutputBytes.byteLength) !==
            input.binding.exactOutputByteLength
    ) {
        destroyOpenedExactOutputRecord(record);
        throw new AuthenticatedRuntimeRecordError(
            'AuthenticationFailed',
            'The exact-output cache does not match its verified binding.',
        );
    }
    return record;
};

export const openDurableStateWitnessService = (input: {
    authorityContext: RuntimeStorageAuthorityContext;
    cryptoProvider?: Crypto;
    encryptionKey: CryptoKey;
    limits: DurableStateWitnessServiceLimits;
    store: UntrustedStorageTransactionStore;
}): DurableStateWitnessService => {
    requireSafePositiveInteger(
        input.limits.maximumCachedVoteCount,
        'maximumCachedVoteCount',
    );
    requireSafePositiveInteger(
        input.limits.maximumExactOutputByteLength,
        'maximumExactOutputByteLength',
    );
    requireSafePositiveInteger(
        input.limits.maximumRecordSealingCount,
        'maximumRecordSealingCount',
    );
    if (input.limits.maximumRecordSealingCount > 0x1_0000_0000) {
        throw new AuthenticatedRuntimeRecordError(
            'InvalidConfiguration',
            'maximumRecordSealingCount exceeds the AES-GCM random-nonce invocation ceiling.',
        );
    }
    requireSafePositiveInteger(
        input.limits.maximumSignedCarrierByteLength,
        'maximumSignedCarrierByteLength',
    );
    requireSafePositiveInteger(
        input.limits.transactionLifetimeMilliseconds,
        'transactionLifetimeMilliseconds',
    );
    const limits = Object.freeze({ ...input.limits });
    const protection = createRuntimeRecordProtection({
        authorityContext: input.authorityContext,
        cryptoProvider: input.cryptoProvider,
        encryptionKey: input.encryptionKey,
    });
    const issuedJournalIdentifiers = new Set<string>();
    const issuedNonces = new Set<string>();

    const cacheExactOutput: DurableStateWitnessService['cacheExactOutput'] =
        async ({ exactOutputBytes, verifiedOutputBinding }) => {
            const binding = copyVerifiedBinding(
                verifiedOutputBinding,
                protection.authorityContext,
            );
            if (
                binding.voteKind !== stateWitnessVoteKinds.output ||
                binding.outputIntentObjectHash === undefined ||
                binding.exactOutputHash === undefined ||
                binding.exactOutputByteLength === undefined
            ) {
                throw new AuthenticatedRuntimeRecordError(
                    'InvalidInput',
                    'Only a verified output binding can seal exact output bytes.',
                );
            }
            const copiedOutput = copyBoundedBytes(
                exactOutputBytes,
                limits.maximumExactOutputByteLength,
                'exactOutputBytes',
                true,
            );
            const observedHash = deriveStateExactOutputHash(
                binding.capabilityKind,
                copiedOutput,
            );
            if (
                BigInt(copiedOutput.byteLength) !==
                    binding.exactOutputByteLength ||
                !bytesEqual(observedHash, binding.exactOutputHash)
            ) {
                copiedOutput.fill(0);
                throw new AuthenticatedRuntimeRecordError(
                    'Conflict',
                    'Exact output bytes do not match the verifier-derived output binding.',
                );
            }
            const logicalRecordKey = exactOutputRecordKey(binding);
            const existing = await readRuntimeRecord({
                logicalRecordKey,
                operationDomain: exactOutputRecordOperationDomain,
                protection,
                store: input.store,
            });
            if (existing !== undefined) {
                const record = decodeExactOutputRecord(
                    existing.plaintext,
                    limits,
                );
                existing.plaintext.fill(0);
                const matches =
                    record.capabilityKind === binding.capabilityKind &&
                    bytesEqual(record.stateKey, binding.stateKey) &&
                    bytesEqual(
                        record.outputIntentObjectHash,
                        binding.outputIntentObjectHash,
                    ) &&
                    bytesEqual(
                        record.exactOutputHash,
                        binding.exactOutputHash,
                    ) &&
                    bytesEqual(record.exactOutputBytes, copiedOutput);
                destroyOpenedExactOutputRecord(record);
                copiedOutput.fill(0);
                if (!matches) {
                    throw new AuthenticatedRuntimeRecordError(
                        'Conflict',
                        'A different exact output is already sealed for this state key.',
                    );
                }
                return;
            }
            const plaintext = encodeExactOutputRecord(binding, copiedOutput);
            copiedOutput.fill(0);
            const transaction = await input.store.beginTransaction({
                lifetimeMilliseconds: limits.transactionLifetimeMilliseconds,
            });
            try {
                await stageRuntimeRecordWrite({
                    expectedCurrentSealedBytes: null,
                    issuedNonces,
                    logicalRecordKey,
                    maximumRecordSealingCount: limits.maximumRecordSealingCount,
                    operationDomain: exactOutputRecordOperationDomain,
                    plaintext,
                    protection,
                    transaction,
                });
                await transaction.commit();
            } catch (error) {
                const mapped = await closeTransactionAfterFailure(
                    transaction,
                    error,
                );
                if (mapped.code !== 'Conflict') {
                    throw mapped;
                }
                const raced = await readRuntimeRecord({
                    logicalRecordKey,
                    operationDomain: exactOutputRecordOperationDomain,
                    protection,
                    store: input.store,
                });
                if (
                    raced === undefined ||
                    !bytesEqual(raced.plaintext, plaintext)
                ) {
                    raced?.plaintext.fill(0);
                    throw mapped;
                }
                raced.plaintext.fill(0);
            } finally {
                plaintext.fill(0);
            }
        };

    const readExactOutput: DurableStateWitnessService['readExactOutput'] =
        async ({ verifiedOutputBinding }) => {
            const binding = copyVerifiedBinding(
                verifiedOutputBinding,
                protection.authorityContext,
            );
            const record = await requireExactOutputCacheMatches({
                binding,
                limits,
                protection,
                store: input.store,
            });
            const exactOutputBytes = record.exactOutputBytes.slice();
            destroyOpenedExactOutputRecord(record);
            return exactOutputBytes;
        };

    const signOrReplayIssuedVote = async (
        issuerState: BrowserLocalStateWitnessVoteIssuerState,
        binding: StateDurableBindingDescription,
        logicalRecordKey: string,
    ): Promise<Uint8Array> => {
        let lockedRecord = await readRuntimeRecord({
            logicalRecordKey,
            operationDomain: stateRecordOperationDomain,
            protection,
            store: input.store,
        });
        let record =
            lockedRecord === undefined
                ? freshStateRecord(binding)
                : decodeStateRecord(lockedRecord.plaintext, limits);
        lockedRecord?.plaintext.fill(0);
        const existingVote = findVote(record, binding);
        if (
            existingVote !== undefined &&
            (existingVote.intentObjectHash !==
                bytesToHex(binding.intentObjectHash) ||
                existingVote.voteKind !== binding.voteKind)
        ) {
            throw new AuthenticatedRuntimeRecordError(
                'Conflict',
                'The witness sequence is already locked to another intent.',
            );
        }
        if (existingVote?.signedCarrier !== undefined) {
            return variableHexToBytes(
                existingVote.signedCarrier,
                limits.maximumSignedCarrierByteLength,
                'signedCarrier',
            );
        }
        if (existingVote === undefined) {
            applyIntentLock(record, binding);
            if (record.votes.length >= limits.maximumCachedVoteCount) {
                throw new AuthenticatedRuntimeRecordError(
                    'ResourceLimit',
                    'The durable state vote cache is full.',
                );
            }
            record.votes.push({
                intentObjectHash: bytesToHex(binding.intentObjectHash),
                journalIdentifier: bytesToHex(
                    sampleRuntimeIdentifier(
                        protection,
                        issuedJournalIdentifiers,
                        'state vote journal identifier',
                    ),
                ),
                voteKind: binding.voteKind,
                witnessVoteSequence: binding.witnessVoteSequence.toString(),
            });
            record.votes.sort((left, right) =>
                BigInt(left.witnessVoteSequence) <
                BigInt(right.witnessVoteSequence)
                    ? -1
                    : 1,
            );
        }
        const lockPlaintext = encodeCanonicalRecord(record);
        const lockTransaction = await input.store.beginTransaction({
            lifetimeMilliseconds: limits.transactionLifetimeMilliseconds,
        });
        try {
            await stageRuntimeRecordWrite({
                expectedCurrentSealedBytes: lockedRecord?.sealedBytes ?? null,
                issuedNonces,
                logicalRecordKey,
                maximumRecordSealingCount: limits.maximumRecordSealingCount,
                operationDomain: stateRecordOperationDomain,
                plaintext: lockPlaintext,
                protection,
                transaction: lockTransaction,
            });
            await lockTransaction.commit();
        } catch (error) {
            const mapped = await closeTransactionAfterFailure(
                lockTransaction,
                error,
            );
            if (mapped.code !== 'Conflict') {
                throw mapped;
            }
            lockedRecord = await readRuntimeRecord({
                logicalRecordKey,
                operationDomain: stateRecordOperationDomain,
                protection,
                store: input.store,
            });
            if (lockedRecord === undefined) {
                throw mapped;
            }
            record = decodeStateRecord(lockedRecord.plaintext, limits);
            lockedRecord.plaintext.fill(0);
            const racedVote = findVote(record, binding);
            if (
                racedVote === undefined ||
                racedVote.intentObjectHash !==
                    bytesToHex(binding.intentObjectHash) ||
                racedVote.voteKind !== binding.voteKind
            ) {
                throw mapped;
            }
            if (racedVote.signedCarrier !== undefined) {
                return variableHexToBytes(
                    racedVote.signedCarrier,
                    limits.maximumSignedCarrierByteLength,
                    'signedCarrier',
                );
            }
        } finally {
            lockPlaintext.fill(0);
        }

        const signedCarrier = copyBoundedBytes(
            await issuerState.issue(),
            limits.maximumSignedCarrierByteLength,
            'signed state-witness carrier',
        );
        const current = await readRuntimeRecord({
            logicalRecordKey,
            operationDomain: stateRecordOperationDomain,
            protection,
            store: input.store,
        });
        if (current === undefined) {
            signedCarrier.fill(0);
            throw new AuthenticatedRuntimeRecordError(
                'MissingRecord',
                'The durable intent lock disappeared before carrier caching.',
            );
        }
        record = decodeStateRecord(current.plaintext, limits);
        current.plaintext.fill(0);
        const vote = findVote(record, binding);
        if (
            vote === undefined ||
            vote.intentObjectHash !== bytesToHex(binding.intentObjectHash) ||
            vote.voteKind !== binding.voteKind
        ) {
            signedCarrier.fill(0);
            throw new AuthenticatedRuntimeRecordError(
                'Conflict',
                'The durable intent lock changed before carrier caching.',
            );
        }
        if (vote.signedCarrier !== undefined) {
            signedCarrier.fill(0);
            return variableHexToBytes(
                vote.signedCarrier,
                limits.maximumSignedCarrierByteLength,
                'signedCarrier',
            );
        }
        vote.signedCarrier = bytesToHex(signedCarrier);
        const carrierPlaintext = encodeCanonicalRecord(record);
        const carrierTransaction = await input.store.beginTransaction({
            lifetimeMilliseconds: limits.transactionLifetimeMilliseconds,
        });
        try {
            await stageRuntimeRecordWrite({
                expectedCurrentSealedBytes: current.sealedBytes,
                issuedNonces,
                logicalRecordKey,
                maximumRecordSealingCount: limits.maximumRecordSealingCount,
                operationDomain: stateRecordOperationDomain,
                plaintext: carrierPlaintext,
                protection,
                transaction: carrierTransaction,
            });
            await carrierTransaction.commit();
            return signedCarrier.slice();
        } catch (error) {
            const mapped = await closeTransactionAfterFailure(
                carrierTransaction,
                error,
            );
            if (mapped.code !== 'Conflict') {
                throw mapped;
            }
            const selected = await readRuntimeRecord({
                logicalRecordKey,
                operationDomain: stateRecordOperationDomain,
                protection,
                store: input.store,
            });
            if (selected === undefined) {
                throw mapped;
            }
            const selectedRecord = decodeStateRecord(
                selected.plaintext,
                limits,
            );
            selected.plaintext.fill(0);
            const selectedVote = findVote(selectedRecord, binding);
            if (
                selectedVote?.intentObjectHash !==
                    bytesToHex(binding.intentObjectHash) ||
                selectedVote.voteKind !== binding.voteKind ||
                selectedVote.signedCarrier === undefined
            ) {
                throw mapped;
            }
            return variableHexToBytes(
                selectedVote.signedCarrier,
                limits.maximumSignedCarrierByteLength,
                'signedCarrier',
            );
        } finally {
            carrierPlaintext.fill(0);
            signedCarrier.fill(0);
        }
    };

    const signOrReplayBrowserLocalVote: DurableStateWitnessService['signOrReplayBrowserLocalVote'] =
        async ({ voteIssuer }) => {
            if (
                (typeof voteIssuer !== 'object' &&
                    typeof voteIssuer !== 'function') ||
                voteIssuer === null
            ) {
                throw new AuthenticatedRuntimeRecordError(
                    'InvalidInput',
                    'The state-witness vote issuer is not an opaque browser-local issuer.',
                );
            }
            const issuerState =
                browserLocalStateWitnessVoteIssuerStates.get(voteIssuer);
            if (issuerState === undefined) {
                throw new AuthenticatedRuntimeRecordError(
                    'InvalidInput',
                    'The state-witness vote issuer was not created by the browser-local issuer boundary.',
                );
            }
            const binding = copyVerifiedBinding(
                issuerState.verifiedIntentBinding,
                protection.authorityContext,
            );
            const logicalRecordKey = stateRecordKey(binding);
            return runSerializedStateVoteOperation({
                logicalRecordKey,
                operation: () =>
                    signOrReplayIssuedVote(
                        issuerState,
                        binding,
                        logicalRecordKey,
                    ),
                store: input.store,
            });
        };

    return Object.freeze({
        cacheExactOutput,
        readExactOutput,
        signOrReplayBrowserLocalVote,
    });
};

export { AuthenticatedRuntimeRecordError as DurableStateWitnessServiceError };
export type {
    AuthenticatedRuntimeRecordErrorCode as DurableStateWitnessServiceErrorCode,
    RuntimeStorageAuthorityContext,
};
