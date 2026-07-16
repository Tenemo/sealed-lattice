import { shake256 } from '@noble/hashes/sha3.js';
import {
    copyVerifiedStateDurableBinding,
    stateCapabilityKinds,
    stateWitnessVoteKinds,
    type StateDurableBindingDescription,
    type VerifiedStateDurableBinding,
} from '@sealed-lattice/wasm';

import {
    AuthenticatedRuntimeRecordError,
    type AuthenticatedRuntimeRecordErrorCode,
    bytesEqual,
    bytesToHex,
    copyBoundedBytes,
    copyRuntimeRecordProtectionAuthorityContext,
    copyRuntimeStorageAuthorityContext,
    createRuntimeRecordProtection,
    mapStorageError,
    readRuntimeRecord,
    releaseRuntimeRecordProtection,
    stageRuntimeRecordWrite,
    type RuntimeRecordProtection,
    type RuntimeStorageAuthorityContext,
} from './authenticated-runtime-record.js';
import {
    ExclusiveResourceLifecycle,
    type ExclusiveResourceOwnerToken,
} from './exclusive-resource-lifecycle.js';
import type {
    UntrustedStorageTransaction,
    UntrustedStorageTransactionStore,
} from './untrusted-storage-transaction-store.js';

const durableStateRecordVersion = 2;
const hashByteLength = 64;
const intentLockRecordOperationDomain =
    'sealed-lattice/runtime/state-intent-lock-record/v1';
const signedVoteCarrierRecordOperationDomain =
    'sealed-lattice/runtime/state-signed-vote-carrier-record/v1';
const exactOutputRecordOperationDomain =
    'sealed-lattice/runtime/state-exact-output-record/v1';
const commonProofApplicationRecordOperationDomain =
    'sealed-lattice/runtime/common-proof-application-record/v1';
const stateExactOutputHashDomain = 'sealed-lattice/state/exact-output/v1';
const intentLockRecordByteLength = 262;
const signedVoteCarrierRecordHeaderByteLength = 214;
const exactOutputRecordHeaderByteLength = 204;
const proofApplicationSlotHashByteLength = 64;
const maximumCommonProofAuthorizationFrameByteLength = 1_048_576;
const textEncoder = new TextEncoder();
const validStateCapabilityKinds = new Set<number>(
    Object.values(stateCapabilityKinds),
);
const validStateWitnessVoteKinds = new Set<number>(
    Object.values(stateWitnessVoteKinds),
);

type OpenedIntentLockRecord = {
    capabilityKind: number;
    outputIntentObjectHash?: Uint8Array;
    reservationIntentObjectHash?: Uint8Array;
    stateKey: Uint8Array;
    subjectParticipantIdentity: Uint8Array;
};

type OpenedSignedVoteCarrierRecord = {
    canonicalSignedVoteCarrier: Uint8Array;
    capabilityKind: number;
    intentObjectHash: Uint8Array;
    stateKey: Uint8Array;
    subjectParticipantIdentity: Uint8Array;
    voteKind: number;
    witnessVoteSequence: bigint;
};

type OpenedExactOutputRecord = {
    capabilityKind: number;
    exactOutputBytes: Uint8Array;
    exactOutputHash: Uint8Array;
    outputIntentObjectHash: Uint8Array;
    stateKey: Uint8Array;
};

export type DurableStateWitnessServiceLimits = Readonly<{
    maximumExactOutputByteLength: number;
    maximumRecordSealingCount: number;
    maximumSignedVoteCarrierByteLength: number;
    transactionLifetimeMilliseconds: number;
}>;

/**
 * Participant-client storage runtime for a roster member's state-witness role.
 * This is not an external network service or a separate ceremony actor.
 */
export type DurableStateWitnessService = Readonly<{
    close(): Promise<void>;
    copyAuthorityContext(): RuntimeStorageAuthorityContext;
    cacheSignedVoteCarrier(input: {
        canonicalSignedVoteCarrier: Uint8Array;
        verifiedIntentBinding: VerifiedStateDurableBinding;
    }): Promise<Uint8Array>;
    cacheExactOutput(input: {
        exactOutputBytes: Uint8Array;
        verifiedOutputBinding: VerifiedStateDurableBinding;
    }): Promise<void>;
    compareAndLockIntent(input: {
        verifiedIntentBinding: VerifiedStateDurableBinding;
    }): Promise<void>;
    readExactOutput(input: {
        verifiedOutputBinding: VerifiedStateDurableBinding;
    }): Promise<Uint8Array>;
    readSignedVoteCarrier(input: {
        verifiedIntentBinding: VerifiedStateDurableBinding;
    }): Promise<Uint8Array>;
}>;

export type TransferableDurableStateWitnessService =
    DurableStateWitnessService &
        Readonly<{
            claimExclusiveOwner(): DurableStateWitnessService;
        }>;

type PersistCommonProofApplicationInput = Readonly<{
    authorizationFrame: Uint8Array;
    onCommitAttempt(): void;
    proofApplicationSlotHash: Uint8Array;
}>;

type PersistCommonProofApplicationOperation = (
    input: PersistCommonProofApplicationInput,
) => Promise<Uint8Array>;

const commonProofApplicationPersistenceOperations = new WeakMap<
    DurableStateWitnessService,
    PersistCommonProofApplicationOperation
>();

/**
 * Same-worker bridge for one verifier-prepared common-proof authorization.
 * It is intentionally absent from the public durable-state service surface.
 */
export const persistCommonProofApplicationAuthorization = (
    service: DurableStateWitnessService,
    input: PersistCommonProofApplicationInput,
): Promise<Uint8Array> => {
    const operation = commonProofApplicationPersistenceOperations.get(service);
    if (operation === undefined) {
        throw new AuthenticatedRuntimeRecordError(
            'InvalidInput',
            'The durable state witness service does not own common-proof application storage in this worker.',
        );
    }
    return operation(input);
};

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

const intentLockRecordKey = (binding: StateDurableBindingDescription): string =>
    `state-intent-lock/${bytesToHex(binding.stateKey)}`;

const signedVoteCarrierRecordKey = (
    binding: StateDurableBindingDescription,
): string =>
    `state-signed-vote-carrier/${bytesToHex(binding.stateKey)}/${binding.witnessVoteSequence.toString(10)}`;

const commonProofApplicationRecordKey = (
    proofApplicationSlotHash: Uint8Array,
): string => `common-proof-application/${bytesToHex(proofApplicationSlotHash)}`;

const writeOptionalHash = (
    bytes: Uint8Array,
    offset: number,
    value: Uint8Array | undefined,
): void => {
    if (value === undefined) {
        bytes[offset] = 0;
        return;
    }
    bytes[offset] = 1;
    bytes.set(value, offset + 1);
};

const readOptionalHash = (
    bytes: Uint8Array,
    offset: number,
    label: string,
): Uint8Array | undefined => {
    const present = bytes[offset];
    const value = bytes.slice(offset + 1, offset + 1 + hashByteLength);
    if (present === 0) {
        const isCanonicalAbsentValue = value.every((byte) => byte === 0);
        value.fill(0);
        if (!isCanonicalAbsentValue) {
            throw new AuthenticatedRuntimeRecordError(
                'AuthenticationFailed',
                `${label} has a noncanonical absent value.`,
            );
        }
        return undefined;
    }
    if (present !== 1) {
        value.fill(0);
        throw new AuthenticatedRuntimeRecordError(
            'AuthenticationFailed',
            `${label} has an invalid presence flag.`,
        );
    }
    return value;
};

const copyIntentLockRecord = (
    record: OpenedIntentLockRecord,
): OpenedIntentLockRecord => ({
    capabilityKind: record.capabilityKind,
    ...(record.outputIntentObjectHash === undefined
        ? {}
        : { outputIntentObjectHash: record.outputIntentObjectHash.slice() }),
    ...(record.reservationIntentObjectHash === undefined
        ? {}
        : {
              reservationIntentObjectHash:
                  record.reservationIntentObjectHash.slice(),
          }),
    stateKey: record.stateKey.slice(),
    subjectParticipantIdentity: record.subjectParticipantIdentity.slice(),
});

const destroyOpenedIntentLockRecord = (
    record: OpenedIntentLockRecord,
): void => {
    record.outputIntentObjectHash?.fill(0);
    record.reservationIntentObjectHash?.fill(0);
    record.stateKey.fill(0);
    record.subjectParticipantIdentity.fill(0);
};

const encodeIntentLockRecord = (record: OpenedIntentLockRecord): Uint8Array => {
    const bytes = new Uint8Array(intentLockRecordByteLength);
    const view = new DataView(bytes.buffer);
    view.setUint16(0, durableStateRecordVersion, true);
    view.setUint16(2, record.capabilityKind, true);
    bytes.set(record.stateKey, 4);
    bytes.set(record.subjectParticipantIdentity, 68);
    writeOptionalHash(bytes, 132, record.reservationIntentObjectHash);
    writeOptionalHash(bytes, 197, record.outputIntentObjectHash);
    return bytes;
};

const decodeIntentLockRecord = (bytes: Uint8Array): OpenedIntentLockRecord => {
    if (bytes.byteLength !== intentLockRecordByteLength) {
        throw new AuthenticatedRuntimeRecordError(
            'AuthenticationFailed',
            'Intent-lock record has noncanonical framing.',
        );
    }
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const recordVersion = view.getUint16(0, true);
    const capabilityKind = view.getUint16(2, true);
    const reservationIntentObjectHash = readOptionalHash(
        bytes,
        132,
        'Intent-lock reservation',
    );
    const outputIntentObjectHash = readOptionalHash(
        bytes,
        197,
        'Intent-lock output',
    );
    if (
        recordVersion !== durableStateRecordVersion ||
        !validStateCapabilityKinds.has(capabilityKind) ||
        (outputIntentObjectHash !== undefined &&
            reservationIntentObjectHash === undefined)
    ) {
        reservationIntentObjectHash?.fill(0);
        outputIntentObjectHash?.fill(0);
        throw new AuthenticatedRuntimeRecordError(
            'AuthenticationFailed',
            'Intent-lock record has inconsistent authenticated state.',
        );
    }
    return {
        capabilityKind,
        ...(outputIntentObjectHash === undefined
            ? {}
            : { outputIntentObjectHash }),
        ...(reservationIntentObjectHash === undefined
            ? {}
            : { reservationIntentObjectHash }),
        stateKey: bytes.slice(4, 68),
        subjectParticipantIdentity: bytes.slice(68, 132),
    };
};

const intentLockRecordsEqual = (
    left: OpenedIntentLockRecord,
    right: OpenedIntentLockRecord,
): boolean =>
    left.capabilityKind === right.capabilityKind &&
    bytesEqual(left.outputIntentObjectHash, right.outputIntentObjectHash) &&
    bytesEqual(
        left.reservationIntentObjectHash,
        right.reservationIntentObjectHash,
    ) &&
    bytesEqual(left.stateKey, right.stateKey) &&
    bytesEqual(
        left.subjectParticipantIdentity,
        right.subjectParticipantIdentity,
    );

const intentLockConflict = (message: string): never => {
    throw new AuthenticatedRuntimeRecordError('Conflict', message);
};

const requireIntentLockIdentity = (
    record: OpenedIntentLockRecord,
    binding: StateDurableBindingDescription,
): void => {
    if (
        record.capabilityKind !== binding.capabilityKind ||
        !bytesEqual(record.stateKey, binding.stateKey) ||
        !bytesEqual(
            record.subjectParticipantIdentity,
            binding.subjectParticipantIdentity,
        )
    ) {
        throw new AuthenticatedRuntimeRecordError(
            'AuthenticationFailed',
            'Intent-lock record does not match its authenticated state key.',
        );
    }
};

const initialIntentLockRecord = (
    binding: StateDurableBindingDescription,
): OpenedIntentLockRecord => {
    if (binding.voteKind !== stateWitnessVoteKinds.reservation) {
        intentLockConflict(
            'An output intent cannot be locked before its reservation.',
        );
    }
    return {
        capabilityKind: binding.capabilityKind,
        reservationIntentObjectHash: binding.intentObjectHash.slice(),
        stateKey: binding.stateKey.slice(),
        subjectParticipantIdentity: binding.subjectParticipantIdentity.slice(),
    };
};

const nextIntentLockRecord = (
    binding: StateDurableBindingDescription,
    currentRecord: OpenedIntentLockRecord | undefined,
): OpenedIntentLockRecord => {
    if (currentRecord === undefined) {
        return initialIntentLockRecord(binding);
    }
    requireIntentLockIdentity(currentRecord, binding);
    const nextRecord = copyIntentLockRecord(currentRecord);
    if (binding.voteKind === stateWitnessVoteKinds.reservation) {
        if (
            currentRecord.reservationIntentObjectHash !== undefined &&
            !bytesEqual(
                currentRecord.reservationIntentObjectHash,
                binding.intentObjectHash,
            )
        ) {
            destroyOpenedIntentLockRecord(nextRecord);
            intentLockConflict(
                'A different reservation intent is already locked for this state key.',
            );
        }
        nextRecord.reservationIntentObjectHash ??=
            binding.intentObjectHash.slice();
        return nextRecord;
    }
    if (
        binding.reservationIntentObjectHash === undefined ||
        !bytesEqual(
            currentRecord.reservationIntentObjectHash,
            binding.reservationIntentObjectHash,
        )
    ) {
        destroyOpenedIntentLockRecord(nextRecord);
        intentLockConflict(
            'The output intent does not extend the durable reservation lock.',
        );
    }
    if (
        currentRecord.outputIntentObjectHash !== undefined &&
        !bytesEqual(
            currentRecord.outputIntentObjectHash,
            binding.intentObjectHash,
        )
    ) {
        destroyOpenedIntentLockRecord(nextRecord);
        intentLockConflict(
            'A different output intent is already locked for this state key.',
        );
    }
    nextRecord.outputIntentObjectHash ??= binding.intentObjectHash.slice();
    return nextRecord;
};

const requireIntentIsLocked = (
    record: OpenedIntentLockRecord,
    binding: StateDurableBindingDescription,
): void => {
    requireIntentLockIdentity(record, binding);
    const matches =
        binding.voteKind === stateWitnessVoteKinds.reservation
            ? bytesEqual(
                  record.reservationIntentObjectHash,
                  binding.intentObjectHash,
              )
            : bytesEqual(
                  record.reservationIntentObjectHash,
                  binding.reservationIntentObjectHash,
              ) &&
              bytesEqual(
                  record.outputIntentObjectHash,
                  binding.intentObjectHash,
              );
    if (!matches) {
        intentLockConflict(
            'The signed vote carrier does not match the current durable intent lock.',
        );
    }
};

const encodeSignedVoteCarrierRecord = (
    binding: StateDurableBindingDescription,
    canonicalSignedVoteCarrier: Uint8Array,
): Uint8Array => {
    const bytes = new Uint8Array(
        signedVoteCarrierRecordHeaderByteLength +
            canonicalSignedVoteCarrier.byteLength,
    );
    const view = new DataView(bytes.buffer);
    view.setUint16(0, durableStateRecordVersion, true);
    view.setUint16(2, binding.capabilityKind, true);
    view.setUint16(4, binding.voteKind, true);
    bytes.set(binding.stateKey, 6);
    bytes.set(binding.subjectParticipantIdentity, 70);
    bytes.set(binding.intentObjectHash, 134);
    view.setBigUint64(198, binding.witnessVoteSequence, true);
    view.setBigUint64(206, BigInt(canonicalSignedVoteCarrier.byteLength), true);
    bytes.set(
        canonicalSignedVoteCarrier,
        signedVoteCarrierRecordHeaderByteLength,
    );
    return bytes;
};

const decodeSignedVoteCarrierRecord = (
    bytes: Uint8Array,
    limits: DurableStateWitnessServiceLimits,
): OpenedSignedVoteCarrierRecord => {
    if (bytes.byteLength < signedVoteCarrierRecordHeaderByteLength) {
        throw new AuthenticatedRuntimeRecordError(
            'AuthenticationFailed',
            'Signed-vote carrier record is truncated.',
        );
    }
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const canonicalSignedVoteCarrierByteLength = view.getBigUint64(206, true);
    const capabilityKind = view.getUint16(2, true);
    const voteKind = view.getUint16(4, true);
    if (
        view.getUint16(0, true) !== durableStateRecordVersion ||
        !validStateCapabilityKinds.has(capabilityKind) ||
        !validStateWitnessVoteKinds.has(voteKind) ||
        canonicalSignedVoteCarrierByteLength === 0n ||
        canonicalSignedVoteCarrierByteLength >
            BigInt(limits.maximumSignedVoteCarrierByteLength) ||
        canonicalSignedVoteCarrierByteLength !==
            BigInt(bytes.byteLength - signedVoteCarrierRecordHeaderByteLength)
    ) {
        throw new AuthenticatedRuntimeRecordError(
            'AuthenticationFailed',
            'Signed-vote carrier record has noncanonical framing.',
        );
    }
    return {
        canonicalSignedVoteCarrier: bytes.slice(
            signedVoteCarrierRecordHeaderByteLength,
        ),
        capabilityKind,
        intentObjectHash: bytes.slice(134, 198),
        stateKey: bytes.slice(6, 70),
        subjectParticipantIdentity: bytes.slice(70, 134),
        voteKind,
        witnessVoteSequence: view.getBigUint64(198, true),
    };
};

const destroyOpenedSignedVoteCarrierRecord = (
    record: OpenedSignedVoteCarrierRecord,
): void => {
    record.canonicalSignedVoteCarrier.fill(0);
    record.intentObjectHash.fill(0);
    record.stateKey.fill(0);
    record.subjectParticipantIdentity.fill(0);
};

const requireSignedVoteCarrierMatchesBinding = (
    record: OpenedSignedVoteCarrierRecord,
    binding: StateDurableBindingDescription,
): void => {
    if (
        !bytesEqual(record.stateKey, binding.stateKey) ||
        record.witnessVoteSequence !== binding.witnessVoteSequence
    ) {
        throw new AuthenticatedRuntimeRecordError(
            'AuthenticationFailed',
            'Signed-vote carrier record does not match its authenticated slot.',
        );
    }
    if (
        record.capabilityKind !== binding.capabilityKind ||
        record.voteKind !== binding.voteKind ||
        !bytesEqual(record.intentObjectHash, binding.intentObjectHash) ||
        !bytesEqual(
            record.subjectParticipantIdentity,
            binding.subjectParticipantIdentity,
        )
    ) {
        intentLockConflict(
            'A different signed vote carrier is already stored in this witness sequence slot.',
        );
    }
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

const exactOutputRecordKey = (
    binding: StateDurableBindingDescription,
): string => `state-exact-output/${bytesToHex(binding.stateKey)}`;

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

const readIntentLockRecord = async (input: {
    binding: StateDurableBindingDescription;
    protection: ReturnType<typeof createRuntimeRecordProtection>;
    store: UntrustedStorageTransactionStore;
}): Promise<
    | Readonly<{
          record: OpenedIntentLockRecord;
          sealedBytes: Uint8Array;
      }>
    | undefined
> => {
    const opened = await readRuntimeRecord({
        logicalRecordKey: intentLockRecordKey(input.binding),
        operationDomain: intentLockRecordOperationDomain,
        protection: input.protection,
        store: input.store,
    });
    if (opened === undefined) {
        return undefined;
    }
    try {
        return {
            record: decodeIntentLockRecord(opened.plaintext),
            sealedBytes: opened.sealedBytes,
        };
    } finally {
        opened.plaintext.fill(0);
    }
};

const readSignedVoteCarrierRecord = async (input: {
    binding: StateDurableBindingDescription;
    limits: DurableStateWitnessServiceLimits;
    protection: ReturnType<typeof createRuntimeRecordProtection>;
    store: UntrustedStorageTransactionStore;
}): Promise<OpenedSignedVoteCarrierRecord | undefined> => {
    const opened = await readRuntimeRecord({
        logicalRecordKey: signedVoteCarrierRecordKey(input.binding),
        operationDomain: signedVoteCarrierRecordOperationDomain,
        protection: input.protection,
        store: input.store,
    });
    if (opened === undefined) {
        return undefined;
    }
    try {
        return decodeSignedVoteCarrierRecord(opened.plaintext, input.limits);
    } finally {
        opened.plaintext.fill(0);
        opened.sealedBytes.fill(0);
    }
};

const beginDurableStateTransaction = async (input: {
    lifetimeMilliseconds: number;
    store: UntrustedStorageTransactionStore;
}): Promise<UntrustedStorageTransaction> => {
    try {
        return await input.store.beginTransaction({
            lifetimeMilliseconds: input.lifetimeMilliseconds,
        });
    } catch (error) {
        throw mapStorageError(error);
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

const validateDurableStateWitnessServiceLimits = (
    limits: DurableStateWitnessServiceLimits,
): DurableStateWitnessServiceLimits => {
    requireSafePositiveInteger(
        limits.maximumExactOutputByteLength,
        'maximumExactOutputByteLength',
    );
    requireSafePositiveInteger(
        limits.maximumRecordSealingCount,
        'maximumRecordSealingCount',
    );
    if (limits.maximumRecordSealingCount > 0x1_0000_0000) {
        throw new AuthenticatedRuntimeRecordError(
            'InvalidConfiguration',
            'maximumRecordSealingCount exceeds the AES-GCM random-nonce invocation ceiling.',
        );
    }
    requireSafePositiveInteger(
        limits.maximumSignedVoteCarrierByteLength,
        'maximumSignedVoteCarrierByteLength',
    );
    requireSafePositiveInteger(
        limits.transactionLifetimeMilliseconds,
        'transactionLifetimeMilliseconds',
    );
    return Object.freeze({ ...limits });
};

export const openDurableStateWitnessServiceWithProtection = (input: {
    limits: DurableStateWitnessServiceLimits;
    protection: RuntimeRecordProtection;
    store: UntrustedStorageTransactionStore;
}): TransferableDurableStateWitnessService => {
    const limits = validateDurableStateWitnessServiceLimits(input.limits);
    const protection = input.protection;
    const authorityContext =
        copyRuntimeRecordProtectionAuthorityContext(protection);

    const compareAndLockIntent: DurableStateWitnessService['compareAndLockIntent'] =
        async ({ verifiedIntentBinding }) => {
            const binding = copyVerifiedBinding(
                verifiedIntentBinding,
                authorityContext,
            );
            const openedCurrentRecord = await readIntentLockRecord({
                binding,
                protection,
                store: input.store,
            });
            let nextRecord: OpenedIntentLockRecord | undefined;
            let plaintext: Uint8Array | undefined;
            try {
                nextRecord = nextIntentLockRecord(
                    binding,
                    openedCurrentRecord?.record,
                );
                if (
                    openedCurrentRecord !== undefined &&
                    intentLockRecordsEqual(
                        openedCurrentRecord.record,
                        nextRecord,
                    )
                ) {
                    return;
                }
                plaintext = encodeIntentLockRecord(nextRecord);
                const transaction = await beginDurableStateTransaction({
                    lifetimeMilliseconds:
                        limits.transactionLifetimeMilliseconds,
                    store: input.store,
                });
                try {
                    await stageRuntimeRecordWrite({
                        expectedCurrentSealedBytes:
                            openedCurrentRecord?.sealedBytes ?? null,
                        logicalRecordKey: intentLockRecordKey(binding),
                        operationDomain: intentLockRecordOperationDomain,
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
                    const racedRecord = await readIntentLockRecord({
                        binding,
                        protection,
                        store: input.store,
                    });
                    if (racedRecord === undefined) {
                        throw mapped;
                    }
                    let replayedRecord: OpenedIntentLockRecord | undefined;
                    try {
                        replayedRecord = nextIntentLockRecord(
                            binding,
                            racedRecord.record,
                        );
                        if (
                            !intentLockRecordsEqual(
                                racedRecord.record,
                                replayedRecord,
                            )
                        ) {
                            throw mapped;
                        }
                    } finally {
                        if (replayedRecord !== undefined) {
                            destroyOpenedIntentLockRecord(replayedRecord);
                        }
                        destroyOpenedIntentLockRecord(racedRecord.record);
                        racedRecord.sealedBytes.fill(0);
                    }
                }
            } finally {
                plaintext?.fill(0);
                if (nextRecord !== undefined) {
                    destroyOpenedIntentLockRecord(nextRecord);
                }
                if (openedCurrentRecord !== undefined) {
                    destroyOpenedIntentLockRecord(openedCurrentRecord.record);
                    openedCurrentRecord.sealedBytes.fill(0);
                }
            }
        };

    const cacheSignedVoteCarrier: DurableStateWitnessService['cacheSignedVoteCarrier'] =
        async ({ canonicalSignedVoteCarrier, verifiedIntentBinding }) => {
            const binding = copyVerifiedBinding(
                verifiedIntentBinding,
                authorityContext,
            );
            const candidateCarrier = copyBoundedBytes(
                canonicalSignedVoteCarrier,
                limits.maximumSignedVoteCarrierByteLength,
                'canonicalSignedVoteCarrier',
            );
            let existingCarrier = await readSignedVoteCarrierRecord({
                binding,
                limits,
                protection,
                store: input.store,
            });
            if (existingCarrier !== undefined) {
                try {
                    requireSignedVoteCarrierMatchesBinding(
                        existingCarrier,
                        binding,
                    );
                    return existingCarrier.canonicalSignedVoteCarrier.slice();
                } finally {
                    candidateCarrier.fill(0);
                    destroyOpenedSignedVoteCarrierRecord(existingCarrier);
                }
            }

            const openedLockRecord = await readIntentLockRecord({
                binding,
                protection,
                store: input.store,
            });
            if (openedLockRecord === undefined) {
                candidateCarrier.fill(0);
                throw new AuthenticatedRuntimeRecordError(
                    'Conflict',
                    'A signed vote carrier cannot be cached before its intent is durably locked.',
                );
            }
            let carrierPlaintext: Uint8Array | undefined;
            let lockPlaintext: Uint8Array | undefined;
            try {
                requireIntentIsLocked(openedLockRecord.record, binding);
                carrierPlaintext = encodeSignedVoteCarrierRecord(
                    binding,
                    candidateCarrier,
                );
                lockPlaintext = encodeIntentLockRecord(openedLockRecord.record);
                const transaction = await beginDurableStateTransaction({
                    lifetimeMilliseconds:
                        limits.transactionLifetimeMilliseconds,
                    store: input.store,
                });
                try {
                    await stageRuntimeRecordWrite({
                        expectedCurrentSealedBytes:
                            openedLockRecord.sealedBytes,
                        logicalRecordKey: intentLockRecordKey(binding),
                        operationDomain: intentLockRecordOperationDomain,
                        plaintext: lockPlaintext,
                        protection,
                        transaction,
                    });
                    await stageRuntimeRecordWrite({
                        expectedCurrentSealedBytes: null,
                        logicalRecordKey: signedVoteCarrierRecordKey(binding),
                        operationDomain: signedVoteCarrierRecordOperationDomain,
                        plaintext: carrierPlaintext,
                        protection,
                        transaction,
                    });
                    await transaction.commit();
                    return candidateCarrier.slice();
                } catch (error) {
                    const mapped = await closeTransactionAfterFailure(
                        transaction,
                        error,
                    );
                    if (mapped.code !== 'Conflict') {
                        throw mapped;
                    }
                    existingCarrier = await readSignedVoteCarrierRecord({
                        binding,
                        limits,
                        protection,
                        store: input.store,
                    });
                    if (existingCarrier === undefined) {
                        throw mapped;
                    }
                    requireSignedVoteCarrierMatchesBinding(
                        existingCarrier,
                        binding,
                    );
                    return existingCarrier.canonicalSignedVoteCarrier.slice();
                }
            } finally {
                candidateCarrier.fill(0);
                carrierPlaintext?.fill(0);
                lockPlaintext?.fill(0);
                destroyOpenedIntentLockRecord(openedLockRecord.record);
                openedLockRecord.sealedBytes.fill(0);
                if (existingCarrier !== undefined) {
                    destroyOpenedSignedVoteCarrierRecord(existingCarrier);
                }
            }
        };

    const cacheExactOutput: DurableStateWitnessService['cacheExactOutput'] =
        async ({ exactOutputBytes, verifiedOutputBinding }) => {
            const binding = copyVerifiedBinding(
                verifiedOutputBinding,
                authorityContext,
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
                    logicalRecordKey,
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
                authorityContext,
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

    const readSignedVoteCarrier: DurableStateWitnessService['readSignedVoteCarrier'] =
        async ({ verifiedIntentBinding }) => {
            const binding = copyVerifiedBinding(
                verifiedIntentBinding,
                authorityContext,
            );
            const record = await readSignedVoteCarrierRecord({
                binding,
                limits,
                protection,
                store: input.store,
            });
            if (record === undefined) {
                throw new AuthenticatedRuntimeRecordError(
                    'MissingRecord',
                    'The signed vote carrier is unavailable.',
                );
            }
            try {
                requireSignedVoteCarrierMatchesBinding(record, binding);
                return record.canonicalSignedVoteCarrier.slice();
            } finally {
                destroyOpenedSignedVoteCarrierRecord(record);
            }
        };

    const persistCommonProofApplication: PersistCommonProofApplicationOperation =
        async ({
            authorizationFrame,
            onCommitAttempt,
            proofApplicationSlotHash,
        }) => {
            if (typeof onCommitAttempt !== 'function') {
                throw new AuthenticatedRuntimeRecordError(
                    'InvalidInput',
                    'Common-proof persistence requires a commit-attempt boundary callback.',
                );
            }
            const copiedAuthorizationFrame = copyBoundedBytes(
                authorizationFrame,
                maximumCommonProofAuthorizationFrameByteLength,
                'Common-proof authorization frame',
            );
            const copiedApplicationSlotHash = copyBoundedBytes(
                proofApplicationSlotHash,
                proofApplicationSlotHashByteLength,
                'Common-proof application slot hash',
            );
            if (
                copiedApplicationSlotHash.byteLength !==
                proofApplicationSlotHashByteLength
            ) {
                copiedAuthorizationFrame.fill(0);
                copiedApplicationSlotHash.fill(0);
                throw new AuthenticatedRuntimeRecordError(
                    'InvalidInput',
                    'Common-proof application slot hash must be exactly 64 bytes.',
                );
            }

            const logicalRecordKey = commonProofApplicationRecordKey(
                copiedApplicationSlotHash,
            );
            let transaction: UntrustedStorageTransaction | undefined;
            let stagedSealedBytes: Uint8Array | undefined;
            try {
                const existing = await readRuntimeRecord({
                    logicalRecordKey,
                    operationDomain:
                        commonProofApplicationRecordOperationDomain,
                    protection,
                    store: input.store,
                });
                if (existing !== undefined) {
                    existing.plaintext.fill(0);
                    existing.sealedBytes.fill(0);
                    throw new AuthenticatedRuntimeRecordError(
                        'Conflict',
                        'The common-proof application slot is already occupied.',
                    );
                }

                transaction = await beginDurableStateTransaction({
                    lifetimeMilliseconds:
                        limits.transactionLifetimeMilliseconds,
                    store: input.store,
                });
                try {
                    stagedSealedBytes = await stageRuntimeRecordWrite({
                        expectedCurrentSealedBytes: null,
                        logicalRecordKey,
                        operationDomain:
                            commonProofApplicationRecordOperationDomain,
                        plaintext: copiedAuthorizationFrame,
                        protection,
                        transaction,
                    });
                } catch (error) {
                    throw await closeTransactionAfterFailure(
                        transaction,
                        error,
                    );
                }

                try {
                    onCommitAttempt();
                } catch (error) {
                    throw await closeTransactionAfterFailure(
                        transaction,
                        error,
                    );
                }
                try {
                    await transaction.commit();
                } catch (error) {
                    throw await closeTransactionAfterFailure(
                        transaction,
                        error,
                    );
                }

                const committed = await readRuntimeRecord({
                    logicalRecordKey,
                    operationDomain:
                        commonProofApplicationRecordOperationDomain,
                    protection,
                    store: input.store,
                });
                if (committed === undefined) {
                    throw new AuthenticatedRuntimeRecordError(
                        'MissingRecord',
                        'The committed common-proof application frame is unavailable.',
                    );
                }
                try {
                    if (
                        !bytesEqual(
                            committed.plaintext,
                            copiedAuthorizationFrame,
                        )
                    ) {
                        throw new AuthenticatedRuntimeRecordError(
                            'AuthenticationFailed',
                            'The committed common-proof application frame differs from the verifier-prepared bytes.',
                        );
                    }
                    return committed.plaintext.slice();
                } finally {
                    committed.plaintext.fill(0);
                    committed.sealedBytes.fill(0);
                }
            } finally {
                copiedAuthorizationFrame.fill(0);
                copiedApplicationSlotHash.fill(0);
                stagedSealedBytes?.fill(0);
            }
        };

    const lifecycle = new ExclusiveResourceLifecycle({
        cleanup: async () => {
            authorityContext.actionContextHash.fill(0);
            authorityContext.ceremonyContextHash.fill(0);
            authorityContext.ownerParticipantIdentity.fill(0);
            authorityContext.runtimeBuildManifestHash.fill(0);
            authorityContext.suiteIdentifier.fill(0);
            await releaseRuntimeRecordProtection(protection);
        },
        createInvalidStateError: (message) =>
            new AuthenticatedRuntimeRecordError('InvalidState', message),
    });
    const initialOwner = lifecycle.initialOwner();
    const createOwnedService = (
        owner: ExclusiveResourceOwnerToken,
    ): DurableStateWitnessService => {
        const service: DurableStateWitnessService = Object.freeze({
            cacheExactOutput: (cacheInput) =>
                lifecycle.run(owner, () => cacheExactOutput(cacheInput)),
            cacheSignedVoteCarrier: (cacheInput) =>
                lifecycle.run(owner, () => cacheSignedVoteCarrier(cacheInput)),
            close: () => lifecycle.close(owner),
            compareAndLockIntent: (compareInput) =>
                lifecycle.run(owner, () => compareAndLockIntent(compareInput)),
            copyAuthorityContext: () => {
                lifecycle.assertOpen(owner);
                return copyRuntimeStorageAuthorityContext(authorityContext);
            },
            readExactOutput: (readInput) =>
                lifecycle.run(owner, () => readExactOutput(readInput)),
            readSignedVoteCarrier: (readInput) =>
                lifecycle.run(owner, () => readSignedVoteCarrier(readInput)),
        });
        commonProofApplicationPersistenceOperations.set(
            service,
            (persistInput) =>
                lifecycle.run(owner, () =>
                    persistCommonProofApplication(persistInput),
                ),
        );
        return service;
    };
    const initialService = createOwnedService(initialOwner);
    const transferableService = Object.freeze({
        ...initialService,
        claimExclusiveOwner: () =>
            createOwnedService(lifecycle.claim(initialOwner)),
    });
    commonProofApplicationPersistenceOperations.set(
        transferableService,
        (persistInput) =>
            lifecycle.run(initialOwner, () =>
                persistCommonProofApplication(persistInput),
            ),
    );
    return transferableService;
};

/** Local-key constructor retained only for focused storage tests. */
export const openDurableStateWitnessService = (input: {
    authorityContext: RuntimeStorageAuthorityContext;
    cryptoProvider?: Crypto;
    encryptionKey: CryptoKey;
    limits: DurableStateWitnessServiceLimits;
    store: UntrustedStorageTransactionStore;
}): TransferableDurableStateWitnessService => {
    const limits = validateDurableStateWitnessServiceLimits(input.limits);
    return openDurableStateWitnessServiceWithProtection({
        limits,
        protection: createRuntimeRecordProtection({
            authorityContext: input.authorityContext,
            cryptoProvider: input.cryptoProvider,
            encryptionKey: input.encryptionKey,
            maximumRecordSealingCount: limits.maximumRecordSealingCount,
        }),
        store: input.store,
    });
};

export { AuthenticatedRuntimeRecordError as DurableStateWitnessServiceError };
export type {
    AuthenticatedRuntimeRecordErrorCode as DurableStateWitnessServiceErrorCode,
    RuntimeStorageAuthorityContext,
};
