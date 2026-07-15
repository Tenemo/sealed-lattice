import { shake256 } from '@noble/hashes/sha3.js';
import {
    copyVerifiedStateDurableBinding,
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
    createRuntimeRecordProtection,
    mapStorageError,
    readRuntimeRecord,
    stageRuntimeRecordWrite,
    type RuntimeStorageAuthorityContext,
} from './authenticated-runtime-record.js';
import type {
    UntrustedStorageTransaction,
    UntrustedStorageTransactionStore,
} from './untrusted-storage-transaction-store.js';

const durableStateRecordVersion = 1;
const hashByteLength = 64;
const exactOutputRecordOperationDomain =
    'sealed-lattice/runtime/state-exact-output-record/v1';
const stateExactOutputHashDomain = 'sealed-lattice/state/exact-output/v1';
const exactOutputRecordHeaderByteLength = 204;
const textEncoder = new TextEncoder();

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
}>;

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
        input.limits.transactionLifetimeMilliseconds,
        'transactionLifetimeMilliseconds',
    );
    const limits = Object.freeze({ ...input.limits });
    const protection = createRuntimeRecordProtection({
        authorityContext: input.authorityContext,
        cryptoProvider: input.cryptoProvider,
        encryptionKey: input.encryptionKey,
        maximumRecordSealingCount: limits.maximumRecordSealingCount,
    });

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

    return Object.freeze({ cacheExactOutput, readExactOutput });
};

export { AuthenticatedRuntimeRecordError as DurableStateWitnessServiceError };
export type {
    AuthenticatedRuntimeRecordErrorCode as DurableStateWitnessServiceErrorCode,
    RuntimeStorageAuthorityContext,
};
