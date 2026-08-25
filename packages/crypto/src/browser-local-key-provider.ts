import { hexToBytes } from '@noble/hashes/utils.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import {
    replicatedKeyComponentOpeningMailboxPayloadType,
    type ProtocolHash,
    type RefusalReason,
    type SetupMailboxSlot,
} from '@sealed-lattice/types';

import { webCryptoRandomBytes } from './web-crypto.js';

const textEncoder = new TextEncoder();
const signingSelfTestContext = textEncoder.encode(
    'sealed-lattice/key-provider/signing-self-test/v1',
);
const signingSelfTestMessage = textEncoder.encode(
    'sealed-lattice browser-local signing capability',
);
const mailboxSignatureContext = textEncoder.encode(
    'sealed-lattice/mailbox-signature/v1',
);
const objectSignatureContext = textEncoder.encode(
    'sealed-lattice/object-signature/v1',
);
const signingHedgeByteLength = 32;
const mailboxAttemptIdentifierByteLength = 32;

const mlDsa65PublicKeyByteLength = ml_dsa65.lengths.publicKey!;
const mlDsa65SignatureByteLength = ml_dsa65.lengths.signature!;
const mlKem768PublicKeyByteLength = ml_kem768.lengths.publicKey!;
const mlKem768CiphertextByteLength = ml_kem768.lengths.cipherText!;
const mlKem768EncapsulationCoinByteLength = ml_kem768.lengths.msg!;
const mlKem768SharedSecretByteLength = 32;

declare const signingCapabilityBrand: unique symbol;
declare const mailboxCapabilityBrand: unique symbol;

export type BrowserLocalSigningCapability = Readonly<{
    readonly [signingCapabilityBrand]: true;
}>;

export type BrowserLocalMailboxCapability = Readonly<{
    readonly [mailboxCapabilityBrand]: true;
}>;

type BrowserLocalResetSafeSetupMailboxScope = Readonly<
    Pick<
        SetupMailboxSlot,
        | 'actionContextHash'
        | 'ceremonyContextHash'
        | 'rosterHash'
        | 'sourceParticipantId'
        | 'suiteId'
    >
>;

/**
 * Internal bridge implemented by the action-randomness runtime. Each method is
 * fixed to one setup-mailbox role; there is deliberately no family, purpose,
 * counter, generic derivation, or caller-selected raw-randomness operation.
 * Encapsulation coins and signature hedges never cross this bridge. The
 * dedicated worker derives each value and immediately consumes it through the
 * exact ML-KEM or ML-DSA operation.
 */
type BrowserLocalResetSafeSetupMailboxRandomnessOperations =
    BrowserLocalResetSafeSetupMailboxScope &
        Readonly<{
            encapsulate(input: {
                readonly recipientEncapsulationKey: Uint8Array;
                readonly setupMailboxSlot: SetupMailboxSlot;
                readonly setupMailboxSlotHash: ProtocolHash;
            }): Readonly<{
                readonly ciphertext: Uint8Array;
                readonly envelopeAttemptIdentifier: Uint8Array;
                readonly sharedSecret: Uint8Array;
            }>;
            signEnvelope(input: {
                readonly envelopeHash: ProtocolHash;
                readonly setupMailboxSlot: SetupMailboxSlot;
                readonly setupMailboxSlotHash: ProtocolHash;
            }): Uint8Array;
            signSetupObject?(input: {
                readonly signatureMessageHash: ProtocolHash;
            }): Uint8Array;
            revoke(): void;
        }>;

export type BrowserLocalKeyProviderFailureCode =
    | 'CapabilityUnavailable'
    | 'EntropyUnavailable'
    | 'Equivocation'
    | 'KeyMismatch'
    | 'MalformedKey'
    | 'MalformedRandomness'
    | 'UnsupportedProvider';

export class BrowserLocalKeyProviderError extends Error {
    public readonly code: BrowserLocalKeyProviderFailureCode;
    public readonly failureCause: unknown;

    public constructor(
        code: BrowserLocalKeyProviderFailureCode,
        message: string,
        failureCause?: unknown,
    ) {
        super(message);
        this.name = 'BrowserLocalKeyProviderError';
        this.code = code;
        this.failureCause = failureCause;
    }

    public get refusalReason(): RefusalReason | undefined {
        return this.code === 'Equivocation' ? 'equivocation' : undefined;
    }
}

export type BrowserLocalExternalKeyProvider = Readonly<{
    signingCapability: BrowserLocalSigningCapability;
    mailboxCapability: BrowserLocalMailboxCapability;
    revokeSigningCapability(): void;
    revokeMailboxCapability(): void;
    close(): void;
}>;

type BrowserLocalSigningOperations = Readonly<{
    readonly verificationKey: Uint8Array;
    signClosedMessage(input: {
        readonly message: Uint8Array;
        readonly context: Uint8Array;
        readonly hedge: Uint8Array;
    }): Uint8Array;
    revoke(): void;
}>;

type BrowserLocalMailboxOperations = Readonly<{
    readonly encapsulationKey: Uint8Array;
    decapsulateClosedCiphertext(ciphertext: Uint8Array): Uint8Array;
    revoke(): void;
}>;

export type BrowserLocalExternalKeyProviderInput = Readonly<{
    signing: BrowserLocalSigningOperations;
    mailbox: BrowserLocalMailboxOperations;
    /** Omission keeps ordinary key operations available but makes setup-mailbox sealing fail closed. */
    resetSafeSetupMailboxRandomness?: BrowserLocalResetSafeSetupMailboxRandomnessOperations;
}>;

type ResetSafeSetupMailboxCacheEntry = {
    readonly ciphertext: Uint8Array;
    readonly envelopeAttemptIdentifier: Uint8Array;
    readonly recipientEncapsulationKey: Uint8Array;
    readonly setupMailboxSlotHash: ProtocolHash;
    readonly sharedSecret: Uint8Array;
    envelopeHash: ProtocolHash | undefined;
    signature: Uint8Array | undefined;
};

type ProviderState = {
    signingOperations: BrowserLocalSigningOperations | undefined;
    signingVerificationKey: Uint8Array | undefined;
    mailboxOperations: BrowserLocalMailboxOperations | undefined;
    mailboxEncapsulationKey: Uint8Array | undefined;
    mailboxSelfTestCiphertext: Uint8Array | undefined;
    mailboxSelfTestSharedSecret: Uint8Array | undefined;
    resetSafeSetupMailboxCache: Map<string, ResetSafeSetupMailboxCacheEntry>;
    resetSafeSetupMailboxRandomnessOperations:
        | BrowserLocalResetSafeSetupMailboxRandomnessOperations
        | undefined;
    resetSafeSetupMailboxScope:
        | BrowserLocalResetSafeSetupMailboxScope
        | undefined;
};

type SigningCapabilityState = Readonly<{ provider: ProviderState }>;
type MailboxCapabilityState = Readonly<{ provider: ProviderState }>;

const signingCapabilityStates = new WeakMap<object, SigningCapabilityState>();
const mailboxCapabilityStates = new WeakMap<object, MailboxCapabilityState>();
const copyExactBytes = (
    value: Uint8Array,
    expectedByteLength: number,
    label: string,
    failureCode: BrowserLocalKeyProviderFailureCode = 'MalformedKey',
): Uint8Array => {
    if (!(value instanceof Uint8Array)) {
        throw new BrowserLocalKeyProviderError(
            failureCode,
            `${label} must be a Uint8Array.`,
        );
    }
    if (value.byteLength !== expectedByteLength) {
        throw new BrowserLocalKeyProviderError(
            failureCode,
            `${label} must contain exactly ${String(expectedByteLength)} bytes.`,
        );
    }

    return value.slice();
};

const readProductionEntropy = (byteLength: number): Uint8Array =>
    webCryptoRandomBytes(
        byteLength,
        'Browser-local key operations require Web Crypto getRandomValues.',
    );

const readEntropy = (byteLength: number): Uint8Array => {
    let bytes: Uint8Array;
    try {
        bytes = readProductionEntropy(byteLength);
    } catch (error) {
        throw new BrowserLocalKeyProviderError(
            'EntropyUnavailable',
            'Browser-local key-provider entropy failed.',
            error,
        );
    }
    if (!(bytes instanceof Uint8Array) || bytes.byteLength !== byteLength) {
        throw new BrowserLocalKeyProviderError(
            'EntropyUnavailable',
            `Browser-local key-provider entropy must return exactly ${String(byteLength)} bytes.`,
        );
    }

    return bytes.slice();
};

const wipe = (bytes: unknown): void => {
    if (bytes instanceof Uint8Array) {
        bytes.fill(0);
    }
};

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

const requireLowercaseHex = (
    value: unknown,
    byteLength: number,
    label: string,
    failureCode: BrowserLocalKeyProviderFailureCode = 'MalformedRandomness',
): string => {
    if (
        typeof value !== 'string' ||
        value.length !== byteLength * 2 ||
        !/^[0-9a-f]+$/u.test(value)
    ) {
        throw new BrowserLocalKeyProviderError(
            failureCode,
            `${label} must be exactly ${String(byteLength)} bytes of lowercase hexadecimal.`,
        );
    }

    return value;
};

const maximumUnsigned64 = 18_446_744_073_709_551_615n;
const canonicalUnsignedDecimalPattern = /^(?:0|[1-9][0-9]*)$/u;

const requireCanonicalUnsigned64 = (value: string, label: string): string => {
    if (
        typeof value !== 'string' ||
        !canonicalUnsignedDecimalPattern.test(value) ||
        value.length > 20 ||
        BigInt(value) > maximumUnsigned64
    ) {
        throw new BrowserLocalKeyProviderError(
            'MalformedRandomness',
            `${label} must be a canonical unsigned 64-bit decimal string.`,
        );
    }

    return value;
};

const copySetupMailboxSlot = (value: SetupMailboxSlot): SetupMailboxSlot => {
    if (typeof value !== 'object' || value === null) {
        throw new BrowserLocalKeyProviderError(
            'MalformedRandomness',
            'The setup-mailbox slot must be an object.',
        );
    }
    const orderedMaterialRoots = value.orderedMaterialRoots;
    if (!Array.isArray(orderedMaterialRoots)) {
        throw new BrowserLocalKeyProviderError(
            'MalformedRandomness',
            'The setup-mailbox material roots must be an array.',
        );
    }
    const payloadType = (value as Readonly<{ payloadType?: unknown }>)
        .payloadType;
    if (payloadType !== replicatedKeyComponentOpeningMailboxPayloadType) {
        throw new BrowserLocalKeyProviderError(
            'MalformedRandomness',
            'The setup-mailbox payload type must be a replicated-key component opening.',
        );
    }
    if (orderedMaterialRoots.length === 0) {
        throw new BrowserLocalKeyProviderError(
            'MalformedRandomness',
            'The setup-mailbox material roots must not be empty.',
        );
    }

    return Object.freeze({
        suiteId: requireLowercaseHex(value.suiteId, 64, 'slot.suiteId'),
        ceremonyContextHash: requireLowercaseHex(
            value.ceremonyContextHash,
            64,
            'slot.ceremonyContextHash',
        ),
        actionContextHash: requireLowercaseHex(
            value.actionContextHash,
            64,
            'slot.actionContextHash',
        ),
        rosterHash: requireLowercaseHex(
            value.rosterHash,
            64,
            'slot.rosterHash',
        ),
        sourceParticipantId: requireLowercaseHex(
            value.sourceParticipantId,
            64,
            'slot.sourceParticipantId',
        ),
        recipientParticipantId: requireLowercaseHex(
            value.recipientParticipantId,
            64,
            'slot.recipientParticipantId',
        ),
        producerSequence: requireCanonicalUnsigned64(
            value.producerSequence,
            'slot.producerSequence',
        ),
        payloadType,
        statementHash: requireLowercaseHex(
            value.statementHash,
            64,
            'slot.statementHash',
        ),
        orderedMaterialRoots: Object.freeze(
            orderedMaterialRoots.map((root, rootIndex) =>
                requireLowercaseHex(
                    root,
                    64,
                    `slot.orderedMaterialRoots[${String(rootIndex)}]`,
                ),
            ),
        ),
    });
};

const copyResetSafeSetupMailboxScope = (
    value: BrowserLocalResetSafeSetupMailboxScope,
): BrowserLocalResetSafeSetupMailboxScope =>
    Object.freeze({
        suiteId: requireLowercaseHex(value.suiteId, 64, 'scope.suiteId'),
        ceremonyContextHash: requireLowercaseHex(
            value.ceremonyContextHash,
            64,
            'scope.ceremonyContextHash',
        ),
        actionContextHash: requireLowercaseHex(
            value.actionContextHash,
            64,
            'scope.actionContextHash',
        ),
        rosterHash: requireLowercaseHex(
            value.rosterHash,
            64,
            'scope.rosterHash',
        ),
        sourceParticipantId: requireLowercaseHex(
            value.sourceParticipantId,
            64,
            'scope.sourceParticipantId',
        ),
    });

const setupMailboxScopeMatches = (
    scope: BrowserLocalResetSafeSetupMailboxScope,
    slot: SetupMailboxSlot,
): boolean =>
    scope.suiteId === slot.suiteId &&
    scope.ceremonyContextHash === slot.ceremonyContextHash &&
    scope.actionContextHash === slot.actionContextHash &&
    scope.rosterHash === slot.rosterHash &&
    scope.sourceParticipantId === slot.sourceParticipantId;

const setupMailboxProducerSlotKey = (slot: SetupMailboxSlot): string =>
    [
        slot.suiteId,
        slot.ceremonyContextHash,
        slot.actionContextHash,
        slot.rosterHash,
        slot.sourceParticipantId,
        slot.recipientParticipantId,
        slot.producerSequence,
        String(slot.payloadType),
    ].join(':');

const wipeResetSafeSetupMailboxEntry = (
    entry: ResetSafeSetupMailboxCacheEntry,
): void => {
    entry.ciphertext.fill(0);
    entry.envelopeAttemptIdentifier.fill(0);
    entry.recipientEncapsulationKey.fill(0);
    entry.sharedSecret.fill(0);
    entry.signature?.fill(0);
    entry.envelopeHash = undefined;
    entry.signature = undefined;
};

const throwRevocationFailures = (
    operation: string,
    failures: readonly unknown[],
): void => {
    if (failures.length !== 0) {
        throw new BrowserLocalKeyProviderError(
            'CapabilityUnavailable',
            `${operation} invalidated every local capability, but one or more external provider handles could not be released.`,
            Object.freeze([...failures]),
        );
    }
};

const attemptRevocation = (
    revoke: (() => void) | undefined,
    failures: unknown[],
): void => {
    try {
        revoke?.();
    } catch (error) {
        failures.push(error);
    }
};

const clearResetSafeSetupMailbox = (
    provider: ProviderState,
): BrowserLocalResetSafeSetupMailboxRandomnessOperations | undefined => {
    const randomnessOperations =
        provider.resetSafeSetupMailboxRandomnessOperations;
    for (const entry of provider.resetSafeSetupMailboxCache.values()) {
        wipeResetSafeSetupMailboxEntry(entry);
    }
    provider.resetSafeSetupMailboxCache.clear();
    provider.resetSafeSetupMailboxRandomnessOperations = undefined;
    provider.resetSafeSetupMailboxScope = undefined;
    return randomnessOperations;
};

const revokeSigning = (provider: ProviderState): void => {
    const failures: unknown[] = [];
    const signingOperations = provider.signingOperations;
    const randomnessOperations = clearResetSafeSetupMailbox(provider);
    wipe(provider.signingVerificationKey);
    provider.signingOperations = undefined;
    provider.signingVerificationKey = undefined;
    attemptRevocation(
        randomnessOperations === undefined
            ? undefined
            : () => randomnessOperations.revoke(),
        failures,
    );
    attemptRevocation(
        signingOperations === undefined
            ? undefined
            : () => signingOperations.revoke(),
        failures,
    );
    throwRevocationFailures('Signing capability revocation', failures);
};

const requireResetSafeSetupMailboxProvider = (
    capability: BrowserLocalSigningCapability,
): ProviderState => {
    const provider = requireSigningProvider(capability);
    if (
        provider.resetSafeSetupMailboxRandomnessOperations === undefined ||
        provider.resetSafeSetupMailboxScope === undefined
    ) {
        throw new BrowserLocalKeyProviderError(
            'UnsupportedProvider',
            'The browser-local provider does not support reset-safe setup-mailbox randomness.',
        );
    }

    return provider;
};

const revokeMailbox = (provider: ProviderState): void => {
    const failures: unknown[] = [];
    const mailboxOperations = provider.mailboxOperations;
    wipe(provider.mailboxEncapsulationKey);
    wipe(provider.mailboxSelfTestCiphertext);
    wipe(provider.mailboxSelfTestSharedSecret);
    provider.mailboxOperations = undefined;
    provider.mailboxEncapsulationKey = undefined;
    provider.mailboxSelfTestCiphertext = undefined;
    provider.mailboxSelfTestSharedSecret = undefined;
    attemptRevocation(
        mailboxOperations === undefined
            ? undefined
            : () => mailboxOperations.revoke(),
        failures,
    );
    throwRevocationFailures('Mailbox capability revocation', failures);
};

const closeProvider = (provider: ProviderState): void => {
    const failures: unknown[] = [];
    try {
        revokeSigning(provider);
    } catch (error) {
        failures.push(error);
    }
    try {
        revokeMailbox(provider);
    } catch (error) {
        failures.push(error);
    }
    throwRevocationFailures('Browser-local provider closure', failures);
};

const throwOpenFailure = (
    operationFailure: unknown,
    cleanupFailure: unknown,
): never => {
    if (cleanupFailure !== undefined) {
        throw new BrowserLocalKeyProviderError(
            'CapabilityUnavailable',
            'The browser-local provider failed to open and could not release every external provider handle.',
            Object.freeze([operationFailure, cleanupFailure]),
        );
    }
    throw operationFailure;
};

const revokeUnopenedInput = (
    input: BrowserLocalExternalKeyProviderInput,
): void => {
    const failures: unknown[] = [];
    const randomnessOperations = input.resetSafeSetupMailboxRandomness;
    const keyOperationsAreReused = input.signing === (input.mailbox as unknown);
    attemptRevocation(
        randomnessOperations === undefined
            ? undefined
            : () => randomnessOperations.revoke(),
        failures,
    );
    attemptRevocation(() => input.signing.revoke(), failures);
    if (!keyOperationsAreReused) {
        attemptRevocation(() => input.mailbox.revoke(), failures);
    }
    throwRevocationFailures('Failed provider input cleanup', failures);
};

const requireSigningProvider = (
    capability: BrowserLocalSigningCapability,
): ProviderState => {
    const capabilityState = signingCapabilityStates.get(capability);
    if (
        capabilityState === undefined ||
        capabilityState.provider.signingOperations === undefined ||
        capabilityState.provider.signingVerificationKey === undefined
    ) {
        throw new BrowserLocalKeyProviderError(
            'CapabilityUnavailable',
            'The browser-local signing capability is unavailable or revoked.',
        );
    }

    return capabilityState.provider;
};

const requireMailboxProvider = (
    capability: BrowserLocalMailboxCapability,
): ProviderState => {
    const capabilityState = mailboxCapabilityStates.get(capability);
    if (
        capabilityState === undefined ||
        capabilityState.provider.mailboxOperations === undefined ||
        capabilityState.provider.mailboxEncapsulationKey === undefined
    ) {
        throw new BrowserLocalKeyProviderError(
            'CapabilityUnavailable',
            'The browser-local mailbox capability is unavailable or revoked.',
        );
    }

    return capabilityState.provider;
};

const invokeSigningOperation = (
    provider: ProviderState,
    message: Uint8Array,
    context: Uint8Array,
    hedge: Uint8Array,
): Uint8Array => {
    const signingOperations = provider.signingOperations;
    if (signingOperations === undefined) {
        throw new BrowserLocalKeyProviderError(
            'CapabilityUnavailable',
            'The browser-local signing operation is unavailable or revoked.',
        );
    }
    const copiedMessage = message.slice();
    const copiedContext = context.slice();
    const copiedHedge = hedge.slice();
    let operationResult: Uint8Array | undefined;
    try {
        operationResult = signingOperations.signClosedMessage({
            message: copiedMessage,
            context: copiedContext,
            hedge: copiedHedge,
        });
        return copyExactBytes(
            operationResult,
            mlDsa65SignatureByteLength,
            'signing operation result',
            'UnsupportedProvider',
        );
    } catch (error) {
        if (error instanceof BrowserLocalKeyProviderError) {
            throw error;
        }
        throw new BrowserLocalKeyProviderError(
            'CapabilityUnavailable',
            'The browser-local signing operation failed.',
            error,
        );
    } finally {
        copiedMessage.fill(0);
        copiedContext.fill(0);
        copiedHedge.fill(0);
        wipe(operationResult);
    }
};

const invokeMailboxDecapsulationOperation = (
    provider: ProviderState,
    ciphertext: Uint8Array,
): Uint8Array => {
    const mailboxOperations = provider.mailboxOperations;
    if (mailboxOperations === undefined) {
        throw new BrowserLocalKeyProviderError(
            'CapabilityUnavailable',
            'The browser-local mailbox decapsulation operation is unavailable or revoked.',
        );
    }
    const copiedCiphertext = ciphertext.slice();
    let operationResult: Uint8Array | undefined;
    try {
        operationResult =
            mailboxOperations.decapsulateClosedCiphertext(copiedCiphertext);
        return copyExactBytes(
            operationResult,
            mlKem768SharedSecretByteLength,
            'mailbox decapsulation result',
            'UnsupportedProvider',
        );
    } catch (error) {
        if (error instanceof BrowserLocalKeyProviderError) {
            throw error;
        }
        throw new BrowserLocalKeyProviderError(
            'CapabilityUnavailable',
            'The browser-local mailbox decapsulation operation failed.',
            error,
        );
    } finally {
        copiedCiphertext.fill(0);
        wipe(operationResult);
    }
};

const validateSigningKeyPair = (provider: ProviderState): void => {
    const verificationKey = provider.signingVerificationKey!;
    const hedge = readEntropy(signingHedgeByteLength);
    const alternateHedge = hedge.slice();
    alternateHedge[alternateHedge.byteLength - 1] ^= 1;
    let firstSignature: Uint8Array | undefined;
    let secondSignature: Uint8Array | undefined;
    let alternateSignature: Uint8Array | undefined;
    try {
        firstSignature = invokeSigningOperation(
            provider,
            signingSelfTestMessage,
            signingSelfTestContext,
            hedge,
        );
        secondSignature = invokeSigningOperation(
            provider,
            signingSelfTestMessage,
            signingSelfTestContext,
            hedge,
        );
        alternateSignature = invokeSigningOperation(
            provider,
            signingSelfTestMessage,
            signingSelfTestContext,
            alternateHedge,
        );
        let signaturesAreValid: boolean;
        try {
            signaturesAreValid =
                ml_dsa65.verify(
                    firstSignature,
                    signingSelfTestMessage,
                    verificationKey,
                    { context: signingSelfTestContext },
                ) &&
                ml_dsa65.verify(
                    secondSignature,
                    signingSelfTestMessage,
                    verificationKey,
                    { context: signingSelfTestContext },
                ) &&
                ml_dsa65.verify(
                    alternateSignature,
                    signingSelfTestMessage,
                    verificationKey,
                    { context: signingSelfTestContext },
                );
        } catch (error) {
            throw new BrowserLocalKeyProviderError(
                'MalformedKey',
                'The frozen roster verification key is not canonical ML-DSA-65.',
                error,
            );
        }
        if (!signaturesAreValid) {
            throw new BrowserLocalKeyProviderError(
                'KeyMismatch',
                'The browser-local signing operation does not match the frozen roster verification key.',
            );
        }
        if (
            !bytesEqual(firstSignature, secondSignature) ||
            bytesEqual(firstSignature, alternateSignature)
        ) {
            throw new BrowserLocalKeyProviderError(
                'UnsupportedProvider',
                'The browser-local signing operation does not honor an exact ML-DSA hedge.',
            );
        }
    } finally {
        hedge.fill(0);
        alternateHedge.fill(0);
        firstSignature?.fill(0);
        secondSignature?.fill(0);
        alternateSignature?.fill(0);
    }
};

const validateMailboxKeyPair = (provider: ProviderState): void => {
    const encapsulationKey = provider.mailboxEncapsulationKey!;
    const encapsulationCoins = readEntropy(mlKem768EncapsulationCoinByteLength);
    let encapsulation: ReturnType<typeof ml_kem768.encapsulate> | undefined;
    let recoveredSharedSecret: Uint8Array | undefined;
    try {
        try {
            encapsulation = ml_kem768.encapsulate(
                encapsulationKey,
                encapsulationCoins,
            );
        } catch (error) {
            throw new BrowserLocalKeyProviderError(
                'MalformedKey',
                'The frozen roster encapsulation key is not canonical ML-KEM-768.',
                error,
            );
        }
        recoveredSharedSecret = invokeMailboxDecapsulationOperation(
            provider,
            encapsulation.cipherText,
        );
        if (!bytesEqual(encapsulation.sharedSecret, recoveredSharedSecret)) {
            throw new BrowserLocalKeyProviderError(
                'KeyMismatch',
                'The browser-local mailbox operation does not match the frozen roster encapsulation key.',
            );
        }
        provider.mailboxSelfTestCiphertext = encapsulation.cipherText.slice();
        provider.mailboxSelfTestSharedSecret =
            encapsulation.sharedSecret.slice();
    } finally {
        encapsulationCoins.fill(0);
        encapsulation?.cipherText.fill(0);
        encapsulation?.sharedSecret.fill(0);
        recoveredSharedSecret?.fill(0);
    }
};

const validateMailboxKeyContinuity = (provider: ProviderState): void => {
    const ciphertext = provider.mailboxSelfTestCiphertext;
    const expectedSharedSecret = provider.mailboxSelfTestSharedSecret;
    if (ciphertext === undefined || expectedSharedSecret === undefined) {
        throw new BrowserLocalKeyProviderError(
            'CapabilityUnavailable',
            'The browser-local mailbox pairwise-test material is unavailable.',
        );
    }

    let recoveredSharedSecret: Uint8Array | undefined;
    try {
        recoveredSharedSecret = invokeMailboxDecapsulationOperation(
            provider,
            ciphertext,
        );
        if (!bytesEqual(expectedSharedSecret, recoveredSharedSecret)) {
            throw new BrowserLocalKeyProviderError(
                'KeyMismatch',
                'The browser-local mailbox operation no longer matches its frozen roster encapsulation key.',
            );
        }
    } finally {
        recoveredSharedSecret?.fill(0);
    }
};

export const openBrowserLocalExternalKeyProvider = (
    input: BrowserLocalExternalKeyProviderInput,
): BrowserLocalExternalKeyProvider => {
    const resetSafeSetupMailboxRandomnessOperations =
        input.resetSafeSetupMailboxRandomness;
    let signingVerificationKey: Uint8Array | undefined;
    let mailboxEncapsulationKey: Uint8Array | undefined;
    let resetSafeSetupMailboxScope:
        | BrowserLocalResetSafeSetupMailboxScope
        | undefined;
    try {
        if (input.signing === (input.mailbox as unknown)) {
            throw new BrowserLocalKeyProviderError(
                'UnsupportedProvider',
                'Signing and mailbox operations must use distinct browser-local capabilities.',
            );
        }
        signingVerificationKey = copyExactBytes(
            input.signing.verificationKey,
            mlDsa65PublicKeyByteLength,
            'signing.verificationKey',
        );
        mailboxEncapsulationKey = copyExactBytes(
            input.mailbox.encapsulationKey,
            mlKem768PublicKeyByteLength,
            'mailbox.encapsulationKey',
        );
        resetSafeSetupMailboxScope =
            resetSafeSetupMailboxRandomnessOperations === undefined
                ? undefined
                : copyResetSafeSetupMailboxScope(
                      resetSafeSetupMailboxRandomnessOperations,
                  );
    } catch (error) {
        signingVerificationKey?.fill(0);
        mailboxEncapsulationKey?.fill(0);
        let cleanupFailure: unknown;
        try {
            revokeUnopenedInput(input);
        } catch (cleanupError) {
            cleanupFailure = cleanupError;
        }
        throwOpenFailure(error, cleanupFailure);
    }
    const provider: ProviderState = {
        signingOperations: input.signing,
        signingVerificationKey,
        mailboxOperations: input.mailbox,
        mailboxEncapsulationKey,
        mailboxSelfTestCiphertext: undefined,
        mailboxSelfTestSharedSecret: undefined,
        resetSafeSetupMailboxCache: new Map(),
        resetSafeSetupMailboxRandomnessOperations,
        resetSafeSetupMailboxScope,
    };

    try {
        validateSigningKeyPair(provider);
        validateMailboxKeyPair(provider);
    } catch (error) {
        let cleanupFailure: unknown;
        try {
            closeProvider(provider);
        } catch (cleanupError) {
            cleanupFailure = cleanupError;
        }
        throwOpenFailure(error, cleanupFailure);
    }

    const signingCapability = Object.freeze(
        {},
    ) as BrowserLocalSigningCapability;
    const mailboxCapability = Object.freeze(
        {},
    ) as BrowserLocalMailboxCapability;
    signingCapabilityStates.set(signingCapability, { provider });
    mailboxCapabilityStates.set(mailboxCapability, { provider });

    return Object.freeze({
        signingCapability,
        mailboxCapability,
        revokeSigningCapability: () => {
            revokeSigning(provider);
        },
        revokeMailboxCapability: () => {
            revokeMailbox(provider);
        },
        close: () => closeProvider(provider),
    });
};

export const decapsulateClosedMailboxCiphertext = (input: {
    capability: BrowserLocalMailboxCapability;
    ciphertext: Uint8Array;
}): Uint8Array => {
    const provider = requireMailboxProvider(input.capability);
    const ciphertext = copyExactBytes(
        input.ciphertext,
        mlKem768CiphertextByteLength,
        'ciphertext',
    );
    try {
        validateMailboxKeyContinuity(provider);
        const sharedSecret = invokeMailboxDecapsulationOperation(
            provider,
            ciphertext,
        );
        try {
            requireMailboxProvider(input.capability);
            return sharedSecret;
        } catch (error) {
            sharedSecret.fill(0);
            throw error;
        }
    } finally {
        ciphertext.fill(0);
    }
};

const resetSafeSetupMailboxInput = (
    provider: ProviderState,
    setupMailboxSlot: SetupMailboxSlot,
    setupMailboxSlotHash: ProtocolHash,
): Readonly<{
    readonly setupMailboxSlot: SetupMailboxSlot;
    readonly setupMailboxSlotHash: ProtocolHash;
}> => {
    const copiedSlot = copySetupMailboxSlot(setupMailboxSlot);
    const copiedSlotHash = requireLowercaseHex(
        setupMailboxSlotHash,
        64,
        'setupMailboxSlotHash',
    );
    const scope = provider.resetSafeSetupMailboxScope;
    if (scope === undefined || !setupMailboxScopeMatches(scope, copiedSlot)) {
        throw new BrowserLocalKeyProviderError(
            'KeyMismatch',
            'The setup-mailbox slot does not match the browser-local provider action and frozen-roster binding.',
        );
    }

    return Object.freeze({
        setupMailboxSlot: copiedSlot,
        setupMailboxSlotHash: copiedSlotHash,
    });
};

const encapsulateWithResetSafeSetupMailboxRandomness = (
    provider: ProviderState,
    input: Readonly<{
        readonly setupMailboxSlot: SetupMailboxSlot;
        readonly setupMailboxSlotHash: ProtocolHash;
    }>,
    recipientEncapsulationKey: Uint8Array,
): Readonly<{
    readonly ciphertext: Uint8Array;
    readonly envelopeAttemptIdentifier: Uint8Array;
    readonly sharedSecret: Uint8Array;
}> => {
    const operations = provider.resetSafeSetupMailboxRandomnessOperations;
    if (operations?.signSetupObject === undefined) {
        throw new BrowserLocalKeyProviderError(
            'UnsupportedProvider',
            'The browser-local provider does not support reset-safe setup-mailbox encapsulation.',
        );
    }
    try {
        const encapsulation = operations.encapsulate({
            ...input,
            recipientEncapsulationKey,
        });
        let ciphertext: Uint8Array | undefined;
        let envelopeAttemptIdentifier: Uint8Array | undefined;
        let sharedSecret: Uint8Array | undefined;
        try {
            ciphertext = copyExactBytes(
                encapsulation.ciphertext,
                mlKem768CiphertextByteLength,
                'reset-safe setup-mailbox ciphertext',
                'MalformedRandomness',
            );
            envelopeAttemptIdentifier = copyExactBytes(
                encapsulation.envelopeAttemptIdentifier,
                mailboxAttemptIdentifierByteLength,
                'reset-safe setup-mailbox envelope attempt identifier',
                'MalformedRandomness',
            );
            sharedSecret = copyExactBytes(
                encapsulation.sharedSecret,
                mlKem768SharedSecretByteLength,
                'reset-safe setup-mailbox shared secret',
                'MalformedRandomness',
            );
            return Object.freeze({
                ciphertext,
                envelopeAttemptIdentifier,
                sharedSecret,
            });
        } catch (error) {
            ciphertext?.fill(0);
            envelopeAttemptIdentifier?.fill(0);
            sharedSecret?.fill(0);
            throw error;
        } finally {
            encapsulation.ciphertext.fill(0);
            encapsulation.envelopeAttemptIdentifier.fill(0);
            encapsulation.sharedSecret.fill(0);
        }
    } catch (error) {
        if (error instanceof BrowserLocalKeyProviderError) {
            throw error;
        }
        if (
            typeof error === 'object' &&
            error !== null &&
            'code' in error &&
            error.code === 'CommitmentMismatch'
        ) {
            throw new BrowserLocalKeyProviderError(
                'KeyMismatch',
                'The setup-mailbox recipient key does not match its frozen-roster slot.',
                error,
            );
        }
        throw new BrowserLocalKeyProviderError(
            'CapabilityUnavailable',
            'The reset-safe setup-mailbox encapsulation input is unavailable.',
            error,
        );
    }
};

export const encapsulateResetSafeSetupMailbox = (input: {
    readonly recipientEncapsulationKey: Uint8Array;
    readonly setupMailboxSlot: SetupMailboxSlot;
    readonly setupMailboxSlotHash: ProtocolHash;
    readonly signingCapability: BrowserLocalSigningCapability;
    readonly sourceVerificationKey: Uint8Array;
}): Readonly<{
    readonly ciphertext: Uint8Array;
    readonly envelopeAttemptIdentifier: Uint8Array;
    readonly sharedSecret: Uint8Array;
}> => {
    const provider = requireResetSafeSetupMailboxProvider(
        input.signingCapability,
    );
    const sourceVerificationKey = copyExactBytes(
        input.sourceVerificationKey,
        mlDsa65PublicKeyByteLength,
        'sourceVerificationKey',
    );
    const recipientEncapsulationKey = copyExactBytes(
        input.recipientEncapsulationKey,
        mlKem768PublicKeyByteLength,
        'recipientEncapsulationKey',
    );
    try {
        if (
            !bytesEqual(sourceVerificationKey, provider.signingVerificationKey!)
        ) {
            throw new BrowserLocalKeyProviderError(
                'KeyMismatch',
                'The source verification key does not match the frozen browser-local signing capability.',
            );
        }
        const resetSafeInput = resetSafeSetupMailboxInput(
            provider,
            input.setupMailboxSlot,
            input.setupMailboxSlotHash,
        );
        const producerSlotKey = setupMailboxProducerSlotKey(
            resetSafeInput.setupMailboxSlot,
        );
        const cached = provider.resetSafeSetupMailboxCache.get(producerSlotKey);
        if (cached !== undefined) {
            if (
                cached.setupMailboxSlotHash !==
                    resetSafeInput.setupMailboxSlotHash ||
                !bytesEqual(
                    cached.recipientEncapsulationKey,
                    recipientEncapsulationKey,
                )
            ) {
                throw new BrowserLocalKeyProviderError(
                    'Equivocation',
                    'The reset-safe setup-mailbox producer slot conflicts with its cached operation.',
                );
            }
            return Object.freeze({
                ciphertext: cached.ciphertext.slice(),
                envelopeAttemptIdentifier:
                    cached.envelopeAttemptIdentifier.slice(),
                sharedSecret: cached.sharedSecret.slice(),
            });
        }

        const encapsulation = encapsulateWithResetSafeSetupMailboxRandomness(
            provider,
            resetSafeInput,
            recipientEncapsulationKey,
        );
        try {
            const entry: ResetSafeSetupMailboxCacheEntry = {
                ciphertext: encapsulation.ciphertext.slice(),
                envelopeHash: undefined,
                envelopeAttemptIdentifier:
                    encapsulation.envelopeAttemptIdentifier.slice(),
                recipientEncapsulationKey: recipientEncapsulationKey.slice(),
                setupMailboxSlotHash: resetSafeInput.setupMailboxSlotHash,
                sharedSecret: encapsulation.sharedSecret.slice(),
                signature: undefined,
            };
            provider.resetSafeSetupMailboxCache.set(producerSlotKey, entry);
            return Object.freeze({
                ciphertext: entry.ciphertext.slice(),
                envelopeAttemptIdentifier:
                    entry.envelopeAttemptIdentifier.slice(),
                sharedSecret: entry.sharedSecret.slice(),
            });
        } finally {
            encapsulation.ciphertext.fill(0);
            encapsulation.envelopeAttemptIdentifier.fill(0);
            encapsulation.sharedSecret.fill(0);
        }
    } finally {
        recipientEncapsulationKey.fill(0);
        sourceVerificationKey.fill(0);
    }
};

const invokeResetSafeSetupMailboxSigningOperation = (
    provider: ProviderState,
    input: Readonly<{
        readonly envelopeHash: ProtocolHash;
        readonly setupMailboxSlot: SetupMailboxSlot;
        readonly setupMailboxSlotHash: ProtocolHash;
    }>,
): Uint8Array => {
    const operations = provider.resetSafeSetupMailboxRandomnessOperations;
    if (operations === undefined) {
        throw new BrowserLocalKeyProviderError(
            'UnsupportedProvider',
            'The browser-local provider does not support reset-safe setup-mailbox signing.',
        );
    }
    let operationResult: Uint8Array | undefined;
    try {
        operationResult = operations.signEnvelope(input);
        return copyExactBytes(
            operationResult,
            mlDsa65SignatureByteLength,
            'reset-safe setup-mailbox signature',
            'UnsupportedProvider',
        );
    } catch (error) {
        if (error instanceof BrowserLocalKeyProviderError) {
            throw error;
        }
        throw new BrowserLocalKeyProviderError(
            'CapabilityUnavailable',
            'The reset-safe setup-mailbox signing operation failed.',
            error,
        );
    } finally {
        wipe(operationResult);
    }
};

export const signResetSafeSetupMailboxEnvelope = (input: {
    readonly envelopeHash: ProtocolHash;
    readonly setupMailboxSlot: SetupMailboxSlot;
    readonly setupMailboxSlotHash: ProtocolHash;
    readonly signingCapability: BrowserLocalSigningCapability;
    readonly sourceVerificationKey: Uint8Array;
}): Uint8Array => {
    const provider = requireResetSafeSetupMailboxProvider(
        input.signingCapability,
    );
    const sourceVerificationKey = copyExactBytes(
        input.sourceVerificationKey,
        mlDsa65PublicKeyByteLength,
        'sourceVerificationKey',
    );
    try {
        if (
            !bytesEqual(sourceVerificationKey, provider.signingVerificationKey!)
        ) {
            throw new BrowserLocalKeyProviderError(
                'KeyMismatch',
                'The source verification key does not match the frozen browser-local signing capability.',
            );
        }
        const resetSafeInput = resetSafeSetupMailboxInput(
            provider,
            input.setupMailboxSlot,
            input.setupMailboxSlotHash,
        );
        const producerSlotKey = setupMailboxProducerSlotKey(
            resetSafeInput.setupMailboxSlot,
        );
        const cached = provider.resetSafeSetupMailboxCache.get(producerSlotKey);
        if (
            cached === undefined ||
            cached.setupMailboxSlotHash !== resetSafeInput.setupMailboxSlotHash
        ) {
            throw new BrowserLocalKeyProviderError(
                'CapabilityUnavailable',
                'The setup-mailbox slot has no matching reset-safe encapsulation.',
            );
        }
        const envelopeHash = requireLowercaseHex(
            input.envelopeHash,
            64,
            'envelopeHash',
        );
        if (
            cached.envelopeHash !== undefined &&
            cached.envelopeHash !== envelopeHash
        ) {
            throw new BrowserLocalKeyProviderError(
                'Equivocation',
                'The reset-safe setup-mailbox producer slot is already bound to another envelope.',
            );
        }
        cached.envelopeHash = envelopeHash;
        if (cached.signature !== undefined) {
            return cached.signature.slice();
        }

        const signature = invokeResetSafeSetupMailboxSigningOperation(
            provider,
            {
                envelopeHash,
                setupMailboxSlot: resetSafeInput.setupMailboxSlot,
                setupMailboxSlotHash: resetSafeInput.setupMailboxSlotHash,
            },
        );
        try {
            requireSigningProvider(input.signingCapability);
            if (
                !ml_dsa65.verify(
                    signature,
                    hexToBytes(envelopeHash),
                    sourceVerificationKey,
                    { context: mailboxSignatureContext },
                )
            ) {
                throw new BrowserLocalKeyProviderError(
                    'KeyMismatch',
                    'The reset-safe setup-mailbox signature does not match the frozen roster verification key.',
                );
            }
            cached.signature = signature.slice();
            return cached.signature.slice();
        } finally {
            signature.fill(0);
        }
    } finally {
        sourceVerificationKey.fill(0);
    }
};

export const signResetSafeSetupObject = (input: {
    readonly signatureMessageHash: ProtocolHash;
    readonly signingCapability: BrowserLocalSigningCapability;
}): Uint8Array => {
    const provider = requireResetSafeSetupMailboxProvider(
        input.signingCapability,
    );
    const operations = provider.resetSafeSetupMailboxRandomnessOperations;
    const signSetupObject = operations?.signSetupObject;
    if (signSetupObject === undefined) {
        throw new BrowserLocalKeyProviderError(
            'UnsupportedProvider',
            'The browser-local provider does not support reset-safe setup-object signing.',
        );
    }
    const signatureMessageHash = requireLowercaseHex(
        input.signatureMessageHash,
        64,
        'signatureMessageHash',
    );
    let operationResult: Uint8Array | undefined;
    let signature: Uint8Array | undefined;
    try {
        operationResult = signSetupObject({
            signatureMessageHash,
        });
        signature = copyExactBytes(
            operationResult,
            mlDsa65SignatureByteLength,
            'reset-safe setup-object signature',
            'UnsupportedProvider',
        );
        requireSigningProvider(input.signingCapability);
        if (
            !ml_dsa65.verify(
                signature,
                hexToBytes(signatureMessageHash),
                provider.signingVerificationKey!,
                { context: objectSignatureContext },
            )
        ) {
            throw new BrowserLocalKeyProviderError(
                'KeyMismatch',
                'The reset-safe setup-object signature does not match the frozen roster verification key.',
            );
        }
        return signature.slice();
    } catch (error) {
        if (error instanceof BrowserLocalKeyProviderError) {
            throw error;
        }
        throw new BrowserLocalKeyProviderError(
            'CapabilityUnavailable',
            'The reset-safe setup-object signing operation failed.',
            error,
        );
    } finally {
        wipe(operationResult);
        wipe(signature);
    }
};
