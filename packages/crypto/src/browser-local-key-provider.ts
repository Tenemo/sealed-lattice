import { hexToBytes } from '@noble/hashes/utils.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import type { ProtocolHash } from '@sealed-lattice/types';

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
declare const freshMailboxSigningPermitBrand: unique symbol;

export type BrowserLocalSigningCapability = Readonly<{
    readonly [signingCapabilityBrand]: true;
}>;

export type BrowserLocalMailboxCapability = Readonly<{
    readonly [mailboxCapabilityBrand]: true;
}>;

type FreshMailboxSigningPermit = Readonly<{
    readonly [freshMailboxSigningPermitBrand]: true;
}>;

export type BrowserLocalKeyProviderFailureCode =
    | 'CapabilityUnavailable'
    | 'EntropyUnavailable'
    | 'KeyMismatch'
    | 'MalformedKey'
    | 'MalformedRandomness';

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
    entropy?: (byteLength: number) => Uint8Array;
}>;

type ProviderState = {
    entropy: (byteLength: number) => Uint8Array;
    signingOperations: BrowserLocalSigningOperations | undefined;
    signingVerificationKey: Uint8Array | undefined;
    mailboxOperations: BrowserLocalMailboxOperations | undefined;
    mailboxEncapsulationKey: Uint8Array | undefined;
};

type SigningCapabilityState = Readonly<{ provider: ProviderState }>;
type MailboxCapabilityState = Readonly<{ provider: ProviderState }>;

type FreshMailboxSigningPermitState = {
    readonly provider: ProviderState;
    consumed: boolean;
};

const signingCapabilityStates = new WeakMap<object, SigningCapabilityState>();
const mailboxCapabilityStates = new WeakMap<object, MailboxCapabilityState>();
const freshMailboxSigningPermitStates = new WeakMap<
    object,
    FreshMailboxSigningPermitState
>();

const copyExactBytes = (
    value: Uint8Array,
    expectedByteLength: number,
    label: string,
): Uint8Array => {
    if (!(value instanceof Uint8Array)) {
        throw new BrowserLocalKeyProviderError(
            'MalformedKey',
            `${label} must be a Uint8Array.`,
        );
    }
    if (value.byteLength !== expectedByteLength) {
        throw new BrowserLocalKeyProviderError(
            'MalformedKey',
            `${label} must contain exactly ${String(expectedByteLength)} bytes.`,
        );
    }

    return value.slice();
};

const defaultEntropy = (byteLength: number): Uint8Array =>
    webCryptoRandomBytes(
        byteLength,
        'Browser-local key operations require Web Crypto getRandomValues.',
    );

const readEntropy = (
    provider: ProviderState,
    byteLength: number,
): Uint8Array => {
    let bytes: Uint8Array;
    try {
        bytes = provider.entropy(byteLength);
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

const wipe = (bytes: Uint8Array | undefined): void => {
    bytes?.fill(0);
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
    value: string,
    byteLength: number,
    label: string,
): string => {
    if (
        typeof value !== 'string' ||
        value.length !== byteLength * 2 ||
        !/^[0-9a-f]+$/u.test(value)
    ) {
        throw new BrowserLocalKeyProviderError(
            'MalformedRandomness',
            `${label} must be exactly ${String(byteLength)} bytes of lowercase hexadecimal.`,
        );
    }

    return value;
};

const revokeSigning = (
    provider: ProviderState,
    revokeExternalOperations = true,
): void => {
    const signingOperations = provider.signingOperations;
    wipe(provider.signingVerificationKey);
    provider.signingOperations = undefined;
    provider.signingVerificationKey = undefined;
    if (revokeExternalOperations) {
        signingOperations?.revoke();
    }
};

const revokeMailbox = (
    provider: ProviderState,
    revokeExternalOperations = true,
): void => {
    const mailboxOperations = provider.mailboxOperations;
    wipe(provider.mailboxEncapsulationKey);
    provider.mailboxOperations = undefined;
    provider.mailboxEncapsulationKey = undefined;
    if (revokeExternalOperations) {
        mailboxOperations?.revoke();
    }
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
    try {
        return copyExactBytes(
            signingOperations.signClosedMessage({
                message: copiedMessage,
                context: copiedContext,
                hedge: copiedHedge,
            }),
            mlDsa65SignatureByteLength,
            'signing operation result',
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
    try {
        return copyExactBytes(
            mailboxOperations.decapsulateClosedCiphertext(copiedCiphertext),
            mlKem768SharedSecretByteLength,
            'mailbox decapsulation result',
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
    }
};

const validateSigningKeyPair = (provider: ProviderState): void => {
    const verificationKey = provider.signingVerificationKey!;
    const hedge = readEntropy(provider, signingHedgeByteLength);
    let signature: Uint8Array | undefined;
    try {
        signature = invokeSigningOperation(
            provider,
            signingSelfTestMessage,
            signingSelfTestContext,
            hedge,
        );
        if (
            !ml_dsa65.verify(
                signature,
                signingSelfTestMessage,
                verificationKey,
                { context: signingSelfTestContext },
            )
        ) {
            throw new BrowserLocalKeyProviderError(
                'KeyMismatch',
                'The browser-local signing operation does not match the frozen roster verification key.',
            );
        }
    } finally {
        hedge.fill(0);
        signature?.fill(0);
    }
};

const validateMailboxKeyPair = (provider: ProviderState): void => {
    const encapsulationKey = provider.mailboxEncapsulationKey!;
    const encapsulationCoins = readEntropy(
        provider,
        mlKem768EncapsulationCoinByteLength,
    );
    let recoveredSharedSecret: Uint8Array | undefined;
    try {
        const encapsulation = ml_kem768.encapsulate(
            encapsulationKey,
            encapsulationCoins,
        );
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
    } finally {
        encapsulationCoins.fill(0);
        recoveredSharedSecret?.fill(0);
    }
};

export const openBrowserLocalExternalKeyProvider = (
    input: BrowserLocalExternalKeyProviderInput,
): BrowserLocalExternalKeyProvider => {
    const provider: ProviderState = {
        entropy: input.entropy ?? defaultEntropy,
        signingOperations: input.signing,
        signingVerificationKey: copyExactBytes(
            input.signing.verificationKey,
            mlDsa65PublicKeyByteLength,
            'signing.verificationKey',
        ),
        mailboxOperations: input.mailbox,
        mailboxEncapsulationKey: copyExactBytes(
            input.mailbox.encapsulationKey,
            mlKem768PublicKeyByteLength,
            'mailbox.encapsulationKey',
        ),
    };

    try {
        validateSigningKeyPair(provider);
        validateMailboxKeyPair(provider);
    } catch (error) {
        revokeSigning(provider, false);
        revokeMailbox(provider, false);
        throw error;
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
        close: () => {
            revokeSigning(provider);
            revokeMailbox(provider);
        },
    });
};

const signClosedMailboxEnvelopeHash = (input: {
    capability: BrowserLocalSigningCapability;
    message: Uint8Array;
}): Uint8Array => {
    const provider = requireSigningProvider(input.capability);
    if (
        !(input.message instanceof Uint8Array) ||
        input.message.byteLength !== 64
    ) {
        throw new TypeError(
            'Closed protocol signature messages must be 64 bytes.',
        );
    }
    const hedge = readEntropy(provider, signingHedgeByteLength);
    try {
        return invokeSigningOperation(
            provider,
            input.message,
            mailboxSignatureContext,
            hedge,
        );
    } finally {
        hedge.fill(0);
    }
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
        return invokeMailboxDecapsulationOperation(provider, ciphertext);
    } finally {
        ciphertext.fill(0);
    }
};

export const encapsulateFreshMailbox = (input: {
    signingCapability: BrowserLocalSigningCapability;
    recipientEncapsulationKey: Uint8Array;
}): Readonly<{
    readonly ciphertext: Uint8Array;
    readonly envelopeAttemptIdentifier: Uint8Array;
    readonly sharedSecret: Uint8Array;
    readonly signingPermit: FreshMailboxSigningPermit;
}> => {
    const provider = requireSigningProvider(input.signingCapability);
    const recipientEncapsulationKey = copyExactBytes(
        input.recipientEncapsulationKey,
        mlKem768PublicKeyByteLength,
        'recipientEncapsulationKey',
    );
    const envelopeAttemptIdentifier = readEntropy(
        provider,
        mailboxAttemptIdentifierByteLength,
    );
    const encapsulationCoins = readEntropy(
        provider,
        mlKem768EncapsulationCoinByteLength,
    );
    try {
        const encapsulation = ml_kem768.encapsulate(
            recipientEncapsulationKey,
            encapsulationCoins,
        );
        const signingPermit = Object.freeze({}) as FreshMailboxSigningPermit;
        freshMailboxSigningPermitStates.set(signingPermit, {
            provider,
            consumed: false,
        });
        return Object.freeze({
            ciphertext: encapsulation.cipherText,
            envelopeAttemptIdentifier,
            sharedSecret: encapsulation.sharedSecret,
            signingPermit,
        });
    } catch (error) {
        envelopeAttemptIdentifier.fill(0);
        throw error;
    } finally {
        encapsulationCoins.fill(0);
        recipientEncapsulationKey.fill(0);
    }
};

export const signFreshMailboxEnvelope = (input: {
    signingCapability: BrowserLocalSigningCapability;
    signingPermit: FreshMailboxSigningPermit;
    envelopeHash: ProtocolHash;
}): Uint8Array => {
    const permit = freshMailboxSigningPermitStates.get(input.signingPermit);
    if (permit === undefined || permit.consumed) {
        throw new BrowserLocalKeyProviderError(
            'CapabilityUnavailable',
            'The fresh-mailbox signing permit is unavailable or already consumed.',
        );
    }
    const provider = requireSigningProvider(input.signingCapability);
    if (permit.provider !== provider) {
        throw new BrowserLocalKeyProviderError(
            'CapabilityUnavailable',
            'The fresh-mailbox signing permit belongs to another provider.',
        );
    }
    const envelopeHash = requireLowercaseHex(
        input.envelopeHash,
        64,
        'envelopeHash',
    );
    permit.consumed = true;
    return signClosedMailboxEnvelopeHash({
        capability: input.signingCapability,
        message: hexToBytes(envelopeHash),
    });
};
