import { kmac256 } from '@noble/hashes/sha3-addons.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
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
const objectSignatureContext = textEncoder.encode(
    'sealed-lattice/object-signature/v1',
);
const mailboxSignatureContext = textEncoder.encode(
    'sealed-lattice/mailbox-signature/v1',
);
const signingHedgeByteLength = 32;
const mailboxAttemptIdentifierByteLength = 32;
const actionRandomnessRootByteLength = 64;
const actionKeyMaterialByteLength = 192;
const privateRandomnessStreamKeyStart = 64;
const privateRandomnessStreamKeyEnd = 128;
const setupMailboxFamily = 0x0200;
const actionKeyHierarchyCustomization = textEncoder.encode(
    'sealed-lattice/private-randomness/action-key-hierarchy/v1',
);
const privateRandomBlockCustomization = textEncoder.encode(
    'sealed-lattice/private-randomness/v1',
);
const setupAttemptCustomization = textEncoder.encode(
    'sealed-lattice/setup/reset-safe-attempt/v1',
);

const mlDsa65PublicKeyByteLength = ml_dsa65.lengths.publicKey!;
const mlDsa65SecretKeyByteLength = ml_dsa65.lengths.secretKey!;
const mlDsa65SignatureByteLength = ml_dsa65.lengths.signature!;
const mlKem768PublicKeyByteLength = ml_kem768.lengths.publicKey!;
const mlKem768SecretKeyByteLength = ml_kem768.lengths.secretKey!;
const mlKem768CiphertextByteLength = ml_kem768.lengths.cipherText!;
const mlKem768EncapsulationCoinByteLength = ml_kem768.lengths.msg!;

declare const signingCapabilityBrand: unique symbol;
declare const mailboxCapabilityBrand: unique symbol;
declare const actionRandomnessCapabilityBrand: unique symbol;
declare const freshMailboxSigningPermitBrand: unique symbol;
declare const setupMailboxSigningPermitBrand: unique symbol;

export type BrowserLocalSigningCapability = Readonly<{
    readonly [signingCapabilityBrand]: true;
}>;

export type BrowserLocalMailboxCapability = Readonly<{
    readonly [mailboxCapabilityBrand]: true;
}>;

export type BrowserLocalActionRandomnessCapability = Readonly<{
    readonly [actionRandomnessCapabilityBrand]: true;
}>;

type ResetSafeSetupMailboxSigningPermit = Readonly<{
    readonly [setupMailboxSigningPermitBrand]: true;
}>;

type FreshMailboxSigningPermit = Readonly<{
    readonly [freshMailboxSigningPermitBrand]: true;
}>;

type BrowserLocalActionRandomnessContext = Readonly<{
    readonly suiteId: ProtocolHash;
    readonly ceremonyContextHash: ProtocolHash;
    readonly actionContextHash: ProtocolHash;
    readonly participantId: string;
}>;

export type BrowserLocalSetupMailboxSlot = Readonly<{
    readonly suiteId: ProtocolHash;
    readonly ceremonyContextHash: ProtocolHash;
    readonly actionContextHash: ProtocolHash;
    readonly rosterHash: ProtocolHash;
    readonly sourceParticipantId: string;
    readonly recipientParticipantId: string;
    readonly producerSequence: string;
    readonly payloadType: 1 | 2;
    readonly statementHash: ProtocolHash;
    readonly orderedMaterialRoots: readonly ProtocolHash[];
}>;

type BrowserLocalPrivateRandomnessKernel = Readonly<{
    encodeActionRandomnessDerivationInput(
        value: BrowserLocalActionRandomnessContext,
    ): Readonly<{ readonly canonicalBytesHex: string }>;
    deriveActionRandomnessCommitment(input: {
        readonly actionRandomnessRootHex: string;
        readonly value: BrowserLocalActionRandomnessContext;
    }): ProtocolHash;
    encodePrivateRandomBlockInput(
        value: BrowserLocalActionRandomnessContext & {
            readonly family: number;
            readonly purpose: number;
            readonly derivationContextHash: ProtocolHash;
            readonly attemptIdentifierHex: string;
            readonly counter: string;
        },
    ): Readonly<{ readonly canonicalBytesHex: string }>;
    deriveSetupMailboxSlotHash(
        value: BrowserLocalSetupMailboxSlot,
    ): ProtocolHash;
}>;

type BrowserLocalActionRandomnessBindingInput = Readonly<{
    readonly actionRandomnessRoot: Uint8Array;
    readonly expectedActionRandomnessCommitment: ProtocolHash;
    readonly context: BrowserLocalActionRandomnessContext;
    readonly kernel: BrowserLocalPrivateRandomnessKernel;
}>;

export type BrowserLocalKeyProviderFailureCode =
    | 'CapabilityUnavailable'
    | 'EntropyUnavailable'
    | 'KeyMismatch'
    | 'MalformedKey'
    | 'MalformedRandomness'
    | 'RandomnessMismatch'
    | 'SelfTestFailed';

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
    bindActionRandomness(
        input: BrowserLocalActionRandomnessBindingInput,
    ): BrowserLocalActionRandomnessCapability;
    revokeActionRandomnessCapability(
        capability: BrowserLocalActionRandomnessCapability,
    ): void;
    revokeSigningCapability(): void;
    revokeMailboxCapability(): void;
    close(): void;
}>;

export type BrowserLocalExternalKeyProviderInput = Readonly<{
    signing: Readonly<{
        expectedVerificationKey: Uint8Array;
        secretKey: Uint8Array;
    }>;
    mailbox: Readonly<{
        expectedEncapsulationKey: Uint8Array;
        decapsulationKey: Uint8Array;
    }>;
    entropy?: (byteLength: number) => Uint8Array;
}>;

type ProviderState = {
    entropy: (byteLength: number) => Uint8Array;
    signingSecretKey: Uint8Array | undefined;
    signingVerificationKey: Uint8Array | undefined;
    mailboxDecapsulationKey: Uint8Array | undefined;
    mailboxEncapsulationKey: Uint8Array | undefined;
    actionRandomnessStates: Set<ActionRandomnessCapabilityState>;
};

type SigningCapabilityState = Readonly<{ provider: ProviderState }>;
type MailboxCapabilityState = Readonly<{ provider: ProviderState }>;
type ActionRandomnessCapabilityState = {
    readonly provider: ProviderState;
    readonly context: BrowserLocalActionRandomnessContext;
    readonly kernel: BrowserLocalPrivateRandomnessKernel;
    readonly actionRandomnessCommitment: ProtocolHash;
    privateRandomnessStreamKey: Uint8Array | undefined;
    setupAttemptIdentifier: Uint8Array | undefined;
};

type SetupMailboxSigningPermitState = {
    readonly actionRandomnessState: ActionRandomnessCapabilityState;
    consumed: boolean;
};

type FreshMailboxSigningPermitState = {
    readonly provider: ProviderState;
    consumed: boolean;
};

const signingCapabilityStates = new WeakMap<object, SigningCapabilityState>();
const mailboxCapabilityStates = new WeakMap<object, MailboxCapabilityState>();
const actionRandomnessCapabilityStates = new WeakMap<
    object,
    ActionRandomnessCapabilityState
>();
const setupMailboxSigningPermitStates = new WeakMap<
    object,
    SetupMailboxSigningPermitState
>();
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

const requireCanonicalHex = (value: string, label: string): string => {
    if (
        typeof value !== 'string' ||
        value.length === 0 ||
        value.length % 2 !== 0 ||
        !/^[0-9a-f]+$/u.test(value)
    ) {
        throw new BrowserLocalKeyProviderError(
            'MalformedRandomness',
            `${label} must be nonempty lowercase hexadecimal bytes.`,
        );
    }
    return value;
};

const copyActionRandomnessContext = (
    context: BrowserLocalActionRandomnessContext,
): BrowserLocalActionRandomnessContext =>
    Object.freeze({
        suiteId: requireLowercaseHex(context.suiteId, 64, 'context.suiteId'),
        ceremonyContextHash: requireLowercaseHex(
            context.ceremonyContextHash,
            64,
            'context.ceremonyContextHash',
        ),
        actionContextHash: requireLowercaseHex(
            context.actionContextHash,
            64,
            'context.actionContextHash',
        ),
        participantId: requireLowercaseHex(
            context.participantId,
            64,
            'context.participantId',
        ),
    });

const revokeActionRandomness = (
    state: ActionRandomnessCapabilityState,
): void => {
    wipe(state.privateRandomnessStreamKey);
    wipe(state.setupAttemptIdentifier);
    state.privateRandomnessStreamKey = undefined;
    state.setupAttemptIdentifier = undefined;
    state.provider.actionRandomnessStates.delete(state);
};

const bindActionRandomness = (
    provider: ProviderState,
    input: BrowserLocalActionRandomnessBindingInput,
): BrowserLocalActionRandomnessCapability => {
    const root = copyExactBytes(
        input.actionRandomnessRoot,
        actionRandomnessRootByteLength,
        'actionRandomnessRoot',
    );
    const context = copyActionRandomnessContext(input.context);
    const expectedCommitment = requireLowercaseHex(
        input.expectedActionRandomnessCommitment,
        64,
        'expectedActionRandomnessCommitment',
    );
    let keyMaterial: Uint8Array | undefined;
    try {
        const canonicalDerivationInputHex = requireCanonicalHex(
            input.kernel.encodeActionRandomnessDerivationInput(context)
                .canonicalBytesHex,
            'canonical action-randomness derivation input',
        );
        const derivedCommitment = input.kernel.deriveActionRandomnessCommitment(
            {
                actionRandomnessRootHex: bytesToHex(root),
                value: context,
            },
        );
        if (derivedCommitment !== expectedCommitment) {
            throw new BrowserLocalKeyProviderError(
                'RandomnessMismatch',
                'The action-randomness root does not match its frozen commitment.',
            );
        }
        keyMaterial = kmac256(root, hexToBytes(canonicalDerivationInputHex), {
            dkLen: actionKeyMaterialByteLength,
            personalization: actionKeyHierarchyCustomization,
        });
        const privateRandomnessStreamKey = keyMaterial.slice(
            privateRandomnessStreamKeyStart,
            privateRandomnessStreamKeyEnd,
        );
        const setupAttemptIdentifier = kmac256(
            privateRandomnessStreamKey,
            hexToBytes(expectedCommitment),
            {
                dkLen: 32,
                personalization: setupAttemptCustomization,
            },
        );
        const state: ActionRandomnessCapabilityState = {
            provider,
            context,
            kernel: input.kernel,
            actionRandomnessCommitment: expectedCommitment,
            privateRandomnessStreamKey,
            setupAttemptIdentifier,
        };
        const capability = Object.freeze(
            {},
        ) as BrowserLocalActionRandomnessCapability;
        actionRandomnessCapabilityStates.set(capability, state);
        provider.actionRandomnessStates.add(state);
        return capability;
    } catch (error) {
        if (error instanceof BrowserLocalKeyProviderError) {
            throw error;
        }
        throw new BrowserLocalKeyProviderError(
            'MalformedRandomness',
            'The action-randomness binding could not be derived.',
            error,
        );
    } finally {
        root.fill(0);
        keyMaterial?.fill(0);
    }
};

const revokeSigning = (provider: ProviderState): void => {
    wipe(provider.signingSecretKey);
    wipe(provider.signingVerificationKey);
    provider.signingSecretKey = undefined;
    provider.signingVerificationKey = undefined;
};

const revokeMailbox = (provider: ProviderState): void => {
    wipe(provider.mailboxDecapsulationKey);
    wipe(provider.mailboxEncapsulationKey);
    provider.mailboxDecapsulationKey = undefined;
    provider.mailboxEncapsulationKey = undefined;
};

const requireSigningProvider = (
    capability: BrowserLocalSigningCapability,
): ProviderState => {
    const capabilityState = signingCapabilityStates.get(capability);
    if (
        capabilityState === undefined ||
        capabilityState.provider.signingSecretKey === undefined ||
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
        capabilityState.provider.mailboxDecapsulationKey === undefined ||
        capabilityState.provider.mailboxEncapsulationKey === undefined
    ) {
        throw new BrowserLocalKeyProviderError(
            'CapabilityUnavailable',
            'The browser-local mailbox capability is unavailable or revoked.',
        );
    }

    return capabilityState.provider;
};

const requireActionRandomnessState = (
    capability: BrowserLocalActionRandomnessCapability,
    signingCapability: BrowserLocalSigningCapability,
): ActionRandomnessCapabilityState => {
    const state = actionRandomnessCapabilityStates.get(capability);
    const signingProvider = requireSigningProvider(signingCapability);
    if (
        state === undefined ||
        state.provider !== signingProvider ||
        state.privateRandomnessStreamKey === undefined ||
        state.setupAttemptIdentifier === undefined
    ) {
        throw new BrowserLocalKeyProviderError(
            'CapabilityUnavailable',
            'The action-randomness capability is unavailable, revoked, or belongs to another signing provider.',
        );
    }
    return state;
};

const deriveResetSafeSetupMailboxBytes = (
    state: ActionRandomnessCapabilityState,
    purpose: 1 | 2 | 3,
    derivationContextHash: ProtocolHash,
): Uint8Array => {
    const canonicalBlockInputHex = requireCanonicalHex(
        state.kernel.encodePrivateRandomBlockInput({
            ...state.context,
            family: setupMailboxFamily,
            purpose,
            derivationContextHash,
            attemptIdentifierHex: bytesToHex(state.setupAttemptIdentifier!),
            counter: '0',
        }).canonicalBytesHex,
        'canonical private-random block input',
    );
    const block = kmac256(
        state.privateRandomnessStreamKey!,
        hexToBytes(canonicalBlockInputHex),
        {
            dkLen: 64,
            personalization: privateRandomBlockCustomization,
        },
    );
    const bytes = block.slice(0, 32);
    block.fill(0);
    return bytes;
};

const requireSetupMailboxSlotContext = (
    state: ActionRandomnessCapabilityState,
    slot: BrowserLocalSetupMailboxSlot,
): void => {
    if (
        slot.suiteId !== state.context.suiteId ||
        slot.ceremonyContextHash !== state.context.ceremonyContextHash ||
        slot.actionContextHash !== state.context.actionContextHash ||
        slot.sourceParticipantId !== state.context.participantId
    ) {
        throw new BrowserLocalKeyProviderError(
            'RandomnessMismatch',
            'The setup mailbox slot does not belong to the bound action-randomness context.',
        );
    }
};

const validateSigningKeyPair = (provider: ProviderState): void => {
    const secretKey = provider.signingSecretKey!;
    const verificationKey = provider.signingVerificationKey!;
    let derivedVerificationKey: Uint8Array;
    try {
        derivedVerificationKey = ml_dsa65.getPublicKey(secretKey);
    } catch (error) {
        throw new BrowserLocalKeyProviderError(
            'MalformedKey',
            'The browser-local ML-DSA-65 secret key is malformed.',
            error,
        );
    }
    if (!bytesEqual(derivedVerificationKey, verificationKey)) {
        throw new BrowserLocalKeyProviderError(
            'KeyMismatch',
            'The browser-local signing key does not match the frozen roster verification key.',
        );
    }

    const hedge = readEntropy(provider, signingHedgeByteLength);
    try {
        const signature = ml_dsa65.sign(signingSelfTestMessage, secretKey, {
            context: signingSelfTestContext,
            extraEntropy: hedge,
        });
        if (
            signature.byteLength !== mlDsa65SignatureByteLength ||
            !ml_dsa65.verify(
                signature,
                signingSelfTestMessage,
                verificationKey,
                { context: signingSelfTestContext },
            )
        ) {
            throw new BrowserLocalKeyProviderError(
                'SelfTestFailed',
                'The browser-local signing capability failed its pairwise self-test.',
            );
        }
    } finally {
        hedge.fill(0);
    }
};

const validateMailboxKeyPair = (provider: ProviderState): void => {
    const decapsulationKey = provider.mailboxDecapsulationKey!;
    const encapsulationKey = provider.mailboxEncapsulationKey!;
    let derivedEncapsulationKey: Uint8Array;
    try {
        derivedEncapsulationKey = ml_kem768.getPublicKey(decapsulationKey);
    } catch (error) {
        throw new BrowserLocalKeyProviderError(
            'MalformedKey',
            'The browser-local ML-KEM-768 decapsulation key is malformed.',
            error,
        );
    }
    if (!bytesEqual(derivedEncapsulationKey, encapsulationKey)) {
        throw new BrowserLocalKeyProviderError(
            'KeyMismatch',
            'The browser-local mailbox key does not match the frozen roster encapsulation key.',
        );
    }

    const encapsulationCoins = readEntropy(
        provider,
        mlKem768EncapsulationCoinByteLength,
    );
    try {
        const encapsulation = ml_kem768.encapsulate(
            encapsulationKey,
            encapsulationCoins,
        );
        const recoveredSharedSecret = ml_kem768.decapsulate(
            encapsulation.cipherText,
            decapsulationKey,
        );
        if (!bytesEqual(encapsulation.sharedSecret, recoveredSharedSecret)) {
            throw new BrowserLocalKeyProviderError(
                'SelfTestFailed',
                'The browser-local mailbox capability failed its pairwise self-test.',
            );
        }
    } finally {
        encapsulationCoins.fill(0);
    }
};

export const openBrowserLocalExternalKeyProvider = (
    input: BrowserLocalExternalKeyProviderInput,
): BrowserLocalExternalKeyProvider => {
    const provider: ProviderState = {
        entropy: input.entropy ?? defaultEntropy,
        signingSecretKey: copyExactBytes(
            input.signing.secretKey,
            mlDsa65SecretKeyByteLength,
            'signing.secretKey',
        ),
        signingVerificationKey: copyExactBytes(
            input.signing.expectedVerificationKey,
            mlDsa65PublicKeyByteLength,
            'signing.expectedVerificationKey',
        ),
        mailboxDecapsulationKey: copyExactBytes(
            input.mailbox.decapsulationKey,
            mlKem768SecretKeyByteLength,
            'mailbox.decapsulationKey',
        ),
        mailboxEncapsulationKey: copyExactBytes(
            input.mailbox.expectedEncapsulationKey,
            mlKem768PublicKeyByteLength,
            'mailbox.expectedEncapsulationKey',
        ),
        actionRandomnessStates: new Set(),
    };

    try {
        validateSigningKeyPair(provider);
        validateMailboxKeyPair(provider);
    } catch (error) {
        revokeSigning(provider);
        revokeMailbox(provider);
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
        bindActionRandomness: (actionRandomnessInput) =>
            bindActionRandomness(provider, actionRandomnessInput),
        revokeActionRandomnessCapability: (capability) => {
            const state = actionRandomnessCapabilityStates.get(capability);
            if (state === undefined || state.provider !== provider) {
                throw new BrowserLocalKeyProviderError(
                    'CapabilityUnavailable',
                    'The action-randomness capability is unavailable, revoked, or belongs to another provider.',
                );
            }
            revokeActionRandomness(state);
        },
        revokeSigningCapability: () => {
            revokeSigning(provider);
        },
        revokeMailboxCapability: () => {
            revokeMailbox(provider);
        },
        close: () => {
            for (const state of [...provider.actionRandomnessStates]) {
                revokeActionRandomness(state);
            }
            revokeSigning(provider);
            revokeMailbox(provider);
        },
    });
};

type ClosedSignatureContext = 'mailbox' | 'object';

const signatureContext = (context: ClosedSignatureContext): Uint8Array =>
    context === 'mailbox' ? mailboxSignatureContext : objectSignatureContext;

const signClosedProtocolMessage = (input: {
    capability: BrowserLocalSigningCapability;
    context: ClosedSignatureContext;
    message: Uint8Array;
    resetSafeHedge?: Uint8Array;
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
    const hedge =
        input.resetSafeHedge === undefined
            ? readEntropy(provider, signingHedgeByteLength)
            : copyExactBytes(
                  input.resetSafeHedge,
                  signingHedgeByteLength,
                  'resetSafeHedge',
              );
    try {
        return ml_dsa65.sign(input.message, provider.signingSecretKey!, {
            context: signatureContext(input.context),
            extraEntropy: hedge,
        });
    } finally {
        hedge.fill(0);
    }
};

export const signStateWitnessVoteMessage = (input: {
    capability: BrowserLocalSigningCapability;
    signatureMessage: Uint8Array;
}): Uint8Array =>
    signClosedProtocolMessage({
        capability: input.capability,
        context: 'object',
        message: input.signatureMessage,
    });

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
        return ml_kem768.decapsulate(
            ciphertext,
            provider.mailboxDecapsulationKey!,
        );
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
    return signClosedProtocolMessage({
        capability: input.signingCapability,
        context: 'mailbox',
        message: hexToBytes(envelopeHash),
    });
};

export const encapsulateResetSafeSetupMailbox = (input: {
    actionRandomnessCapability: BrowserLocalActionRandomnessCapability;
    signingCapability: BrowserLocalSigningCapability;
    slot: BrowserLocalSetupMailboxSlot;
    recipientEncapsulationKey: Uint8Array;
}): Readonly<{
    readonly envelopeAttemptIdentifier: Uint8Array;
    readonly sharedSecret: Uint8Array;
    readonly ciphertext: Uint8Array;
    readonly signingPermit: ResetSafeSetupMailboxSigningPermit;
}> => {
    const state = requireActionRandomnessState(
        input.actionRandomnessCapability,
        input.signingCapability,
    );
    requireSetupMailboxSlotContext(state, input.slot);
    const recipientEncapsulationKey = copyExactBytes(
        input.recipientEncapsulationKey,
        mlKem768PublicKeyByteLength,
        'recipientEncapsulationKey',
    );
    const setupMailboxSlotHash = state.kernel.deriveSetupMailboxSlotHash(
        input.slot,
    );
    requireLowercaseHex(setupMailboxSlotHash, 64, 'setupMailboxSlotHash');
    const envelopeAttemptIdentifier = deriveResetSafeSetupMailboxBytes(
        state,
        1,
        setupMailboxSlotHash,
    );
    const encapsulationCoins = deriveResetSafeSetupMailboxBytes(
        state,
        2,
        setupMailboxSlotHash,
    );
    try {
        const encapsulation = ml_kem768.encapsulate(
            recipientEncapsulationKey,
            encapsulationCoins,
        );
        const signingPermit = Object.freeze(
            {},
        ) as ResetSafeSetupMailboxSigningPermit;
        setupMailboxSigningPermitStates.set(signingPermit, {
            actionRandomnessState: state,
            consumed: false,
        });
        return Object.freeze({
            envelopeAttemptIdentifier,
            sharedSecret: encapsulation.sharedSecret,
            ciphertext: encapsulation.cipherText,
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

export const signResetSafeSetupMailboxEnvelope = (input: {
    signingCapability: BrowserLocalSigningCapability;
    signingPermit: ResetSafeSetupMailboxSigningPermit;
    envelopeHash: ProtocolHash;
}): Uint8Array => {
    const permit = setupMailboxSigningPermitStates.get(input.signingPermit);
    if (permit === undefined || permit.consumed) {
        throw new BrowserLocalKeyProviderError(
            'CapabilityUnavailable',
            'The reset-safe setup-mailbox signing permit is unavailable or already consumed.',
        );
    }
    const provider = requireSigningProvider(input.signingCapability);
    if (
        permit.actionRandomnessState.provider !== provider ||
        permit.actionRandomnessState.privateRandomnessStreamKey === undefined
    ) {
        throw new BrowserLocalKeyProviderError(
            'CapabilityUnavailable',
            'The reset-safe setup-mailbox signing permit belongs to another or revoked provider.',
        );
    }
    const envelopeHash = requireLowercaseHex(
        input.envelopeHash,
        64,
        'envelopeHash',
    );
    permit.consumed = true;
    const hedge = deriveResetSafeSetupMailboxBytes(
        permit.actionRandomnessState,
        3,
        envelopeHash,
    );
    try {
        return signClosedProtocolMessage({
            capability: input.signingCapability,
            context: 'mailbox',
            message: hexToBytes(envelopeHash),
            resetSafeHedge: hedge,
        });
    } finally {
        hedge.fill(0);
    }
};
