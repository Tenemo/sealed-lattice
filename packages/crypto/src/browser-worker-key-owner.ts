import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';

import {
    BrowserLocalKeyProviderError,
    type BrowserLocalExternalKeyProviderInput,
} from './browser-local-key-provider.js';
import { webCryptoRandomBytes } from './web-crypto.js';

const mlDsa65SeedByteLength = ml_dsa65.lengths.seed!;
const mlDsa65PublicKeyByteLength = ml_dsa65.lengths.publicKey!;
const mlDsa65SecretKeyByteLength = ml_dsa65.lengths.secretKey!;
const mlDsa65SignatureByteLength = ml_dsa65.lengths.signature!;
const mlDsa65HedgeByteLength = 32;
const mlDsa65MaximumContextByteLength = 255;

const mlKem768SeedByteLength = ml_kem768.lengths.seed!;
const mlKem768PublicKeyByteLength = ml_kem768.lengths.publicKey!;
const mlKem768SecretKeyByteLength = ml_kem768.lengths.secretKey!;
const mlKem768CiphertextByteLength = ml_kem768.lengths.cipherText!;
const mlKem768SharedSecretByteLength = 32;

export type BrowserWorkerOwnedKeyPublicMaterial = Readonly<{
    mailboxEncapsulationKey: Uint8Array;
    signingVerificationKey: Uint8Array;
}>;

/**
 * One exclusive lease over the retained keys. The existing browser-local key
 * provider adopts the two operation objects and revokes them on closure. A
 * caller whose consumer fails before adoption must close the lease itself.
 */
export type BrowserWorkerOwnedKeyOperationLease = Readonly<{
    mailbox: BrowserLocalExternalKeyProviderInput['mailbox'];
    signing: BrowserLocalExternalKeyProviderInput['signing'];
    close(): void;
}>;

/**
 * Opaque owner of one browser participant's ML-DSA and ML-KEM secret keys.
 * Only copied public keys and closed signing or decapsulation operations leave
 * the owner. A document-owning browser realm cannot create one.
 */
export type BrowserWorkerOwnedKeyOwner = Readonly<{
    copyPublicKeyMaterial(): BrowserWorkerOwnedKeyPublicMaterial;
    openOperationLease(): BrowserWorkerOwnedKeyOperationLease;
    close(): void;
}>;

type BrowserWorkerOwnedKeyOwnerState = {
    activeLease: BrowserWorkerOwnedKeyOperationLeaseState | undefined;
    abortListener: (() => void) | undefined;
    abortSignal: AbortSignal | undefined;
    mailboxEncapsulationKey: Uint8Array | undefined;
    mailboxSecretKey: Uint8Array | undefined;
    signingSecretKey: Uint8Array | undefined;
    signingVerificationKey: Uint8Array | undefined;
    state: 'active' | 'released';
};

type BrowserWorkerOwnedKeyOperationLeaseState = {
    mailboxIsActive: boolean;
    ownerState: BrowserWorkerOwnedKeyOwnerState;
    signingIsActive: boolean;
};

const browserWorkerOwnedKeyOwnerStates = new WeakMap<
    BrowserWorkerOwnedKeyOwner,
    BrowserWorkerOwnedKeyOwnerState
>();

const requireWorkerCompatibleRealm = (): void => {
    if (typeof document !== 'undefined') {
        throw new BrowserLocalKeyProviderError(
            'UnsupportedProvider',
            'Browser participant keys may only be created and used inside their owning worker.',
        );
    }
};

const copyBytes = (value: unknown, label: string): Uint8Array => {
    if (!(value instanceof Uint8Array)) {
        throw new BrowserLocalKeyProviderError(
            'MalformedRandomness',
            `${label} must be a Uint8Array.`,
        );
    }

    return value.slice();
};

const copyExactBytes = (
    value: unknown,
    expectedByteLength: number,
    label: string,
): Uint8Array => {
    const copiedBytes = copyBytes(value, label);
    if (copiedBytes.byteLength !== expectedByteLength) {
        copiedBytes.fill(0);
        throw new BrowserLocalKeyProviderError(
            'MalformedRandomness',
            `${label} must contain exactly ${String(expectedByteLength)} bytes.`,
        );
    }

    return copiedBytes;
};

const requireOwnedExactBytes = (
    value: unknown,
    expectedByteLength: number,
    label: string,
): Uint8Array => {
    if (
        !(value instanceof Uint8Array) ||
        value.byteLength !== expectedByteLength
    ) {
        if (value instanceof Uint8Array) {
            value.fill(0);
        }
        throw new BrowserLocalKeyProviderError(
            'MalformedKey',
            `${label} must contain exactly ${String(expectedByteLength)} bytes.`,
        );
    }

    return value;
};

const readKeyGenerationSeed = (
    byteLength: number,
    label: string,
): Uint8Array => {
    let seed: Uint8Array;
    try {
        seed = webCryptoRandomBytes(
            byteLength,
            'Browser-worker key generation requires Web Crypto getRandomValues.',
        );
    } catch (error) {
        throw new BrowserLocalKeyProviderError(
            'EntropyUnavailable',
            `${label} generation could not read browser CSPRNG bytes.`,
            error,
        );
    }
    if (seed.byteLength !== byteLength) {
        seed.fill(0);
        throw new BrowserLocalKeyProviderError(
            'EntropyUnavailable',
            `${label} generation did not receive the requested browser CSPRNG bytes.`,
        );
    }

    return seed;
};

const throwIfAborted = (signal: AbortSignal | undefined): void => {
    signal?.throwIfAborted();
};

const requireActiveOwnerState = (
    owner: BrowserWorkerOwnedKeyOwner,
): BrowserWorkerOwnedKeyOwnerState => {
    requireWorkerCompatibleRealm();
    const ownerState = browserWorkerOwnedKeyOwnerStates.get(owner);
    if (
        ownerState === undefined ||
        ownerState.state !== 'active' ||
        ownerState.signingSecretKey === undefined ||
        ownerState.signingVerificationKey === undefined ||
        ownerState.mailboxSecretKey === undefined ||
        ownerState.mailboxEncapsulationKey === undefined
    ) {
        throw new BrowserLocalKeyProviderError(
            'CapabilityUnavailable',
            'The browser-worker key owner is unavailable or released.',
        );
    }
    if (ownerState.abortSignal?.aborted === true) {
        releaseOwnerState(ownerState);
        throw new BrowserLocalKeyProviderError(
            'CapabilityUnavailable',
            'The browser-worker key owner was cancelled and released.',
        );
    }

    return ownerState;
};

const finishLeaseWhenReleased = (
    leaseState: BrowserWorkerOwnedKeyOperationLeaseState,
): void => {
    if (
        !leaseState.signingIsActive &&
        !leaseState.mailboxIsActive &&
        leaseState.ownerState.activeLease === leaseState
    ) {
        leaseState.ownerState.activeLease = undefined;
    }
};

const revokeSigningLease = (
    leaseState: BrowserWorkerOwnedKeyOperationLeaseState,
): void => {
    leaseState.signingIsActive = false;
    finishLeaseWhenReleased(leaseState);
};

const revokeMailboxLease = (
    leaseState: BrowserWorkerOwnedKeyOperationLeaseState,
): void => {
    leaseState.mailboxIsActive = false;
    finishLeaseWhenReleased(leaseState);
};

const closeOperationLease = (
    leaseState: BrowserWorkerOwnedKeyOperationLeaseState,
): void => {
    leaseState.signingIsActive = false;
    leaseState.mailboxIsActive = false;
    finishLeaseWhenReleased(leaseState);
};

const requireActiveLeaseOwnerState = (
    leaseState: BrowserWorkerOwnedKeyOperationLeaseState,
    operationKind: 'mailbox' | 'signing',
): BrowserWorkerOwnedKeyOwnerState => {
    requireWorkerCompatibleRealm();
    const ownerState = leaseState.ownerState;
    const operationIsActive =
        operationKind === 'signing'
            ? leaseState.signingIsActive
            : leaseState.mailboxIsActive;
    if (
        !operationIsActive ||
        ownerState.state !== 'active' ||
        ownerState.activeLease !== leaseState ||
        ownerState.signingSecretKey === undefined ||
        ownerState.signingVerificationKey === undefined ||
        ownerState.mailboxSecretKey === undefined ||
        ownerState.mailboxEncapsulationKey === undefined
    ) {
        throw new BrowserLocalKeyProviderError(
            'CapabilityUnavailable',
            `The browser-worker ${operationKind} operation is unavailable or released.`,
        );
    }
    if (ownerState.abortSignal?.aborted === true) {
        releaseOwnerState(ownerState);
        throw new BrowserLocalKeyProviderError(
            'CapabilityUnavailable',
            `The browser-worker ${operationKind} operation was cancelled and released.`,
        );
    }

    return ownerState;
};

const releaseOwnerState = (
    ownerState: BrowserWorkerOwnedKeyOwnerState,
): void => {
    if (ownerState.state === 'released') {
        return;
    }
    ownerState.state = 'released';
    if (ownerState.activeLease !== undefined) {
        ownerState.activeLease.signingIsActive = false;
        ownerState.activeLease.mailboxIsActive = false;
        ownerState.activeLease = undefined;
    }
    const abortSignal = ownerState.abortSignal;
    const abortListener = ownerState.abortListener;
    ownerState.abortListener = undefined;
    ownerState.abortSignal = undefined;
    ownerState.signingSecretKey?.fill(0);
    ownerState.signingVerificationKey?.fill(0);
    ownerState.mailboxSecretKey?.fill(0);
    ownerState.mailboxEncapsulationKey?.fill(0);
    ownerState.signingSecretKey = undefined;
    ownerState.signingVerificationKey = undefined;
    ownerState.mailboxSecretKey = undefined;
    ownerState.mailboxEncapsulationKey = undefined;
    if (abortSignal !== undefined && abortListener !== undefined) {
        abortSignal.removeEventListener('abort', abortListener);
    }
};

const createSigningOperations = (
    leaseState: BrowserWorkerOwnedKeyOperationLeaseState,
): BrowserLocalExternalKeyProviderInput['signing'] =>
    Object.freeze({
        get verificationKey(): Uint8Array {
            const ownerState = requireActiveLeaseOwnerState(
                leaseState,
                'signing',
            );
            return ownerState.signingVerificationKey!.slice();
        },
        signClosedMessage: (input: {
            readonly context: Uint8Array;
            readonly hedge: Uint8Array;
            readonly message: Uint8Array;
        }): Uint8Array => {
            const ownerState = requireActiveLeaseOwnerState(
                leaseState,
                'signing',
            );
            let message: Uint8Array | undefined;
            let context: Uint8Array | undefined;
            let hedge: Uint8Array | undefined;
            let signature: Uint8Array | undefined;
            try {
                message = copyBytes(input?.message, 'Signing message');
                context = copyBytes(input?.context, 'Signing context');
                hedge = copyExactBytes(
                    input?.hedge,
                    mlDsa65HedgeByteLength,
                    'Signing hedge',
                );
                if (context.byteLength > mlDsa65MaximumContextByteLength) {
                    throw new BrowserLocalKeyProviderError(
                        'MalformedRandomness',
                        `Signing context must contain at most ${String(mlDsa65MaximumContextByteLength)} bytes.`,
                    );
                }
                signature = ml_dsa65.sign(
                    message,
                    ownerState.signingSecretKey!,
                    {
                        context,
                        extraEntropy: hedge,
                    },
                );
                if (signature.byteLength !== mlDsa65SignatureByteLength) {
                    throw new BrowserLocalKeyProviderError(
                        'CapabilityUnavailable',
                        'ML-DSA-65 returned a malformed signature.',
                    );
                }
                requireActiveLeaseOwnerState(leaseState, 'signing');
                return signature.slice();
            } catch (error) {
                if (error instanceof BrowserLocalKeyProviderError) {
                    throw error;
                }
                throw new BrowserLocalKeyProviderError(
                    'CapabilityUnavailable',
                    'The browser-worker ML-DSA-65 signing operation failed.',
                    error,
                );
            } finally {
                message?.fill(0);
                context?.fill(0);
                hedge?.fill(0);
                signature?.fill(0);
            }
        },
        revoke: (): void => revokeSigningLease(leaseState),
    });

const createMailboxOperations = (
    leaseState: BrowserWorkerOwnedKeyOperationLeaseState,
): BrowserLocalExternalKeyProviderInput['mailbox'] =>
    Object.freeze({
        get encapsulationKey(): Uint8Array {
            const ownerState = requireActiveLeaseOwnerState(
                leaseState,
                'mailbox',
            );
            return ownerState.mailboxEncapsulationKey!.slice();
        },
        decapsulateClosedCiphertext: (input: Uint8Array): Uint8Array => {
            const ownerState = requireActiveLeaseOwnerState(
                leaseState,
                'mailbox',
            );
            const ciphertext = copyExactBytes(
                input,
                mlKem768CiphertextByteLength,
                'ML-KEM ciphertext',
            );
            let sharedSecret: Uint8Array | undefined;
            try {
                sharedSecret = ml_kem768.decapsulate(
                    ciphertext,
                    ownerState.mailboxSecretKey!,
                );
                if (
                    sharedSecret.byteLength !== mlKem768SharedSecretByteLength
                ) {
                    throw new BrowserLocalKeyProviderError(
                        'CapabilityUnavailable',
                        'ML-KEM-768 returned a malformed shared secret.',
                    );
                }
                requireActiveLeaseOwnerState(leaseState, 'mailbox');
                return sharedSecret.slice();
            } catch (error) {
                if (error instanceof BrowserLocalKeyProviderError) {
                    throw error;
                }
                throw new BrowserLocalKeyProviderError(
                    'CapabilityUnavailable',
                    'The browser-worker ML-KEM-768 decapsulation operation failed.',
                    error,
                );
            } finally {
                ciphertext.fill(0);
                sharedSecret?.fill(0);
            }
        },
        revoke: (): void => revokeMailboxLease(leaseState),
    });

const createOperationLease = (
    ownerState: BrowserWorkerOwnedKeyOwnerState,
): BrowserWorkerOwnedKeyOperationLease => {
    if (ownerState.activeLease !== undefined) {
        throw new BrowserLocalKeyProviderError(
            'CapabilityUnavailable',
            'The browser-worker key owner already has an active operation lease.',
        );
    }
    const leaseState: BrowserWorkerOwnedKeyOperationLeaseState = {
        mailboxIsActive: true,
        ownerState,
        signingIsActive: true,
    };
    ownerState.activeLease = leaseState;
    const mailbox = createMailboxOperations(leaseState);
    const signing = createSigningOperations(leaseState);

    return Object.freeze({
        mailbox,
        signing,
        close: (): void => closeOperationLease(leaseState),
    });
};

const generateSigningKeyPair = (): Readonly<{
    secretKey: Uint8Array;
    verificationKey: Uint8Array;
}> => {
    const seed = readKeyGenerationSeed(
        mlDsa65SeedByteLength,
        'ML-DSA-65 key',
    );
    let keyPair: ReturnType<typeof ml_dsa65.keygen> | undefined;
    try {
        keyPair = ml_dsa65.keygen(seed);
        return Object.freeze({
            secretKey: requireOwnedExactBytes(
                keyPair.secretKey,
                mlDsa65SecretKeyByteLength,
                'ML-DSA-65 secret key',
            ),
            verificationKey: requireOwnedExactBytes(
                keyPair.publicKey,
                mlDsa65PublicKeyByteLength,
                'ML-DSA-65 verification key',
            ),
        });
    } catch (error) {
        keyPair?.secretKey.fill(0);
        keyPair?.publicKey.fill(0);
        if (error instanceof BrowserLocalKeyProviderError) {
            throw error;
        }
        throw new BrowserLocalKeyProviderError(
            'CapabilityUnavailable',
            'Browser-worker ML-DSA-65 key generation failed.',
            error,
        );
    } finally {
        seed.fill(0);
    }
};

const generateMailboxKeyPair = (): Readonly<{
    encapsulationKey: Uint8Array;
    secretKey: Uint8Array;
}> => {
    const seed = readKeyGenerationSeed(
        mlKem768SeedByteLength,
        'ML-KEM-768 key',
    );
    let keyPair: ReturnType<typeof ml_kem768.keygen> | undefined;
    try {
        keyPair = ml_kem768.keygen(seed);
        return Object.freeze({
            encapsulationKey: requireOwnedExactBytes(
                keyPair.publicKey,
                mlKem768PublicKeyByteLength,
                'ML-KEM-768 encapsulation key',
            ),
            secretKey: requireOwnedExactBytes(
                keyPair.secretKey,
                mlKem768SecretKeyByteLength,
                'ML-KEM-768 secret key',
            ),
        });
    } catch (error) {
        keyPair?.secretKey.fill(0);
        keyPair?.publicKey.fill(0);
        if (error instanceof BrowserLocalKeyProviderError) {
            throw error;
        }
        throw new BrowserLocalKeyProviderError(
            'CapabilityUnavailable',
            'Browser-worker ML-KEM-768 key generation failed.',
            error,
        );
    } finally {
        seed.fill(0);
    }
};

export const openBrowserWorkerOwnedKeyOwner = (input?: {
    readonly signal?: AbortSignal;
}): BrowserWorkerOwnedKeyOwner => {
    requireWorkerCompatibleRealm();
    throwIfAborted(input?.signal);

    let signingKeyPair:
        | Readonly<{
              secretKey: Uint8Array;
              verificationKey: Uint8Array;
          }>
        | undefined;
    let mailboxKeyPair:
        | Readonly<{
              encapsulationKey: Uint8Array;
              secretKey: Uint8Array;
          }>
        | undefined;
    try {
        signingKeyPair = generateSigningKeyPair();
        throwIfAborted(input?.signal);
        mailboxKeyPair = generateMailboxKeyPair();
        throwIfAborted(input?.signal);
    } catch (error) {
        signingKeyPair?.secretKey.fill(0);
        signingKeyPair?.verificationKey.fill(0);
        mailboxKeyPair?.secretKey.fill(0);
        mailboxKeyPair?.encapsulationKey.fill(0);
        throw error;
    }
    if (signingKeyPair === undefined || mailboxKeyPair === undefined) {
        signingKeyPair?.secretKey.fill(0);
        signingKeyPair?.verificationKey.fill(0);
        mailboxKeyPair?.secretKey.fill(0);
        mailboxKeyPair?.encapsulationKey.fill(0);
        throw new BrowserLocalKeyProviderError(
            'CapabilityUnavailable',
            'Browser-worker key generation did not return both required key pairs.',
        );
    }

    const ownerState: BrowserWorkerOwnedKeyOwnerState = {
        activeLease: undefined,
        abortListener: undefined,
        abortSignal: input?.signal,
        mailboxEncapsulationKey: mailboxKeyPair.encapsulationKey,
        mailboxSecretKey: mailboxKeyPair.secretKey,
        signingSecretKey: signingKeyPair.secretKey,
        signingVerificationKey: signingKeyPair.verificationKey,
        state: 'active',
    };
    let owner: BrowserWorkerOwnedKeyOwner;
    owner = Object.freeze({
        copyPublicKeyMaterial: (): BrowserWorkerOwnedKeyPublicMaterial => {
            const currentOwnerState = requireActiveOwnerState(owner);
            return Object.freeze({
                mailboxEncapsulationKey:
                    currentOwnerState.mailboxEncapsulationKey!.slice(),
                signingVerificationKey:
                    currentOwnerState.signingVerificationKey!.slice(),
            });
        },
        openOperationLease: (): BrowserWorkerOwnedKeyOperationLease =>
            createOperationLease(requireActiveOwnerState(owner)),
        close: (): void => releaseOwnerState(ownerState),
    });
    browserWorkerOwnedKeyOwnerStates.set(owner, ownerState);

    if (input?.signal !== undefined) {
        const abortListener = (): void => releaseOwnerState(ownerState);
        ownerState.abortListener = abortListener;
        input.signal.addEventListener('abort', abortListener, { once: true });
        if (input.signal.aborted) {
            releaseOwnerState(ownerState);
            input.signal.throwIfAborted();
        }
    }

    return owner;
};
