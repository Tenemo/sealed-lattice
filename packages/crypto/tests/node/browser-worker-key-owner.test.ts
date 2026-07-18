import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { afterEach, describe, expect, it, vi } from 'vitest';

import {
    BrowserLocalKeyProviderError,
    openBrowserLocalExternalKeyProvider,
} from '../../src/browser-local-key-provider.js';
import { openBrowserWorkerOwnedKeyOwner } from '../../src/browser-worker-key-owner.js';

const installDeterministicWebCrypto = (): ReturnType<typeof vi.fn> => {
    let nextByte = 1;
    const getRandomValues = vi.fn(
        <Value extends ArrayBufferView | null>(value: Value): Value => {
            if (!(value instanceof Uint8Array)) {
                throw new Error(
                    'The deterministic test CSPRNG accepts Uint8Array values only.',
                );
            }
            for (let byteIndex = 0; byteIndex < value.byteLength; byteIndex += 1) {
                value[byteIndex] = nextByte;
                nextByte = (nextByte + 29) & 0xff;
            }
            return value;
        },
    );
    vi.stubGlobal('crypto', { getRandomValues });
    return getRandomValues;
};

const expectProviderFailureCode = (
    operation: () => unknown,
    expectedCode: BrowserLocalKeyProviderError['code'],
): void => {
    try {
        operation();
        throw new Error('Expected the browser-worker key operation to fail.');
    } catch (error) {
        expect(error).toBeInstanceOf(BrowserLocalKeyProviderError);
        expect((error as BrowserLocalKeyProviderError).code).toBe(
            expectedCode,
        );
    }
};

afterEach(() => {
    vi.unstubAllGlobals();
});

describe('browser-worker-owned key owner', () => {
    it('generates both key pairs from worker CSPRNG bytes and renews closed-operation leases', () => {
        const getRandomValues = installDeterministicWebCrypto();
        const owner = openBrowserWorkerOwnedKeyOwner();
        const firstPublicMaterial = owner.copyPublicKeyMaterial();
        const originalSigningVerificationKey =
            firstPublicMaterial.signingVerificationKey.slice();
        const originalMailboxEncapsulationKey =
            firstPublicMaterial.mailboxEncapsulationKey.slice();

        expect(getRandomValues).toHaveBeenNthCalledWith(
            1,
            expect.objectContaining({
                byteLength: ml_dsa65.lengths.seed,
            }),
        );
        expect(getRandomValues).toHaveBeenNthCalledWith(
            2,
            expect.objectContaining({
                byteLength: ml_kem768.lengths.seed,
            }),
        );
        firstPublicMaterial.signingVerificationKey.fill(0);
        firstPublicMaterial.mailboxEncapsulationKey.fill(0);
        const secondPublicMaterial = owner.copyPublicKeyMaterial();
        expect(secondPublicMaterial.signingVerificationKey).toEqual(
            originalSigningVerificationKey,
        );
        expect(secondPublicMaterial.mailboxEncapsulationKey).toEqual(
            originalMailboxEncapsulationKey,
        );

        const lease = owner.openOperationLease();
        expectProviderFailureCode(
            () => owner.openOperationLease(),
            'CapabilityUnavailable',
        );
        const provider = openBrowserLocalExternalKeyProvider(lease);
        provider.close();

        const replacementLease = owner.openOperationLease();
        expect(replacementLease.signing.verificationKey).toEqual(
            originalSigningVerificationKey,
        );
        expect(replacementLease.mailbox.encapsulationKey).toEqual(
            originalMailboxEncapsulationKey,
        );
        replacementLease.close();
        owner.close();
        owner.close();

        expectProviderFailureCode(
            () => owner.copyPublicKeyMaterial(),
            'CapabilityUnavailable',
        );
        expectProviderFailureCode(
            () => replacementLease.signing.verificationKey,
            'CapabilityUnavailable',
        );
        expectProviderFailureCode(
            () => replacementLease.mailbox.encapsulationKey,
            'CapabilityUnavailable',
        );

        originalSigningVerificationKey.fill(0);
        originalMailboxEncapsulationKey.fill(0);
        secondPublicMaterial.signingVerificationKey.fill(0);
        secondPublicMaterial.mailboxEncapsulationKey.fill(0);
    });

    it('signs and decapsulates through copied inputs without releasing secret bytes or admitting malformed lengths', () => {
        installDeterministicWebCrypto();
        const owner = openBrowserWorkerOwnedKeyOwner();
        const publicMaterial = owner.copyPublicKeyMaterial();
        const lease = owner.openOperationLease();
        const message = new Uint8Array([9, 7, 5, 3, 1]);
        const context = new TextEncoder().encode(
            'sealed-lattice/browser-worker-key-owner-test/v1',
        );
        const hedge = new Uint8Array(32).fill(0x73);
        const messageBeforeSigning = message.slice();
        const contextBeforeSigning = context.slice();
        const hedgeBeforeSigning = hedge.slice();
        const signature = lease.signing.signClosedMessage({
            context,
            hedge,
            message,
        });

        expect(
            ml_dsa65.verify(
                signature,
                message,
                publicMaterial.signingVerificationKey,
                { context },
            ),
        ).toBe(true);
        expect(message).toEqual(messageBeforeSigning);
        expect(context).toEqual(contextBeforeSigning);
        expect(hedge).toEqual(hedgeBeforeSigning);

        const encapsulationCoins = new Uint8Array(
            ml_kem768.lengths.msg!,
        ).fill(0x42);
        const encapsulation = ml_kem768.encapsulate(
            publicMaterial.mailboxEncapsulationKey,
            encapsulationCoins,
        );
        const ciphertextBeforeDecapsulation = encapsulation.cipherText.slice();
        const recoveredSharedSecret =
            lease.mailbox.decapsulateClosedCiphertext(
                encapsulation.cipherText,
            );
        expect(recoveredSharedSecret).toEqual(encapsulation.sharedSecret);
        expect(encapsulation.cipherText).toEqual(
            ciphertextBeforeDecapsulation,
        );

        expectProviderFailureCode(
            () =>
                lease.signing.signClosedMessage({
                    context,
                    hedge: hedge.subarray(1),
                    message,
                }),
            'MalformedRandomness',
        );
        expectProviderFailureCode(
            () =>
                lease.signing.signClosedMessage({
                    context: new Uint8Array(256),
                    hedge,
                    message,
                }),
            'MalformedRandomness',
        );
        expectProviderFailureCode(
            () =>
                lease.mailbox.decapsulateClosedCiphertext(
                    encapsulation.cipherText.subarray(1),
                ),
            'MalformedRandomness',
        );

        owner.close();
        expectProviderFailureCode(
            () =>
                lease.signing.signClosedMessage({
                    context,
                    hedge,
                    message,
                }),
            'CapabilityUnavailable',
        );
        expectProviderFailureCode(
            () =>
                lease.mailbox.decapsulateClosedCiphertext(
                    encapsulation.cipherText,
                ),
            'CapabilityUnavailable',
        );

        signature.fill(0);
        encapsulationCoins.fill(0);
        encapsulation.cipherText.fill(0);
        encapsulation.sharedSecret.fill(0);
        recoveredSharedSecret.fill(0);
        publicMaterial.signingVerificationKey.fill(0);
        publicMaterial.mailboxEncapsulationKey.fill(0);
        message.fill(0);
        context.fill(0);
        hedge.fill(0);
        messageBeforeSigning.fill(0);
        contextBeforeSigning.fill(0);
        hedgeBeforeSigning.fill(0);
        ciphertextBeforeDecapsulation.fill(0);
    });

    it('releases every operation when cancelled and fails before generation when cancellation is already known', () => {
        const getRandomValues = installDeterministicWebCrypto();
        const cancellation = new AbortController();
        const owner = openBrowserWorkerOwnedKeyOwner({
            signal: cancellation.signal,
        });
        const lease = owner.openOperationLease();
        cancellation.abort();

        expectProviderFailureCode(
            () => owner.copyPublicKeyMaterial(),
            'CapabilityUnavailable',
        );
        expectProviderFailureCode(
            () => lease.signing.verificationKey,
            'CapabilityUnavailable',
        );
        expectProviderFailureCode(
            () => lease.mailbox.encapsulationKey,
            'CapabilityUnavailable',
        );
        lease.close();
        owner.close();

        const alreadyCancelled = new AbortController();
        alreadyCancelled.abort();
        const entropyCallCountBeforeRejectedOpen = getRandomValues.mock.calls.length;
        expect(() =>
            openBrowserWorkerOwnedKeyOwner({
                signal: alreadyCancelled.signal,
            }),
        ).toThrow();
        expect(getRandomValues).toHaveBeenCalledTimes(
            entropyCallCountBeforeRejectedOpen,
        );
    });

    it('rejects document-owning browser realms and fails closed when production entropy is unavailable', () => {
        const getRandomValues = installDeterministicWebCrypto();
        vi.stubGlobal('document', Object.freeze({}));
        expectProviderFailureCode(
            () => openBrowserWorkerOwnedKeyOwner(),
            'UnsupportedProvider',
        );
        expect(getRandomValues).not.toHaveBeenCalled();

        vi.unstubAllGlobals();
        vi.stubGlobal('crypto', {
            getRandomValues: (): never => {
                throw new Error('No browser CSPRNG is available.');
            },
        });
        expectProviderFailureCode(
            () => openBrowserWorkerOwnedKeyOwner(),
            'EntropyUnavailable',
        );
    });
});
