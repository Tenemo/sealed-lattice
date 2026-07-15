import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';

import type { BrowserLocalExternalKeyProviderInput } from '../../src/index.js';

type SigningKeyPair = Readonly<{
    readonly publicKey: Uint8Array;
    readonly secretKey: Uint8Array;
}>;

type MailboxKeyPair = Readonly<{
    readonly publicKey: Uint8Array;
    readonly secretKey: Uint8Array;
}>;

export const createBrowserLocalSigningOperations = (
    keyPair: SigningKeyPair,
): BrowserLocalExternalKeyProviderInput['signing'] => {
    const verificationKey = keyPair.publicKey.slice();
    const secretKey = keyPair.secretKey.slice();
    let active = true;

    return {
        verificationKey,
        signClosedMessage: ({ message, context, hedge }) => {
            if (!active) {
                throw new Error('The test signing operation is revoked.');
            }
            return ml_dsa65.sign(message, secretKey, {
                context,
                extraEntropy: hedge,
            });
        },
        revoke: () => {
            if (!active) {
                return;
            }
            active = false;
            secretKey.fill(0);
            verificationKey.fill(0);
        },
    };
};

export const createBrowserLocalMailboxOperations = (
    keyPair: MailboxKeyPair,
): BrowserLocalExternalKeyProviderInput['mailbox'] => {
    const encapsulationKey = keyPair.publicKey.slice();
    const secretKey = keyPair.secretKey.slice();
    let active = true;

    return {
        encapsulationKey,
        decapsulateClosedCiphertext: (ciphertext) => {
            if (!active) {
                throw new Error('The test mailbox operation is revoked.');
            }
            return ml_kem768.decapsulate(ciphertext, secretKey);
        },
        revoke: () => {
            if (!active) {
                return;
            }
            active = false;
            secretKey.fill(0);
            encapsulationKey.fill(0);
        },
    };
};

export const createBrowserLocalKeyOperations = (input: {
    readonly signing: SigningKeyPair;
    readonly mailbox: MailboxKeyPair;
}): Pick<BrowserLocalExternalKeyProviderInput, 'mailbox' | 'signing'> => ({
    signing: createBrowserLocalSigningOperations(input.signing),
    mailbox: createBrowserLocalMailboxOperations(input.mailbox),
});
