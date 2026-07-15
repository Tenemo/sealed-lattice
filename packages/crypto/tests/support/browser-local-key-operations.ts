import { hexToBytes } from '@noble/hashes/utils.js';
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

type ResetSafeSetupMailboxScope = Readonly<{
    readonly actionContextHash: string;
    readonly ceremonyContextHash: string;
    readonly rosterHash: string;
    readonly sourceParticipantId: string;
    readonly suiteId: string;
}>;

export type ResetSafeSetupMailboxRandomnessObservation = {
    encapsulationConsumptionCount: number;
};

export const defaultResetSafeSetupMailboxScope = Object.freeze({
    suiteId: '11'.repeat(64),
    ceremonyContextHash: '22'.repeat(64),
    actionContextHash: '33'.repeat(64),
    rosterHash: '44'.repeat(64),
    sourceParticipantId: '55'.repeat(64),
});

const createResetSafeSetupMailboxRandomnessOperations = (
    scope: ResetSafeSetupMailboxScope,
    observation?: ResetSafeSetupMailboxRandomnessObservation,
): NonNullable<
    BrowserLocalExternalKeyProviderInput['resetSafeSetupMailboxRandomness']
> => {
    let active = true;

    return {
        ...scope,
        encapsulate: ({ recipientEncapsulationKey, setupMailboxSlotHash }) => {
            if (!active) {
                throw new Error(
                    'The test reset-safe mailbox randomness is revoked.',
                );
            }
            if (observation !== undefined) {
                observation.encapsulationConsumptionCount += 1;
            }
            const slotHashBytes = hexToBytes(setupMailboxSlotHash);
            let encapsulation:
                | Readonly<{
                      readonly cipherText: Uint8Array;
                      readonly sharedSecret: Uint8Array;
                  }>
                | undefined;
            try {
                encapsulation = ml_kem768.encapsulate(
                    recipientEncapsulationKey,
                    slotHashBytes.subarray(32),
                );
                return Object.freeze({
                    ciphertext: encapsulation.cipherText.slice(),
                    envelopeAttemptIdentifier: slotHashBytes.slice(0, 32),
                    sharedSecret: encapsulation.sharedSecret.slice(),
                });
            } finally {
                slotHashBytes.fill(0);
                encapsulation?.cipherText.fill(0);
                encapsulation?.sharedSecret.fill(0);
            }
        },
        revoke: () => {
            active = false;
        },
    };
};

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
    readonly resetSafeSetupMailboxRandomnessObservation?: ResetSafeSetupMailboxRandomnessObservation;
    readonly resetSafeSetupMailboxScope?: ResetSafeSetupMailboxScope;
}): Pick<
    BrowserLocalExternalKeyProviderInput,
    'mailbox' | 'resetSafeSetupMailboxRandomness' | 'signing'
> => ({
    signing: createBrowserLocalSigningOperations(input.signing),
    mailbox: createBrowserLocalMailboxOperations(input.mailbox),
    resetSafeSetupMailboxRandomness:
        createResetSafeSetupMailboxRandomnessOperations(
            input.resetSafeSetupMailboxScope ??
                defaultResetSafeSetupMailboxScope,
            input.resetSafeSetupMailboxRandomnessObservation,
        ),
});
