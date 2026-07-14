import { bytesToHex } from '@noble/hashes/utils.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { describe, expect, it } from 'vitest';

import {
    BrowserLocalKeyProviderError,
    type BrowserLocalMailboxCapability,
    decapsulateClosedMailboxCiphertext,
    encapsulateFreshMailbox,
    openBrowserLocalExternalKeyProvider,
    signFreshMailboxEnvelope,
    signStateWitnessVoteMessage,
} from '../../src/browser-local-key-provider.js';

const textEncoder = new TextEncoder();
const mailboxSignatureContext = textEncoder.encode(
    'sealed-lattice/mailbox-signature/v1',
);

const createKeyMaterial = () => {
    const signing = ml_dsa65.keygen(
        new Uint8Array(ml_dsa65.lengths.seed!).fill(0x31),
    );
    const mailbox = ml_kem768.keygen(
        new Uint8Array(ml_kem768.lengths.seed!).fill(0x52),
    );

    return { signing, mailbox };
};

const deterministicEntropy = () => {
    let callIndex = 0;

    return (byteLength: number): Uint8Array => {
        callIndex += 1;

        return new Uint8Array(byteLength).fill(callIndex);
    };
};

const expectProviderError = (
    operation: () => unknown,
    code: BrowserLocalKeyProviderError['code'],
): void => {
    try {
        operation();
        throw new Error(
            'Expected browser-local key-provider operation to fail.',
        );
    } catch (error) {
        expect(error).toBeInstanceOf(BrowserLocalKeyProviderError);
        expect((error as BrowserLocalKeyProviderError).code).toBe(code);
    }
};

describe('browser-local external key provider', () => {
    it('opens distinct opaque capabilities only after both roster key pairs pass self-tests', () => {
        const { signing, mailbox } = createKeyMaterial();
        const provider = openBrowserLocalExternalKeyProvider({
            signing: {
                expectedVerificationKey: signing.publicKey,
                secretKey: signing.secretKey,
            },
            mailbox: {
                expectedEncapsulationKey: mailbox.publicKey,
                decapsulationKey: mailbox.secretKey,
            },
            entropy: deterministicEntropy(),
        });

        expect(provider.signingCapability).not.toBe(provider.mailboxCapability);
        expect(Object.isFrozen(provider)).toBe(true);
        expect(Object.isFrozen(provider.signingCapability)).toBe(true);
        expect(Object.isFrozen(provider.mailboxCapability)).toBe(true);

        const envelopeHashBytes = new Uint8Array(64).fill(0xa7);
        const freshMailbox = encapsulateFreshMailbox({
            signingCapability: provider.signingCapability,
            recipientEncapsulationKey: mailbox.publicKey,
        });
        const signature = signFreshMailboxEnvelope({
            signingCapability: provider.signingCapability,
            signingPermit: freshMailbox.signingPermit,
            envelopeHash: bytesToHex(envelopeHashBytes),
        });
        expect(
            ml_dsa65.verify(signature, envelopeHashBytes, signing.publicKey, {
                context: mailboxSignatureContext,
            }),
        ).toBe(true);
        expectProviderError(
            () =>
                signFreshMailboxEnvelope({
                    signingCapability: provider.signingCapability,
                    signingPermit: freshMailbox.signingPermit,
                    envelopeHash: bytesToHex(envelopeHashBytes),
                }),
            'CapabilityUnavailable',
        );

        const encapsulation = ml_kem768.encapsulate(
            mailbox.publicKey,
            new Uint8Array(ml_kem768.lengths.msg!).fill(0x8d),
        );
        const recoveredSharedSecret = decapsulateClosedMailboxCiphertext({
            capability: provider.mailboxCapability,
            ciphertext: encapsulation.cipherText,
        });
        expect(recoveredSharedSecret).toEqual(encapsulation.sharedSecret);
    });

    it('refuses malformed and mismatched frozen roster keys', () => {
        const first = createKeyMaterial();
        const secondSigning = ml_dsa65.keygen(
            new Uint8Array(ml_dsa65.lengths.seed!).fill(0x72),
        );
        const secondMailbox = ml_kem768.keygen(
            new Uint8Array(ml_kem768.lengths.seed!).fill(0x93),
        );

        expectProviderError(
            () =>
                openBrowserLocalExternalKeyProvider({
                    signing: {
                        expectedVerificationKey: secondSigning.publicKey,
                        secretKey: first.signing.secretKey,
                    },
                    mailbox: {
                        expectedEncapsulationKey: first.mailbox.publicKey,
                        decapsulationKey: first.mailbox.secretKey,
                    },
                    entropy: deterministicEntropy(),
                }),
            'KeyMismatch',
        );
        expectProviderError(
            () =>
                openBrowserLocalExternalKeyProvider({
                    signing: {
                        expectedVerificationKey: first.signing.publicKey,
                        secretKey: first.signing.secretKey,
                    },
                    mailbox: {
                        expectedEncapsulationKey: secondMailbox.publicKey,
                        decapsulationKey: first.mailbox.secretKey,
                    },
                    entropy: deterministicEntropy(),
                }),
            'KeyMismatch',
        );
        expectProviderError(
            () =>
                openBrowserLocalExternalKeyProvider({
                    signing: {
                        expectedVerificationKey:
                            first.signing.publicKey.subarray(1),
                        secretKey: first.signing.secretKey,
                    },
                    mailbox: {
                        expectedEncapsulationKey: first.mailbox.publicKey,
                        decapsulationKey: first.mailbox.secretKey,
                    },
                    entropy: deterministicEntropy(),
                }),
            'MalformedKey',
        );
    });

    it('fails closed when entropy is unavailable or returns the wrong length', () => {
        const { signing, mailbox } = createKeyMaterial();
        const input = {
            signing: {
                expectedVerificationKey: signing.publicKey,
                secretKey: signing.secretKey,
            },
            mailbox: {
                expectedEncapsulationKey: mailbox.publicKey,
                decapsulationKey: mailbox.secretKey,
            },
        } as const;

        expectProviderError(
            () =>
                openBrowserLocalExternalKeyProvider({
                    ...input,
                    entropy: () => {
                        throw new Error('entropy source failed');
                    },
                }),
            'EntropyUnavailable',
        );
        expectProviderError(
            () =>
                openBrowserLocalExternalKeyProvider({
                    ...input,
                    entropy: (byteLength) => new Uint8Array(byteLength - 1),
                }),
            'EntropyUnavailable',
        );

        let entropyAvailable = true;
        const provider = openBrowserLocalExternalKeyProvider({
            ...input,
            entropy: (byteLength) => {
                if (!entropyAvailable) {
                    throw new Error('entropy source was lost after opening');
                }
                return new Uint8Array(byteLength).fill(0x58);
            },
        });
        entropyAvailable = false;
        expectProviderError(
            () =>
                encapsulateFreshMailbox({
                    signingCapability: provider.signingCapability,
                    recipientEncapsulationKey: mailbox.publicKey,
                }),
            'EntropyUnavailable',
        );
        provider.close();
    });

    it('keeps revocation scoped to the named capability and closes both capabilities', () => {
        const { signing, mailbox } = createKeyMaterial();
        const provider = openBrowserLocalExternalKeyProvider({
            signing: {
                expectedVerificationKey: signing.publicKey,
                secretKey: signing.secretKey,
            },
            mailbox: {
                expectedEncapsulationKey: mailbox.publicKey,
                decapsulationKey: mailbox.secretKey,
            },
            entropy: deterministicEntropy(),
        });
        const encapsulation = ml_kem768.encapsulate(
            mailbox.publicKey,
            new Uint8Array(ml_kem768.lengths.msg!).fill(0x21),
        );

        provider.revokeSigningCapability();
        expectProviderError(
            () =>
                signStateWitnessVoteMessage({
                    capability: provider.signingCapability,
                    signatureMessage: new Uint8Array(64),
                }),
            'CapabilityUnavailable',
        );
        expect(
            decapsulateClosedMailboxCiphertext({
                capability: provider.mailboxCapability,
                ciphertext: encapsulation.cipherText,
            }),
        ).toEqual(encapsulation.sharedSecret);

        provider.close();
        expectProviderError(
            () =>
                decapsulateClosedMailboxCiphertext({
                    capability: provider.mailboxCapability,
                    ciphertext: encapsulation.cipherText,
                }),
            'CapabilityUnavailable',
        );
    });

    it('rejects capability-kind substitution at runtime', () => {
        const { signing, mailbox } = createKeyMaterial();
        const provider = openBrowserLocalExternalKeyProvider({
            signing: {
                expectedVerificationKey: signing.publicKey,
                secretKey: signing.secretKey,
            },
            mailbox: {
                expectedEncapsulationKey: mailbox.publicKey,
                decapsulationKey: mailbox.secretKey,
            },
            entropy: deterministicEntropy(),
        });

        expectProviderError(
            () =>
                decapsulateClosedMailboxCiphertext({
                    capability:
                        provider.signingCapability as unknown as BrowserLocalMailboxCapability,
                    ciphertext: new Uint8Array(ml_kem768.lengths.cipherText!),
                }),
            'CapabilityUnavailable',
        );
        const freshMailbox = encapsulateFreshMailbox({
            signingCapability: provider.signingCapability,
            recipientEncapsulationKey: mailbox.publicKey,
        });
        expect(freshMailbox.envelopeAttemptIdentifier).toHaveLength(32);
        expect(
            ml_kem768.decapsulate(freshMailbox.ciphertext, mailbox.secretKey),
        ).toEqual(freshMailbox.sharedSecret);
    });
});
