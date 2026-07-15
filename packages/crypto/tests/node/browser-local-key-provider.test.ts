import { bytesToHex } from '@noble/hashes/utils.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { describe, expect, it, vi } from 'vitest';

import {
    BrowserLocalKeyProviderError,
    type BrowserLocalExternalKeyProviderInput,
    type BrowserLocalMailboxCapability,
    type BrowserLocalSigningCapability,
    decapsulateClosedMailboxCiphertext,
    encapsulateFreshMailbox,
    encapsulateResetSafeSetupMailbox,
    openBrowserLocalExternalKeyProvider,
    signFreshMailboxEnvelope,
} from '../../src/browser-local-key-provider.js';

import {
    createBrowserLocalKeyOperations,
    createBrowserLocalMailboxOperations,
    createBrowserLocalSigningOperations,
    defaultResetSafeSetupMailboxScope,
} from '#packages/crypto/tests/support/browser-local-key-operations';

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

const setupMailboxSlot = Object.freeze({
    ...defaultResetSafeSetupMailboxScope,
    recipientParticipantId: '66'.repeat(64),
    producerSequence: '0',
    payloadType: 2 as const,
    statementHash: '77'.repeat(64),
    orderedMaterialRoots: Object.freeze(['88'.repeat(64)]),
});

const setupMailboxSlotHash = 'a5'.repeat(64);
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
            ...createBrowserLocalKeyOperations({ signing, mailbox }),
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
        signature.fill(0);
        freshMailbox.ciphertext.fill(0);
        freshMailbox.envelopeAttemptIdentifier.fill(0);
        freshMailbox.sharedSecret.fill(0);
        encapsulation.cipherText.fill(0);
        encapsulation.sharedSecret.fill(0);
        recoveredSharedSecret.fill(0);
        provider.close();
    });

    it('rejects one operation object reused for signing and mailbox capabilities', () => {
        const { signing, mailbox } = createKeyMaterial();
        const signingOperations = createBrowserLocalSigningOperations(signing);
        const mailboxOperations = createBrowserLocalMailboxOperations(mailbox);
        let revocationCount = 0;
        const reusedOperations = {
            decapsulateClosedCiphertext:
                mailboxOperations.decapsulateClosedCiphertext,
            encapsulationKey: mailboxOperations.encapsulationKey,
            revoke: () => {
                revocationCount += 1;
                signingOperations.revoke();
                mailboxOperations.revoke();
            },
            signClosedMessage: signingOperations.signClosedMessage,
            verificationKey: signingOperations.verificationKey,
        };

        expectProviderError(
            () =>
                openBrowserLocalExternalKeyProvider({
                    mailbox: reusedOperations,
                    signing: reusedOperations,
                }),
            'UnsupportedProvider',
        );
        expect(revocationCount).toBe(1);
    });

    it('replays one reset-safe setup-mailbox operation byte-identically without deriving another view', () => {
        const { signing, mailbox } = createKeyMaterial();
        const randomnessObservation = {
            encapsulationConsumptionCount: 0,
        };
        const provider = openBrowserLocalExternalKeyProvider({
            ...createBrowserLocalKeyOperations({
                signing,
                mailbox,
                resetSafeSetupMailboxRandomnessObservation:
                    randomnessObservation,
            }),
        });
        expect(randomnessObservation).toEqual({
            encapsulationConsumptionCount: 0,
        });

        const first = encapsulateResetSafeSetupMailbox({
            recipientEncapsulationKey: mailbox.publicKey,
            setupMailboxSlot,
            setupMailboxSlotHash,
            signingCapability: provider.signingCapability,
            sourceVerificationKey: signing.publicKey,
        });
        const firstCiphertext = first.ciphertext.slice();
        const firstAttemptIdentifier = first.envelopeAttemptIdentifier.slice();
        const firstSharedSecret = first.sharedSecret.slice();
        first.ciphertext.fill(0);
        first.envelopeAttemptIdentifier.fill(0);
        first.sharedSecret.fill(0);

        const replay = encapsulateResetSafeSetupMailbox({
            recipientEncapsulationKey: mailbox.publicKey,
            setupMailboxSlot,
            setupMailboxSlotHash,
            signingCapability: provider.signingCapability,
            sourceVerificationKey: signing.publicKey,
        });
        expect(replay.ciphertext).toEqual(firstCiphertext);
        expect(replay.envelopeAttemptIdentifier).toEqual(
            firstAttemptIdentifier,
        );
        expect(replay.sharedSecret).toEqual(firstSharedSecret);
        expect(
            ml_kem768.decapsulate(replay.ciphertext, mailbox.secretKey),
        ).toEqual(replay.sharedSecret);
        expect(randomnessObservation).toEqual({
            encapsulationConsumptionCount: 1,
        });

        provider.close();
    });

    it('refuses conflicting reset-safe producer slots as typed equivocation', () => {
        const { signing, mailbox } = createKeyMaterial();
        const provider = openBrowserLocalExternalKeyProvider({
            ...createBrowserLocalKeyOperations({ signing, mailbox }),
        });
        const first = encapsulateResetSafeSetupMailbox({
            recipientEncapsulationKey: mailbox.publicKey,
            setupMailboxSlot,
            setupMailboxSlotHash,
            signingCapability: provider.signingCapability,
            sourceVerificationKey: signing.publicKey,
        });
        expectProviderError(
            () =>
                encapsulateResetSafeSetupMailbox({
                    recipientEncapsulationKey: mailbox.publicKey,
                    setupMailboxSlot: {
                        ...setupMailboxSlot,
                        statementHash: '99'.repeat(64),
                    },
                    setupMailboxSlotHash: 'c7'.repeat(64),
                    signingCapability: provider.signingCapability,
                    sourceVerificationKey: signing.publicKey,
                }),
            'Equivocation',
        );
        const wrongRecipient = ml_kem768.keygen(
            new Uint8Array(ml_kem768.lengths.seed!).fill(0xe9),
        );
        expectProviderError(
            () =>
                encapsulateResetSafeSetupMailbox({
                    recipientEncapsulationKey: wrongRecipient.publicKey,
                    setupMailboxSlot,
                    setupMailboxSlotHash,
                    signingCapability: provider.signingCapability,
                    sourceVerificationKey: signing.publicKey,
                }),
            'Equivocation',
        );

        first.ciphertext.fill(0);
        first.envelopeAttemptIdentifier.fill(0);
        first.sharedSecret.fill(0);
        provider.close();
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
                        ...createBrowserLocalSigningOperations(first.signing),
                        verificationKey: secondSigning.publicKey,
                    },
                    mailbox: createBrowserLocalMailboxOperations(first.mailbox),
                }),
            'KeyMismatch',
        );
        expectProviderError(
            () =>
                openBrowserLocalExternalKeyProvider({
                    signing: createBrowserLocalSigningOperations(first.signing),
                    mailbox: {
                        ...createBrowserLocalMailboxOperations(first.mailbox),
                        encapsulationKey: secondMailbox.publicKey,
                    },
                }),
            'KeyMismatch',
        );
        expectProviderError(
            () =>
                openBrowserLocalExternalKeyProvider({
                    signing: {
                        ...createBrowserLocalSigningOperations(first.signing),
                        verificationKey: first.signing.publicKey.subarray(1),
                    },
                    mailbox: createBrowserLocalMailboxOperations(first.mailbox),
                }),
            'MalformedKey',
        );
        expectProviderError(
            () =>
                openBrowserLocalExternalKeyProvider({
                    signing: createBrowserLocalSigningOperations(first.signing),
                    mailbox: {
                        ...createBrowserLocalMailboxOperations(first.mailbox),
                        encapsulationKey: new Uint8Array(
                            ml_kem768.lengths.publicKey!,
                        ).fill(0xff),
                    },
                }),
            'MalformedKey',
        );
    });

    it('fails closed when Web Crypto entropy is unavailable during opening or use', () => {
        const { signing, mailbox } = createKeyMaterial();
        const entropySpy = vi.spyOn(globalThis.crypto, 'getRandomValues');
        try {
            entropySpy.mockImplementationOnce(() => {
                throw new Error('entropy source failed while opening');
            });
            expectProviderError(
                () =>
                    openBrowserLocalExternalKeyProvider({
                        ...createBrowserLocalKeyOperations({
                            signing,
                            mailbox,
                        }),
                    }),
                'EntropyUnavailable',
            );

            const provider = openBrowserLocalExternalKeyProvider({
                ...createBrowserLocalKeyOperations({ signing, mailbox }),
            });
            entropySpy.mockImplementationOnce(() => {
                throw new Error('entropy source failed after opening');
            });
            expectProviderError(
                () =>
                    encapsulateFreshMailbox({
                        signingCapability: provider.signingCapability,
                        recipientEncapsulationKey: mailbox.publicKey,
                    }),
                'EntropyUnavailable',
            );
            provider.close();
        } finally {
            entropySpy.mockRestore();
        }
    });

    it('fails closed for unsupported, lost, and wrong-context reset-safe randomness capabilities', () => {
        const { signing, mailbox } = createKeyMaterial();
        const keyOperations = createBrowserLocalKeyOperations({
            signing,
            mailbox,
        });
        const providerWithoutResetSafeRandomness =
            openBrowserLocalExternalKeyProvider({
                signing: keyOperations.signing,
                mailbox: keyOperations.mailbox,
            });
        expectProviderError(
            () =>
                encapsulateResetSafeSetupMailbox({
                    recipientEncapsulationKey: mailbox.publicKey,
                    setupMailboxSlot,
                    setupMailboxSlotHash,
                    signingCapability:
                        providerWithoutResetSafeRandomness.signingCapability,
                    sourceVerificationKey: signing.publicKey,
                }),
            'UnsupportedProvider',
        );
        providerWithoutResetSafeRandomness.close();

        const wrongContextProvider = openBrowserLocalExternalKeyProvider({
            ...createBrowserLocalKeyOperations({
                signing,
                mailbox,
                resetSafeSetupMailboxScope: {
                    ...defaultResetSafeSetupMailboxScope,
                    actionContextHash: 'f1'.repeat(64),
                },
            }),
        });
        expectProviderError(
            () =>
                encapsulateResetSafeSetupMailbox({
                    recipientEncapsulationKey: mailbox.publicKey,
                    setupMailboxSlot,
                    setupMailboxSlotHash,
                    signingCapability: wrongContextProvider.signingCapability,
                    sourceVerificationKey: signing.publicKey,
                }),
            'KeyMismatch',
        );
        wrongContextProvider.close();

        const revocableOperations = createBrowserLocalKeyOperations({
            signing,
            mailbox,
        });
        const providerWithLostRandomness = openBrowserLocalExternalKeyProvider({
            ...revocableOperations,
        });
        revocableOperations.resetSafeSetupMailboxRandomness!.revoke();
        expectProviderError(
            () =>
                encapsulateResetSafeSetupMailbox({
                    recipientEncapsulationKey: mailbox.publicKey,
                    setupMailboxSlot,
                    setupMailboxSlotHash,
                    signingCapability:
                        providerWithLostRandomness.signingCapability,
                    sourceVerificationKey: signing.publicKey,
                }),
            'CapabilityUnavailable',
        );
        providerWithLostRandomness.close();
    });

    it('rejects signing providers that ignore exact hedges or replace their frozen key', () => {
        const first = createKeyMaterial();
        const replacementSigning = ml_dsa65.keygen(
            new Uint8Array(ml_dsa65.lengths.seed!).fill(0xfa),
        );
        let hiddenRandomnessCounter = 0;
        expectProviderError(
            () =>
                openBrowserLocalExternalKeyProvider({
                    ...createBrowserLocalKeyOperations(first),
                    signing: {
                        verificationKey: first.signing.publicKey,
                        signClosedMessage: ({ message, context }) => {
                            hiddenRandomnessCounter += 1;
                            return ml_dsa65.sign(
                                message,
                                first.signing.secretKey,
                                {
                                    context,
                                    extraEntropy: new Uint8Array(32).fill(
                                        hiddenRandomnessCounter,
                                    ),
                                },
                            );
                        },
                        revoke: () => undefined,
                    },
                }),
            'UnsupportedProvider',
        );
        expectProviderError(
            () =>
                openBrowserLocalExternalKeyProvider({
                    ...createBrowserLocalKeyOperations(first),
                    signing: {
                        verificationKey: first.signing.publicKey,
                        signClosedMessage: ({ message, context }) =>
                            ml_dsa65.sign(message, first.signing.secretKey, {
                                context,
                                extraEntropy: false,
                            }),
                        revoke: () => undefined,
                    },
                }),
            'UnsupportedProvider',
        );

        let activeSigningSecretKey = first.signing.secretKey;
        const provider = openBrowserLocalExternalKeyProvider({
            ...createBrowserLocalKeyOperations(first),
            signing: {
                verificationKey: first.signing.publicKey,
                signClosedMessage: ({ message, context, hedge }) =>
                    ml_dsa65.sign(message, activeSigningSecretKey, {
                        context,
                        extraEntropy: hedge,
                    }),
                revoke: () => undefined,
            },
        });
        activeSigningSecretKey = replacementSigning.secretKey;
        const freshMailbox = encapsulateFreshMailbox({
            recipientEncapsulationKey: first.mailbox.publicKey,
            signingCapability: provider.signingCapability,
        });
        expectProviderError(
            () =>
                signFreshMailboxEnvelope({
                    envelopeHash: 'b6'.repeat(64),
                    signingCapability: provider.signingCapability,
                    signingPermit: freshMailbox.signingPermit,
                }),
            'KeyMismatch',
        );
        provider.close();
    });

    it('detects mailbox-key replacement before protocol decapsulation', () => {
        const first = createKeyMaterial();
        const replacementMailbox = ml_kem768.keygen(
            new Uint8Array(ml_kem768.lengths.seed!).fill(0xfb),
        );
        let activeMailboxSecretKey = first.mailbox.secretKey;
        const provider = openBrowserLocalExternalKeyProvider({
            ...createBrowserLocalKeyOperations(first),
            mailbox: {
                encapsulationKey: first.mailbox.publicKey,
                decapsulateClosedCiphertext: (ciphertext) =>
                    ml_kem768.decapsulate(ciphertext, activeMailboxSecretKey),
                revoke: () => undefined,
            },
        });
        const encapsulation = ml_kem768.encapsulate(
            first.mailbox.publicKey,
            new Uint8Array(ml_kem768.lengths.msg!).fill(0x9b),
        );

        activeMailboxSecretKey = replacementMailbox.secretKey;
        expectProviderError(
            () =>
                decapsulateClosedMailboxCiphertext({
                    capability: provider.mailboxCapability,
                    ciphertext: encapsulation.cipherText,
                }),
            'KeyMismatch',
        );

        encapsulation.cipherText.fill(0);
        encapsulation.sharedSecret.fill(0);
        provider.close();
    });

    it('fails closed after external signing or mailbox capability loss', () => {
        const signingLossMaterial = createKeyMaterial();
        const signingLossOperations =
            createBrowserLocalKeyOperations(signingLossMaterial);
        const signingLossProvider = openBrowserLocalExternalKeyProvider({
            ...signingLossOperations,
        });
        const freshMailbox = encapsulateFreshMailbox({
            signingCapability: signingLossProvider.signingCapability,
            recipientEncapsulationKey: signingLossMaterial.mailbox.publicKey,
        });
        signingLossOperations.signing.revoke();
        expectProviderError(
            () =>
                signFreshMailboxEnvelope({
                    envelopeHash: 'd1'.repeat(64),
                    signingCapability: signingLossProvider.signingCapability,
                    signingPermit: freshMailbox.signingPermit,
                }),
            'CapabilityUnavailable',
        );
        freshMailbox.ciphertext.fill(0);
        freshMailbox.envelopeAttemptIdentifier.fill(0);
        freshMailbox.sharedSecret.fill(0);
        signingLossProvider.close();

        const mailboxLossMaterial = createKeyMaterial();
        const mailboxLossOperations =
            createBrowserLocalKeyOperations(mailboxLossMaterial);
        const mailboxLossProvider = openBrowserLocalExternalKeyProvider({
            ...mailboxLossOperations,
        });
        const mailboxCiphertext = ml_kem768.encapsulate(
            mailboxLossMaterial.mailbox.publicKey,
            new Uint8Array(ml_kem768.lengths.msg!).fill(0x4b),
        );
        mailboxLossOperations.mailbox.revoke();
        expectProviderError(
            () =>
                decapsulateClosedMailboxCiphertext({
                    capability: mailboxLossProvider.mailboxCapability,
                    ciphertext: mailboxCiphertext.cipherText,
                }),
            'CapabilityUnavailable',
        );
        mailboxCiphertext.cipherText.fill(0);
        mailboxCiphertext.sharedSecret.fill(0);
        mailboxLossProvider.close();
    });

    it('refuses asynchronous key operations without a remote fallback', () => {
        const signingMaterial = createKeyMaterial();
        const signingOperations =
            createBrowserLocalKeyOperations(signingMaterial);
        expectProviderError(
            () =>
                openBrowserLocalExternalKeyProvider({
                    ...signingOperations,
                    signing: {
                        ...signingOperations.signing,
                        signClosedMessage: (() =>
                            Promise.resolve(
                                new Uint8Array(ml_dsa65.lengths.signature!),
                            )) as unknown as BrowserLocalExternalKeyProviderInput['signing']['signClosedMessage'],
                    },
                }),
            'UnsupportedProvider',
        );

        const mailboxMaterial = createKeyMaterial();
        const mailboxOperations =
            createBrowserLocalKeyOperations(mailboxMaterial);
        expectProviderError(
            () =>
                openBrowserLocalExternalKeyProvider({
                    ...mailboxOperations,
                    mailbox: {
                        ...mailboxOperations.mailbox,
                        decapsulateClosedCiphertext: (() =>
                            Promise.resolve(
                                new Uint8Array(32),
                            )) as unknown as BrowserLocalExternalKeyProviderInput['mailbox']['decapsulateClosedCiphertext'],
                    },
                }),
            'UnsupportedProvider',
        );
    });

    it('keeps revocation scoped to the named capability and closes both capabilities', () => {
        const { signing, mailbox } = createKeyMaterial();
        const provider = openBrowserLocalExternalKeyProvider({
            ...createBrowserLocalKeyOperations({ signing, mailbox }),
        });
        const encapsulation = ml_kem768.encapsulate(
            mailbox.publicKey,
            new Uint8Array(ml_kem768.lengths.msg!).fill(0x21),
        );

        provider.revokeSigningCapability();
        expectProviderError(
            () =>
                encapsulateFreshMailbox({
                    signingCapability: provider.signingCapability,
                    recipientEncapsulationKey: mailbox.publicKey,
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

    it('invalidates every capability and attempts every external revocation when close callbacks fail', () => {
        const { signing, mailbox } = createKeyMaterial();
        const operations = createBrowserLocalKeyOperations({
            signing,
            mailbox,
        });
        const revocations: string[] = [];
        const provider = openBrowserLocalExternalKeyProvider({
            signing: {
                ...operations.signing,
                revoke: () => {
                    revocations.push('signing');
                    operations.signing.revoke();
                    throw new Error('signing revocation failed');
                },
            },
            mailbox: {
                ...operations.mailbox,
                revoke: () => {
                    revocations.push('mailbox');
                    operations.mailbox.revoke();
                    throw new Error('mailbox revocation failed');
                },
            },
            resetSafeSetupMailboxRandomness: {
                ...operations.resetSafeSetupMailboxRandomness!,
                revoke: () => {
                    revocations.push('reset-safe randomness');
                    operations.resetSafeSetupMailboxRandomness!.revoke();
                    throw new Error('randomness revocation failed');
                },
            },
        });
        const encapsulation = ml_kem768.encapsulate(
            mailbox.publicKey,
            new Uint8Array(ml_kem768.lengths.msg!).fill(0x64),
        );

        expectProviderError(() => provider.close(), 'CapabilityUnavailable');
        expect(revocations).toEqual([
            'reset-safe randomness',
            'signing',
            'mailbox',
        ]);
        expectProviderError(
            () =>
                encapsulateFreshMailbox({
                    signingCapability: provider.signingCapability,
                    recipientEncapsulationKey: mailbox.publicKey,
                }),
            'CapabilityUnavailable',
        );
        expectProviderError(
            () =>
                decapsulateClosedMailboxCiphertext({
                    capability: provider.mailboxCapability,
                    ciphertext: encapsulation.cipherText,
                }),
            'CapabilityUnavailable',
        );
        expect(() => provider.close()).not.toThrow();
    });

    it('attempts every external revocation when key self-testing and cleanup both fail', () => {
        const first = createKeyMaterial();
        const secondSigning = ml_dsa65.keygen(
            new Uint8Array(ml_dsa65.lengths.seed!).fill(0x75),
        );
        const operations = createBrowserLocalKeyOperations(first);
        const revocations: string[] = [];

        expectProviderError(
            () =>
                openBrowserLocalExternalKeyProvider({
                    signing: {
                        ...operations.signing,
                        verificationKey: secondSigning.publicKey,
                        revoke: () => {
                            revocations.push('signing');
                            operations.signing.revoke();
                            throw new Error('signing revocation failed');
                        },
                    },
                    mailbox: {
                        ...operations.mailbox,
                        revoke: () => {
                            revocations.push('mailbox');
                            operations.mailbox.revoke();
                            throw new Error('mailbox revocation failed');
                        },
                    },
                    resetSafeSetupMailboxRandomness: {
                        ...operations.resetSafeSetupMailboxRandomness!,
                        revoke: () => {
                            revocations.push('reset-safe randomness');
                            operations.resetSafeSetupMailboxRandomness!.revoke();
                            throw new Error('randomness revocation failed');
                        },
                    },
                }),
            'CapabilityUnavailable',
        );
        expect(revocations).toEqual([
            'reset-safe randomness',
            'signing',
            'mailbox',
        ]);
    });

    it('rejects capability-kind substitution at runtime', () => {
        const { signing, mailbox } = createKeyMaterial();
        const provider = openBrowserLocalExternalKeyProvider({
            ...createBrowserLocalKeyOperations({ signing, mailbox }),
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
        expectProviderError(
            () =>
                encapsulateFreshMailbox({
                    signingCapability:
                        provider.mailboxCapability as unknown as BrowserLocalSigningCapability,
                    recipientEncapsulationKey: mailbox.publicKey,
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
        freshMailbox.ciphertext.fill(0);
        freshMailbox.envelopeAttemptIdentifier.fill(0);
        freshMailbox.sharedSecret.fill(0);
        provider.close();
    });
});
