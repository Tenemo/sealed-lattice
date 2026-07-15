import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { describe, expect, it } from 'vitest';

import {
    BrowserLocalKeyProviderError,
    type BrowserLocalMailboxCapability,
    decapsulateClosedMailboxCiphertext,
    encapsulateFreshMailbox,
    encapsulateResetSafeSetupMailbox,
    openBrowserLocalExternalKeyProvider,
    signFreshMailboxEnvelope,
    signResetSafeSetupMailboxEnvelope,
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

const deterministicEntropy = () => {
    let callIndex = 0;

    return (byteLength: number): Uint8Array => {
        callIndex += 1;

        return new Uint8Array(byteLength).fill(callIndex);
    };
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
const setupMailboxEnvelopeHash = 'b6'.repeat(64);

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

    it('replays one reset-safe setup-mailbox operation byte-identically without deriving another view', () => {
        const { signing, mailbox } = createKeyMaterial();
        const randomnessObservation = {
            encapsulationConsumptionCount: 0,
            signatureConsumptionCount: 0,
        };
        const provider = openBrowserLocalExternalKeyProvider({
            ...createBrowserLocalKeyOperations({
                signing,
                mailbox,
                resetSafeSetupMailboxRandomnessObservation:
                    randomnessObservation,
            }),
            entropy: deterministicEntropy(),
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
        const firstSignature = signResetSafeSetupMailboxEnvelope({
            envelopeHash: setupMailboxEnvelopeHash,
            signingCapability: provider.signingCapability,
            signingPermit: first.signingPermit,
        });

        first.ciphertext.fill(0);
        first.envelopeAttemptIdentifier.fill(0);
        first.sharedSecret.fill(0);
        firstSignature.fill(0);

        const replay = encapsulateResetSafeSetupMailbox({
            recipientEncapsulationKey: mailbox.publicKey,
            setupMailboxSlot,
            setupMailboxSlotHash,
            signingCapability: provider.signingCapability,
            sourceVerificationKey: signing.publicKey,
        });
        const replaySignature = signResetSafeSetupMailboxEnvelope({
            envelopeHash: setupMailboxEnvelopeHash,
            signingCapability: provider.signingCapability,
            signingPermit: replay.signingPermit,
        });

        expect(replay.ciphertext).toEqual(firstCiphertext);
        expect(replay.envelopeAttemptIdentifier).toEqual(
            firstAttemptIdentifier,
        );
        expect(replay.sharedSecret).toEqual(firstSharedSecret);
        expect(
            ml_kem768.decapsulate(replay.ciphertext, mailbox.secretKey),
        ).toEqual(replay.sharedSecret);
        expect(
            ml_dsa65.verify(
                replaySignature,
                hexToBytes(setupMailboxEnvelopeHash),
                signing.publicKey,
                { context: mailboxSignatureContext },
            ),
        ).toBe(true);
        expect(randomnessObservation).toEqual({
            encapsulationConsumptionCount: 1,
            signatureConsumptionCount: 1,
        });

        provider.close();
    });

    it('refuses conflicting reset-safe producer slots and envelope hashes as typed equivocation', () => {
        const { signing, mailbox } = createKeyMaterial();
        const provider = openBrowserLocalExternalKeyProvider({
            ...createBrowserLocalKeyOperations({ signing, mailbox }),
            entropy: deterministicEntropy(),
        });
        const first = encapsulateResetSafeSetupMailbox({
            recipientEncapsulationKey: mailbox.publicKey,
            setupMailboxSlot,
            setupMailboxSlotHash,
            signingCapability: provider.signingCapability,
            sourceVerificationKey: signing.publicKey,
        });
        signResetSafeSetupMailboxEnvelope({
            envelopeHash: setupMailboxEnvelopeHash,
            signingCapability: provider.signingCapability,
            signingPermit: first.signingPermit,
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
        expectProviderError(
            () =>
                signResetSafeSetupMailboxEnvelope({
                    envelopeHash: 'd8'.repeat(64),
                    signingCapability: provider.signingCapability,
                    signingPermit: first.signingPermit,
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
                    entropy: deterministicEntropy(),
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
                    entropy: deterministicEntropy(),
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
                    entropy: deterministicEntropy(),
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
                    entropy: deterministicEntropy(),
                }),
            'MalformedKey',
        );
    });

    it('fails closed when entropy is unavailable or returns the wrong length', () => {
        const { signing, mailbox } = createKeyMaterial();
        const input = {
            ...createBrowserLocalKeyOperations({ signing, mailbox }),
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
                entropy: deterministicEntropy(),
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
            entropy: deterministicEntropy(),
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
            entropy: deterministicEntropy(),
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
                    entropy: deterministicEntropy(),
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
                    entropy: deterministicEntropy(),
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
            entropy: deterministicEntropy(),
        });
        activeSigningSecretKey = replacementSigning.secretKey;
        const encapsulation = encapsulateResetSafeSetupMailbox({
            recipientEncapsulationKey: first.mailbox.publicKey,
            setupMailboxSlot,
            setupMailboxSlotHash,
            signingCapability: provider.signingCapability,
            sourceVerificationKey: first.signing.publicKey,
        });
        expectProviderError(
            () =>
                signResetSafeSetupMailboxEnvelope({
                    envelopeHash: setupMailboxEnvelopeHash,
                    signingCapability: provider.signingCapability,
                    signingPermit: encapsulation.signingPermit,
                }),
            'KeyMismatch',
        );
        provider.close();
    });

    it('keeps revocation scoped to the named capability and closes both capabilities', () => {
        const { signing, mailbox } = createKeyMaterial();
        const provider = openBrowserLocalExternalKeyProvider({
            ...createBrowserLocalKeyOperations({ signing, mailbox }),
            entropy: deterministicEntropy(),
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

    it('rejects capability-kind substitution at runtime', () => {
        const { signing, mailbox } = createKeyMaterial();
        const provider = openBrowserLocalExternalKeyProvider({
            ...createBrowserLocalKeyOperations({ signing, mailbox }),
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
