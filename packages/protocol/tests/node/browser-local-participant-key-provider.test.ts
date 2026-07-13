import type { ParticipantIdentity } from '@sealed-lattice/types';
import { describe, expect, it } from 'vitest';

import {
    openBrowserLocalParticipantKeySession,
    type BrowserLocalMailboxProviderCapability,
    type BrowserLocalParticipantKeyProvider,
    type BrowserLocalParticipantKeySession,
    type BrowserLocalSigningProviderCapability,
    type MailboxCapabilityPairwiseSelfTestInput,
    type ParticipantKeyCapabilityState,
    type SigningCapabilityPairwiseSelfTestInput,
} from '#packages/protocol/src/runtime/browser-local-participant-key-provider';

const signingVerificationKeyByteLength = 1_952;
const mailboxEncapsulationKeyByteLength = 1_184;
const participantIdentity = '17'.repeat(64) as ParticipantIdentity;
const actionContextHash = '29'.repeat(64);

const deterministicBytes = (
    byteLength: number,
    initialByte: number,
): Uint8Array => {
    const bytes = new Uint8Array(byteLength);
    for (let byteIndex = 0; byteIndex < bytes.byteLength; byteIndex += 1) {
        bytes[byteIndex] = (initialByte + byteIndex * 31) & 0xff;
    }

    return bytes;
};

const bytesEqual = (left: Uint8Array, right: Uint8Array): boolean =>
    left.byteLength === right.byteLength &&
    left.every((value, byteIndex) => value === right[byteIndex]);

type MutableCapabilityState =
    | 'available'
    | 'lost'
    | 'replaced'
    | 'revoked'
    | 'unavailable';

class DeterministicParticipantKeyProvider implements BrowserLocalParticipantKeyProvider {
    public executionLocation: 'browser-local' | 'remote' = 'browser-local';
    public operationInterface:
        | 'sealed-lattice-closed-operations'
        | 'generic-hidden-randomness-only' = 'sealed-lattice-closed-operations';
    public signingCapabilityIdentifier = 'deterministic-signing-capability';
    public mailboxCapabilityIdentifier = 'deterministic-mailbox-capability';
    public signingCapabilityResolved = true;
    public mailboxCapabilityResolved = true;
    public signingCapabilityState: MutableCapabilityState = 'available';
    public mailboxCapabilityState: MutableCapabilityState = 'available';
    public signingSelfTestPasses = true;
    public mailboxSelfTestPasses = true;
    public signingSelfTestThrows = false;
    public mailboxSelfTestThrows = false;
    public signingSelfTestCount = 0;
    public mailboxSelfTestCount = 0;
    public lastSigningSelfTestInput:
        | SigningCapabilityPairwiseSelfTestInput
        | undefined;
    public lastMailboxSelfTestInput:
        | MailboxCapabilityPairwiseSelfTestInput
        | undefined;
    public signingPublicKey = deterministicBytes(
        signingVerificationKeyByteLength,
        11,
    );
    public mailboxPublicKey = deterministicBytes(
        mailboxEncapsulationKeyByteLength,
        83,
    );

    public resolveSigningCapability():
        | BrowserLocalSigningProviderCapability
        | undefined {
        if (!this.signingCapabilityResolved) {
            return undefined;
        }

        return {
            capabilityIdentifier: this.signingCapabilityIdentifier,
            capabilityPurpose: 'participant-signing',
            readState: () =>
                this.#capabilityState(
                    this.signingCapabilityState,
                    this.signingPublicKey,
                ),
            performPairwiseSelfTest: (input) => {
                this.signingSelfTestCount += 1;
                if (this.signingSelfTestThrows) {
                    throw new Error('Deterministic signing provider failure.');
                }
                this.lastSigningSelfTestInput = {
                    ...input,
                    context: input.context.slice(),
                    expectedVerificationKey:
                        input.expectedVerificationKey.slice(),
                    message: input.message.slice(),
                };

                return (
                    this.signingSelfTestPasses &&
                    bytesEqual(
                        input.expectedVerificationKey,
                        this.signingPublicKey,
                    )
                );
            },
        };
    }

    public resolveMailboxCapability():
        | BrowserLocalMailboxProviderCapability
        | undefined {
        if (!this.mailboxCapabilityResolved) {
            return undefined;
        }

        return {
            capabilityIdentifier: this.mailboxCapabilityIdentifier,
            capabilityPurpose: 'participant-mailbox',
            readState: () =>
                this.#capabilityState(
                    this.mailboxCapabilityState,
                    this.mailboxPublicKey,
                ),
            performPairwiseSelfTest: (input) => {
                this.mailboxSelfTestCount += 1;
                if (this.mailboxSelfTestThrows) {
                    throw new Error('Deterministic mailbox provider failure.');
                }
                this.lastMailboxSelfTestInput = {
                    ...input,
                    expectedEncapsulationKey:
                        input.expectedEncapsulationKey.slice(),
                };

                return (
                    this.mailboxSelfTestPasses &&
                    bytesEqual(
                        input.expectedEncapsulationKey,
                        this.mailboxPublicKey,
                    )
                );
            },
        };
    }

    #capabilityState(
        state: MutableCapabilityState,
        publicKey: Uint8Array,
    ): ParticipantKeyCapabilityState {
        return state === 'available'
            ? { state, publicKey: publicKey.slice() }
            : { state };
    }
}

const createProvider = (): DeterministicParticipantKeyProvider => {
    return new DeterministicParticipantKeyProvider();
};

const openSession = (
    provider: DeterministicParticipantKeyProvider,
): Promise<BrowserLocalParticipantKeySession> =>
    openBrowserLocalParticipantKeySession({
        actionContextHash,
        participantKeyBinding: {
            participantIdentity,
            rosterEntry: {
                mailboxEncapsulationKey: provider.mailboxPublicKey.slice(),
                role: 1,
                rosterPosition: 4,
                signingVerificationKey: provider.signingPublicKey.slice(),
            },
        },
        provider,
    });

describe('Browser-local participant key provider', () => {
    it('opens only after both purpose-specific pairwise self-tests and returns distinct opaque handles', async () => {
        const provider = createProvider();
        const session = await openSession(provider);

        const signingHandle = await session.requireSigningHandle();
        const mailboxHandle = await session.requireMailboxHandle();

        expect(signingHandle.capabilityKind).toBe('participant-signing');
        expect(mailboxHandle.capabilityKind).toBe('participant-mailbox');
        expect(signingHandle).not.toBe(mailboxHandle);
        expect(Object.isFrozen(signingHandle)).toBe(true);
        expect(Object.isFrozen(mailboxHandle)).toBe(true);
        expect(provider.signingSelfTestCount).toBe(1);
        expect(provider.mailboxSelfTestCount).toBe(1);
        expect(provider.lastSigningSelfTestInput).toMatchObject({
            actionContextHash,
            participantIdentity,
        });
        expect(provider.lastMailboxSelfTestInput).toMatchObject({
            actionContextHash,
            participantIdentity,
        });
        const signingSelfTestInput = provider.lastSigningSelfTestInput;
        const mailboxSelfTestInput = provider.lastMailboxSelfTestInput;
        if (
            signingSelfTestInput === undefined ||
            mailboxSelfTestInput === undefined
        ) {
            throw new Error('Expected both provider pairwise self-tests.');
        }
        expect(new TextDecoder().decode(signingSelfTestInput.message)).toBe(
            'sealed-lattice external-key-provider ML-DSA-65 pairwise self-test v1',
        );
        expect(new TextDecoder().decode(signingSelfTestInput.context)).toBe(
            'sealed-lattice/key-provider-self-test/v1',
        );
        expect(signingSelfTestInput.expectedVerificationKey).toEqual(
            provider.signingPublicKey,
        );
        expect(mailboxSelfTestInput.expectedEncapsulationKey).toEqual(
            provider.mailboxPublicKey,
        );

        session.close();
        await expect(session.requireSigningHandle()).rejects.toMatchObject({
            code: 'SessionClosed',
        });
    });

    it.each(['signing', 'mailbox'] as const)(
        'rejects a %s private handle whose public key differs from the frozen roster',
        async (capabilityKind) => {
            const provider = createProvider();
            const opening = openSession(provider);
            if (capabilityKind === 'signing') {
                provider.signingPublicKey[0] ^= 0x80;
            } else {
                provider.mailboxPublicKey[0] ^= 0x80;
            }

            await expect(opening).rejects.toMatchObject({
                code: 'PrivateHandlePublicKeyMismatch',
            });
            expect(provider.signingSelfTestCount).toBe(0);
            expect(provider.mailboxSelfTestCount).toBe(0);
        },
    );

    it('rejects one provider capability reused for signing and mailbox purposes', async () => {
        const provider = createProvider();
        provider.mailboxCapabilityIdentifier =
            provider.signingCapabilityIdentifier;

        await expect(openSession(provider)).rejects.toMatchObject({
            code: 'CapabilityPurposeReuse',
        });
        expect(provider.signingSelfTestCount).toBe(0);
        expect(provider.mailboxSelfTestCount).toBe(0);
    });

    it.each([
        ['lost', 'CapabilityLost'],
        ['revoked', 'CapabilityRevoked'],
    ] as const)(
        'fails closed when an established signing capability becomes %s',
        async (state, expectedCode) => {
            const provider = createProvider();
            const session = await openSession(provider);
            provider.signingCapabilityState = state;

            await expect(session.requireSigningHandle()).rejects.toMatchObject({
                code: expectedCode,
            });
        },
    );

    it('fails closed when an established mailbox capability is replaced', async () => {
        const provider = createProvider();
        const session = await openSession(provider);
        provider.mailboxPublicKey = deterministicBytes(
            mailboxEncapsulationKeyByteLength,
            197,
        );

        await expect(session.requireMailboxHandle()).rejects.toMatchObject({
            code: 'CapabilityReplaced',
        });
    });

    it.each(['signing', 'mailbox'] as const)(
        'fails closed when the %s capability is unavailable',
        async (capabilityKind) => {
            const provider = createProvider();
            if (capabilityKind === 'signing') {
                provider.signingCapabilityResolved = false;
            } else {
                provider.mailboxCapabilityResolved = false;
            }

            await expect(openSession(provider)).rejects.toMatchObject({
                code: 'CapabilityUnavailable',
            });
        },
    );

    it.each([
        [
            'remote',
            'sealed-lattice-closed-operations',
            'RemoteProviderRejected',
        ],
        [
            'browser-local',
            'generic-hidden-randomness-only',
            'GenericHiddenRandomnessProviderRejected',
        ],
    ] as const)(
        'rejects the %s provider using the %s interface',
        async (executionLocation, operationInterface, expectedCode) => {
            const provider = createProvider();
            provider.executionLocation = executionLocation;
            provider.operationInterface = operationInterface;

            await expect(openSession(provider)).rejects.toMatchObject({
                code: expectedCode,
            });
            expect(provider.signingSelfTestCount).toBe(0);
            expect(provider.mailboxSelfTestCount).toBe(0);
        },
    );

    it.each(['signing', 'mailbox'] as const)(
        'rejects a failed %s pairwise self-test without returning a session',
        async (capabilityKind) => {
            const provider = createProvider();
            if (capabilityKind === 'signing') {
                provider.signingSelfTestPasses = false;
            } else {
                provider.mailboxSelfTestPasses = false;
            }

            await expect(openSession(provider)).rejects.toMatchObject({
                code:
                    capabilityKind === 'signing'
                        ? 'SigningSelfTestFailed'
                        : 'MailboxSelfTestFailed',
            });
        },
    );

    it.each(['signing', 'mailbox'] as const)(
        'preserves a thrown %s self-test error as a provider failure',
        async (capabilityKind) => {
            const provider = createProvider();
            if (capabilityKind === 'signing') {
                provider.signingSelfTestThrows = true;
            } else {
                provider.mailboxSelfTestThrows = true;
            }

            await expect(openSession(provider)).rejects.toMatchObject({
                code: 'ProviderFailure',
            });
        },
    );
});
