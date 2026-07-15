import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { foundationProfile } from '@sealed-lattice/types';
import { beforeAll, describe, expect, it } from 'vitest';

import {
    encapsulateResetSafeSetupMailbox,
    signResetSafeSetupMailboxEnvelope,
} from '#packages/crypto/src/browser-local-key-provider';
import {
    createBrowserLocalMailboxOperations,
    createBrowserLocalSigningOperations,
} from '#packages/crypto/tests/support/browser-local-key-operations';
import { openBrowserLocalActionCryptographicProvider } from '#packages/protocol/src/index';
import {
    createWasmBrowserActionStorageWorkerKernel,
    loadFreshTranscriptCoreKernel,
    type TranscriptCoreKernel,
} from '#packages/wasm/src/index';
import { stateCapabilityKinds } from '#packages/wasm/src/state-verifier-runtime';
import { actionRandomnessTestVector } from '#packages/wasm/tests/action-randomness-test-vectors';
import {
    createStateVerifierTestVector,
    deriveSetupActionRandomnessAuthorization,
} from '#packages/wasm/tests/state-verifier-test-vectors';

const mailboxSignatureContext = new TextEncoder().encode(
    'sealed-lattice/mailbox-signature/v1',
);

const deterministicOrdinaryEntropy = () => {
    let callIndex = 0;
    return (byteLength: number): Uint8Array => {
        callIndex += 1;
        return new Uint8Array(byteLength).fill(callIndex);
    };
};

describe('Browser-local action cryptographic provider', () => {
    let kernel: TranscriptCoreKernel;

    beforeAll(async () => {
        kernel = await loadFreshTranscriptCoreKernel();
    });

    it('consumes worker-held commitment-authorized mailbox randomness without exposing its raw inputs', async () => {
        const signingSeed = new Uint8Array(ml_dsa65.lengths.seed!);
        signingSeed[0] = 1;
        signingSeed[signingSeed.byteLength - 1] =
            foundationProfile.participantCount;
        const signingKeyPair = ml_dsa65.keygen(signingSeed);
        signingSeed.fill(0);
        const sourceMailboxSeed = new Uint8Array(ml_kem768.lengths.seed!);
        sourceMailboxSeed[0] = 1;
        sourceMailboxSeed[sourceMailboxSeed.byteLength - 1] =
            foundationProfile.participantCount;
        const sourceMailboxKeyPair = ml_kem768.keygen(sourceMailboxSeed);
        sourceMailboxSeed.fill(0);
        const recipientMailboxSeed = new Uint8Array(ml_kem768.lengths.seed!);
        recipientMailboxSeed[0] = 2;
        recipientMailboxSeed[recipientMailboxSeed.byteLength - 1] =
            foundationProfile.participantCount - 1;
        const recipientMailboxKeyPair = ml_kem768.keygen(
            recipientMailboxSeed,
        );
        recipientMailboxSeed.fill(0);
        const baseStateVector = createStateVerifierTestVector();
        const workerKernel = createWasmBrowserActionStorageWorkerKernel({
            kernel,
        });
        await workerKernel.createAndStageDeviceWrappingState({
            binding: {
                actionContextHash: baseStateVector.actionContextHash,
                ceremonyContextHash:
                    baseStateVector.ceremonyContextHash,
                participantId:
                    baseStateVector.subjectParticipantIdentity,
                suiteId: baseStateVector.suiteIdentifier,
            },
        });
        await workerKernel.commitStagedActionStorageRoot({
            mutationIdentifier: new Uint8Array(32).fill(0x73),
        });
        const created = await workerKernel.createAndSealActionRandomness({
            creationRecoveryEpoch: 0n,
            recordVersion: 0n,
        });
        const stateVector = createStateVerifierTestVector({
            setupActionRandomnessAuthorizationHash:
                deriveSetupActionRandomnessAuthorization(
                    baseStateVector,
                    created.actionRandomnessCommitment,
                ),
        });
        const openedStateSession =
            await workerKernel.openActionStateVerifierSession({
                canonicalRosterBytes: stateVector.canonicalRosterBytes,
                maximumRecoveryTransitionsPerStateKey: 2,
            });
        if (!openedStateSession.isValid) {
            throw new Error(openedStateSession.refusalReason);
        }
        const rootReservationVector = stateVector.reservationOnly.find(
            ({ capabilityKind }) =>
                capabilityKind ===
                stateCapabilityKinds.setupActionRandomnessRoot,
        );
        if (rootReservationVector === undefined) {
            throw new Error('Missing action-randomness reservation vector.');
        }
        const rootReservation =
            await workerKernel.verifyActionRandomnessReservation({
                actionRandomnessSessionIdentifier:
                    created.actionRandomnessSessionIdentifier,
                canonicalReservationIntentCarrier:
                    rootReservationVector.certifiedIntent
                        .canonicalIntentCarrier,
                canonicalStateCertificate:
                    rootReservationVector.certifiedIntent
                        .canonicalStateCertificate,
                stateVerifierSessionIdentifier: openedStateSession.value,
            });
        if (!rootReservation.isValid) {
            throw new Error(rootReservation.refusalReason);
        }
        const provider = await openBrowserLocalActionCryptographicProvider({
            actionRandomnessSessionIdentifier:
                created.actionRandomnessSessionIdentifier,
            mailbox: createBrowserLocalMailboxOperations(
                sourceMailboxKeyPair,
            ),
            ordinaryOperationEntropy: deterministicOrdinaryEntropy(),
            signing: createBrowserLocalSigningOperations(signingKeyPair),
            stateReservationIdentifier: rootReservation.value,
            workerKernel,
        });
        const setupMailboxSlot = Object.freeze({
            ...actionRandomnessTestVector.setupMailbox.setupMailboxSlot,
            actionContextHash: bytesToHex(stateVector.actionContextHash),
            ceremonyContextHash: bytesToHex(
                stateVector.ceremonyContextHash,
            ),
            recipientParticipantId: bytesToHex(
                stateVector.witnessParticipantIdentity,
            ),
            rosterHash: bytesToHex(stateVector.rosterHash),
            sourceParticipantId: bytesToHex(
                stateVector.subjectParticipantIdentity,
            ),
            suiteId: bytesToHex(stateVector.suiteIdentifier),
        });
        const setupMailboxSlotHash = kernel.deriveSetupMailboxSlotHash(
            setupMailboxSlot,
        );

        try {
            encapsulateResetSafeSetupMailbox({
                recipientEncapsulationKey:
                    sourceMailboxKeyPair.publicKey,
                setupMailboxSlot,
                setupMailboxSlotHash,
                signingCapability:
                    provider.externalKeyProvider.signingCapability,
                sourceVerificationKey: signingKeyPair.publicKey,
            });
            throw new Error(
                'Expected a recipient key outside the frozen roster slot to be refused.',
            );
        } catch (error) {
            expect(error).toMatchObject({
                code: 'KeyMismatch',
                name: 'BrowserLocalKeyProviderError',
            });
        }

        const firstEncapsulation = encapsulateResetSafeSetupMailbox({
            recipientEncapsulationKey: recipientMailboxKeyPair.publicKey,
            setupMailboxSlot,
            setupMailboxSlotHash,
            signingCapability: provider.externalKeyProvider.signingCapability,
            sourceVerificationKey: signingKeyPair.publicKey,
        });
        const firstSignature = signResetSafeSetupMailboxEnvelope({
            envelopeHash: actionRandomnessTestVector.setupMailbox.envelopeHash,
            signingCapability: provider.externalKeyProvider.signingCapability,
            signingPermit: firstEncapsulation.signingPermit,
        });

        expect(provider.actionRandomnessSessionIdentifier).toBe(
            created.actionRandomnessSessionIdentifier,
        );
        expect(
            ml_kem768.decapsulate(
                firstEncapsulation.ciphertext,
                recipientMailboxKeyPair.secretKey,
            ),
        ).toEqual(firstEncapsulation.sharedSecret);
        expect(
            ml_dsa65.verify(
                firstSignature,
                hexToBytes(
                    actionRandomnessTestVector.setupMailbox.envelopeHash,
                ),
                signingKeyPair.publicKey,
                { context: mailboxSignatureContext },
            ),
        ).toBe(true);

        const replayedEncapsulation = encapsulateResetSafeSetupMailbox({
            recipientEncapsulationKey: recipientMailboxKeyPair.publicKey,
            setupMailboxSlot,
            setupMailboxSlotHash,
            signingCapability: provider.externalKeyProvider.signingCapability,
            sourceVerificationKey: signingKeyPair.publicKey,
        });
        const replayedSignature = signResetSafeSetupMailboxEnvelope({
            envelopeHash: actionRandomnessTestVector.setupMailbox.envelopeHash,
            signingCapability: provider.externalKeyProvider.signingCapability,
            signingPermit: replayedEncapsulation.signingPermit,
        });
        expect(replayedEncapsulation.envelopeAttemptIdentifier).toEqual(
            firstEncapsulation.envelopeAttemptIdentifier,
        );
        expect(replayedEncapsulation.ciphertext).toEqual(
            firstEncapsulation.ciphertext,
        );
        expect(replayedEncapsulation.sharedSecret).toEqual(
            firstEncapsulation.sharedSecret,
        );
        expect(replayedSignature).toEqual(firstSignature);

        firstEncapsulation.envelopeAttemptIdentifier.fill(0);
        firstEncapsulation.ciphertext.fill(0);
        firstEncapsulation.sharedSecret.fill(0);
        firstSignature.fill(0);
        replayedEncapsulation.envelopeAttemptIdentifier.fill(0);
        replayedEncapsulation.ciphertext.fill(0);
        replayedEncapsulation.sharedSecret.fill(0);
        replayedSignature.fill(0);
        await provider.close();
        await provider.close();
        await workerKernel.closeActionStateVerifierSession(
            openedStateSession.value,
        );
        await workerKernel.destroyActiveActionStorageRoot();
        signingKeyPair.secretKey.fill(0);
        sourceMailboxKeyPair.secretKey.fill(0);
        recipientMailboxKeyPair.secretKey.fill(0);
    });
});
