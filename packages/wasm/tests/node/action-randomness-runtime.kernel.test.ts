import { bytesToHex } from '@noble/hashes/utils.js';
import { beforeEach, describe, expect, it } from 'vitest';

import {
    ActionRandomnessRuntimeError,
    openActionRandomnessSession,
} from '#packages/wasm/src/action-randomness-runtime';
import {
    loadFreshTranscriptCoreKernel,
    type TranscriptCoreKernel,
} from '#packages/wasm/src/index';
import {
    openStateVerifierSession,
    stateCapabilityKinds,
    type StateVerifierSession,
    type VerifiedStateReservation,
} from '#packages/wasm/src/state-verifier-runtime';
import {
    actionRandomnessTestVector,
    createDeterministicCryptoProvider,
} from '#packages/wasm/tests/action-randomness-test-vectors';
import { createStateVerifierTestVector } from '#packages/wasm/tests/state-verifier-test-vectors';

const expectRuntimeError = (
    operation: () => unknown,
    code: ActionRandomnessRuntimeError['code'],
): void => {
    try {
        operation();
        throw new Error('Expected the action-randomness operation to fail.');
    } catch (error) {
        expect(error).toBeInstanceOf(ActionRandomnessRuntimeError);
        expect((error as ActionRandomnessRuntimeError).code).toBe(code);
    }
};

describe('Action-randomness real-WASM runtime in Node', () => {
    let kernel: TranscriptCoreKernel;

    beforeEach(async () => {
        kernel = await loadFreshTranscriptCoreKernel();
    });

    it('matches the exact Rust vectors without exporting the action root or child keys', () => {
        const entropy = createDeterministicCryptoProvider([
            {
                byteLength: 64,
                fillByte: actionRandomnessTestVector.rootFillByte,
            },
            { byteLength: 32, fillByte: 0x70 },
            { byteLength: 32, fillByte: 0x91 },
        ]);
        const session = openActionRandomnessSession({
            cryptoProvider: entropy.cryptoProvider,
            kernel,
            scope: actionRandomnessTestVector.scope,
        });

        expect(session.actionRandomnessCommitment).toBe(
            actionRandomnessTestVector.actionRandomnessCommitment,
        );
        const ordinaryProof = session.beginOrdinaryProofAttempt({
            applicationStatementHash:
                actionRandomnessTestVector.ordinaryProof
                    .applicationStatementHash,
            producerSequence:
                actionRandomnessTestVector.ordinaryProof.producerSequence,
            rosterPosition:
                actionRandomnessTestVector.ordinaryProof.rosterPosition,
        });
        expect(ordinaryProof.applicationSlotHash).toBe(
            actionRandomnessTestVector.ordinaryProof.applicationSlotHash,
        );
        expect(bytesToHex(ordinaryProof.attemptIdentifier)).toBe(
            actionRandomnessTestVector.ordinaryProof.attemptIdentifier,
        );
        expect(bytesToHex(ordinaryProof.ordinaryProofAttemptNonce)).toBe(
            actionRandomnessTestVector.ordinaryProof.nonce,
        );

        const freshBallotAttempt = session.beginFreshBallotAttempt();
        expect(bytesToHex(freshBallotAttempt)).toBe(
            actionRandomnessTestVector.freshBallotAttemptIdentifier,
        );
        expect(entropy.callCount()).toBe(3);

        ordinaryProof.attemptIdentifier.fill(0);
        ordinaryProof.ordinaryProofAttemptNonce.fill(0);
        freshBallotAttempt.fill(0);
        session.close();
    });

    it('fails closed after the action-randomness session closes', () => {
        const entropy = createDeterministicCryptoProvider([
            {
                byteLength: 64,
                fillByte: actionRandomnessTestVector.rootFillByte,
            },
        ]);
        const session = openActionRandomnessSession({
            cryptoProvider: entropy.cryptoProvider,
            kernel,
            scope: actionRandomnessTestVector.scope,
        });
        session.close();
        expectRuntimeError(
            () => session.beginFreshBallotAttempt(),
            'InvalidState',
        );
        expect(entropy.callCount()).toBe(1);
    });

    it('requires matching live durable reservations for persistent and target attempts', () => {
        const vector = createStateVerifierTestVector();
        const openedStateSession = openStateVerifierSession({
            configuration: {
                actionContextHash: vector.actionContextHash,
                canonicalRosterBytes: vector.canonicalRosterBytes,
                ceremonyContextHash: vector.ceremonyContextHash,
                maximumRecoveryTransitionsPerStateKey: 2,
                suiteIdentifier: vector.suiteIdentifier,
            },
            kernel,
        });
        expect(openedStateSession.isValid).toBe(true);
        if (!openedStateSession.isValid) {
            throw new Error(openedStateSession.refusalReason);
        }
        const stateSession: StateVerifierSession = openedStateSession.value;
        const verifyReservation = (
            capabilityKind:
                | typeof stateCapabilityKinds.targetRelease
                | typeof stateCapabilityKinds.setupDealerSetBranch,
        ): VerifiedStateReservation => {
            const certifiedIntent =
                capabilityKind === stateCapabilityKinds.targetRelease
                    ? vector.reservation
                    : vector.reservationOnly.find(
                          (candidate) =>
                              candidate.capabilityKind === capabilityKind,
                      )?.certifiedIntent;
            if (certifiedIntent === undefined) {
                throw new Error('Missing state-reservation test vector.');
            }
            const verified = stateSession.verifyReservation({
                canonicalReservationIntentCarrier:
                    certifiedIntent.canonicalIntentCarrier,
                canonicalStateCertificate:
                    certifiedIntent.canonicalStateCertificate,
                capabilityKind,
                expectedAuthorizationHash: vector.authorizationHash,
                subjectParticipantIdentity: vector.subjectParticipantIdentity,
            });
            expect(verified.isValid).toBe(true);
            if (!verified.isValid) {
                throw new Error(verified.refusalReason);
            }
            return verified.value;
        };
        const targetReservation = verifyReservation(
            stateCapabilityKinds.targetRelease,
        );
        const dealerSetReservation = verifyReservation(
            stateCapabilityKinds.setupDealerSetBranch,
        );
        const entropy = createDeterministicCryptoProvider([
            {
                byteLength: 64,
                fillByte: actionRandomnessTestVector.rootFillByte,
            },
        ]);
        const session = openActionRandomnessSession({
            cryptoProvider: entropy.cryptoProvider,
            kernel,
            scope: {
                actionContextHash: bytesToHex(vector.actionContextHash),
                ceremonyContextHash: bytesToHex(vector.ceremonyContextHash),
                participantId: bytesToHex(vector.subjectParticipantIdentity),
                suiteId: bytesToHex(vector.suiteIdentifier),
            },
        });
        const persistentInput = {
            applicationStatementHash: '66'.repeat(64),
            rosterPosition: 0,
            statementSchemaIdentifier: 0x1211 as const,
            verifiedReservation: dealerSetReservation,
        };
        const firstPersistent =
            session.derivePersistentProofAttempt(persistentInput);
        const replayedPersistent =
            session.derivePersistentProofAttempt(persistentInput);
        expect(replayedPersistent).toEqual(firstPersistent);

        const targetInput = {
            rosterPosition: 0,
            verifiedReservation: targetReservation,
        };
        const firstTarget = session.deriveTargetReleaseAttempt(targetInput);
        const replayedTarget = session.deriveTargetReleaseAttempt(targetInput);
        expect(replayedTarget).toEqual(firstTarget);
        expectRuntimeError(
            () =>
                session.derivePersistentProofAttempt({
                    ...persistentInput,
                    verifiedReservation: targetReservation,
                }),
            'InvalidInput',
        );
        expectRuntimeError(
            () =>
                session.deriveTargetReleaseAttempt({
                    rosterPosition: 0,
                    verifiedReservation: dealerSetReservation,
                }),
            'InvalidInput',
        );

        firstPersistent.attemptIdentifier.fill(0);
        replayedPersistent.attemptIdentifier.fill(0);
        firstTarget.attemptIdentifier.fill(0);
        replayedTarget.attemptIdentifier.fill(0);
        session.close();
        stateSession.cancel();
    });

    it('does not open a session when platform entropy fails', () => {
        const cryptoProvider = {
            getRandomValues: () => {
                throw new Error('Entropy source failed.');
            },
        } as unknown as Crypto;

        expectRuntimeError(
            () =>
                openActionRandomnessSession({
                    cryptoProvider,
                    kernel,
                    scope: actionRandomnessTestVector.scope,
                }),
            'EntropyUnavailable',
        );
    });
});
