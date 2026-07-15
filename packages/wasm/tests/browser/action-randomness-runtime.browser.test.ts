import { bytesToHex } from '@noble/hashes/utils.js';
import { describe, expect, it } from 'vitest';

import { openActionRandomnessSession } from '#packages/wasm/src/action-randomness-runtime';
import { loadFreshTranscriptCoreKernel } from '#packages/wasm/src/index';
import {
    openStateVerifierSession,
    stateCapabilityKinds,
} from '#packages/wasm/src/state-verifier-runtime';
import {
    actionRandomnessTestVector,
    createDeterministicCryptoProvider,
} from '#packages/wasm/tests/action-randomness-test-vectors';
import { createStateVerifierTestVector } from '#packages/wasm/tests/state-verifier-test-vectors';

describe('Action-randomness real-WASM runtime in browsers', () => {
    it('matches the exact closed-operation vectors in the browser kernel', async () => {
        const kernel = await loadFreshTranscriptCoreKernel();
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
        const ordinaryProof = session.beginOrdinaryProofAttempt({
            applicationStatementHash:
                actionRandomnessTestVector.ordinaryProof
                    .applicationStatementHash,
            producerSequence:
                actionRandomnessTestVector.ordinaryProof.producerSequence,
            rosterPosition:
                actionRandomnessTestVector.ordinaryProof.rosterPosition,
        });
        const freshBallotAttempt = session.beginFreshBallotAttempt();

        expect(session.actionRandomnessCommitment).toBe(
            actionRandomnessTestVector.actionRandomnessCommitment,
        );
        expect(ordinaryProof.applicationSlotHash).toBe(
            actionRandomnessTestVector.ordinaryProof.applicationSlotHash,
        );
        expect(bytesToHex(ordinaryProof.attemptIdentifier)).toBe(
            actionRandomnessTestVector.ordinaryProof.attemptIdentifier,
        );
        expect(bytesToHex(ordinaryProof.ordinaryProofAttemptNonce)).toBe(
            actionRandomnessTestVector.ordinaryProof.nonce,
        );
        expect(bytesToHex(freshBallotAttempt)).toBe(
            actionRandomnessTestVector.freshBallotAttemptIdentifier,
        );
        expect(entropy.callCount()).toBe(3);

        ordinaryProof.attemptIdentifier.fill(0);
        ordinaryProof.ordinaryProofAttemptNonce.fill(0);
        freshBallotAttempt.fill(0);
        session.close();

        const stateVector = createStateVerifierTestVector();
        const openedStateSession = openStateVerifierSession({
            configuration: {
                actionContextHash: stateVector.actionContextHash,
                canonicalRosterBytes: stateVector.canonicalRosterBytes,
                ceremonyContextHash: stateVector.ceremonyContextHash,
                maximumRecoveryTransitionsPerStateKey: 2,
                suiteIdentifier: stateVector.suiteIdentifier,
            },
            kernel,
        });
        expect(openedStateSession.isValid).toBe(true);
        if (!openedStateSession.isValid) {
            throw new Error(openedStateSession.refusalReason);
        }
        const stateSession = openedStateSession.value;
        const targetReservation = stateSession.verifyReservation({
            canonicalReservationIntentCarrier:
                stateVector.reservation.canonicalIntentCarrier,
            canonicalStateCertificate:
                stateVector.reservation.canonicalStateCertificate,
            capabilityKind: stateCapabilityKinds.targetRelease,
            expectedAuthorizationHash: stateVector.authorizationHash,
            subjectParticipantIdentity: stateVector.subjectParticipantIdentity,
        });
        expect(targetReservation.isValid).toBe(true);
        if (!targetReservation.isValid) {
            throw new Error(targetReservation.refusalReason);
        }
        const dealerSetVector = stateVector.reservationOnly.find(
            (candidate) =>
                candidate.capabilityKind ===
                stateCapabilityKinds.setupDealerSetBranch,
        );
        if (dealerSetVector === undefined) {
            throw new Error('Missing dealer-set reservation vector.');
        }
        const dealerSetReservation = stateSession.verifyReservation({
            canonicalReservationIntentCarrier:
                dealerSetVector.certifiedIntent.canonicalIntentCarrier,
            canonicalStateCertificate:
                dealerSetVector.certifiedIntent.canonicalStateCertificate,
            capabilityKind: stateCapabilityKinds.setupDealerSetBranch,
            expectedAuthorizationHash: stateVector.authorizationHash,
            subjectParticipantIdentity: stateVector.subjectParticipantIdentity,
        });
        expect(dealerSetReservation.isValid).toBe(true);
        if (!dealerSetReservation.isValid) {
            throw new Error(dealerSetReservation.refusalReason);
        }
        const reservedActionSession = openActionRandomnessSession({
            cryptoProvider: createDeterministicCryptoProvider([
                {
                    byteLength: 64,
                    fillByte: actionRandomnessTestVector.rootFillByte,
                },
            ]).cryptoProvider,
            kernel,
            scope: {
                actionContextHash: bytesToHex(stateVector.actionContextHash),
                ceremonyContextHash: bytesToHex(
                    stateVector.ceremonyContextHash,
                ),
                participantId: bytesToHex(
                    stateVector.subjectParticipantIdentity,
                ),
                suiteId: bytesToHex(stateVector.suiteIdentifier),
            },
        });
        const persistentInput = {
            applicationStatementHash: '66'.repeat(64),
            rosterPosition: 0,
            statementSchemaIdentifier: 0x1211 as const,
            verifiedReservation: dealerSetReservation.value,
        };
        const persistentAttempt =
            reservedActionSession.derivePersistentProofAttempt(persistentInput);
        expect(
            reservedActionSession.derivePersistentProofAttempt(persistentInput),
        ).toEqual(persistentAttempt);
        const targetInput = {
            rosterPosition: 0,
            verifiedReservation: targetReservation.value,
        };
        const targetAttempt =
            reservedActionSession.deriveTargetReleaseAttempt(targetInput);
        expect(
            reservedActionSession.deriveTargetReleaseAttempt(targetInput),
        ).toEqual(targetAttempt);
        persistentAttempt.attemptIdentifier.fill(0);
        targetAttempt.attemptIdentifier.fill(0);
        reservedActionSession.close();
        stateSession.cancel();
    });
});
