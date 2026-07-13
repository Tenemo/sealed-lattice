import {
    foundationProfile,
    stateCapabilityKinds,
    type StateCapabilityKind,
} from '@sealed-lattice/types';

import {
    createCanonicalCarrierSigningKeyPairFixtures,
    signCanonicalCarrierFixtureMessage,
} from '#packages/crypto/tests/support/canonical-carrier-signature-fixtures';
import {
    asciiItem,
    canonicalItem,
    canonicalTuple,
    concatenateBytes,
    createCanonicalTestRosterBytes,
    emptyHomogeneousListItem,
    emptyOptionalItem,
    foundationHash512,
    hashItem,
    presentOptionalItem,
    unsigned16Item,
    unsigned16LittleEndian,
    unsigned32LittleEndian,
    unsigned64Item,
    variableBytesItem,
    variableValue,
} from '#packages/wasm/tests/canonical-tuple-test-helpers';

const stateReservationObjectType = 0x0051;
const stateOutputIntentObjectType = 0x0052;
const stateWitnessVoteObjectType = 0x0053;
const stateRecoveryTransitionObjectType = 0x0054;
const targetReleaseCapabilityKind = 3;
const finalitySignatureCapabilityKind = 2;

type SignedCarrierVector = Readonly<{
    canonicalCarrierBytes: Uint8Array;
    objectHash: Uint8Array;
}>;

export type CertifiedStateIntentTestVector = Readonly<{
    canonicalIntentCarrier: Uint8Array;
    canonicalStateCertificate: Uint8Array;
    objectHash: Uint8Array;
}>;

export type ReservationOnlyStateIntentTestVector = Readonly<{
    capabilityKind: StateCapabilityKind;
    certifiedIntent: CertifiedStateIntentTestVector;
}>;

export type StateVerifierTestVector = Readonly<{
    actionContextHash: Uint8Array;
    authorizationHash: Uint8Array;
    canonicalRosterBytes: Uint8Array;
    ceremonyContextHash: Uint8Array;
    exactOutputBytes: Uint8Array;
    invalidExtraOutputCertificate: Uint8Array;
    output: CertifiedStateIntentTestVector;
    recoveryFirst: CertifiedStateIntentTestVector;
    recoverySecond: CertifiedStateIntentTestVector;
    reservation: CertifiedStateIntentTestVector;
    reservationOnly: readonly ReservationOnlyStateIntentTestVector[];
    subjectParticipantIdentity: Uint8Array;
    suiteIdentifier: Uint8Array;
}>;

const stateCertificate = (
    canonicalVoteCarriers: readonly Uint8Array[],
): Uint8Array =>
    canonicalTuple(
        0x1613,
        canonicalItem(
            0x0e,
            concatenateBytes(
                unsigned16LittleEndian(0x01),
                unsigned32LittleEndian(canonicalVoteCarriers.length),
                ...canonicalVoteCarriers.map(variableValue),
            ),
        ),
    );

const stateExactOutputHash = (
    capabilityKind: number,
    exactOutputBytes: Uint8Array,
): Uint8Array =>
    foundationHash512(
        'sealed-lattice/state/exact-output/v1',
        unsigned16Item(capabilityKind),
        unsigned64Item(BigInt(exactOutputBytes.byteLength)),
        variableBytesItem(exactOutputBytes),
    );

export const createStateVerifierTestVector = (): StateVerifierTestVector => {
    const signingKeyPairs = createCanonicalCarrierSigningKeyPairFixtures(
        foundationProfile.participantCount,
    );
    try {
        const suiteIdentifier = new Uint8Array(64).fill(0x11);
        const ceremonyContextHash = new Uint8Array(64).fill(0x22);
        const actionContextHash = new Uint8Array(64).fill(0x33);
        const canonicalRosterBytes = createCanonicalTestRosterBytes(
            signingKeyPairs.map(({ publicKey }) => publicKey),
        );
        const rosterHash = foundationHash512(
            'sealed-lattice/foundation/roster/v1',
            variableBytesItem(canonicalRosterBytes),
        );
        const participantIdentities = signingKeyPairs.map(({ publicKey }) =>
            foundationHash512(
                'sealed-lattice/foundation/participant-id/v1',
                canonicalItem(0x01, publicKey),
            ),
        );

        const signedCarrier = (input: {
            objectType: number;
            payloadBytes: Uint8Array;
            predecessorTransitionHash?: Uint8Array;
            producerRosterPosition: number;
            producerSequence: bigint;
            recoveryEpoch: bigint;
            signaturePurpose: string;
        }): SignedCarrierVector => {
            const canonicalEnvelopeBytes = canonicalTuple(
                0x0100,
                asciiItem('sealed-lattice'),
                unsigned16Item(1),
                hashItem(suiteIdentifier),
                unsigned16Item(input.objectType),
                hashItem(ceremonyContextHash),
                hashItem(actionContextHash),
                unsigned64Item(input.recoveryEpoch),
                input.predecessorTransitionHash === undefined
                    ? emptyOptionalItem(0x06)
                    : presentOptionalItem(
                          0x06,
                          input.predecessorTransitionHash,
                      ),
                presentOptionalItem(
                    0x07,
                    participantIdentities[input.producerRosterPosition],
                ),
                unsigned64Item(input.producerSequence),
                emptyHomogeneousListItem(0x06),
                variableBytesItem(input.payloadBytes),
            );
            const objectHash = foundationHash512(
                'sealed-lattice/foundation/object/v1',
                variableBytesItem(canonicalEnvelopeBytes),
            );
            const signatureMessage = foundationHash512(
                'sealed-lattice/foundation/signature-message/v1',
                hashItem(objectHash),
                hashItem(rosterHash),
                asciiItem(input.signaturePurpose),
            );
            const signature = signCanonicalCarrierFixtureMessage(
                signatureMessage,
                signingKeyPairs[input.producerRosterPosition].secretKey,
            );
            return {
                canonicalCarrierBytes: canonicalTuple(
                    0x0101,
                    variableBytesItem(canonicalEnvelopeBytes),
                    canonicalItem(0x01, signature),
                ),
                objectHash,
            };
        };

        const certificateFor = (
            intentObjectHash: Uint8Array,
            producerSequence: bigint,
            witnessRosterPositions: readonly number[],
            corruptLastVote = false,
        ): Uint8Array => {
            const votes = witnessRosterPositions.map(
                (producerRosterPosition) =>
                    signedCarrier({
                        objectType: stateWitnessVoteObjectType,
                        payloadBytes: canonicalTuple(
                            0x1612,
                            hashItem(intentObjectHash),
                        ),
                        producerRosterPosition,
                        producerSequence,
                        recoveryEpoch: 0n,
                        signaturePurpose: 'state-witness-vote',
                    }).canonicalCarrierBytes,
            );
            if (corruptLastVote) {
                const lastVoteIndex = votes.length - 1;
                const malformedVote = Uint8Array.from(votes[lastVoteIndex]);
                malformedVote[malformedVote.byteLength - 1] ^= 1;
                votes[lastVoteIndex] = malformedVote;
            }
            return stateCertificate(votes);
        };

        const authorizationHash = new Uint8Array(64).fill(0xa1);
        const reservationCarrier = signedCarrier({
            objectType: stateReservationObjectType,
            payloadBytes: canonicalTuple(
                0x1610,
                unsigned16Item(targetReleaseCapabilityKind),
                hashItem(authorizationHash),
            ),
            producerRosterPosition: 0,
            producerSequence: 0n,
            recoveryEpoch: 0n,
            signaturePurpose: 'state-reservation-intent',
        });
        const reservation: CertifiedStateIntentTestVector = {
            canonicalIntentCarrier: reservationCarrier.canonicalCarrierBytes,
            canonicalStateCertificate: certificateFor(
                reservationCarrier.objectHash,
                1n,
                [1, 2, 3, 4, 5, 6, 7],
            ),
            objectHash: reservationCarrier.objectHash,
        };
        const reservationOnly = [
            stateCapabilityKinds.setupActionRandomnessRoot,
            stateCapabilityKinds.setupPublicSeedBranch,
            stateCapabilityKinds.setupDealerSetBranch,
            stateCapabilityKinds.setupRkgRoundOneBranch,
            stateCapabilityKinds.setupTerminalPackage,
        ].map((capabilityKind): ReservationOnlyStateIntentTestVector => {
            const carrier = signedCarrier({
                objectType: stateReservationObjectType,
                payloadBytes: canonicalTuple(
                    0x1610,
                    unsigned16Item(capabilityKind),
                    hashItem(authorizationHash),
                ),
                producerRosterPosition: 0,
                producerSequence: 0n,
                recoveryEpoch: 0n,
                signaturePurpose: 'state-reservation-intent',
            });
            return {
                capabilityKind,
                certifiedIntent: {
                    canonicalIntentCarrier: carrier.canonicalCarrierBytes,
                    canonicalStateCertificate: certificateFor(
                        carrier.objectHash,
                        1n,
                        [1, 2, 3, 4, 5, 6, 7],
                    ),
                    objectHash: carrier.objectHash,
                },
            };
        });

        const exactOutputBytes = new Uint8Array(
            foundationProfile.streamChunkByteLength + 17,
        );
        for (
            let byteIndex = 0;
            byteIndex < exactOutputBytes.byteLength;
            byteIndex += 1
        ) {
            exactOutputBytes[byteIndex] = (byteIndex * 197 + 29) & 0xff;
        }
        const outputCarrier = signedCarrier({
            objectType: stateOutputIntentObjectType,
            payloadBytes: canonicalTuple(
                0x1611,
                hashItem(reservationCarrier.objectHash),
                hashItem(
                    stateExactOutputHash(
                        targetReleaseCapabilityKind,
                        exactOutputBytes,
                    ),
                ),
            ),
            producerRosterPosition: 0,
            producerSequence: 0n,
            recoveryEpoch: 0n,
            signaturePurpose: 'state-output-intent',
        });
        const output: CertifiedStateIntentTestVector = {
            canonicalIntentCarrier: outputCarrier.canonicalCarrierBytes,
            canonicalStateCertificate: certificateFor(
                outputCarrier.objectHash,
                2n,
                [1, 2, 3, 4, 5, 6, 7],
            ),
            objectHash: outputCarrier.objectHash,
        };
        const invalidExtraOutputCertificate = certificateFor(
            outputCarrier.objectHash,
            2n,
            [1, 2, 3, 4, 5, 6, 7, 8],
            true,
        );

        const recoveryFirstCarrier = signedCarrier({
            objectType: stateRecoveryTransitionObjectType,
            payloadBytes: canonicalTuple(
                0x1614,
                unsigned16Item(finalitySignatureCapabilityKind),
                emptyOptionalItem(0x06),
            ),
            producerRosterPosition: 0,
            producerSequence: 1n,
            recoveryEpoch: 0n,
            signaturePurpose: 'state-recovery-transition',
        });
        const recoveryFirst: CertifiedStateIntentTestVector = {
            canonicalIntentCarrier: recoveryFirstCarrier.canonicalCarrierBytes,
            canonicalStateCertificate: certificateFor(
                recoveryFirstCarrier.objectHash,
                3n,
                [1, 2, 3, 4, 5, 6, 7],
            ),
            objectHash: recoveryFirstCarrier.objectHash,
        };

        const recoverySecondCarrier = signedCarrier({
            objectType: stateRecoveryTransitionObjectType,
            payloadBytes: canonicalTuple(
                0x1614,
                unsigned16Item(finalitySignatureCapabilityKind),
                emptyOptionalItem(0x06),
            ),
            predecessorTransitionHash: recoveryFirstCarrier.objectHash,
            producerRosterPosition: 0,
            producerSequence: 2n,
            recoveryEpoch: 1n,
            signaturePurpose: 'state-recovery-transition',
        });
        const recoverySecond: CertifiedStateIntentTestVector = {
            canonicalIntentCarrier: recoverySecondCarrier.canonicalCarrierBytes,
            canonicalStateCertificate: certificateFor(
                recoverySecondCarrier.objectHash,
                6n,
                [1, 2, 3, 4, 5, 6, 7],
            ),
            objectHash: recoverySecondCarrier.objectHash,
        };

        return {
            actionContextHash,
            authorizationHash,
            canonicalRosterBytes,
            ceremonyContextHash,
            exactOutputBytes,
            invalidExtraOutputCertificate,
            output,
            recoveryFirst,
            recoverySecond,
            reservation,
            reservationOnly,
            subjectParticipantIdentity: participantIdentities[0],
            suiteIdentifier,
        };
    } finally {
        for (const { secretKey } of signingKeyPairs) {
            secretKey.fill(0);
        }
    }
};
