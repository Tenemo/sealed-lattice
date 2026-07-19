import {
    foundationProfile,
    stateCapabilityKinds,
    type StateCapabilityKind,
} from '@sealed-lattice/types';

import {
    createCanonicalCarrierMailboxKeyPairFixtures,
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
    foundationHash512,
    hashItem,
    participantIdentityItem,
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
const targetReleaseCapabilityKind = 3;

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
    conflictingReservation: CertifiedStateIntentTestVector;
    exactOutputBytes: Uint8Array;
    invalidExtraOutputCertificate: Uint8Array;
    output: CertifiedStateIntentTestVector;
    reservation: CertifiedStateIntentTestVector;
    reservationVoteCarriers: readonly Uint8Array[];
    reservationOnly: readonly ReservationOnlyStateIntentTestVector[];
    rosterHash: Uint8Array;
    subjectParticipantIdentity: Uint8Array;
    suiteIdentifier: Uint8Array;
    witnessParticipantIdentity: Uint8Array;
}>;

export const deriveSetupActionRandomnessAuthorization = (
    input: Pick<
        StateVerifierTestVector,
        | 'actionContextHash'
        | 'canonicalRosterBytes'
        | 'ceremonyContextHash'
        | 'subjectParticipantIdentity'
        | 'suiteIdentifier'
    >,
    actionRandomnessCommitment: Uint8Array,
): Uint8Array => {
    if (actionRandomnessCommitment.byteLength !== 64) {
        throw new TypeError(
            'The action-randomness commitment must contain exactly 64 bytes.',
        );
    }
    const rosterHash = foundationHash512(
        'sealed-lattice/foundation/roster/v1',
        variableBytesItem(input.canonicalRosterBytes),
    );

    return foundationHash512(
        'sealed-lattice/setup/state/action-randomness/v1',
        hashItem(input.suiteIdentifier),
        hashItem(input.ceremonyContextHash),
        hashItem(input.actionContextHash),
        hashItem(rosterHash),
        participantIdentityItem(input.subjectParticipantIdentity),
        hashItem(actionRandomnessCommitment),
    );
};

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

export const createStateVerifierTestVector = (
    input: {
        actionContextHash?: Uint8Array;
        ceremonyContextHash?: Uint8Array;
        setupActionRandomnessAuthorizationHash?: Uint8Array;
        subjectRosterPosition?: number;
        suiteIdentifier?: Uint8Array;
    } = {},
): StateVerifierTestVector => {
    for (const [fieldName, value] of [
        ['actionContextHash', input.actionContextHash],
        ['ceremonyContextHash', input.ceremonyContextHash],
        [
            'setupActionRandomnessAuthorizationHash',
            input.setupActionRandomnessAuthorizationHash,
        ],
        ['suiteIdentifier', input.suiteIdentifier],
    ] as const) {
        if (value !== undefined && value.byteLength !== 64) {
            throw new TypeError(
                `The ${fieldName} value must contain exactly 64 bytes.`,
            );
        }
    }
    const subjectRosterPosition = input.subjectRosterPosition ?? 0;
    if (
        !Number.isSafeInteger(subjectRosterPosition) ||
        subjectRosterPosition < 0 ||
        subjectRosterPosition >= foundationProfile.participantCount
    ) {
        throw new TypeError(
            'The subjectRosterPosition value must name one participant in the fixed roster.',
        );
    }
    const signingKeyPairs = createCanonicalCarrierSigningKeyPairFixtures(
        foundationProfile.participantCount,
    );
    const mailboxKeyPairs = createCanonicalCarrierMailboxKeyPairFixtures(
        foundationProfile.participantCount,
    );
    try {
        const suiteIdentifier =
            input.suiteIdentifier?.slice() ?? new Uint8Array(64).fill(0x11);
        const ceremonyContextHash =
            input.ceremonyContextHash?.slice() ?? new Uint8Array(64).fill(0x22);
        const actionContextHash =
            input.actionContextHash?.slice() ?? new Uint8Array(64).fill(0x33);
        const canonicalRosterBytes = createCanonicalTestRosterBytes(
            signingKeyPairs.map(({ publicKey }, rosterPosition) => ({
                signingVerificationKey: publicKey,
                mailboxEncapsulationKey:
                    mailboxKeyPairs[rosterPosition].publicKey,
            })),
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
        const stateWitnessRosterPositions = Array.from(
            { length: foundationProfile.participantCount },
            (_unused, rosterPosition) => rosterPosition,
        )
            .filter(
                (rosterPosition) =>
                    rosterPosition !== subjectRosterPosition,
            )
            .slice(0, foundationProfile.stateWitnessQuorum);
        const witnessRosterPosition = stateWitnessRosterPositions[0];
        if (
            stateWitnessRosterPositions.length !==
                foundationProfile.stateWitnessQuorum ||
            witnessRosterPosition === undefined
        ) {
            throw new Error(
                'The deterministic state vector could not select its fixed-roster witnesses.',
            );
        }

        const signedCarrier = (carrierInput: {
            objectType: number;
            payloadBytes: Uint8Array;
            producerRosterPosition: number;
            producerSequence: bigint;
            signaturePurpose: string;
        }): SignedCarrierVector => {
            const canonicalEnvelopeBytes = canonicalTuple(
                0x0100,
                asciiItem('sealed-lattice'),
                unsigned16Item(1),
                hashItem(suiteIdentifier),
                unsigned16Item(carrierInput.objectType),
                hashItem(ceremonyContextHash),
                hashItem(actionContextHash),
                presentOptionalItem(
                    0x07,
                    participantIdentities[carrierInput.producerRosterPosition],
                ),
                unsigned64Item(carrierInput.producerSequence),
                emptyHomogeneousListItem(0x06),
                variableBytesItem(carrierInput.payloadBytes),
            );
            const objectHash = foundationHash512(
                'sealed-lattice/foundation/object/v1',
                variableBytesItem(canonicalEnvelopeBytes),
            );
            const signatureMessage = foundationHash512(
                'sealed-lattice/foundation/signature-message/v1',
                hashItem(objectHash),
                hashItem(rosterHash),
                asciiItem(carrierInput.signaturePurpose),
            );
            const signature = signCanonicalCarrierFixtureMessage(
                signatureMessage,
                signingKeyPairs[carrierInput.producerRosterPosition].secretKey,
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
            producerRosterPosition: subjectRosterPosition,
            producerSequence: 0n,
            signaturePurpose: 'state-reservation-intent',
        });
        const reservation: CertifiedStateIntentTestVector = {
            canonicalIntentCarrier: reservationCarrier.canonicalCarrierBytes,
            canonicalStateCertificate: certificateFor(
                reservationCarrier.objectHash,
                1n,
                stateWitnessRosterPositions,
            ),
            objectHash: reservationCarrier.objectHash,
        };
        const reservationVoteCarriers = stateWitnessRosterPositions.map(
            (producerRosterPosition) =>
                signedCarrier({
                    objectType: stateWitnessVoteObjectType,
                    payloadBytes: canonicalTuple(
                        0x1612,
                        hashItem(reservationCarrier.objectHash),
                    ),
                    producerRosterPosition,
                    producerSequence: 1n,
                    signaturePurpose: 'state-witness-vote',
                }).canonicalCarrierBytes,
        );
        const conflictingAuthorizationHash = authorizationHash.slice();
        conflictingAuthorizationHash[0] ^= 0xff;
        const conflictingReservationCarrier = signedCarrier({
            objectType: stateReservationObjectType,
            payloadBytes: canonicalTuple(
                0x1610,
                unsigned16Item(targetReleaseCapabilityKind),
                hashItem(conflictingAuthorizationHash),
            ),
            producerRosterPosition: subjectRosterPosition,
            producerSequence: 0n,
            signaturePurpose: 'state-reservation-intent',
        });
        const conflictingReservation: CertifiedStateIntentTestVector = {
            canonicalIntentCarrier:
                conflictingReservationCarrier.canonicalCarrierBytes,
            canonicalStateCertificate: certificateFor(
                conflictingReservationCarrier.objectHash,
                1n,
                stateWitnessRosterPositions,
            ),
            objectHash: conflictingReservationCarrier.objectHash,
        };
        const reservationOnly = [
            stateCapabilityKinds.setupActionRandomnessRoot,
            stateCapabilityKinds.setupTerminalPackage,
        ].map((capabilityKind): ReservationOnlyStateIntentTestVector => {
            const reservationAuthorizationHash =
                capabilityKind ===
                    stateCapabilityKinds.setupActionRandomnessRoot &&
                input.setupActionRandomnessAuthorizationHash !== undefined
                    ? input.setupActionRandomnessAuthorizationHash
                    : authorizationHash;
            const carrier = signedCarrier({
                objectType: stateReservationObjectType,
                payloadBytes: canonicalTuple(
                    0x1610,
                    unsigned16Item(capabilityKind),
                    hashItem(reservationAuthorizationHash),
                ),
                producerRosterPosition: subjectRosterPosition,
                producerSequence: 0n,
                signaturePurpose: 'state-reservation-intent',
            });
            return {
                capabilityKind,
                certifiedIntent: {
                    canonicalIntentCarrier: carrier.canonicalCarrierBytes,
                    canonicalStateCertificate: certificateFor(
                        carrier.objectHash,
                        1n,
                        stateWitnessRosterPositions,
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
            producerRosterPosition: subjectRosterPosition,
            producerSequence: 0n,
            signaturePurpose: 'state-output-intent',
        });
        const output: CertifiedStateIntentTestVector = {
            canonicalIntentCarrier: outputCarrier.canonicalCarrierBytes,
            canonicalStateCertificate: certificateFor(
                outputCarrier.objectHash,
                2n,
                stateWitnessRosterPositions,
            ),
            objectHash: outputCarrier.objectHash,
        };
        const invalidExtraOutputCertificate = certificateFor(
            outputCarrier.objectHash,
            2n,
            [
                ...stateWitnessRosterPositions,
                ...Array.from(
                    { length: foundationProfile.participantCount },
                    (_unused, rosterPosition) => rosterPosition,
                ).filter(
                    (rosterPosition) =>
                        rosterPosition !== subjectRosterPosition &&
                        !stateWitnessRosterPositions.includes(rosterPosition),
                ),
            ].slice(0, foundationProfile.stateWitnessQuorum + 1),
            true,
        );

        return {
            actionContextHash,
            authorizationHash,
            canonicalRosterBytes,
            ceremonyContextHash,
            conflictingReservation,
            exactOutputBytes,
            invalidExtraOutputCertificate,
            output,
            reservation,
            reservationVoteCarriers,
            reservationOnly,
            rosterHash,
            subjectParticipantIdentity:
                participantIdentities[subjectRosterPosition],
            suiteIdentifier,
            witnessParticipantIdentity:
                participantIdentities[witnessRosterPosition],
        };
    } finally {
        for (const { secretKey } of signingKeyPairs) {
            secretKey.fill(0);
        }
        for (const { secretKey } of mailboxKeyPairs) {
            secretKey.fill(0);
        }
    }
};
