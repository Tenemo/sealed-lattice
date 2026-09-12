import { compileThresholdCompletionProfile } from '#tests/threshold-completion-model.js';

const signatureBytes = 3309n;
const tupleBytes = (purpose: string, fixedBytes: bigint, fields: bigint) =>
    8n +
    6n * fields +
    4n +
    BigInt(Buffer.byteLength(purpose, 'ascii')) +
    fixedBytes;

export const compileSlotPublicationResourceCensus = (
    participantCount: number,
) => {
    const profile = compileThresholdCompletionProfile(participantCount);
    const participants = BigInt(participantCount);
    const otherWitnesses = BigInt(profile.maximumCorruptParticipantCount);
    const closeBodyBytes = tupleBytes(
        'sealed-lattice/ballot-close/v1',
        128n,
        3n,
    );
    const emptyBodyBytes = tupleBytes(
        'sealed-lattice/empty-slot/v1',
        128n + 2n + 64n,
        5n,
    );
    const witnessBodyBytes = tupleBytes(
        'sealed-lattice/slot-witness/v1',
        128n + 2n + 4n + 64n * otherWitnesses,
        5n,
    );
    const closedBodyBytes = tupleBytes(
        'sealed-lattice/closed-slots/v1',
        128n + 64n + 4n + 64n * participants,
        5n,
    );
    const ballotEnvelopeBytes = 4n + 64n + 64n + 2n + 8n + 64n;
    const maximumSourceMetadataBytes =
        participants *
        ((emptyBodyBytes > ballotEnvelopeBytes
            ? emptyBodyBytes
            : ballotEnvelopeBytes) +
            signatureBytes);
    const ordinaryWitnessBytes =
        otherWitnesses === 0n
            ? 0n
            : participants * (witnessBodyBytes + signatureBytes);
    // A corrupt witness may have used different valid batches in different
    // completed slot certificates. Preserve each required carrier rather than
    // requiring a newly coherent global row from that corrupt participant.
    const maximumWitnessCarrierBytes =
        participants * otherWitnesses * (witnessBodyBytes + signatureBytes);
    return {
        participantCount: participants,
        otherWitnesses,
        closeBodyBytes,
        emptyBodyBytes,
        witnessBodyBytes,
        closedBodyBytes,
        ballotEnvelopeBytes,
        signatureBytes,
        maximumSourceMetadataBytes,
        ordinaryWitnessBytes,
        maximumWitnessCarrierBytes,
        maximumEvidenceMetadataBytes:
            closeBodyBytes +
            signatureBytes +
            maximumSourceMetadataBytes +
            maximumWitnessCarrierBytes +
            closedBodyBytes,
        ordinarySignatureEvaluations:
            1n + participants + (otherWitnesses === 0n ? 0n : participants),
    };
};
