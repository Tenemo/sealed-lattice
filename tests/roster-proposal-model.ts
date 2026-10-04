import {
    compileRegistrationEnrollmentCensus,
    participantIdentityAsciiBytes,
    retainedRosterBytes,
} from '#tests/registration-enrollment-model.js';
import { compileRegistrationKeyRelationCensus } from '#tests/registration-key-relation-model.js';

export const compileRosterProposalCensus = (participantCount: number) => {
    if (
        !Number.isSafeInteger(participantCount) ||
        participantCount < 3 ||
        participantCount > 20
    )
        throw new RangeError('Unsupported roster size.');
    const count = BigInt(participantCount);
    const registration = compileRegistrationEnrollmentCensus();
    const key = compileRegistrationKeyRelationCensus();
    const bytes = (value: string) => BigInt(Buffer.byteLength(value));
    const roleBytes =
        8n +
        6n * 6n +
        4n +
        bytes('sealed-lattice/setup-contribution/v2') +
        4n +
        participantIdentityAsciiBytes +
        3n * 64n +
        2n;
    const proposalBytes =
        8n +
        4n * 6n +
        4n +
        bytes('sealed-lattice/roster-proposal/v1') +
        2n * 64n +
        4n +
        4n +
        count * 64n;
    return {
        participantCount,
        roleBytes,
        proposalBytes,
        retainedRosterBytes: retainedRosterBytes(count),
        retainedRecipientKeyBytes: count * key.publicKeyBytes,
        retainedRecordPayloadBytes:
            count *
            (key.publicKeyBytes + registration.maximumHeaderBytes + 64n),
        maximumPublicCorpusBytes:
            registration.maximumPollDefinitionBytes +
            registration.signatureBytes +
            count *
                (key.publicKeyBytes +
                    key.maximumProofBytes +
                    registration.maximumHeaderBytes +
                    registration.signatureBytes),
    };
};
