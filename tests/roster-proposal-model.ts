import { compileRegistrationEnrollmentCensus } from '#tests/registration-enrollment-model.js';
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
        5n * 6n +
        4n +
        bytes('sealed-lattice/setup-contribution/v1') +
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
        contributionControlBytes: 4n + 4n + roleBytes + count * 64n,
        retainedRecipientKeyBytes: count * key.publicKeyBytes,
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
