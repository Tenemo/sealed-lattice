import { compileRegistrationKeyRelationCensus } from '#tests/registration-key-relation-model.js';

const registrationEnrollmentInputs = {
    signingPublicKeyBytes: 1952n,
    mailboxPublicKeyBytes: 1184n,
    signatureBytes: 3309n,
    maximumUsernameBytes: 128n,
    maximumUsernameIngressBytes: 512n,
    maximumHeaderInputBytes: 4096n,
    maximumPollDefinitionBytes: 1_048_576n,
} as const;

export const compileRegistrationEnrollmentCensus = () => {
    const key = compileRegistrationKeyRelationCensus();
    const inputs = registrationEnrollmentInputs;
    const ceiling = (value: bigint, divisor: bigint) =>
        (value + divisor - 1n) / divisor;
    const bytes = (value: string) => BigInt(Buffer.byteLength(value, 'utf8'));
    const maximumHeaderBytes =
        8n +
        8n * 6n +
        4n +
        bytes('sealed-lattice/registration-header/v2') +
        3n * 64n +
        inputs.signingPublicKeyBytes +
        inputs.mailboxPublicKeyBytes +
        8n +
        4n +
        inputs.maximumUsernameBytes;
    const recipientCapsuleBytes = 4n + key.support * 2n + 16n;
    const signingCapsuleBytes = 4n + 32n + 16n;
    const maximumEnrollmentRecords =
        ceiling(key.publicKeyBytes, 1_048_576n) +
        ceiling(key.maximumProofBytes, 1_048_576n) +
        6n;
    const maximumRecords = maximumEnrollmentRecords + 2n;
    const manifestPrefixBytes = 4n + 2n * 32n + 64n + 4n;
    const maximumEnrollmentManifestBytes =
        manifestPrefixBytes + maximumEnrollmentRecords * 73n;
    const maximumProposalIntentManifestBytes =
        manifestPrefixBytes + (maximumEnrollmentRecords + 1n) * 73n + 32n;
    const maximumManifestBytes =
        manifestPrefixBytes + maximumRecords * 73n + 32n;
    const maximumRootBytes = maximumManifestBytes + 16n;
    const proofRoleBytes =
        bytes('registered-recipient-key/1') + 2n * 64n + 128n;
    const pollDefinitionOverheadBytes =
        8n +
        6n * 6n +
        4n +
        bytes('sealed-lattice/poll-definition/v1') +
        64n +
        32n +
        inputs.signingPublicKeyBytes +
        4n +
        2n;
    return {
        ...inputs,
        maximumHeaderBytes,
        recipientCapsuleBytes,
        signingCapsuleBytes,
        maximumRecords,
        maximumEnrollmentRecords,
        maximumEnrollmentManifestBytes,
        maximumProposalIntentManifestBytes,
        manifestPrefixBytes,
        maximumManifestBytes,
        maximumRootBytes,
        proofRoleBytes,
        pollDefinitionOverheadBytes,
        maximumCreatorInputBytes:
            64n +
            2n +
            4n +
            inputs.maximumPollDefinitionBytes -
            pollDefinitionOverheadBytes +
            4n +
            inputs.maximumUsernameIngressBytes +
            64n,
        maximumJoinInputBytes:
            128n +
            4n +
            inputs.maximumPollDefinitionBytes +
            inputs.signatureBytes +
            4n +
            inputs.maximumUsernameIngressBytes +
            64n,
        recipientAssociatedBytes: 4n + 4n + proofRoleBytes + 3n * 64n,
        signingAssociatedBytes: bytes('registration-signing-seed/1') + 64n,
        rootAssociatedBytes: 4n + 64n,
        maximumRestoreInputBytes:
            128n +
            4n +
            inputs.maximumHeaderInputBytes +
            128n +
            64n +
            key.publicKeyBytes +
            recipientCapsuleBytes +
            signingCapsuleBytes +
            1n,
        maximumRetainedPayloadBytes:
            key.publicKeyBytes +
            key.maximumProofBytes +
            maximumHeaderBytes +
            inputs.signatureBytes +
            recipientCapsuleBytes +
            signingCapsuleBytes +
            maximumRootBytes +
            inputs.maximumPollDefinitionBytes +
            inputs.signatureBytes +
            2048n +
            inputs.signatureBytes,
        initialRootDistinctBlockInputs:
            1n +
            2n +
            ceiling(68n, 16n) +
            ceiling(maximumEnrollmentManifestBytes, 16n),
        // Proposal transitions each use a fresh root key for one encryption.
        rootDistinctBlockInputs: 2n + ceiling(maximumManifestBytes, 16n),
        signingDistinctBlockInputs:
            1n + 1n + ceiling(signingCapsuleBytes - 16n, 16n),
    };
};
