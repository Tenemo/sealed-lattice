import { compileRegistrationKeyRelationCensus } from '#tests/registration-key-relation-model.js';

const registrationEnrollmentInputs = {
    signingPublicKeyBytes: 1952n,
    mailboxPublicKeyBytes: 1184n,
    signatureBytes: 3309n,
    maximumUsernameBytes: 128n,
    maximumUsernameIngressBytes: 512n,
    maximumHeaderInputBytes: 4096n,
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
    const maximumRecords =
        ceiling(key.publicKeyBytes, 1_048_576n) +
        ceiling(key.maximumProofBytes, 1_048_576n) +
        4n;
    const manifestPrefixBytes = 4n + 2n * 32n + 4n;
    const maximumManifestBytes = manifestPrefixBytes + maximumRecords * 73n;
    const maximumRootBytes = maximumManifestBytes + 16n;
    const proofRoleBytes =
        bytes('registered-recipient-key/1') + 2n * 64n + 128n;
    return {
        ...inputs,
        maximumHeaderBytes,
        recipientCapsuleBytes,
        signingCapsuleBytes,
        maximumRecords,
        manifestPrefixBytes,
        maximumManifestBytes,
        maximumRootBytes,
        proofRoleBytes,
        recipientAssociatedBytes: 4n + 4n + proofRoleBytes + 3n * 64n,
        signingAssociatedBytes: bytes('registration-signing-seed/1') + 64n,
        rootAssociatedBytes: 4n + 2n * 64n,
        maximumRestoreInputBytes:
            128n +
            4n +
            inputs.maximumHeaderInputBytes +
            128n +
            64n +
            key.publicKeyBytes +
            recipientCapsuleBytes +
            signingCapsuleBytes,
        maximumRetainedPayloadBytes:
            key.publicKeyBytes +
            key.maximumProofBytes +
            maximumHeaderBytes +
            inputs.signatureBytes +
            recipientCapsuleBytes +
            signingCapsuleBytes +
            maximumRootBytes,
        rootDistinctBlockInputs:
            1n + 2n + 1n + ceiling(maximumManifestBytes, 16n),
        signingDistinctBlockInputs:
            1n + 1n + ceiling(signingCapsuleBytes - 16n, 16n),
    };
};
