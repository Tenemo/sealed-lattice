import { compileRegistrationKeyRelationCensus } from '#tests/registration-key-relation-model.js';

export const compileRegistrationCustodyCensus = () => {
    const relation = compileRegistrationKeyRelationCensus();
    const chunkBytes = 1_048_576n;
    const ceiling = (value: bigint, divisor: bigint) =>
        (value + divisor - 1n) / divisor;
    const indexBytes = BigInt(
        Math.ceil(Math.log2(Number(relation.degree)) / 8),
    );
    const secretPlaintextBytes = 4n + relation.support * indexBytes;
    const capsuleBytes = secretPlaintextBytes + 16n;
    const recordCount =
        ceiling(relation.publicKeyBytes, chunkBytes) +
        ceiling(relation.maximumProofBytes, chunkBytes) +
        ceiling(capsuleBytes, chunkBytes);
    const manifestPrefixBytes = 4n + 2n * 64n + 32n + 4n;
    const recordReferenceBytes = 1n + 4n + 4n + 64n;
    const maximumManifestBytes =
        manifestPrefixBytes + recordCount * recordReferenceBytes;
    const maximumRootBytes = maximumManifestBytes + 16n;
    const maximumRoleBytes = 1024n;
    const maximumRootAssociatedBytes = 4n + 4n + maximumRoleBytes + 64n;
    const maximumCapsuleAssociatedBytes = maximumRootAssociatedBytes + 2n * 64n;
    const capsuleDistinctBlockInputs =
        1n + 1n + ceiling(secretPlaintextBytes, 16n);
    const rootDistinctBlockInputs =
        1n + 2n + ceiling(4n, 16n) + ceiling(maximumManifestBytes, 16n);
    const maximumCapsuleHashDegree =
        ceiling(maximumCapsuleAssociatedBytes, 16n) +
        ceiling(secretPlaintextBytes, 16n) +
        1n;
    const maximumRootHashDegree =
        ceiling(maximumRootAssociatedBytes, 16n) +
        ceiling(maximumManifestBytes, 16n) +
        1n;
    return {
        indexBytes,
        secretPlaintextBytes,
        capsuleBytes,
        recordCount,
        manifestPrefixBytes,
        recordReferenceBytes,
        maximumManifestBytes,
        maximumRootBytes,
        maximumRootAssociatedBytes,
        maximumCapsuleAssociatedBytes,
        maximumRestoreInputBytes:
            4n +
            maximumRoleBytes +
            64n +
            32n +
            2n * 64n +
            relation.publicKeyBytes +
            capsuleBytes,
        retainedPayloadBytes:
            relation.publicKeyBytes +
            relation.maximumProofBytes +
            capsuleBytes +
            maximumRootBytes,
        capsuleSealInvocations: 1n,
        rootSealInvocations: 2n,
        capsuleDistinctBlockInputs,
        rootDistinctBlockInputs,
        maximumCapsuleHashDegree,
        maximumRootHashDegree,
    };
};

export const registrationRootNonce = (ordinal: 0 | 1): Uint8Array => {
    const nonce = new Uint8Array(12);
    nonce[11] = ordinal;
    return nonce;
};
