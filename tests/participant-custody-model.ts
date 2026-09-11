import { compileBallotRandomnessBudget } from '#tests/ballot-randomness-budget-model.js';
import { compileContributionAuthenticationCensus } from '#tests/contribution-authentication-model.js';
import { compileContributionBodyCensus } from '#tests/contribution-body-model.js';
import { compileFirstOracleCheckpointCensus } from '#tests/first-oracle-checkpoint-model.js';
import { compileParticipantBallotCustody } from '#tests/participant-ballot-custody-model.js';
import { compileRegistrationEnrollmentCensus } from '#tests/registration-enrollment-model.js';
import { compileSetupContributionRelationCensus } from '#tests/setup-contribution-relation-model.js';

export const compileParticipantCustodyCensus = () => {
    const body = compileContributionBodyCensus();
    const checkpoint = compileFirstOracleCheckpointCensus();
    const enrollment = compileRegistrationEnrollmentCensus();
    const authentication = compileContributionAuthenticationCensus(
        body.participantCount,
    );
    const relation = compileSetupContributionRelationCensus();
    const chunkBytes = 1n << 20n;
    const publicRecords = body.polynomials.flatMap((polynomial) => {
        const records = [];
        for (let offset = 0n; offset < polynomial.bytes; offset += chunkBytes) {
            const remaining = polynomial.bytes - offset;
            records.push({
                object: polynomial.expandedIndex + 1,
                offset,
                length: remaining < chunkBytes ? remaining : chunkBytes,
            });
        }
        return records;
    });
    const checkpointLengths = checkpoint.fields.flatMap((field) => {
        const lengths = [];
        for (let used = 0n; used < field.units; used += field.unitsPerRecord) {
            const remaining = field.units - used;
            lengths.push(
                (remaining < field.unitsPerRecord
                    ? remaining
                    : field.unitsPerRecord) *
                    field.unitBytes +
                    16n,
            );
        }
        return lengths;
    });
    const maximumProofRecords =
        (body.maximumProofBytes + chunkBytes - 1n) / chunkBytes;
    const metadataPrefixBytes = 4n + 2n + body.saltBytes + 4n * 4n;
    const maximumCheckpointMetadataBytes =
        metadataPrefixBytes +
        checkpoint.maximumHeaderBytes +
        106n * BigInt(publicRecords.length) +
        96n * checkpoint.recordCount;
    const maximumCompletedMetadataBytes =
        metadataPrefixBytes +
        106n * (BigInt(publicRecords.length) + maximumProofRecords) +
        5n * 102n;
    const maximumMetadataBytes =
        maximumCheckpointMetadataBytes > maximumCompletedMetadataBytes
            ? maximumCheckpointMetadataBytes
            : maximumCompletedMetadataBytes;
    const maximumRootRecords = enrollment.maximumRecords + 1n;
    const ballot = compileParticipantBallotCustody();
    const setupReferenceBytes =
        4n + 64n + 64n * BigInt(body.polynomials.length);
    const maximumWithBallot =
        maximumCompletedMetadataBytes + 4n + ballot.maximumStateBytes;
    const maximumCombinedMetadata =
        maximumWithBallot > maximumMetadataBytes
            ? maximumWithBallot
            : maximumMetadataBytes;
    const maximumRootBytes =
        enrollment.manifestPrefixBytes +
        73n * maximumRootRecords +
        4n +
        maximumCombinedMetadata +
        16n;
    const maximumPublicBodyCiphertextBytes =
        body.polynomialPayloadBytes +
        body.maximumProofBytes +
        16n * (BigInt(publicRecords.length) + maximumProofRecords);
    const maximumSigningPlaintextBytes =
        authentication.confirmationBodyBytes +
        authentication.openingBodyBytes +
        2n * authentication.signatureBytes +
        4n +
        BigInt(body.participantCount) * authentication.confirmationPacketBytes;
    const maximumRetainedPayloadBytes =
        enrollment.maximumRetainedPayloadBytes -
        enrollment.maximumRootBytes +
        maximumRootBytes +
        setupReferenceBytes +
        maximumPublicBodyCiphertextBytes +
        checkpoint.ciphertextBytes +
        maximumSigningPlaintextBytes +
        5n * 16n;
    return {
        participants: body.participantCount,
        publicRecords,
        checkpointLengths,
        metadataPrefixBytes,
        maximumCheckpointMetadataBytes,
        maximumCompletedMetadataBytes,
        maximumMetadataBytes,
        maximumRootRecords,
        setupReferenceBytes,
        maximumRootBytes,
        maximumPublicBodyCiphertextBytes,
        maximumSigningPlaintextBytes,
        maximumRetainedPayloadBytes,
        expandedStatementBytes: relation.expandedStatementByteLength,
    };
};

type GcmInvocation = Readonly<{
    nonce: bigint;
    plaintextBytes: bigint;
    associatedBytes: bigint;
}>;

// SP 800-38D Algorithms 4/5 with 96-bit nonces and full tags. A history
// belongs to one sampled key, including all copies of that key's handle.
export const compileGcmKeyHistory = (
    encryptions: readonly GcmInvocation[],
    verifications: readonly GcmInvocation[],
) => {
    const blocks = (bytes: bigint) => (bytes + 15n) / 16n;
    const usedEncryptionNonces = new Set<bigint>();
    const payloadBlocksByNonce = new Map<bigint, bigint>();
    let algorithmicAesCallUpperBound = 0n;
    let maximumHashDegree = 0n;
    for (const [isEncryption, invocations] of [
        [true, encryptions],
        [false, verifications],
    ] as const) {
        for (const invocation of invocations) {
            const { nonce, plaintextBytes, associatedBytes } = invocation;
            if (
                nonce < 0n ||
                nonce >= 1n << 96n ||
                plaintextBytes < 0n ||
                plaintextBytes > (1n << 36n) - 32n ||
                associatedBytes < 0n ||
                associatedBytes >= 1n << 61n
            )
                throw new Error('Invocation exceeds the GCM byte bounds.');
            if (isEncryption) {
                if (usedEncryptionNonces.has(nonce))
                    throw new Error('An encryption key reused its nonce.');
                usedEncryptionNonces.add(nonce);
            }
            const payloadBlocks = blocks(plaintextBytes);
            const previous = payloadBlocksByNonce.get(nonce) ?? 0n;
            payloadBlocksByNonce.set(
                nonce,
                payloadBlocks > previous ? payloadBlocks : previous,
            );
            algorithmicAesCallUpperBound += 2n + payloadBlocks;
            const degree = blocks(associatedBytes) + payloadBlocks + 1n;
            if (degree > maximumHashDegree) maximumHashDegree = degree;
        }
    }
    // H uses the zero block. Every nonce has tag counter 1 and payload
    // counters 2..blocks+1; the length bound prevents wraparound.
    const distinctAesInputUpperBound =
        payloadBlocksByNonce.size === 0
            ? 0n
            : 1n +
              [...payloadBlocksByNonce.values()].reduce(
                  (total, payloadBlocks) => total + 1n + payloadBlocks,
                  0n,
              );
    return {
        encryptions: BigInt(encryptions.length),
        verifications: BigInt(verifications.length),
        distinctAesInputUpperBound,
        algorithmicAesCallUpperBound,
        maximumHashDegree,
        // Conditional terms after replacing the secret-key AES instances.
        // The multi-key QPT PRP advantage is additional, not zero.
        permutationSwitchNumerator:
            (distinctAesInputUpperBound * (distinctAesInputUpperBound - 1n)) /
            2n,
        authenticationNumerator:
            BigInt(verifications.length) * maximumHashDegree,
        statisticalDenominator: 1n << 128n,
    };
};

export const compileParticipantVaultKeyClasses = () => {
    const enrollment = compileRegistrationEnrollmentCensus();
    const custody = compileParticipantCustodyCensus();
    const body = compileContributionBodyCensus();
    const checkpoint = compileFirstOracleCheckpointCensus();
    const ballot = compileParticipantBallotCustody();
    const randomness = compileBallotRandomnessBudget();
    const authentication = compileContributionAuthenticationCensus(
        body.participantCount,
    );
    const maximumSigningRecordBytes = [
        authentication.confirmationBodyBytes,
        authentication.openingBodyBytes,
        authentication.signatureBytes,
        4n +
            BigInt(body.participantCount) *
                authentication.confirmationPacketBytes,
    ].reduce((maximum, bytes) => (bytes > maximum ? bytes : maximum), 0n);
    const chunkBytes = 1n << 20n;
    const contributionAssociatedBytes =
        BigInt(Buffer.byteLength('participant-contribution-record/1')) +
        128n +
        64n +
        2n +
        2n +
        4n +
        4n;
    const ballotAssociatedBytes =
        BigInt(
            Buffer.byteLength('sealed-lattice/participant-ballot-record/v1'),
        ) +
        3n * 64n +
        2n +
        1n +
        2n +
        4n;
    const invocation = (
        plaintextBytes: bigint,
        associatedBytes: bigint,
        nonce = 0n,
    ) => ({ nonce, plaintextBytes, associatedBytes });
    const classes = [
        {
            name: 'Initial root',
            maximumPerCompletedCorpus: 1n,
            encryptions: [
                invocation(68n, enrollment.rootAssociatedBytes),
                invocation(
                    enrollment.maximumEnrollmentManifestBytes,
                    enrollment.rootAssociatedBytes,
                    1n,
                ),
            ],
        },
        {
            name: 'Later root',
            maximumPerCompletedCorpus: null,
            encryptions: [
                invocation(
                    custody.maximumRootBytes - 16n,
                    enrollment.rootAssociatedBytes,
                ),
            ],
        },
        {
            name: 'Recipient capsule',
            maximumPerCompletedCorpus: 1n,
            encryptions: [
                invocation(
                    enrollment.recipientCapsuleBytes - 16n,
                    enrollment.recipientAssociatedBytes,
                ),
            ],
        },
        {
            name: 'Signing capsule',
            maximumPerCompletedCorpus: 1n,
            encryptions: [
                invocation(
                    enrollment.signingCapsuleBytes - 16n,
                    enrollment.signingAssociatedBytes,
                ),
            ],
        },
        {
            name: 'Contribution body record',
            maximumPerCompletedCorpus:
                BigInt(custody.publicRecords.length) +
                (body.maximumProofBytes + chunkBytes - 1n) / chunkBytes,
            encryptions: [invocation(chunkBytes, contributionAssociatedBytes)],
        },
        {
            name: 'Contribution checkpoint record',
            maximumPerCompletedCorpus: checkpoint.recordCount,
            encryptions: [
                invocation(
                    checkpoint.maximumPlaintextRecordBytes,
                    BigInt(Buffer.byteLength('first-oracle-checkpoint/1')) +
                        64n +
                        4n,
                ),
            ],
        },
        {
            name: 'Contribution signing record',
            maximumPerCompletedCorpus: 5n,
            encryptions: [
                invocation(
                    maximumSigningRecordBytes,
                    contributionAssociatedBytes,
                ),
            ],
        },
        {
            name: 'Ballot journal record',
            maximumPerCompletedCorpus: randomness.recordCount,
            encryptions: [
                invocation(randomness.recordBytes, ballotAssociatedBytes),
            ],
        },
        {
            name: 'Ballot body record',
            maximumPerCompletedCorpus: ballot.maximumBodyRecords,
            encryptions: [
                invocation(randomness.recordBytes, ballotAssociatedBytes),
            ],
        },
    ];
    return classes.map((value) => {
        const work = compileGcmKeyHistory(value.encryptions, []);
        return {
            ...value,
            encryptionWork: {
                invocations: work.encryptions,
                distinctAesInputUpperBound: work.distinctAesInputUpperBound,
                algorithmicAesCallUpperBound: work.algorithmicAesCallUpperBound,
                maximumHashDegree: work.maximumHashDegree,
            },
            lifetimeKeys: null,
            lifetimeVerifications: null,
        };
    });
};
