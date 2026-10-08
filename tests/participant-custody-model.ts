import { compileContributionBodyCensus } from '#tests/contribution-body-model.js';
import { compileFirstOracleCheckpointCensus } from '#tests/first-oracle-checkpoint-model.js';
import { operationSeedBytes } from '#tests/operation-seed-model.js';
import { compileParticipantBallotCustody } from '#tests/participant-ballot-custody-model.js';
import { compileParticipantCloseCustody } from '#tests/participant-close-custody-model.js';
import { compileParticipantReleaseCustody } from '#tests/participant-release-custody-model.js';
import { compileRegistrationEnrollmentCensus } from '#tests/registration-enrollment-model.js';
import { compileSetupContributionRelationCensus } from '#tests/setup-contribution-relation-model.js';
import { compileSetupSelectionWireCensus } from '#tests/setup-selection-wire-model.js';
import type { SupportedProfile } from '#tests/supported-profile-model.js';
import { compileTargetSigningStateCensus } from '#tests/target-signing-state-model.js';

const retainedProofRecordBytes = 1n << 20n;
const retainedRecordTagBytes = 16n;
const retainedPublicReferenceBytes = 2n + 4n + 4n + 32n + 64n;

const proofRecordLayout = (maximumProofBytes: bigint) => {
    const records: { offset: bigint; length: bigint }[] = [];
    for (
        let offset = 0n;
        offset < maximumProofBytes;
        offset += retainedProofRecordBytes
    )
        records.push({
            offset,
            length:
                maximumProofBytes - offset < retainedProofRecordBytes
                    ? maximumProofBytes - offset
                    : retainedProofRecordBytes,
        });
    return records;
};

export const compileContributionProofStorage = (profile: SupportedProfile) => {
    const body = compileContributionBodyCensus(profile);
    const records = proofRecordLayout(body.maximumProofBytes);
    const count = BigInt(records.length);
    return {
        records,
        plaintextBytes: body.maximumProofBytes,
        ciphertextBytes:
            body.maximumProofBytes + retainedRecordTagBytes * count,
        dataKeyBytes: 32n * count,
        recordIdentityBytes: 64n * count,
        recordReferenceBytes: retainedPublicReferenceBytes * count,
        completedBodyHeaderBytes: body.headerBytes,
    };
};

// A byte/work projection for one observed complete proof length. The format's
// lower framing bound does not assert that a proof of that length is possible.
// Every full consumer authenticates the whole fixed slot set, including its
// zero tail; only the original proof prefix is hashed or published publicly.
export const projectContributionProofPadding = (
    profile: SupportedProfile,
    observedProofBytes: bigint,
    completeReadPasses: bigint,
) => {
    const body = compileContributionBodyCensus(profile);
    if (
        observedProofBytes < body.minimumProofBytes ||
        observedProofBytes > body.maximumProofBytes ||
        completeReadPasses < 0n
    )
        throw new RangeError(
            'Proof length or complete-read count is outside its bounds.',
        );
    const variableRecords = BigInt(
        proofRecordLayout(observedProofBytes).length,
    );
    const fixed = compileContributionProofStorage(profile);
    const addedRecords = BigInt(fixed.records.length) - variableRecords;
    const paddingBytes = fixed.plaintextBytes - observedProofBytes;
    const additionalProofCiphertextBytes =
        paddingBytes + retainedRecordTagBytes * addedRecords;
    const additionalCompletedRootBytes =
        body.headerBytes + retainedPublicReferenceBytes * addedRecords;
    return {
        observedProofBytes,
        completeReadPasses,
        paddingBytes,
        additionalProofRecords: addedRecords,
        additionalProofRecordKeyBytes: 32n * addedRecords,
        additionalProofRecordIdentityBytes: 64n * addedRecords,
        additionalProofRecordTagBytes: retainedRecordTagBytes * addedRecords,
        additionalProofCiphertextBytes,
        additionalCompletedRootBytes,
        additionalCompletedRetainedBytes:
            additionalProofCiphertextBytes + additionalCompletedRootBytes,
        additionalProofWriteBytes: additionalProofCiphertextBytes,
        additionalProofReadBytes:
            completeReadPasses * additionalProofCiphertextBytes,
        additionalProofVerificationCalls: completeReadPasses * addedRecords,
        // The source-opening salt stays in SCB2; padding changes no proof bytes.
        publishedProofBytes: observedProofBytes,
    };
};

export const compileParticipantCustodyCensus = (profile: SupportedProfile) => {
    const body = compileContributionBodyCensus(profile);
    const checkpoint = compileFirstOracleCheckpointCensus(profile);
    const enrollment = compileRegistrationEnrollmentCensus();
    const wire = compileSetupSelectionWireCensus(profile.participantCount);
    const relation = compileSetupContributionRelationCensus(profile);
    const chunkBytes = 1n << 20n;
    const chunks = (bytes: bigint) => (bytes + chunkBytes - 1n) / chunkBytes;
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
    const maximumProofRecords = chunks(body.maximumProofBytes);
    // PCS5 owns its phase independently of global preparation generation.
    const metadataPrefixBytes = 4n + 1n + 2n + 4n * 4n;
    const maximumCheckpointMetadataBytes =
        metadataPrefixBytes +
        checkpoint.maximumHeaderBytes +
        106n * BigInt(publicRecords.length) +
        96n * checkpoint.recordCount +
        operationSeedBytes;
    const maximumCompletedMetadataBytes =
        metadataPrefixBytes +
        body.headerBytes +
        106n * (BigInt(publicRecords.length) + maximumProofRecords) +
        2n * 102n;
    const maximumMetadataBytes =
        maximumCheckpointMetadataBytes > maximumCompletedMetadataBytes
            ? maximumCheckpointMetadataBytes
            : maximumCompletedMetadataBytes;
    // SAV1 and SPI1 contain the semantic selection identity, ordered aggregate
    // polynomial identities and the owning verifier's credential-keyed tag.
    const setupReferenceBytes =
        4n + 64n + 64n * BigInt(body.polynomials.length) + 64n;
    const selectionReferenceBytes = setupReferenceBytes;
    const setupCertificateBytes = wire.certificateBytes;
    const emptyPreparationBytes = 4n + 3n * 4n;
    const maximumSelectionSlotBytes =
        1n + wire.selectionBodyBytes + wire.signatureBytes;
    const maximumEndorsementSlotBytes =
        1n +
        wire.selectionBodyBytes +
        wire.signatureBytes +
        selectionReferenceBytes +
        wire.endorsementBodyBytes +
        wire.signatureBytes;
    const maximumPreparationBytes =
        emptyPreparationBytes +
        maximumMetadataBytes +
        maximumSelectionSlotBytes +
        maximumEndorsementSlotBytes;
    const maximumEnrollmentRootRecords = enrollment.maximumRecords;
    const maximumRootRecords =
        enrollment.maximumRecords -
        chunks(enrollment.maximumSourceCapsuleBytes) +
        chunks(setupReferenceBytes) +
        chunks(setupCertificateBytes);
    const ballot = compileParticipantBallotCustody(profile);
    const close = compileParticipantCloseCustody(profile);
    const targetSigning = compileTargetSigningStateCensus();
    const release = compileParticipantReleaseCustody(profile);
    const completedBallotBytes = ballot.phaseBytes.find(
        (value) => value.phase === 17,
    )!.bytes;
    const maximumBallotSuffixes =
        4n +
        emptyPreparationBytes +
        4n +
        ballot.maximumStateBytes +
        4n +
        close.collectingBytes;
    const maximumReleaseSuffixes =
        4n +
        emptyPreparationBytes +
        4n +
        completedBallotBytes +
        4n +
        close.maximumStateBytes +
        4n +
        targetSigning.maximumStateBytes +
        4n +
        release.maximumStateBytes;
    const maximumLaterSuffixes =
        maximumBallotSuffixes > maximumReleaseSuffixes
            ? maximumBallotSuffixes
            : maximumReleaseSuffixes;
    const maximumPreparationRootBytes =
        enrollment.manifestPrefixBytes +
        73n * maximumEnrollmentRootRecords +
        4n +
        maximumPreparationBytes +
        16n;
    const maximumPreparedRootBytes =
        enrollment.preparedManifestPrefixBytes +
        73n * maximumRootRecords +
        maximumLaterSuffixes +
        16n;
    const maximumRootBytes =
        maximumPreparationRootBytes > maximumPreparedRootBytes
            ? maximumPreparationRootBytes
            : maximumPreparedRootBytes;
    const maximumPublicBodyCiphertextBytes =
        body.polynomialPayloadBytes +
        body.maximumProofBytes +
        16n * (BigInt(publicRecords.length) + maximumProofRecords);
    const maximumSigningPlaintextBytes =
        wire.offerEnvelopeBytes + wire.signatureBytes;
    // This reservation covers the activation overlap before the source,
    // private checkpoint and own contribution stores are atomically retired.
    const maximumRetainedPayloadBytes =
        enrollment.maximumRetainedPayloadBytes -
        enrollment.maximumRootBytes +
        maximumRootBytes +
        setupReferenceBytes +
        setupCertificateBytes +
        maximumPublicBodyCiphertextBytes +
        checkpoint.ciphertextBytes +
        maximumSigningPlaintextBytes +
        2n * 16n;
    return {
        maximumReleaseStateBytes: release.maximumStateBytes,
        participants: body.participantCount,
        publicRecords,
        checkpointLengths,
        metadataPrefixBytes,
        maximumCheckpointMetadataBytes,
        maximumCompletedMetadataBytes,
        completedBodyHeaderBytes: body.headerBytes,
        maximumMetadataBytes,
        emptyPreparationBytes,
        maximumPreparationBytes,
        maximumSelectionSlotBytes,
        maximumEndorsementSlotBytes,
        selectionReferenceBytes,
        maximumEnrollmentRootRecords,
        maximumRootRecords,
        setupReferenceBytes,
        setupCertificateBytes,
        maximumPreparationRootBytes,
        maximumPreparedRootBytes,
        maximumRootBytes,
        maximumCloseStateBytes: close.maximumStateBytes,
        maximumTargetSigningStateBytes: targetSigning.maximumStateBytes,
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

export const compileParticipantVaultKeyClasses = (
    profile: SupportedProfile,
) => {
    const enrollment = compileRegistrationEnrollmentCensus();
    const custody = compileParticipantCustodyCensus(profile);
    const body = compileContributionBodyCensus(profile);
    const checkpoint = compileFirstOracleCheckpointCensus(profile);
    const ballot = compileParticipantBallotCustody(profile);
    const release = compileParticipantReleaseCustody(profile);
    const authentication = compileSetupSelectionWireCensus(
        body.participantCount,
    );
    const maximumSigningRecordBytes = [
        authentication.offerEnvelopeBytes,
        authentication.signatureBytes,
    ].reduce((maximum, bytes) => (bytes > maximum ? bytes : maximum), 0n);
    const chunkBytes = 1n << 20n;
    // The poll and proposal identities, the position and the record's
    // object, offset and length.
    const contributionAssociatedBytes =
        BigInt(
            Buffer.byteLength(
                'sealed-lattice/participant-contribution-record/v2',
            ),
        ) +
        64n +
        64n +
        2n +
        2n +
        4n +
        4n;
    // The poll and setup inventory, the position, a release's certified
    // target digest, and the record's index and length.
    const ballotAssociatedBytes =
        BigInt(
            Buffer.byteLength('sealed-lattice/participant-ballot-record/v3'),
        ) +
        2n * 64n +
        2n +
        2n +
        4n;
    const releaseAssociatedBytes =
        BigInt(
            Buffer.byteLength('sealed-lattice/participant-release-record/v3'),
        ) +
        2n * 64n +
        2n +
        64n +
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
            name: 'FHE source capsule',
            maximumPerCompletedCorpus: 1n,
            encryptions: [
                invocation(
                    enrollment.maximumSourceCapsuleBytes - 16n,
                    enrollment.sourceAssociatedBytes,
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
            maximumPerCompletedCorpus: 2n,
            encryptions: [
                invocation(
                    maximumSigningRecordBytes,
                    contributionAssociatedBytes,
                ),
            ],
        },
        {
            name: 'Ballot body record',
            maximumPerCompletedCorpus: ballot.maximumBodyRecords,
            encryptions: [
                invocation(ballot.recordBytes, ballotAssociatedBytes),
            ],
        },
        {
            name: 'Release body record',
            maximumPerCompletedCorpus: release.maximumBodyRecords,
            encryptions: [
                invocation(release.recordBytes, releaseAssociatedBytes),
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
