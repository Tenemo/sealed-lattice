import { operationSeedBytes, readModuleMemory } from './participant-module.js';
import type { ParticipantModule } from './participant-module.js';

// Every bound the worker enforces. The participant module reports the sizes
// of the objects it encodes or verifies; the worker adds the layouts of the
// state it retains itself. The page supplies none of them, and the profile
// comes from authenticated retained state.

type Range = Readonly<{ minimum: number; maximum: number }>;

// The foreground visit limit bounds every wait the worker cannot otherwise
// end: a state validation, and the waits for one public record's bytes.
export const foregroundVisitMilliseconds = 15 * 60 * 1000;

// A retained or published record holds at most one mebibyte, and a sealed
// record adds its AES-GCM tag. Each private record has its own key, and every
// record and root is named by its 64-byte identity.
export const chunkBytes = 1 << 20;
export const tagBytes = 16;
export const recordKeyBytes = 32;
export const identityBytes = 64;
const chunks = (bytes: number) => Math.ceil(bytes / chunkBytes);
const maximum = (...values: number[]) => Math.max(...values);

// The encrypted root manifest: its marker, data keys, poll and record
// count, then one reference per data record. Generation two retains the
// organizer's proposal intent, and each suffix has a length.
// The reservation includes the source key retained before setup. Later
// roots retire that key and its capsule and use a shorter actual prefix.
const rootPrefixBytes = 4 + 96 + 64 + 4;
const preparedRootPrefixBytes = 4 + 64 + 64 + 4;
// A root reference: its kind, ordinal, length and identity.
export const rootReferenceBytes = 1 + 4 + 4 + identityBytes;
const suffixLengthBytes = 4;

export type ParticipantLimits = Readonly<{
    participants: Range;
    options: Range;
    registration: Readonly<{
        publicKeyBytes: number;
        maximumHeaderBytes: number;
        maximumPollDefinitionBytes: number;
        maximumUsernameIngressBytes: number;
        signatureBytes: number;
        recipientCapsuleBytes: number;
        signingCapsuleBytes: number;
        maximumSourceCapsuleBytes: number;
        maximumProposalBytes: number;
    }>;
    root: Readonly<{
        maximumRecords: number;
        // Roots through the accepted roster retain only enrollment records,
        // the proposal and its signature.
        maximumEnrollmentRootBytes: number;
        // A later root, its setup reference and its setup certificate before
        // the retained proposal names the profile: the largest of any
        // supported profile.
        maximumRootBytes: number;
        maximumSetupReferenceBytes: number;
        maximumSetupCertificateBytes: number;
    }>;
}>;

export type ParticipantProfile = Readonly<{
    participantCount: number;
    optionCount: number;
    // Exactly d contributions are selected from the first k eligible positions.
    setupContributorCount: number;
    eligibleContributorCount: number;
    proposalBytes: number;
    registration: ParticipantLimits['registration'];
    root: Readonly<{
        maximumRecords: number;
        maximumRootBytes: number;
        setupReferenceBytes: number;
        // The setup certificate the setup was verified against.
        setupCertificateBytes: number;
    }>;
    contribution: Readonly<{
        // Setup polynomial i is statement object i + 1; object zero is the
        // statement header.
        expandedPolynomials: number;
        // The prover commits these witness columns, the base mask and the
        // degree mask in the first oracle.
        firstOracleColumns: number;
        statementBytes: number;
        bodyHeaderBytes: number;
        proofHeaderBytes: number;
        minimumProofBytes: number;
        maximumProofBytes: number;
        maximumStateBytes: number;
        maximumCheckpointHeaderBytes: number;
        offerEnvelopeBytes: number;
        requiredStorageBytes: number;
        // The polynomials a contribution body carries, in body order, each
        // of coefficients of one width.
        polynomials: readonly Readonly<{
            expandedIndex: number;
            bytes: number;
            coefficients: number;
        }>[];
        // Their retained records of at most one mebibyte.
        publicRecords: readonly Readonly<{
            object: number;
            offset: number;
            length: number;
        }>[];
        checkpointLengths: readonly number[];
    }>;
    preparation: Readonly<{
        selectionBodyBytes: number;
        endorsementBodyBytes: number;
        selectionReferenceBytes: number;
        certificateBytes: number;
        endorsementPacketBytes: number;
    }>;
    ballot: Readonly<{
        minimumScore: number;
        maximumScore: number;
        recordBytes: number;
        maximumStateBytes: number;
        headerBytes: number;
        minimumBodyBytes: number;
        maximumBodyBytes: number;
        envelopeBytes: number;
        requiredStorageBytes: number;
    }>;
    close: Readonly<{
        quorum: number;
        // An envelope and its signature.
        submissionBytes: number;
        intentBodyBytes: number;
        minimumResponseBodyBytes: number;
        maximumResponseBodyBytes: number;
        proposalBodyBytes: number;
        // A response the organizer takes, with every envelope it may list.
        maximumResponseRecordBytes: number;
        maximumEvents: number;
        maximumRecords: number;
        maximumStateBytes: number;
    }>;
    target: Readonly<{
        maximumBodyBytes: number;
        // The signer's position, the target identity and the signature.
        votePacketBytes: number;
        maximumStateBytes: number;
    }>;
    release: Readonly<{
        recordBytes: number;
        bodyHeaderBytes: number;
        minimumBodyBytes: number;
        maximumBodyBytes: number;
        envelopeBytes: number;
        maximumStateBytes: number;
    }>;
    // A stored working value of the public evaluation: both ciphertext
    // components' coefficients, each of whole little-endian words.
    evaluation: Readonly<{
        polynomialDegree: number;
        storedCoefficientBytes: number;
    }>;
}>;

// Reads the module's last bounds record, one little-endian 64-bit word per
// value, in the order the module writes them.
const moduleRecord = (module: ParticipantModule, count: number) => {
    const bytes = readModuleMemory(
        module,
        module.participant_bounds_pointer(),
        8 * count,
    );
    const view = new DataView(bytes.buffer);
    let next = 0;
    const take = () => {
        if (next === count)
            throw new Error('A participant bounds record is truncated.');
        const value = view.getBigUint64(8 * next++, true);
        if (value > BigInt(Number.MAX_SAFE_INTEGER))
            throw new Error('A participant bound is out of range.');
        return Number(value);
    };
    const list = <Item>(item: () => Item) =>
        Array.from({ length: take() }, item);
    const finish = () => {
        if (next !== count)
            throw new Error('A participant bounds record has extra values.');
    };
    return { take, list, finish };
};

// The bounds every profile shares, as the module reports them.
const readModuleLimits = (module: ParticipantModule) => {
    const { take, finish } = moduleRecord(module, module.participant_limits());
    const limits = {
        participants: { minimum: take(), maximum: take() },
        options: { minimum: take(), maximum: take() },
        registration: {
            publicKeyBytes: take(),
            maximumHeaderBytes: take(),
            maximumPollDefinitionBytes: take(),
            maximumUsernameIngressBytes: take(),
            signatureBytes: take(),
            recipientCapsuleBytes: take(),
            signingCapsuleBytes: take(),
            maximumSourceCapsuleBytes: take(),
            maximumProposalBytes: take(),
        },
        contribution: {
            bodyHeaderBytes: take(),
            proofHeaderBytes: take(),
            offerEnvelopeBytes: take(),
        },
        preparation: {
            endorsementBodyBytes: take(),
            endorsementPacketBytes: take(),
        },
        ballot: {
            minimumScore: take(),
            maximumScore: take(),
            recordBytes: take(),
            headerBytes: take(),
            envelopeBytes: take(),
        },
        close: {
            submissionBytes: take(),
            intentBodyBytes: take(),
            intentPacketBytes: take(),
            minimumResponseBodyBytes: take(),
            maximumListedEnvelopesPerSlot: take(),
        },
        target: { maximumBodyBytes: take(), votePacketBytes: take() },
        release: {
            recordBytes: take(),
            bodyHeaderBytes: take(),
            envelopeBytes: take(),
        },
        polynomialDegree: take(),
    };
    finish();
    return limits;
};
type ModuleLimits = ReturnType<typeof readModuleLimits>;

// One profile's sizes, as the module reports them.
const readModuleProfile = (
    module: ParticipantModule,
    participants: number,
    options: number,
) => {
    const count = module.participant_profile_bounds(participants, options);
    if (count === 0) return undefined;
    const { take, list, finish } = moduleRecord(module, count);
    const profile = {
        participantCount: take(),
        optionCount: take(),
        proposalBytes: take(),
        expandedPolynomials: take(),
        firstOracleColumns: take(),
        statementBytes: take(),
        minimumProofBytes: take(),
        maximumProofBytes: take(),
        maximumCheckpointHeaderBytes: take(),
        minimumBallotBodyBytes: take(),
        maximumBallotBodyBytes: take(),
        quorum: take(),
        faultBound: take(),
        setupContributorCount: take(),
        eligibleContributorCount: take(),
        maximumResponseBodyBytes: take(),
        maximumResponsePacketBytes: take(),
        proposalBodyBytes: take(),
        proposalPacketBytes: take(),
        minimumReleaseBodyBytes: take(),
        maximumReleaseBodyBytes: take(),
        storedCoefficientBytes: take(),
        selectionBodyBytes: take(),
        certificateBytes: take(),
        selectionReferenceBytes: take(),
        checkpointLengths: list(take),
        polynomials: list(() => ({
            expandedIndex: take(),
            bytes: take(),
            coefficients: take(),
        })),
    };
    finish();
    if (
        profile.participantCount !== participants ||
        profile.optionCount !== options
    )
        throw new Error('The participant module reported another profile.');
    return profile;
};
type ModuleProfile = NonNullable<ReturnType<typeof readModuleProfile>>;

// The data record kinds' largest lengths, in manifest order, with the
// proposal at its cap and the given setup reference and setup certificate.
const dataKindMaximums = (
    registration: ParticipantLimits['registration'],
    setupReferenceBytes: number,
    setupCertificateBytes: number,
) => [
    registration.publicKeyBytes,
    registration.maximumHeaderBytes,
    registration.signatureBytes,
    registration.recipientCapsuleBytes,
    registration.signingCapsuleBytes,
    registration.maximumPollDefinitionBytes,
    registration.signatureBytes,
    registration.maximumProposalBytes,
    registration.signatureBytes,
    setupReferenceBytes,
    setupCertificateBytes,
    registration.maximumSourceCapsuleBytes,
];

// The largest enrollment root: every record but the setup reference and
// certificate, which it lacks, and the organizer's proposal intent.
const enrollmentRootBytes = (registration: ParticipantLimits['registration']) =>
    rootPrefixBytes +
    rootReferenceBytes *
        dataKindMaximums(registration, 0, 0).reduce(
            (total, bytes) => total + chunks(bytes),
            0,
        ) +
    tagBytes;

// Everything the participant retains through its accepted roster: the
// registration records, the enrollment root, the poll and its signature, and
// the proposal and its signature.
const enrollmentPayloadBytes = (
    registration: ParticipantLimits['registration'],
) =>
    registration.publicKeyBytes +
    registration.maximumHeaderBytes +
    registration.signatureBytes +
    registration.recipientCapsuleBytes +
    registration.signingCapsuleBytes +
    registration.maximumSourceCapsuleBytes +
    enrollmentRootBytes(registration) +
    registration.maximumPollDefinitionBytes +
    registration.signatureBytes +
    registration.maximumProposalBytes +
    registration.signatureBytes;

// The contribution suffix: its marker, own phase, position and counts, the
// checkpoint header, a reference per public and private record, each
// signing record, and the seed of an interrupted generation or
// continuation.
const contributionPrefixBytes = 4 + 1 + 2 + 16;
export const publicEntryBytes = 2 + 4 + 4 + recordKeyBytes + identityBytes;
export const privateEntryBytes = recordKeyBytes + identityBytes;
export const signingEntryBytes = 2 + 4 + recordKeyBytes + identityBytes;
const signingRecords = 2;

const contributionBounds = (
    moduleLimits: ModuleLimits,
    profile: ModuleProfile,
) => {
    const { contribution } = moduleLimits;
    const publicRecords = profile.polynomials.flatMap((polynomial) =>
        Array.from({ length: chunks(polynomial.bytes) }, (_unused, index) => ({
            object: polynomial.expandedIndex + 1,
            offset: index * chunkBytes,
            length: Math.min(chunkBytes, polynomial.bytes - index * chunkBytes),
        })),
    );
    const maximumProofRecords = chunks(profile.maximumProofBytes);
    const prefix = contributionPrefixBytes;
    const completedStateBytes =
        prefix +
        contribution.bodyHeaderBytes +
        publicEntryBytes * (publicRecords.length + maximumProofRecords) +
        signingEntryBytes * signingRecords;
    return {
        expandedPolynomials: profile.expandedPolynomials,
        firstOracleColumns: profile.firstOracleColumns,
        statementBytes: profile.statementBytes,
        ...contribution,
        minimumProofBytes: profile.minimumProofBytes,
        maximumProofBytes: profile.maximumProofBytes,
        maximumCheckpointHeaderBytes: profile.maximumCheckpointHeaderBytes,
        maximumStateBytes: maximum(
            prefix +
                profile.maximumCheckpointHeaderBytes +
                publicEntryBytes * publicRecords.length +
                privateEntryBytes * profile.checkpointLengths.length +
                operationSeedBytes,
            completedStateBytes,
        ),
        polynomials: profile.polynomials,
        publicRecords,
        checkpointLengths: profile.checkpointLengths,
        // Sealed body and proof records, checkpoint records and signing
        // records.
        publicCiphertextBytes:
            profile.polynomials.reduce(
                (total, polynomial) => total + polynomial.bytes,
                0,
            ) +
            profile.maximumProofBytes +
            tagBytes * (publicRecords.length + maximumProofRecords),
        checkpointCiphertextBytes: profile.checkpointLengths.reduce(
            (total, length) => total + length,
            0,
        ),
        signingBytes:
            contribution.offerEnvelopeBytes +
            moduleLimits.registration.signatureBytes +
            tagBytes * signingRecords,
    };
};

// The ballot suffix: its marker, score count, body length and key count,
// the scores, the attempt's ballot time until the envelope carries it, the
// randomness seed until the body is retained, a key per body record, the
// envelope and the signature.
const ballotPrefixBytes = 4 + 1 + 4 + 2;
const ballotTimeBytes = 8;

const ballotBounds = (
    moduleLimits: ModuleLimits,
    limits: ParticipantLimits,
    profile: ModuleProfile,
) => {
    const { ballot } = moduleLimits;
    const bodyRecords = Math.ceil(
        profile.maximumBallotBodyBytes / ballot.recordBytes,
    );
    const attempt =
        ballotPrefixBytes + limits.options.maximum + ballotTimeBytes;
    const retainedBody = recordKeyBytes * bodyRecords + ballot.envelopeBytes;
    const signedStateBytes =
        ballotPrefixBytes +
        retainedBody +
        moduleLimits.registration.signatureBytes;
    return {
        ...ballot,
        bodyRecords,
        maximumStateBytes: maximum(
            attempt + operationSeedBytes,
            attempt + retainedBody,
            signedStateBytes,
        ),
        signedStateBytes,
        minimumBodyBytes: profile.minimumBallotBodyBytes,
        maximumBodyBytes: profile.maximumBallotBodyBytes,
        sealedBodyBytes:
            profile.maximumBallotBodyBytes + tagBytes * bodyRecords,
    };
};

// The close suffix: its marker and event count, then the accepted close
// inputs in arrival order. Each event holds its kind, its record count, the
// serial that locates its records, its payload length and a key per
// record: a held body has its envelope and body records, and a response the
// organizer takes one record.
const closePrefixBytes = 4 + 4;
const eventBytes = (records: number) =>
    1 + 2 + 4 + 4 + recordKeyBytes * records;

const closeBounds = (
    moduleLimits: ModuleLimits,
    profile: ModuleProfile,
    ballotBodyRecords: number,
) => {
    const { close } = moduleLimits;
    const participants = profile.participantCount;
    const corrupt = profile.faultBound;
    const listed = close.maximumListedEnvelopesPerSlot;
    // An honest author's one body arrives once; a corrupt slot can deliver
    // two before the intent lock and two on-time bodies after it, and
    // delivery keeps at most two envelopes per slot.
    const heldBodies = participants - corrupt + corrupt * listed;
    const responseEvents = participants - 1;
    const deliveryEventBytes = heldBodies * eventBytes(1 + ballotBodyRecords);
    const organizerEventBytes =
        deliveryEventBytes + eventBytes(0) + responseEvents * eventBytes(1);
    const intentStateBytes =
        closePrefixBytes + close.intentPacketBytes + organizerEventBytes;
    const completedStateBytes =
        intentStateBytes +
        profile.maximumResponsePacketBytes +
        profile.proposalPacketBytes;
    const collectingBytes = closePrefixBytes + deliveryEventBytes;
    return {
        quorum: profile.quorum,
        submissionBytes: close.submissionBytes,
        intentBodyBytes: close.intentBodyBytes,
        minimumResponseBodyBytes: close.minimumResponseBodyBytes,
        maximumResponseBodyBytes: profile.maximumResponseBodyBytes,
        proposalBodyBytes: profile.proposalBodyBytes,
        maximumResponseRecordBytes:
            profile.maximumResponsePacketBytes +
            listed * participants * close.submissionBytes,
        maximumEvents: heldBodies + 1 + responseEvents,
        maximumRecords: heldBodies * (1 + ballotBodyRecords) + responseEvents,
        maximumStateBytes: maximum(
            collectingBytes,
            collectingBytes + close.intentBodyBytes,
            intentStateBytes + 4 + profile.maximumResponseBodyBytes,
            intentStateBytes +
                profile.maximumResponsePacketBytes +
                profile.proposalBodyBytes,
            completedStateBytes,
        ),
        collectingBytes,
    };
};

// The target suffix: its marker, the close phase it follows, the own
// ballot's status and the body length, the target body, then the signed vote once completed.
const targetBounds = (moduleLimits: ModuleLimits) => {
    const { target } = moduleLimits;
    const prefix = 4 + 1 + 1 + 2;
    return {
        ...target,
        maximumStateBytes:
            prefix + target.maximumBodyBytes + target.votePacketBytes,
    };
};

// The release suffix: its marker, predecessor, own ballot status, target
// length, body length and key count, the target body, the randomness seed until the body exists,
// a key per body record, the envelope and the signature.
const releaseBounds = (moduleLimits: ModuleLimits, profile: ModuleProfile) => {
    const { release } = moduleLimits;
    const bodyRecords = Math.ceil(
        profile.maximumReleaseBodyBytes / release.recordBytes,
    );
    const attempt =
        4 + 1 + 1 + 2 + 4 + 2 + moduleLimits.target.maximumBodyBytes;
    const retainedBody = recordKeyBytes * bodyRecords + release.envelopeBytes;
    return {
        ...release,
        minimumBodyBytes: profile.minimumReleaseBodyBytes,
        maximumBodyBytes: profile.maximumReleaseBodyBytes,
        maximumStateBytes: maximum(
            attempt + operationSeedBytes,
            attempt + retainedBody,
            attempt + retainedBody + moduleLimits.registration.signatureBytes,
        ),
    };
};

// Marker, setup identity, one digest per aggregate polynomial, and the
// credential-keyed tag that the ballot step checks before parsing.
const setupReferenceBytes = (profile: ModuleProfile) =>
    4 + identityBytes * (profile.polynomials.length + 2);

// The setup certificate.
const setupCertificateBytes = (profile: ModuleProfile) =>
    profile.certificateBytes;

// Assembles one profile's bounds from the module's sizes and the retained
// layouts.
const profileBounds = (
    moduleLimits: ModuleLimits,
    limits: ParticipantLimits,
    profile: ModuleProfile,
): ParticipantProfile => {
    const {
        publicCiphertextBytes,
        checkpointCiphertextBytes,
        signingBytes,
        ...contribution
    } = contributionBounds(moduleLimits, profile);
    const { bodyRecords, signedStateBytes, sealedBodyBytes, ...ballot } =
        ballotBounds(moduleLimits, limits, profile);
    const { collectingBytes, ...close } = closeBounds(
        moduleLimits,
        profile,
        bodyRecords,
    );
    const target = targetBounds(moduleLimits);
    const release = releaseBounds(moduleLimits, profile);
    const setupReference = setupReferenceBytes(profile);
    const setupCertificate = setupCertificateBytes(profile);
    const preparation = {
        ...moduleLimits.preparation,
        selectionBodyBytes: profile.selectionBodyBytes,
        selectionReferenceBytes: profile.selectionReferenceBytes,
        certificateBytes: profile.certificateBytes,
    };
    // PRE2 frames three independent slots. Each signing slot retains the locked body,
    // followed by the signature on completion. At activation all slots empty.
    const emptyPreparationBytes = 4 + 3 * suffixLengthBytes;
    const selectionSlotBytes =
        1 +
        preparation.selectionBodyBytes +
        moduleLimits.registration.signatureBytes;
    const endorsementSlotBytes =
        1 +
        preparation.selectionBodyBytes +
        moduleLimits.registration.signatureBytes +
        preparation.selectionReferenceBytes +
        preparation.endorsementBodyBytes +
        moduleLimits.registration.signatureBytes;
    const maximumPreparationBytes =
        emptyPreparationBytes +
        contribution.maximumStateBytes +
        selectionSlotBytes +
        endorsementSlotBytes;
    const enrollmentRecords = dataKindMaximums(
        limits.registration,
        0,
        0,
    ).reduce((total, bytes) => total + chunks(bytes), 0);
    // Preparation retains the source capsule and own work; later roots
    // retire them and retain the verified setup reference and certificate.
    const suffixes = (...bytes: number[]) =>
        bytes.reduce((total, value) => total + suffixLengthBytes + value, 0);
    const maximumRootBytes =
        maximum(
            rootPrefixBytes +
                rootReferenceBytes * enrollmentRecords +
                suffixes(maximumPreparationBytes),
            preparedRootPrefixBytes +
                rootReferenceBytes * limits.root.maximumRecords +
                maximum(
                    suffixes(
                        emptyPreparationBytes,
                        ballot.maximumStateBytes,
                        collectingBytes,
                    ),
                    suffixes(
                        emptyPreparationBytes,
                        signedStateBytes,
                        close.maximumStateBytes,
                        target.maximumStateBytes,
                        release.maximumStateBytes,
                    ),
                ),
        ) + tagBytes;
    return {
        participantCount: profile.participantCount,
        optionCount: profile.optionCount,
        setupContributorCount: profile.setupContributorCount,
        eligibleContributorCount: profile.eligibleContributorCount,
        proposalBytes: profile.proposalBytes,
        registration: limits.registration,
        root: {
            maximumRecords: limits.root.maximumRecords,
            maximumRootBytes,
            setupReferenceBytes: setupReference,
            setupCertificateBytes: setupCertificate,
        },
        contribution: {
            ...contribution,
            requiredStorageBytes:
                enrollmentPayloadBytes(limits.registration) -
                enrollmentRootBytes(limits.registration) +
                maximumRootBytes +
                setupReference +
                setupCertificate +
                publicCiphertextBytes +
                checkpointCiphertextBytes +
                signingBytes,
        },
        preparation,
        ballot: {
            ...ballot,
            requiredStorageBytes:
                sealedBodyBytes + ballot.maximumStateBytes + maximumRootBytes,
        },
        close,
        target,
        release,
        evaluation: {
            polynomialDegree: moduleLimits.polynomialDegree,
            storedCoefficientBytes: profile.storedCoefficientBytes,
        },
    };
};

// Reads the module's shared bounds and the largest supported profile's,
// which bound a root and its setup reference before the retained proposal
// names the profile.
export const readParticipantLimits = (
    module: ParticipantModule,
): ParticipantLimits => {
    const moduleLimits = readModuleLimits(module);
    const { participants, options, registration } = moduleLimits;
    const largest = readModuleProfile(
        module,
        participants.maximum,
        options.maximum,
    );
    if (largest === undefined)
        throw new Error('The participant module lacks its largest profile.');
    const maximumSetupReferenceBytes = setupReferenceBytes(largest);
    const maximumSetupCertificateBytes = setupCertificateBytes(largest);
    const enrollment: ParticipantLimits = {
        participants,
        options,
        registration,
        root: {
            maximumRecords: dataKindMaximums(
                { ...registration, maximumSourceCapsuleBytes: 0 },
                maximumSetupReferenceBytes,
                maximumSetupCertificateBytes,
            ).reduce((total, bytes) => total + chunks(bytes), 0),
            maximumEnrollmentRootBytes: enrollmentRootBytes(registration),
            maximumRootBytes: 0,
            maximumSetupReferenceBytes,
            maximumSetupCertificateBytes,
        },
    };
    return {
        ...enrollment,
        root: {
            ...enrollment.root,
            maximumRootBytes: profileBounds(moduleLimits, enrollment, largest)
                .root.maximumRootBytes,
        },
    };
};

// A supported profile's bounds, or undefined for another profile.
export const readParticipantProfile = (
    module: ParticipantModule,
    limits: ParticipantLimits,
    participantCount: number,
    optionCount: number,
): ParticipantProfile | undefined => {
    const profile = readModuleProfile(module, participantCount, optionCount);
    return profile === undefined
        ? undefined
        : profileBounds(readModuleLimits(module), limits, profile);
};

export const participantDataKindMaximums = (limits: ParticipantLimits) =>
    dataKindMaximums(
        limits.registration,
        limits.root.maximumSetupReferenceBytes,
        limits.root.maximumSetupCertificateBytes,
    );
