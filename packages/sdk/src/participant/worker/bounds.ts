import { operationSeedBytes, readKernel } from './kernel.js';
import type { ParticipantKernel } from './kernel.js';

// Every bound the worker enforces. The participant module reports the sizes
// of the objects it encodes or verifies; the worker adds the layouts of the
// state it retains itself. The page supplies none of them, and the profile
// comes from authenticated retained state.

type Range = Readonly<{ minimum: number; maximum: number }>;

// A retained or published record holds at most one mebibyte, and a sealed
// record adds its AES-GCM tag.
const chunkBytes = 1 << 20;
const tagBytes = 16;
const keyBytes = 32;
const identityBytes = 64;
// The archive index's content identity and unsigned 64-bit encoded length.
export const setupArchiveReferenceBytes = identityBytes + 8;
const coinBytes = 32;
const chunks = (bytes: number) => Math.ceil(bytes / chunkBytes);
const maximum = (...values: number[]) => Math.max(...values);

// The encrypted root manifest: its marker, data keys, poll and record
// count, then one reference per data record. Generation two retains the
// organizer's proposal signing coins, and each suffix has a length.
const rootPrefixBytes = 4 + 64 + 64 + 4;
const rootReferenceBytes = 1 + 4 + 4 + identityBytes;
const suffixLengthBytes = 4;

export type ParticipantLimits = Readonly<{
    participants: Range;
    options: Range;
    registration: Readonly<{
        publicKeyBytes: number;
        maximumProofBytes: number;
        maximumHeaderBytes: number;
        maximumPollDefinitionBytes: number;
        maximumUsernameIngressBytes: number;
        signatureBytes: number;
        recipientCapsuleBytes: number;
        signingCapsuleBytes: number;
        maximumProposalBytes: number;
        // The participant's verification of its own registration, keyed to
        // its credential.
        retainedRegistrationBytes: number;
    }>;
    root: Readonly<{
        maximumRecords: number;
        // Roots through the accepted roster retain only enrollment records,
        // the proposal, its signature, the retained roster and the retained
        // registration.
        maximumEnrollmentRootBytes: number;
        // A later root, its setup reference, its setup inventory and the
        // retained roster before the roster names the profile: the largest
        // of any supported profile.
        maximumRootBytes: number;
        maximumSetupReferenceBytes: number;
        maximumSetupInventoryBytes: number;
        maximumRetainedRosterBytes: number;
    }>;
}>;

export type ParticipantProfile = Readonly<{
    participantCount: number;
    optionCount: number;
    // Only the first roster positions contribute setup key material; every
    // participant verifies their contributions.
    setupContributorCount: number;
    proposalBytes: number;
    registration: ParticipantLimits['registration'];
    root: Readonly<{
        maximumRecords: number;
        maximumRootBytes: number;
        setupReferenceBytes: number;
        // The confirmation inventory the setup was verified against.
        setupInventoryBytes: number;
        // The participant's roster verification, keyed to its credential.
        retainedRosterBytes: number;
    }>;
    contribution: Readonly<{
        // Setup polynomial i is statement object i + 1; object zero is the
        // statement header.
        expandedPolynomials: number;
        // The prover commits these witness columns, the base mask and the
        // degree mask in the first oracle.
        firstOracleColumns: number;
        statementBytes: number;
        saltBytes: number;
        bodyHeaderBytes: number;
        proofHeaderBytes: number;
        minimumProofBytes: number;
        maximumProofBytes: number;
        maximumStateBytes: number;
        maximumCheckpointHeaderBytes: number;
        confirmationBodyBytes: number;
        openingBodyBytes: number;
        confirmationPacketBytes: number;
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
const moduleRecord = (kernel: ParticipantKernel, count: number) => {
    const bytes = readKernel(
        kernel,
        kernel.participant_bounds_pointer(),
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
const readModuleLimits = (kernel: ParticipantKernel) => {
    const { take, finish } = moduleRecord(kernel, kernel.participant_limits());
    const limits = {
        participants: { minimum: take(), maximum: take() },
        options: { minimum: take(), maximum: take() },
        registration: {
            publicKeyBytes: take(),
            maximumProofBytes: take(),
            maximumHeaderBytes: take(),
            maximumPollDefinitionBytes: take(),
            maximumUsernameIngressBytes: take(),
            signatureBytes: take(),
            recipientCapsuleBytes: take(),
            signingCapsuleBytes: take(),
            maximumProposalBytes: take(),
            retainedRegistrationBytes: take(),
        },
        contribution: {
            saltBytes: take(),
            bodyHeaderBytes: take(),
            proofHeaderBytes: take(),
            confirmationBodyBytes: take(),
            openingBodyBytes: take(),
            confirmationPacketBytes: take(),
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
    kernel: ParticipantKernel,
    participants: number,
    options: number,
) => {
    const count = kernel.participant_profile_bounds(participants, options);
    if (count === 0) return undefined;
    const { take, list, finish } = moduleRecord(kernel, count);
    const profile = {
        participantCount: take(),
        optionCount: take(),
        proposalBytes: take(),
        retainedRosterBytes: take(),
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
        maximumResponseBodyBytes: take(),
        maximumResponsePacketBytes: take(),
        proposalBodyBytes: take(),
        proposalPacketBytes: take(),
        minimumReleaseBodyBytes: take(),
        maximumReleaseBodyBytes: take(),
        storedCoefficientBytes: take(),
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
// proposal at its cap and the given setup reference, inventory and retained
// roster.
const dataKindMaximums = (
    registration: ParticipantLimits['registration'],
    setupReferenceBytes: number,
    setupInventoryBytes: number,
    retainedRosterBytes: number,
) => [
    registration.publicKeyBytes,
    registration.maximumProofBytes,
    registration.maximumHeaderBytes,
    registration.signatureBytes,
    registration.recipientCapsuleBytes,
    registration.signingCapsuleBytes,
    registration.maximumPollDefinitionBytes,
    registration.signatureBytes,
    registration.maximumProposalBytes,
    registration.signatureBytes,
    setupReferenceBytes,
    setupInventoryBytes,
    retainedRosterBytes,
    registration.retainedRegistrationBytes,
    setupReferenceBytes === 0 ? 0 : setupArchiveReferenceBytes,
];

// The largest enrollment root: every record but the setup reference and
// inventory, which it lacks, and the organizer's proposal coins.
const enrollmentRootBytes = (
    registration: ParticipantLimits['registration'],
    retainedRosterBytes: number,
) =>
    rootPrefixBytes +
    rootReferenceBytes *
        dataKindMaximums(registration, 0, 0, retainedRosterBytes).reduce(
            (total, bytes) => total + chunks(bytes),
            0,
        ) +
    coinBytes +
    tagBytes;

// Everything the participant retains through its accepted roster: the
// registration records, the enrollment root, the poll and its signature,
// the proposal and its signature, the retained roster and the retained
// registration.
const enrollmentPayloadBytes = (
    registration: ParticipantLimits['registration'],
    retainedRosterBytes: number,
) =>
    registration.publicKeyBytes +
    registration.maximumProofBytes +
    registration.maximumHeaderBytes +
    registration.signatureBytes +
    registration.recipientCapsuleBytes +
    registration.signingCapsuleBytes +
    enrollmentRootBytes(registration, retainedRosterBytes) +
    registration.maximumPollDefinitionBytes +
    registration.signatureBytes +
    registration.maximumProposalBytes +
    registration.signatureBytes +
    retainedRosterBytes +
    registration.retainedRegistrationBytes;

// The contribution suffix: its marker, position, salt and counts, the
// checkpoint header, a reference per public and private record, each
// signing record, and the seed of an interrupted generation or
// continuation.
const contributionPrefixBytes = (saltBytes: number) => 4 + 2 + saltBytes + 16;
const publicEntryBytes = 2 + 4 + 4 + keyBytes + identityBytes;
const privateEntryBytes = keyBytes + identityBytes;
const signingEntryBytes = 2 + 4 + keyBytes + identityBytes;
const signingRecords = 5;

const contributionBounds = (module: ModuleLimits, profile: ModuleProfile) => {
    const { contribution } = module;
    const publicRecords = profile.polynomials.flatMap((polynomial) =>
        Array.from({ length: chunks(polynomial.bytes) }, (_unused, index) => ({
            object: polynomial.expandedIndex + 1,
            offset: index * chunkBytes,
            length: Math.min(chunkBytes, polynomial.bytes - index * chunkBytes),
        })),
    );
    const maximumProofRecords = chunks(profile.maximumProofBytes);
    const prefix = contributionPrefixBytes(contribution.saltBytes);
    const completedStateBytes =
        prefix +
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
        completedStateBytes,
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
            contribution.confirmationBodyBytes +
            contribution.openingBodyBytes +
            2 * module.registration.signatureBytes +
            setupInventoryBytes(module, profile) +
            tagBytes * signingRecords,
    };
};

// The ballot suffix: its marker, score count, body length and key count,
// the scores, the attempt's ballot time until the envelope carries it, the
// randomness seed until the body is retained, a key per body record, the
// envelope, the signing coins and the signature.
const ballotPrefixBytes = 4 + 1 + 4 + 2;
const ballotTimeBytes = 8;

const ballotBounds = (
    module: ModuleLimits,
    limits: ParticipantLimits,
    profile: ModuleProfile,
) => {
    const { ballot } = module;
    const bodyRecords = Math.ceil(
        profile.maximumBallotBodyBytes / ballot.recordBytes,
    );
    const attempt =
        ballotPrefixBytes + limits.options.maximum + ballotTimeBytes;
    const retainedBody = keyBytes * bodyRecords + ballot.envelopeBytes;
    const signedStateBytes =
        ballotPrefixBytes + retainedBody + module.registration.signatureBytes;
    return {
        ...ballot,
        bodyRecords,
        maximumStateBytes: maximum(
            attempt + operationSeedBytes,
            attempt + retainedBody + coinBytes,
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
// record: a known envelope has one record, a held body its envelope and
// body records, and a response the organizer takes one record.
const closePrefixBytes = 4 + 4;
const eventBytes = (records: number) => 1 + 2 + 4 + 4 + keyBytes * records;

const closeBounds = (
    module: ModuleLimits,
    profile: ModuleProfile,
    ballotBodyRecords: number,
) => {
    const { close } = module;
    const participants = profile.participantCount;
    const corrupt = profile.faultBound;
    const listed = close.maximumListedEnvelopesPerSlot;
    // An honest author's one body arrives once; a corrupt slot can deliver
    // two before the intent lock and two on-time bodies after it, and
    // delivery keeps at most two envelopes per slot.
    const heldBodies = participants - corrupt + corrupt * listed;
    const knownEnvelopes = heldBodies;
    const responseEvents = participants - 1;
    const deliveryEventBytes =
        knownEnvelopes * eventBytes(1) +
        heldBodies * eventBytes(1 + ballotBodyRecords);
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
        maximumEvents: knownEnvelopes + heldBodies + 1 + responseEvents,
        maximumRecords:
            knownEnvelopes +
            heldBodies * (1 + ballotBodyRecords) +
            responseEvents,
        maximumStateBytes: maximum(
            collectingBytes,
            collectingBytes + close.intentBodyBytes + coinBytes,
            intentStateBytes + 4 + profile.maximumResponseBodyBytes + coinBytes,
            intentStateBytes +
                profile.maximumResponsePacketBytes +
                profile.proposalBodyBytes +
                coinBytes,
            completedStateBytes,
        ),
        collectingBytes,
    };
};

// The target suffix: its marker, phase and signer position, the target body,
// then its signing coins or the signed vote.
const targetBounds = (module: ModuleLimits) => {
    const { target } = module;
    const prefix = 4 + 1 + 2;
    return {
        ...target,
        maximumStateBytes:
            prefix +
            target.maximumBodyBytes +
            maximum(coinBytes, target.votePacketBytes),
    };
};

// The release suffix: its marker, predecessor, target length, body length
// and key count, the target body, the randomness seed until the body exists,
// a key per body record, the envelope, the signing coins and the signature.
const releaseBounds = (module: ModuleLimits, profile: ModuleProfile) => {
    const { release } = module;
    const bodyRecords = Math.ceil(
        profile.maximumReleaseBodyBytes / release.recordBytes,
    );
    const attempt = 4 + 1 + 2 + 4 + 2 + module.target.maximumBodyBytes;
    const retainedBody = keyBytes * bodyRecords + release.envelopeBytes;
    return {
        ...release,
        minimumBodyBytes: profile.minimumReleaseBodyBytes,
        maximumBodyBytes: profile.maximumReleaseBodyBytes,
        maximumStateBytes: maximum(
            attempt + operationSeedBytes,
            attempt + retainedBody + coinBytes,
            attempt + retainedBody + module.registration.signatureBytes,
        ),
    };
};

// Marker, inventory identity, one digest per aggregate polynomial, and the
// credential-keyed tag that the ballot step checks before parsing.
const setupReferenceBytes = (profile: ModuleProfile) =>
    4 + identityBytes * (profile.polynomials.length + 2);

// The count and every participant's confirmation packet.
const setupInventoryBytes = (module: ModuleLimits, profile: ModuleProfile) =>
    4 + profile.participantCount * module.contribution.confirmationPacketBytes;

// Assembles one profile's bounds from the module's sizes and the retained
// layouts.
const profileBounds = (
    module: ModuleLimits,
    limits: ParticipantLimits,
    profile: ModuleProfile,
): ParticipantProfile => {
    const {
        completedStateBytes,
        publicCiphertextBytes,
        checkpointCiphertextBytes,
        signingBytes,
        ...contribution
    } = contributionBounds(module, profile);
    const { bodyRecords, signedStateBytes, sealedBodyBytes, ...ballot } =
        ballotBounds(module, limits, profile);
    const { collectingBytes, ...close } = closeBounds(
        module,
        profile,
        bodyRecords,
    );
    const target = targetBounds(module);
    const release = releaseBounds(module, profile);
    const setupReference = setupReferenceBytes(profile);
    const setupInventory = setupInventoryBytes(module, profile);
    // The suffixes present together: the completed contribution with the
    // ballot collecting deliveries, or with the completed ballot, the close,
    // target signing and release.
    const suffixes = (...bytes: number[]) =>
        bytes.reduce((total, value) => total + suffixLengthBytes + value, 0);
    const maximumRootBytes =
        rootPrefixBytes +
        rootReferenceBytes * limits.root.maximumRecords +
        maximum(
            suffixes(contribution.maximumStateBytes),
            suffixes(
                completedStateBytes,
                ballot.maximumStateBytes,
                collectingBytes,
            ),
            suffixes(
                completedStateBytes,
                signedStateBytes,
                close.maximumStateBytes,
                target.maximumStateBytes,
                release.maximumStateBytes,
            ),
        ) +
        tagBytes;
    return {
        participantCount: profile.participantCount,
        optionCount: profile.optionCount,
        setupContributorCount: profile.setupContributorCount,
        proposalBytes: profile.proposalBytes,
        registration: limits.registration,
        root: {
            maximumRecords: limits.root.maximumRecords,
            maximumRootBytes,
            setupReferenceBytes: setupReference,
            setupInventoryBytes: setupInventory,
            retainedRosterBytes: profile.retainedRosterBytes,
        },
        contribution: {
            ...contribution,
            requiredStorageBytes:
                enrollmentPayloadBytes(
                    limits.registration,
                    limits.root.maximumRetainedRosterBytes,
                ) -
                enrollmentRootBytes(
                    limits.registration,
                    limits.root.maximumRetainedRosterBytes,
                ) +
                maximumRootBytes +
                setupReference +
                setupInventory +
                setupArchiveReferenceBytes +
                publicCiphertextBytes +
                checkpointCiphertextBytes +
                signingBytes,
        },
        ballot: {
            ...ballot,
            requiredStorageBytes:
                sealedBodyBytes + ballot.maximumStateBytes + maximumRootBytes,
        },
        close,
        target,
        release,
        evaluation: {
            polynomialDegree: module.polynomialDegree,
            storedCoefficientBytes: profile.storedCoefficientBytes,
        },
    };
};

// Reads the module's shared bounds and the largest supported profile's,
// which bound a root and its setup reference before the retained roster
// names the profile.
export const readParticipantLimits = (
    kernel: ParticipantKernel,
): ParticipantLimits => {
    const module = readModuleLimits(kernel);
    const { participants, options, registration } = module;
    const largest = readModuleProfile(
        kernel,
        participants.maximum,
        options.maximum,
    );
    if (largest === undefined)
        throw new Error('The participant module lacks its largest profile.');
    const maximumSetupReferenceBytes = setupReferenceBytes(largest);
    const maximumSetupInventoryBytes = setupInventoryBytes(module, largest);
    const maximumRetainedRosterBytes = largest.retainedRosterBytes;
    const enrollment: ParticipantLimits = {
        participants,
        options,
        registration,
        root: {
            maximumRecords: dataKindMaximums(
                registration,
                maximumSetupReferenceBytes,
                maximumSetupInventoryBytes,
                maximumRetainedRosterBytes,
            ).reduce((total, bytes) => total + chunks(bytes), 0),
            maximumEnrollmentRootBytes: enrollmentRootBytes(
                registration,
                maximumRetainedRosterBytes,
            ),
            maximumRootBytes: 0,
            maximumSetupReferenceBytes,
            maximumSetupInventoryBytes,
            maximumRetainedRosterBytes,
        },
    };
    return {
        ...enrollment,
        root: {
            ...enrollment.root,
            maximumRootBytes: profileBounds(module, enrollment, largest).root
                .maximumRootBytes,
        },
    };
};

// A supported profile's bounds, or undefined for another profile.
export const readParticipantProfile = (
    kernel: ParticipantKernel,
    limits: ParticipantLimits,
    participantCount: number,
    optionCount: number,
): ParticipantProfile | undefined => {
    const profile = readModuleProfile(kernel, participantCount, optionCount);
    return profile === undefined
        ? undefined
        : profileBounds(readModuleLimits(kernel), limits, profile);
};

export const participantDataKindMaximums = (limits: ParticipantLimits) =>
    dataKindMaximums(
        limits.registration,
        limits.root.maximumSetupReferenceBytes,
        limits.root.maximumSetupInventoryBytes,
        limits.root.maximumRetainedRosterBytes,
    );
