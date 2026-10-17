import type { ParticipantProfileContext } from '../../module/context.js';
import { operationSeedBytes } from '../../module/participant-module.js';
import type { ParticipantProfile } from '../../module/runtime-bounds.js';
import {
    contributionPrefixBytes,
    privateEntryBytes,
    publicEntryBytes,
    recordKeyBytes,
    signingEntryBytes,
} from '../../module/runtime-bounds.js';
import {
    concatenate,
    encodeText,
    readUnsigned16,
    readUnsigned32,
    unsigned16,
    unsigned32,
} from '../../shared/bytes.js';
import { discardStagedRecords } from '../../storage/database.js';
import type { ParticipantStoredRecord } from '../../storage/predecessor.js';
import { sealedLength } from '../../storage/private-records.js';

import { proofLength, proofRecordLayout } from './contribution-proof.js';

// Own offer work advances independently of the preparation journal. Its
// generation and continuation seeds reproduce interrupted work exactly.
// Every signature has a durable message intent before any public derivative is exposed.

type RecordLocation = Readonly<{
    object: number;
    offset: number;
    length: number;
}>;

export type ContributionRecord = RecordLocation &
    Readonly<{ key: Uint8Array; hash: Uint8Array }>;

export type CheckpointRecord = Readonly<{ key: Uint8Array; hash: Uint8Array }>;

export const contributionPhase = {
    generationIntent: 4,
    checkpoint: 5,
    continuationIntent: 6,
    body: 7,
    signingIntent: 8,
    signed: 9,
} as const;

export type ContributionPhase =
    (typeof contributionPhase)[keyof typeof contributionPhase];

export type ContributionState = Readonly<{
    phase: ContributionPhase;
    position: number;
    // The first-oracle checkpoint header until completion, then the body
    // header.
    header: Uint8Array;
    publicRecords: readonly ContributionRecord[];
    privateRecords: readonly CheckpointRecord[];
    signingRecords: readonly ContributionRecord[];
    // The randomness seed of a generation or continuation intent.
    seed: Uint8Array;
}>;

// What a contribution record is bound to besides its location: the poll,
// whose identity names the runtime, the roster proposal and the
// participant.
export type ProposalRecordContext = Readonly<{
    poll: Uint8Array;
    proposal: Uint8Array;
    position: number;
}>;

const signingKinds = ['offerEnvelope', 'offerSignature'] as const;

export type SigningKind = (typeof signingKinds)[number];

// Setup polynomial i is object i + 1, as the prover emits it; the proof and
// the signing records follow the last setup polynomial.
export const proofObject = (profile: ParticipantProfile) =>
    profile.contribution.expandedPolynomials + 1;

export const signingObject = (profile: ParticipantProfile, kind: SigningKind) =>
    proofObject(profile) + 1 + signingKinds.indexOf(kind);

const signingLength = (profile: ParticipantProfile, kind: SigningKind) =>
    kind === 'offerEnvelope'
        ? profile.contribution.offerEnvelopeBytes
        : profile.registration.signatureBytes;

const retainedShape = (phase: number) => ({
    signingRecords:
        phase <= contributionPhase.body
            ? 0
            : phase === contributionPhase.signingIntent
              ? 1
              : 2,
    seedBytes:
        phase === contributionPhase.generationIntent ||
        phase === contributionPhase.continuationIntent
            ? operationSeedBytes
            : 0,
});

const encodeSigningRecord = (record: ContributionRecord) =>
    concatenate(
        unsigned16(record.object),
        unsigned32(record.length),
        record.key,
        record.hash,
    );

export const encodeContributionState = (state: ContributionState) =>
    concatenate(
        new Uint8Array([state.phase]),
        unsigned16(state.position),
        unsigned32(state.header.length),
        unsigned32(state.publicRecords.length),
        unsigned32(state.privateRecords.length),
        unsigned32(state.signingRecords.length),
        state.header,
        ...state.publicRecords.map((record) =>
            concatenate(
                unsigned16(record.object),
                unsigned32(record.offset),
                unsigned32(record.length),
                record.key,
                record.hash,
            ),
        ),
        ...state.privateRecords.map((record) =>
            concatenate(record.key, record.hash),
        ),
        ...state.signingRecords.map(encodeSigningRecord),
        state.seed,
    );

// Decodes the first signing records in their order from the offset.
const decodeSigningRecords = (
    bytes: Uint8Array,
    offset: number,
    count: number,
    profile: ParticipantProfile,
) =>
    signingKinds.slice(0, count).map((kind, index) => {
        const start = offset + index * signingEntryBytes;
        const record = {
            object: readUnsigned16(bytes, start),
            offset: 0,
            length: readUnsigned32(bytes, start + 2),
            key: bytes.slice(start + 6, start + 6 + recordKeyBytes),
            hash: bytes.slice(
                start + 6 + recordKeyBytes,
                start + signingEntryBytes,
            ),
        };
        if (
            record.object !== signingObject(profile, kind) ||
            record.length !== signingLength(profile, kind)
        )
            throw new Error('Noncanonical contribution signing record.');
        return record;
    });

// Decodes the contribution suffix of an authenticated root. The body records
// follow the profile's polynomial plan. Completed proof records follow the
// authenticated body's exact length, and signing records match the phase.
export const decodeContributionState = (
    bytes: Uint8Array,
    profile: ParticipantProfile,
): ContributionState => {
    const bounds = profile.contribution;
    const prefix = contributionPrefixBytes;
    const phase = bytes[0];
    if (
        phase === undefined ||
        phase < contributionPhase.generationIntent ||
        phase > contributionPhase.signed ||
        bytes.length < prefix ||
        bytes.length > bounds.maximumStateBytes
    )
        throw new Error('Invalid contribution state.');
    const position = readUnsigned16(bytes, 1);
    const counts = 3;
    const headerLength = readUnsigned32(bytes, counts);
    const publicCount = readUnsigned32(bytes, counts + 4);
    const privateCount = readUnsigned32(bytes, counts + 8);
    const signingCount = readUnsigned32(bytes, counts + 12);
    const shape = retainedShape(phase);
    const bodyRecords = bounds.publicRecords.length;
    const proofRecords =
        phase >= contributionPhase.body &&
        headerLength === bounds.bodyHeaderBytes &&
        bytes.length >= prefix + headerLength
            ? proofRecordLayout(
                  bounds,
                  proofLength(
                      bounds,
                      bytes.subarray(prefix, prefix + headerLength),
                  ),
              )
            : [];
    const shaped =
        phase === contributionPhase.generationIntent
            ? headerLength === 0 && publicCount === 0 && privateCount === 0
            : phase <= contributionPhase.continuationIntent
              ? headerLength >= 1 &&
                headerLength <= bounds.maximumCheckpointHeaderBytes &&
                publicCount === bodyRecords &&
                privateCount === bounds.checkpointLengths.length
              : headerLength === bounds.bodyHeaderBytes &&
                privateCount === 0 &&
                publicCount === bodyRecords + proofRecords.length;
    if (
        position >= profile.eligibleContributorCount ||
        !shaped ||
        signingCount !== shape.signingRecords ||
        bytes.length !==
            prefix +
                headerLength +
                publicEntryBytes * publicCount +
                privateEntryBytes * privateCount +
                signingEntryBytes * signingCount +
                shape.seedBytes
    )
        throw new Error('The contribution state does not match its phase.');
    let offset = prefix + headerLength;
    const publicRecords: ContributionRecord[] = [];
    for (let index = 0; index < publicCount; index++) {
        const record = {
            object: readUnsigned16(bytes, offset),
            offset: readUnsigned32(bytes, offset + 2),
            length: readUnsigned32(bytes, offset + 6),
            key: bytes.slice(offset + 10, offset + 10 + recordKeyBytes),
            hash: bytes.slice(
                offset + 10 + recordKeyBytes,
                offset + publicEntryBytes,
            ),
        };
        let canonical: boolean;
        if (index < bodyRecords) {
            const expected = bounds.publicRecords[index];
            canonical =
                record.object === expected.object &&
                record.offset === expected.offset &&
                record.length === expected.length;
        } else {
            const expected = proofRecords[index - bodyRecords];
            canonical =
                record.object === proofObject(profile) &&
                record.offset === expected.offset &&
                record.length === expected.length;
        }
        if (!canonical) throw new Error('Noncanonical contribution record.');
        publicRecords.push(record);
        offset += publicEntryBytes;
    }
    const privateRecords: CheckpointRecord[] = [];
    for (let index = 0; index < privateCount; index++) {
        privateRecords.push({
            key: bytes.slice(offset, offset + recordKeyBytes),
            hash: bytes.slice(
                offset + recordKeyBytes,
                offset + privateEntryBytes,
            ),
        });
        offset += privateEntryBytes;
    }
    const signingRecords = decodeSigningRecords(
        bytes,
        offset,
        signingCount,
        profile,
    );
    offset += signingEntryBytes * signingCount;
    return {
        phase: phase as ContributionPhase,
        position,
        header: bytes.slice(prefix, prefix + headerLength),
        publicRecords,
        privateRecords,
        signingRecords,
        seed: bytes.slice(offset, offset + shape.seedBytes),
    };
};

// Each record has its own key, so the fixed zero nonce is used once per key.
export const recordAssociatedData = (
    context: ProposalRecordContext,
    record: RecordLocation,
) =>
    concatenate(
        encodeText('sealed-lattice/participant-contribution-record'),
        context.poll,
        context.proposal,
        unsigned16(context.position),
        unsigned16(record.object),
        unsigned32(record.offset),
        unsigned32(record.length),
    );

// The stored records a contribution state lists. Public and signing records
// are authenticated by their own keys; checkpoint records, which the module
// seals, by their ciphertext hashes.
export const contributionInventory = (
    profile: ParticipantProfile,
    state: ContributionState,
    context: ProposalRecordContext,
): ParticipantStoredRecord[] => [
    ...[...state.publicRecords, ...state.signingRecords].map((record) => ({
        store: 'contribution',
        key: [record.object, record.offset],
        byteLength: sealedLength(record.length),
        encryption: {
            key: record.key,
            additionalData: recordAssociatedData(context, record),
        },
    })),
    ...state.privateRecords.map((record, index) => ({
        store: 'checkpoint',
        key: index,
        byteLength: profile.contribution.checkpointLengths[index],
        identity: record.hash,
    })),
];

// Only records outside the authenticated own intent can be discarded. This
// applies before every preparation operation, including certification of a
// different contributor set after an interrupted own proof.
export const discardInterruptedRecords = async (
    context: ParticipantProfileContext,
    state: ContributionState | undefined,
) => {
    const proof = proofObject(context.profile);
    if (state?.phase === contributionPhase.generationIntent)
        await discardStagedRecords(context.database, [
            { store: 'contribution' },
            { store: 'checkpoint' },
        ]);
    else if (state?.phase === contributionPhase.continuationIntent)
        await discardStagedRecords(context.database, [
            {
                store: 'contribution',
                keys: IDBKeyRange.bound([proof], [proof + 1], false, true),
            },
        ]);
};
