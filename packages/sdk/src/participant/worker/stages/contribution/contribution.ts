import { writeModuleInput } from '../../module/context.js';
import type { ParticipantProfileContext } from '../../module/context.js';
import {
    custodyIdentity,
    custodyPurpose,
} from '../../module/custody-identity.js';
import {
    operationSeedBytes,
    readModuleMemory,
    readParticipantOutput,
    seededRandomness,
    writeProofInput,
} from '../../module/participant-module.js';
import type { ParticipantProfile } from '../../module/runtime-bounds.js';
import {
    chunkBytes,
    identityBytes,
    privateEntryBytes,
    publicEntryBytes,
    recordKeyBytes,
    signingEntryBytes,
} from '../../module/runtime-bounds.js';
import { findCandidate, readCandidateFile } from '../../relay/candidates.js';
import { publishOfferAnnouncement } from '../../relay/offer-discovery.js';
import { createCandidatePublication } from '../../relay/publication.js';
import type { PublicRelay } from '../../relay/relay.js';
import {
    concatenate,
    encodeText,
    equalBytes,
    hexadecimal,
    readUnsigned16,
    readUnsigned32,
    tupleFields,
    unsigned16,
    unsigned32,
    unsigned64,
} from '../../shared/bytes.js';
import { PublicInputFailure, StorageFailure } from '../../shared/failures.js';
import { decodeSignedPacket } from '../../shared/signed-packet.js';
import type { SignedPacket } from '../../shared/signed-packet.js';
import {
    addParticipantRecords,
    awaitLater,
    discardStagedRecords,
    readParticipantValue,
    snapshotParticipant,
} from '../../storage/database.js';
import { openDelivery } from '../../storage/delivery.js';
import type { ParticipantStoredRecord } from '../../storage/predecessor.js';
import {
    openSealedRecord,
    sealRecord,
    sealedLength,
} from '../../storage/private-records.js';
import { rootGeneration } from '../../storage/root-generation.js';
import type { AuthenticatedRoot } from '../../storage/root.js';
import {
    authenticateRecords,
    commitRoot,
    dataKind,
    dataRecordInventory,
    readDataKind,
} from '../../storage/root.js';
import type { VerifiedProposal } from '../roster/roster.js';
import {
    proposalRegistrationBodyDigests,
    registrationFile,
    registrationCandidateKey,
} from '../roster/roster.js';

import {
    createProofWriter,
    proofLength,
    proofRecordLayout,
    readProof,
} from './contribution-proof.js';
import {
    decodePreparationState,
    encodePreparationState,
} from './preparation-state.js';
import type { PreparationState } from './preparation-state.js';

// Own offer work advances independently of the preparation journal. Its
// generation and continuation seeds reproduce interrupted work exactly.
// Every signature has a durable message intent before any public derivative is exposed.

type RecordLocation = Readonly<{
    object: number;
    offset: number;
    length: number;
}>;

type ContributionRecord = RecordLocation &
    Readonly<{ key: Uint8Array; hash: Uint8Array }>;

type CheckpointRecord = Readonly<{ key: Uint8Array; hash: Uint8Array }>;

export type ContributionState = Readonly<{
    phase: number;
    position: number;
    // The first-oracle checkpoint header until completion, then SCB2.
    header: Uint8Array;
    publicRecords: readonly ContributionRecord[];
    privateRecords: readonly CheckpointRecord[];
    signingRecords: readonly ContributionRecord[];
    // The randomness seed of a generation or continuation intent.
    seed: Uint8Array;
}>;

// What a contribution record is bound to besides its location: the poll,
// the runtime, the roster proposal and the participant.
type ProposalRecordContext = Readonly<{
    poll: Uint8Array;
    runtime: Uint8Array;
    proposal: Uint8Array;
    position: number;
}>;

// Every original roster member has the same preparation journal. Own offer
// work is optional and advances independently from quorum selection.
export type ParticipantSession = {
    readonly context: ParticipantProfileContext;
    readonly records: ProposalRecordContext;
    root: AuthenticatedRoot;
    state?: ContributionState;
    preparation: PreparationState;
};

export type ContributionSession = ParticipantSession & {
    state: ContributionState;
};

export const isContributionSession = (
    session: ParticipantSession,
): session is ContributionSession => session.state !== undefined;

// The sealed checkpoint bytes one write stores while the next are sealed.
const checkpointWriteBytes = 4 << 20;

// Prover phases: generation below one hundred, then one hundred plus the
// proof phase.
const proverPhase = {
    firstInitialize: 103,
    firstColumn: 104,
    polynomials: 107,
    output: 110,
    done: 111,
} as const;

const proverOperation = {
    generate: 2,
    step: 7,
    beginPolynomial: 8,
    pushPolynomial: 9,
    finishPolynomial: 10,
    nextOutput: 11,
    consumePredecessor: 14,
} as const;

const checkpointOperation = {
    exportHeader: 1,
    seal: 2,
    complete: 3,
    import: 4,
    open: 5,
    finish: 6,
} as const;

const signingOperation = {
    beginBody: 1,
    polynomial: 2,
    proof: 3,
    finishBody: 4,
    signOffer: 5,
    bodyHeader: 8,
} as const;

const signingKinds = ['offerEnvelope', 'offerSignature'] as const;
type SigningKind = (typeof signingKinds)[number];

// Setup polynomial i is object i + 1, as the prover emits it; the proof and
// the signing records follow the last setup polynomial.
const proofObject = (profile: ParticipantProfile) =>
    profile.contribution.expandedPolynomials + 1;

const signingObject = (profile: ParticipantProfile, kind: SigningKind) =>
    proofObject(profile) + 1 + signingKinds.indexOf(kind);

const signingLength = (profile: ParticipantProfile, kind: SigningKind) =>
    kind === 'offerEnvelope'
        ? profile.contribution.offerEnvelopeBytes
        : profile.registration.signatureBytes;

const retainedShape = (phase: number) => ({
    stage: phase,
    signingRecords: phase <= 7 ? 0 : phase === 8 ? 1 : 2,
    seedBytes: phase === 4 || phase === 6 ? operationSeedBytes : 0,
});

const prefixBytes = 4 + 1 + 2 + 4 * 4;

const encodeSigningRecord = (record: ContributionRecord) =>
    concatenate(
        unsigned16(record.object),
        unsigned32(record.length),
        record.key,
        record.hash,
    );

export const encodeContributionState = (state: ContributionState) =>
    concatenate(
        encodeText('PCS5'),
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
// and every physical proof slot follow the profile's fixed plan. From
// completion onward SCB2 frames the logical proof prefix inside those slots,
// and the signing records agree with its independent phase.
export const decodeContributionState = (
    bytes: Uint8Array,
    profile: ParticipantProfile,
): ContributionState => {
    const bounds = profile.contribution;
    const prefix = prefixBytes;
    const phase = bytes[4];
    if (
        phase === undefined ||
        phase < 4 ||
        phase > 9 ||
        bytes.length < prefix ||
        bytes.length > bounds.maximumStateBytes ||
        !equalBytes(bytes.subarray(0, 4), encodeText('PCS5'))
    )
        throw new Error('Invalid contribution state.');
    const position = readUnsigned16(bytes, 5);
    const counts = 7;
    const headerLength = readUnsigned32(bytes, counts);
    const publicCount = readUnsigned32(bytes, counts + 4);
    const privateCount = readUnsigned32(bytes, counts + 8);
    const signingCount = readUnsigned32(bytes, counts + 12);
    const shape = retainedShape(phase);
    const bodyRecords = bounds.publicRecords.length;
    const proofRecords = proofRecordLayout(bounds);
    const shaped =
        shape.stage === 4
            ? headerLength === 0 && publicCount === 0 && privateCount === 0
            : shape.stage <= 6
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
    if (shape.stage >= 7)
        proofLength(bounds, bytes.subarray(prefix, prefix + headerLength));
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
        phase,
        position,
        header: bytes.slice(prefix, prefix + headerLength),
        publicRecords,
        privateRecords,
        signingRecords,
        seed: bytes.slice(offset, offset + shape.seedBytes),
    };
};

// Each record has its own key, so the fixed zero nonce is used once per key.
const recordAssociatedData = (
    context: ProposalRecordContext,
    record: RecordLocation,
) =>
    concatenate(
        encodeText('participant-contribution-record/1'),
        context.poll,
        context.runtime,
        context.proposal,
        unsigned16(context.position),
        unsigned16(record.object),
        unsigned32(record.offset),
        unsigned32(record.length),
    );

type SealedOutput = Readonly<{
    record: ContributionRecord;
    ciphertext: Uint8Array;
}>;

const sealContributionRecord = async (
    session: ParticipantSession,
    object: number,
    offset: number,
    bytes: Uint8Array,
): Promise<SealedOutput> => {
    const location = { object, offset, length: bytes.length };
    const { key, ciphertext } = await sealRecord(
        recordAssociatedData(session.records, location),
        bytes,
    );
    return {
        record: {
            ...location,
            key,
            hash: custodyIdentity(
                session.context.module,
                custodyPurpose.record,
                ciphertext,
            ),
        },
        ciphertext,
    };
};

const openContributionRecord = async (
    session: ParticipantSession,
    record: ContributionRecord,
) => {
    const blob = await readParticipantValue(
        session.context.database,
        'contribution',
        [record.object, record.offset],
    );
    if (!(blob instanceof Blob) || blob.size !== sealedLength(record.length))
        throw new Error('A contribution record is missing.');
    const ciphertext = new Uint8Array(await blob.arrayBuffer());
    if (
        !equalBytes(
            custodyIdentity(
                session.context.module,
                custodyPurpose.record,
                ciphertext,
            ),
            record.hash,
        )
    )
        throw new Error('A contribution record changed.');
    return openSealedRecord(
        record.key,
        recordAssociatedData(session.records, record),
        ciphertext,
    );
};

const openSigning = (session: ContributionSession, kind: SigningKind) => {
    const object = signingObject(session.context.profile, kind);
    const record = session.state.signingRecords.find(
        (value) => value.object === object,
    );
    if (record === undefined)
        throw new Error('A contribution signing record is missing.');
    return openContributionRecord(session, record);
};

// The stored records a contribution state lists. Public and signing records
// are authenticated by their own keys; checkpoint records, which the module
// seals, by their ciphertext hashes.
const contributionInventory = (
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

type ContributionTransition = Readonly<{
    phase: number;
    state: ContributionState;
    // Generated records stored ahead of this root; its transition checks
    // that each one opens before it commits.
    staged?: boolean;
    // Signing records written with the root.
    signing?: readonly SealedOutput[];
    clearCheckpoint?: boolean;
}>;

const commitContribution = async (
    session: ParticipantSession,
    transition: ContributionTransition,
) => {
    const { context, root } = session;
    const profile = context.profile;
    const predecessor =
        root.head.generation >= rootGeneration.preparation &&
        session.state !== undefined
            ? contributionInventory(profile, session.state, session.records)
            : [];
    const listed = new Set(
        predecessor.map(
            (record) => record.store + ':' + JSON.stringify(record.key),
        ),
    );
    const staged =
        transition.staged === true
            ? contributionInventory(
                  profile,
                  transition.state,
                  session.records,
              ).filter(
                  (record) =>
                      !listed.has(
                          record.store + ':' + JSON.stringify(record.key),
                      ),
              )
            : [];
    session.root = await commitRoot(context, root, {
        generation: rootGeneration.preparation,
        manifest: {
            ...root.manifest,
            suffixes: {
                ...root.manifest.suffixes,
                preparation: encodePreparationState({
                    ...session.preparation,
                    contribution: encodeContributionState({
                        ...transition.state,
                        phase: transition.phase,
                    }),
                }),
            },
        },
        predecessorRecords: [
            ...dataRecordInventory(root.manifest),
            ...predecessor,
        ],
        stagedRecords: staged,
        write: (transaction) => {
            for (const output of transition.signing ?? [])
                transaction
                    .objectStore('contribution')
                    .add(new Blob([new Uint8Array(output.ciphertext)]), [
                        output.record.object,
                        output.record.offset,
                    ]);
            if (transition.clearCheckpoint === true)
                transaction.objectStore('checkpoint').clear();
        },
    });
    session.state = { ...transition.state, phase: transition.phase };
    session.preparation = {
        ...session.preparation,
        contribution: encodeContributionState(session.state),
    };
    for (const output of transition.signing ?? [])
        (await openContributionRecord(session, output.record)).fill(0);
};

const proverOutput = (context: ParticipantProfileContext) =>
    readModuleMemory(
        context.module,
        context.module.contribution_proof_output_pointer(),
        context.module.contribution_proof_output_length(),
    );

const checkpoint = (
    context: ParticipantProfileContext,
    operation: number,
    position = 0,
    bytes: Uint8Array = new Uint8Array(),
) => {
    writeProofInput(context.module, bytes);
    return context.module.contribution_checkpoint_command(
        operation,
        position,
        bytes.length,
    );
};

const signing = (
    context: ParticipantProfileContext,
    operation: number,
    bytes: Uint8Array = new Uint8Array(),
    argument = 0,
) => {
    writeModuleInput(context, bytes);
    if (
        context.module.offer_signing_command(
            operation,
            argument,
            bytes.length,
        ) !== 0
    )
        throw new Error('The contribution signer refused an operation.');
    return readParticipantOutput(context.module);
};

// Runs prover commands with the randomness of one generation or
// continuation, which the module expands from its retained seed. Only
// generation emits statement output; its retained body output is sealed and
// stored as it arrives.
const proverRun = (session: ContributionSession, statement: boolean) => {
    const { context } = session;
    const { module, handlers, profile } = context;
    const bounds = profile.contribution;
    const bodyObjects = new Set(
        bounds.publicRecords.map((record) => record.object),
    );
    const lengths = new Map<number, number>();
    const pending: { object: number; offset: number; bytes: Uint8Array }[] = [];
    const stored: ContributionRecord[] = [];
    let current = 0;
    let emitted = 0;
    const randomness = seededRandomness(
        module,
        'contribution',
        session.state.seed,
    );
    handlers.contribution = (object, offset, bytes) => {
        if (
            !statement ||
            (object !== current && object !== current + 1) ||
            object > bounds.expandedPolynomials ||
            bytes.length < 1 ||
            bytes.length > chunkBytes ||
            offset !== (lengths.get(object) ?? 0) ||
            bytes.length > bounds.statementBytes - emitted
        )
            throw new Error('Invalid generated contribution output.');
        current = object;
        if (bodyObjects.has(object)) pending.push({ object, offset, bytes });
        lengths.set(object, offset + bytes.length);
        emitted += bytes.length;
    };
    // Seals body output in the profile's record order and stores it.
    const storeRecords = async (records: typeof pending) => {
        const outputs: SealedOutput[] = [];
        try {
            for (const [index, record] of records.entries()) {
                const expected = bounds.publicRecords[stored.length + index];
                if (
                    stored.length + index >= bounds.publicRecords.length ||
                    record.object !== expected.object ||
                    record.offset !== expected.offset ||
                    record.bytes.length !== expected.length
                )
                    throw new Error('Generated body output is noncanonical.');
            }
            const sealed = await Promise.allSettled(
                records.map((record) =>
                    sealContributionRecord(
                        session,
                        record.object,
                        record.offset,
                        record.bytes,
                    ),
                ),
            );
            for (const result of sealed) {
                if (result.status === 'rejected') throw result.reason;
                outputs.push(result.value);
            }
        } finally {
            for (const record of records) record.bytes.fill(0);
        }
        if (outputs.length === 0) return;
        await addParticipantRecords(
            context.database,
            'contribution',
            outputs.map((output) => ({
                key: [output.record.object, output.record.offset],
                bytes: output.ciphertext,
            })),
        );
        stored.push(...outputs.map((output) => output.record));
    };
    // Stores the pending body output once every earlier store ends, while
    // the prover continues. A prover command waits only for the stores
    // before the latest, so at most one runs beside the prover.
    let storing: Promise<void> = Promise.resolve();
    const store = () => {
        const records = pending.splice(0);
        storing = awaitLater(storing.then(() => storeRecords(records)));
        return storing;
    };
    const advance = async (
        operation: number,
        argument = 0,
        bytes: Uint8Array = new Uint8Array(),
    ) => {
        writeProofInput(module, bytes);
        if (
            module.contribution_proof_command(
                operation,
                argument,
                bytes.length,
            ) !== 0
        )
            throw new Error('The contribution prover refused an operation.');
        const earlier = storing;
        void store();
        await earlier;
    };
    return {
        advance,
        store,
        // Waits until every body output emitted so far is stored.
        flush: () => storing,
        stored,
        phase: () => module.contribution_proof_phase(),
        objects: () => lengths.size,
        emitted: () => emitted,
        randomBytes: randomness.drawn,
        close: () => {
            handlers.contribution = undefined;
            for (const record of pending) record.bytes.fill(0);
            pending.length = 0;
            randomness.discard();
        },
    };
};

// Only records outside the authenticated own intent can be discarded. This
// applies before every preparation operation, including certification of a
// different contributor set after an interrupted own proof.
const discardInterruptedRecords = async (
    context: ParticipantProfileContext,
    state: ContributionState | undefined,
) => {
    const proof = proofObject(context.profile);
    if (state?.phase === 4)
        await discardStagedRecords(context.database, [
            { store: 'contribution' },
            { store: 'checkpoint' },
        ]);
    else if (state?.phase === 6)
        await discardStagedRecords(context.database, [
            {
                store: 'contribution',
                keys: IDBKeyRange.bound([proof], [proof + 1], false, true),
            },
        ]);
};

export const beginContribution = async (
    session: ParticipantSession,
): Promise<ContributionSession> => {
    const { context, root } = session;
    if (
        root.head.generation !== rootGeneration.preparation ||
        session.state !== undefined ||
        context.position >= context.profile.eligibleContributorCount
    )
        throw new Error('No confirmed roster awaits an eligible offer.');
    const estimate = await navigator.storage.estimate();
    if (
        estimate.quota === undefined ||
        estimate.usage === undefined ||
        estimate.quota - estimate.usage <
            context.profile.contribution.requiredStorageBytes
    )
        throw new StorageFailure('The origin lacks room for a contribution.');
    const state: ContributionState = {
        phase: 4,
        position: context.position,
        header: new Uint8Array(),
        publicRecords: [],
        privateRecords: [],
        signingRecords: [],
        seed: crypto.getRandomValues(new Uint8Array(operationSeedBytes)),
    };
    await commitContribution(session, { phase: 4, state });
    if (!isContributionSession(session))
        throw new Error('No contribution intent was retained.');
    return session;
};

// Generates the contribution from the intent's seed, advances the proof to
// the last first-oracle column, and retains the sealed checkpoint with the
// body polynomials. The checkpoint retires the seed. An interrupted
// generation runs again from the same seed once its stored records are
// discarded.
export const generateContribution = async (session: ContributionSession) => {
    const { context } = session;
    const { module, profile } = context;
    const bounds = profile.contribution;
    if (session.state.phase !== 4)
        throw new Error('No contribution intent is locked.');
    const run = proverRun(session, true);
    const privateRecords: CheckpointRecord[] = [];
    let header: Uint8Array;
    try {
        if (module.begin_contribution(session.state.position) !== 0)
            throw new Error('The credential refused contribution generation.');
        await run.store();
        while (run.phase() < 100) await run.advance(proverOperation.generate);
        await run.flush();
        if (
            run.phase() !== proverPhase.firstInitialize ||
            run.objects() !== bounds.expandedPolynomials + 1 ||
            run.emitted() !== bounds.statementBytes ||
            run.stored.length !== bounds.publicRecords.length
        )
            throw new Error('The generated contribution is incomplete.');
        // The checkpoint follows every first-oracle column but the last.
        for (let step = 0; step < bounds.firstOracleColumns + 2; step++)
            await run.advance(proverOperation.step);
        if (
            run.phase() !== proverPhase.firstColumn ||
            module.contribution_checkpoint_records() !==
                bounds.checkpointLengths.length ||
            checkpoint(context, checkpointOperation.exportHeader) !== 0
        )
            throw new Error('The first-oracle checkpoint is unavailable.');
        header = proverOutput(context);
        if (
            header.length < 1 ||
            header.length > bounds.maximumCheckpointHeaderBytes
        )
            throw new Error('The checkpoint header has an invalid length.');
        // Each batch is written while the next one is sealed. The module
        // draws each record's fresh key and returns it ahead of the record.
        const batch: { key: number; bytes: Uint8Array }[] = [];
        let batchBytes = 0;
        let writing: Promise<void> = Promise.resolve();
        context.handlers.random = (target) => {
            crypto.getRandomValues(target);
        };
        for (const [index, length] of bounds.checkpointLengths.entries()) {
            if (checkpoint(context, checkpointOperation.seal) !== 0)
                throw new Error('A checkpoint record was refused.');
            const output = proverOutput(context);
            const key = output.slice(0, recordKeyBytes);
            output.fill(0, 0, recordKeyBytes);
            const sealed = output.subarray(recordKeyBytes);
            if (sealed.length !== length)
                throw new Error('A checkpoint record has another length.');
            privateRecords.push({
                key,
                hash: custodyIdentity(module, custodyPurpose.record, sealed),
            });
            batch.push({ key: index, bytes: sealed });
            batchBytes += sealed.length;
            if (
                batchBytes >= checkpointWriteBytes ||
                index === bounds.checkpointLengths.length - 1
            ) {
                await writing;
                writing = awaitLater(
                    addParticipantRecords(
                        context.database,
                        'checkpoint',
                        batch.splice(0),
                    ),
                );
                batchBytes = 0;
            }
        }
        await writing;
        await run.flush();
        if (checkpoint(context, checkpointOperation.complete) !== 0)
            throw new Error('The checkpoint is incomplete.');
    } finally {
        context.handlers.random = undefined;
        run.close();
    }
    await commitContribution(session, {
        phase: 5,
        state: {
            ...session.state,
            header,
            publicRecords: run.stored,
            privateRecords,
            seed: new Uint8Array(),
        },
        staged: true,
    });
    return run.randomBytes();
};

// Resumes the checkpointed prover in a new instance. Each recipient key comes
// from its public registration and must match the checkpoint's key hash.
export const restoreCheckpoint = async (
    session: ContributionSession,
    relay: PublicRelay,
) => {
    const { context, state } = session;
    const { module, profile } = context;
    const phase = session.state.phase;
    if (phase !== 5 && phase !== 6)
        throw new Error('No contribution checkpoint is retained.');
    if (
        checkpoint(
            context,
            checkpointOperation.import,
            state.position,
            concatenate(
                session.records.poll,
                session.records.runtime,
                session.records.proposal,
                state.header,
            ),
        ) !== 0
    )
        throw new Error('The retained proof context was refused.');
    for (const [index, record] of state.privateRecords.entries()) {
        const blob = await readParticipantValue(
            context.database,
            'checkpoint',
            index,
        );
        const length = profile.contribution.checkpointLengths[index];
        if (!(blob instanceof Blob) || blob.size !== length)
            throw new Error('A checkpoint record is missing.');
        const sealed = new Uint8Array(await blob.arrayBuffer());
        if (
            !equalBytes(
                custodyIdentity(context.module, custodyPurpose.record, sealed),
                record.hash,
            )
        )
            throw new Error('A checkpoint record changed.');
        const input = concatenate(record.key, sealed);
        try {
            if (checkpoint(context, checkpointOperation.open, 0, input) !== 0)
                throw new Error('A checkpoint record was refused.');
        } finally {
            input.fill(0);
        }
    }
    const registrationBodyDigests = proposalRegistrationBodyDigests(
        await readDataKind(context, session.root.manifest, dataKind.proposal),
    );
    for (const [position, id] of registrationBodyDigests.entries()) {
        await findCandidate(
            relay,
            registrationCandidateKey(id),
            async (candidate) => {
                const key = await readCandidateFile(
                    relay,
                    candidate,
                    registrationFile.publicKey,
                    profile.registration.publicKeyBytes,
                );
                writeProofInput(module, key);
                if (
                    module.contribution_checkpoint_key(position, key.length) !==
                    0
                )
                    throw new PublicInputFailure(
                        'A recipient key does not match the checkpoint.',
                    );
            },
        );
    }
    if (
        checkpoint(context, checkpointOperation.finish) !== 0 ||
        module.contribution_proof_phase() !== proverPhase.firstColumn
    )
        throw new Error('The contribution did not resume exactly.');
};

// Locks the continuation with a fresh randomness seed, completes the proof
// over the retained body, and retains the complete body, which retires the
// seed. An interrupted continuation runs again from the same seed once its
// stored proof records are discarded.
export const continueContribution = async (session: ContributionSession) => {
    const { context } = session;
    const { profile } = context;
    const bounds = profile.contribution;
    const phase = session.state.phase;
    if (phase !== 5 && phase !== 6)
        throw new Error('No contribution checkpoint is retained.');
    if (phase === 5)
        await commitContribution(session, {
            phase: 6,
            state: {
                ...session.state,
                seed: crypto.getRandomValues(
                    new Uint8Array(operationSeedBytes),
                ),
            },
        });
    const { state } = session;
    const run = proverRun(session, false);
    const proof: ContributionRecord[] = [];
    const writer = createProofWriter(bounds, async (slot, bytes) => {
        const output = await sealContributionRecord(
            session,
            proofObject(profile),
            slot.offset,
            bytes,
        );
        await addParticipantRecords(context.database, 'contribution', [
            {
                key: [output.record.object, output.record.offset],
                bytes: output.ciphertext,
            },
        ]);
        proof.push(output.record);
    });
    let header: Uint8Array;
    // The retained body records in the order the prover takes them; the
    // next one is opened while the prover takes the current one.
    const retained = Array.from(
        { length: bounds.expandedPolynomials },
        (_, index) =>
            state.publicRecords.filter((record) => record.object === index + 1),
    );
    const order = retained.flat();
    let taken = 0;
    let opening =
        order.length > 0
            ? awaitLater(openContributionRecord(session, order[0]))
            : undefined;
    const openNext = async () => {
        if (opening === undefined)
            throw new Error('A contribution record is missing.');
        const bytes = await opening;
        taken++;
        opening =
            taken < order.length
                ? awaitLater(openContributionRecord(session, order[taken]))
                : undefined;
        return bytes;
    };
    try {
        while (run.phase() !== proverPhase.polynomials)
            await run.advance(proverOperation.step);
        for (const [index, records] of retained.entries()) {
            if (records.length === 0) {
                await run.advance(proverOperation.consumePredecessor, index);
                continue;
            }
            await run.advance(proverOperation.beginPolynomial, index);
            for (let count = records.length; count > 0; count--) {
                const bytes = await openNext();
                try {
                    await run.advance(proverOperation.pushPolynomial, 0, bytes);
                } finally {
                    bytes.fill(0);
                }
            }
            await run.advance(proverOperation.finishPolynomial);
        }
        // The linear oracle, then the folded combination.
        await run.advance(proverOperation.step);
        await run.advance(proverOperation.step);
        while (run.phase() === proverPhase.output) {
            await run.advance(proverOperation.nextOutput);
            const bytes = proverOutput(context);
            try {
                await writer.append(bytes);
            } finally {
                bytes.fill(0);
            }
        }
        if (run.phase() !== proverPhase.done)
            throw new Error('The continued proof is incomplete.');
        // The own intent remains at phase six while the same record writer
        // fills every remaining profile slot, including padding-only slots.
        const length = await writer.finish();
        header = signing(
            context,
            signingOperation.bodyHeader,
            concatenate(unsigned16(state.position), unsigned64(BigInt(length))),
        );
        if (proofLength(bounds, header) !== length)
            throw new Error(
                'The original contribution header has another proof length.',
            );
    } finally {
        writer.close();
        // A record opened ahead that the prover never took is cleared too.
        if (opening !== undefined)
            (await opening.catch(() => undefined))?.fill(0);
        run.close();
    }
    await commitContribution(session, {
        phase: 7,
        state: {
            ...state,
            header,
            publicRecords: [...state.publicRecords, ...proof],
            privateRecords: [],
            seed: new Uint8Array(),
        },
        staged: true,
        clearCheckpoint: true,
    });
    return run.randomBytes();
};

// Reads every authenticated private proof slot and its padding. Only the
// exact framed proof reaches the signer or relay, and completion of either
// caller waits for the full fixed record pass.
const readRetainedProof = (
    session: ContributionSession,
    consume: (offset: number, bytes: Uint8Array) => void | Promise<void>,
) => {
    const { profile } = session.context;
    const records = session.state.publicRecords.filter(
        (record) => record.object === proofObject(profile),
    );
    return readProof(
        profile.contribution,
        session.state.header,
        async (slot, index) => {
            const record = records[index];
            if (
                record === undefined ||
                record.offset !== slot.offset ||
                record.length !== slot.length
            )
                throw new Error('The private proof record plan changed.');
            return openContributionRecord(session, record);
        },
        consume,
    );
};

// Recomputes the commitment to the retained body in the module's signer.
const bodyOffer = async (session: ContributionSession) => {
    const { context, state } = session;
    const { profile } = context;
    const control = concatenate(
        unsigned16(state.position),
        unsigned64(BigInt(proofLength(profile.contribution, state.header))),
    );
    try {
        const header = signing(context, signingOperation.beginBody, control);
        if (!equalBytes(header, state.header))
            throw new Error('The original source opening changed.');
    } finally {
        control.fill(0);
    }
    for (const polynomial of profile.contribution.polynomials)
        for (const record of state.publicRecords.filter(
            (value) => value.object === polynomial.expandedIndex + 1,
        )) {
            const bytes = await openContributionRecord(session, record);
            const input = concatenate(unsigned32(record.offset), bytes);
            try {
                signing(
                    context,
                    signingOperation.polynomial,
                    input,
                    polynomial.expandedIndex,
                );
            } finally {
                bytes.fill(0);
                input.fill(0);
            }
        }
    await readRetainedProof(session, (offset, bytes) => {
        signing(context, signingOperation.proof, bytes, offset);
    });
    return signing(context, signingOperation.finishBody);
};

const storedOffer = async (
    session: ContributionSession,
): Promise<SignedPacket> => ({
    body: await openSigning(session, 'offerEnvelope'),
    signature: await openSigning(session, 'offerSignature'),
});

export const signContribution = async (
    session: ContributionSession,
): Promise<SignedPacket> => {
    const { context } = session;
    const { profile } = context;
    if (session.state.phase < 7)
        throw new Error('No complete contribution is retained.');
    if (session.state.phase === 9) return storedOffer(session);
    const envelope = await bodyOffer(session);
    if (session.state.phase === 7) {
        const output = await sealContributionRecord(
            session,
            signingObject(profile, 'offerEnvelope'),
            0,
            envelope,
        );
        await commitContribution(session, {
            phase: 8,
            state: {
                ...session.state,
                signingRecords: [output.record],
            },
            signing: [output],
        });
    }
    const body = await openSigning(session, 'offerEnvelope');
    if (!equalBytes(envelope, body))
        throw new Error('The locked offer changed.');
    const signed = decodeSignedPacket(
        signing(context, signingOperation.signOffer),
        profile.registration.signatureBytes,
    );
    if (signed === undefined)
        throw new Error('Malformed signed contribution packet.');
    if (!equalBytes(signed.body, body))
        throw new Error('The signer changed the offer.');
    const output = await sealContributionRecord(
        session,
        signingObject(profile, 'offerSignature'),
        0,
        signed.signature,
    );
    await commitContribution(session, {
        phase: 9,
        state: {
            ...session.state,
            signingRecords: [...session.state.signingRecords, output.record],
        },
        signing: [output],
    });
    return storedOffer(session);
};

export const contributionCandidateKey = (
    position: number,
    bodyIdentity: Uint8Array,
) => 'contribution-' + String(position) + '/' + hexadecimal(bodyIdentity);

export const polynomialFile = (expandedIndex: number) =>
    'polynomial-' + String(expandedIndex).padStart(2, '0') + '.bin';

// Has the module retain the stored proposal's context at this participant's
// position and returns the proposal's identity.
const retainProposal = async (
    context: ParticipantProfileContext,
    root: AuthenticatedRoot,
) => {
    const { module } = context;
    const proposal = await readDataKind(
        context,
        root.manifest,
        dataKind.proposal,
    );
    const control = concatenate(
        root.manifest.poll,
        context.runtime,
        unsigned16(context.position),
        unsigned32(proposal.length),
        proposal,
    );
    writeModuleInput(context, control);
    if (module.retain_proposal(control.length) !== 0)
        throw new Error('The retained proposal context was refused.');
    return readModuleMemory(
        module,
        module.retained_proposal_identity_pointer(),
        identityBytes,
    );
};

export const resumeParticipant = async (
    context: ParticipantProfileContext,
    root: AuthenticatedRoot,
    verified?: VerifiedProposal,
): Promise<ParticipantSession> => {
    const { generation } = root.head;
    const suffix = root.manifest.suffixes.preparation;
    if (
        generation < rootGeneration.rosterSigned ||
        (generation === rootGeneration.rosterSigned) !== (suffix === undefined)
    )
        throw new Error('No accepted roster is retained.');
    const preparation =
        suffix === undefined
            ? {}
            : decodePreparationState(suffix, context.profile);
    if (
        generation >= rootGeneration.setupRetained &&
        Object.keys(preparation).length !== 0
    )
        throw new Error('Retired preparation authority is still present.');
    const state =
        preparation.contribution === undefined
            ? undefined
            : decodeContributionState(
                  preparation.contribution,
                  context.profile,
              );
    if (state !== undefined && state.position !== context.position)
        throw new Error('The retained offer names another participant.');
    await discardInterruptedRecords(context, state);
    const snapshot = await snapshotParticipant(context.database);
    if (
        snapshot.counts.contribution !==
            (state === undefined
                ? 0
                : state.publicRecords.length + state.signingRecords.length) ||
        snapshot.counts.checkpoint !== (state?.privateRecords.length ?? 0)
    )
        throw new Error('The contribution records changed.');
    if (verified !== undefined && verified.position !== context.position)
        throw new Error('The verified proposal moved this participant.');
    const proposal =
        verified?.identity ?? (await retainProposal(context, root));
    if (
        generation >= rootGeneration.preparation &&
        context.module.confirm_roster() !== 0
    )
        throw new Error('The original confirmed roster could not be restored.');
    const session: ParticipantSession = {
        context,
        root,
        preparation,
        records: {
            poll: root.manifest.poll,
            runtime: context.runtime,
            proposal,
            position: context.position,
        },
        ...(state === undefined ? {} : { state }),
    };
    if (generation < rootGeneration.setupRetained)
        await authenticateRecords(context, root, [
            ...dataRecordInventory(root.manifest),
            ...contributionRecords(session),
        ]);
    return session;
};

export const resumeContribution = async (
    context: ParticipantProfileContext,
    root: AuthenticatedRoot,
    verified?: VerifiedProposal,
): Promise<ContributionSession> => {
    const session = await resumeParticipant(context, root, verified);
    if (!isContributionSession(session))
        throw new Error('No own contribution is retained.');
    return session;
};

export const commitPreparation = async (
    session: ParticipantSession,
    update: Pick<PreparationState, 'selection' | 'endorsement'>,
) => {
    if (
        session.root.head.generation !== rootGeneration.rosterSigned &&
        session.root.head.generation !== rootGeneration.preparation
    )
        throw new Error('Preparation is already retired.');
    const preparation = { ...session.preparation, ...update };
    session.root = await commitRoot(session.context, session.root, {
        generation: rootGeneration.preparation,
        manifest: {
            ...session.root.manifest,
            suffixes: { preparation: encodePreparationState(preparation) },
        },
        predecessorRecords: [
            ...dataRecordInventory(session.root.manifest),
            ...contributionRecords(session),
        ],
    });
    session.preparation = preparation;
};

// The human confirms the displayed, verified roster before any setup work.
export const confirmRoster = async (session: ParticipantSession) => {
    if (session.root.head.generation === rootGeneration.rosterSigned)
        await commitPreparation(session, {});
    if (session.context.module.confirm_roster() !== 0)
        throw new Error('The credential refused the confirmed roster.');
};

// The stored records the retained contribution or roster confirmation
// lists, if any.
export const contributionRecords = (session: ParticipantSession) =>
    isContributionSession(session)
        ? contributionInventory(
              session.context.profile,
              session.state,
              session.records,
          )
        : [];

// Publishes one correlated complete signed offer, then announces its body.
export const publishOffer = async (
    session: ContributionSession,
    relay: PublicRelay,
    offer: SignedPacket,
) => {
    const { profile } = session.context;
    const fields = tupleFields(offer.body);
    if (fields.length !== 5 || fields[4].length !== 64)
        throw new Error('The retained offer envelope is malformed.');
    const bodyIdentity = fields[4];
    const key = contributionCandidateKey(session.state.position, bodyIdentity);
    const delivery = await openDelivery(session.context, session.root);
    const publication = createCandidatePublication(relay, key, delivery);
    await publication.addBytes('offer.bin', offer.body);
    await publication.addBytes('offer-signature.bin', offer.signature);
    await publication.addBytes('body-header.bin', session.state.header);
    for (const polynomial of profile.contribution.polynomials) {
        await publication.addStream(
            polynomialFile(polynomial.expandedIndex),
            polynomial.bytes,
            async (accept) => {
                for (const record of session.state.publicRecords.filter(
                    (value) => value.object === polynomial.expandedIndex + 1,
                )) {
                    const bytes = await openContributionRecord(session, record);
                    try {
                        await accept(bytes);
                    } finally {
                        bytes.fill(0);
                    }
                }
            },
        );
    }
    await publication.addStream(
        'proof.bin',
        proofLength(profile.contribution, session.state.header),
        async (accept) => {
            await readRetainedProof(session, async (_offset, bytes) => {
                try {
                    await accept(bytes);
                } finally {
                    bytes.fill(0);
                }
            });
        },
    );
    await publication.finish();
    await delivery.transfer(() =>
        publishOfferAnnouncement(relay, session.state.position, bodyIdentity),
    );
};
