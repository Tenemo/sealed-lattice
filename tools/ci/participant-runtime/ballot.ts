import type { ParticipantStoredRecord } from '../protocol-participant-predecessor.js';

import {
    concatenate,
    encodeText,
    equalBytes,
    readUnsigned16,
    readUnsigned32,
    readUnsigned64,
    unsigned16,
    unsigned32,
    unsigned64,
} from './bytes.js';
import { describe, PublicInputFailure, sessionInput } from './context.js';
import type { ParticipantContext } from './context.js';
import {
    contributionRecords,
    openedInventory,
    storedOpening,
} from './contribution.js';
import type { ContributionSession } from './contribution.js';
import type { ParticipantDescriptor } from './descriptor.js';
import { readKernel } from './kernel.js';
import type { KernelHandlers } from './kernel.js';
import { publishChunk, publishRecord } from './public.js';
import type { PublicRelay } from './public.js';
import {
    commitRoot,
    dataKind,
    dataRecordInventory,
    readDataKind,
    StoragePending,
} from './root.js';
import { readFinalAggregate } from './setup.js';
import { readParticipantValue, snapshotParticipant } from './storage.js';

// A participant's ballot beneath its authenticated root. Generation 13 locks
// the attempt's scores and ballot time and appends the randomness journal
// one record at a time; the append of its final record enters generation 14.
// Generation 15 retains the envelope and a growing prefix of body records;
// generation 16 the complete body and the signing coins; generation 17 the
// signature, retiring the journal and the scores. Every append commits its
// record with a root sealed under a fresh key, so a repeated generation is
// not nonce reuse. An interruption replays the same journal and must
// reproduce the retained envelope.

const phase = { locked: 13, ready: 14, body: 15, signing: 16, signed: 17 };
const marker = encodeText('BST1');
const envelopeMarker = encodeText('LBE2');
const keyBytes = 32;
const coinBytes = 32;
const journalKind = 0;
const bodyKind = 1;
// The FHE and auxiliary encryption keys the ballot encrypts under.
const ballotKeys = 2;
const randomRequestBytes = 65_536;

type BallotState = Readonly<{
    scores: Uint8Array;
    ballotTime: bigint;
    journalKeys: readonly Uint8Array[];
    bodyLength: number;
    bodyKeys: readonly Uint8Array[];
    envelope: Uint8Array;
    coins: Uint8Array;
    signature: Uint8Array;
}>;

// What a ballot record is bound to besides its kind, index and length.
type RecordContext = Readonly<{
    poll: Uint8Array;
    runtime: Uint8Array;
    inventory: Uint8Array;
    position: number;
}>;

export type BallotSession = {
    readonly contribution: ContributionSession;
    readonly records: RecordContext;
    state: BallotState;
};

const validScores = (descriptor: ParticipantDescriptor, scores: Uint8Array) =>
    scores.length === descriptor.optionCount &&
    scores.every(
        (score) =>
            score >= descriptor.ballot.minimumScore &&
            score <= descriptor.ballot.maximumScore,
    );

// The ordered scores a request supplies, or undefined when they are not one
// valid score per option.
export const parseBallotScores = (
    descriptor: ParticipantDescriptor,
    value: unknown,
): Uint8Array | undefined => {
    if (
        !Array.isArray(value) ||
        !value.every((score) => Number.isInteger(score))
    )
        return undefined;
    const scores = Uint8Array.from(value as number[]);
    return value.length === scores.length &&
        scores.every((score, index) => score === value[index]) &&
        validScores(descriptor, scores)
        ? scores
        : undefined;
};

// Each journal record's bank and plaintext length: the encryption bank's
// records, then the proof bank's.
const journalLayout = (descriptor: ParticipantDescriptor) => {
    const { recordBytes, randomBudgets, journalRecords } = descriptor.ballot;
    const layout = randomBudgets.flatMap((total, bank) =>
        Array.from(
            { length: Math.ceil(total / recordBytes) },
            (_unused, index) => ({
                bank,
                length: Math.min(recordBytes, total - index * recordBytes),
            }),
        ),
    );
    if (layout.length !== journalRecords)
        throw new Error('The ballot journal differs from its descriptor.');
    return layout;
};

const recordLength = (
    descriptor: ParticipantDescriptor,
    state: BallotState,
    kind: number,
    index: number,
) =>
    kind === journalKind
        ? journalLayout(descriptor)[index].length
        : Math.min(
              descriptor.ballot.recordBytes,
              state.bodyLength - index * descriptor.ballot.recordBytes,
          );

const encodeBallotState = (generation: number, state: BallotState) =>
    concatenate(
        marker,
        Uint8Array.of(state.scores.length),
        state.scores,
        generation < phase.signed
            ? unsigned64(state.ballotTime)
            : new Uint8Array(),
        unsigned16(state.journalKeys.length),
        ...state.journalKeys,
        unsigned32(state.bodyLength),
        unsigned16(state.bodyKeys.length),
        ...state.bodyKeys,
        state.envelope,
        state.coins,
        state.signature,
    );

// The envelope's context fields at their offsets: the poll, the setup
// inventory, the author's position, the ballot time and the body length.
const envelopeMatches = (
    envelope: Uint8Array,
    context: RecordContext,
    bodyLength: number,
    ballotTime?: bigint,
) =>
    equalBytes(envelope.subarray(0, 4), envelopeMarker) &&
    equalBytes(envelope.subarray(4, 68), context.poll) &&
    equalBytes(envelope.subarray(68, 132), context.inventory) &&
    readUnsigned16(envelope, 132) === context.position &&
    (ballotTime === undefined ||
        readUnsigned64(envelope, 134) === ballotTime) &&
    readUnsigned64(envelope, 142) === BigInt(bodyLength);

// Decodes the ballot suffix under the phase its root generation supplies;
// each phase has exactly one shape.
const decodeBallotState = (
    descriptor: ParticipantDescriptor,
    context: RecordContext,
    generation: number,
    bytes: Uint8Array,
): BallotState => {
    const bounds = descriptor.ballot;
    if (
        generation < phase.locked ||
        generation > phase.signed ||
        bytes.length > bounds.maximumStateBytes ||
        !equalBytes(bytes.subarray(0, marker.length), marker)
    )
        throw new Error('The ballot state is malformed.');
    let offset = marker.length;
    const take = (length: number) => {
        if (length > bytes.length - offset)
            throw new Error('The ballot state is truncated.');
        const value = bytes.slice(offset, offset + length);
        offset += length;
        return value;
    };
    const scores = take(take(1)[0]);
    if (
        generation === phase.signed
            ? scores.length !== 0
            : !validScores(descriptor, scores)
    )
        throw new Error('The locked scores changed.');
    const ballotTime =
        generation === phase.signed ? 0n : readUnsigned64(take(8), 0);
    const journalCount = readUnsigned16(take(2), 0);
    if (
        generation === phase.locked
            ? journalCount >= bounds.journalRecords
            : journalCount !==
              (generation === phase.signed ? 0 : bounds.journalRecords)
    )
        throw new Error('The ballot journal is inconsistent.');
    const journalKeys = Array.from({ length: journalCount }, () =>
        take(keyBytes),
    );
    const bodyLength = readUnsigned32(take(4), 0);
    const bodyCount = readUnsigned16(take(2), 0);
    const bodyRecords = Math.ceil(bodyLength / bounds.recordBytes);
    if (
        generation < phase.body
            ? bodyLength !== 0 || bodyCount !== 0
            : bodyLength < bounds.minimumBodyBytes ||
              bodyLength > bounds.maximumBodyBytes ||
              bodyCount > bodyRecords ||
              (generation > phase.body && bodyCount !== bodyRecords)
    )
        throw new Error('The retained ballot body is inconsistent.');
    const bodyKeys = Array.from({ length: bodyCount }, () => take(keyBytes));
    const envelope =
        generation >= phase.body
            ? take(bounds.envelopeBytes)
            : new Uint8Array();
    const coins =
        generation === phase.signing ? take(coinBytes) : new Uint8Array();
    const signature =
        generation === phase.signed
            ? take(descriptor.registration.signatureBytes)
            : new Uint8Array();
    if (offset !== bytes.length)
        throw new Error('The ballot state has extra bytes.');
    if (
        generation >= phase.body &&
        !envelopeMatches(
            envelope,
            context,
            bodyLength,
            generation === phase.signed ? undefined : ballotTime,
        )
    )
        throw new Error('The retained envelope changed its context.');
    return {
        scores,
        ballotTime,
        journalKeys,
        bodyLength,
        bodyKeys,
        envelope,
        coins,
        signature,
    };
};

const recordAssociatedData = (
    context: RecordContext,
    kind: number,
    index: number,
    length: number,
) =>
    concatenate(
        encodeText('sealed-lattice/participant-ballot-record/v1'),
        context.poll,
        context.runtime,
        context.inventory,
        unsigned16(context.position),
        Uint8Array.of(kind),
        unsigned16(index),
        unsigned32(length),
    );

const recordCipher = (key: Uint8Array, usage: 'encrypt' | 'decrypt') =>
    crypto.subtle.importKey('raw', new Uint8Array(key), 'AES-GCM', false, [
        usage,
    ]);

type SealedRecord = Readonly<{
    kind: number;
    index: number;
    key: Uint8Array;
    ciphertext: Uint8Array;
}>;

const sealRecord = async (
    context: RecordContext,
    kind: number,
    index: number,
    bytes: Uint8Array,
): Promise<SealedRecord> => {
    const key = crypto.getRandomValues(new Uint8Array(keyBytes));
    const ciphertext = new Uint8Array(
        await crypto.subtle.encrypt(
            {
                name: 'AES-GCM',
                iv: new Uint8Array(12),
                additionalData: new Uint8Array(
                    recordAssociatedData(context, kind, index, bytes.length),
                ),
            },
            await recordCipher(key, 'encrypt'),
            new Uint8Array(bytes),
        ),
    );
    return { kind, index, key, ciphertext };
};

const openRecord = async (
    session: BallotSession,
    kind: number,
    index: number,
) => {
    const { context } = session.contribution;
    const keys =
        kind === journalKind
            ? session.state.journalKeys
            : session.state.bodyKeys;
    const length = recordLength(context.descriptor, session.state, kind, index);
    const blob = await readParticipantValue(context.database, 'ballot', [
        kind,
        index,
    ]);
    if (!(blob instanceof Blob) || blob.size !== length + 16)
        throw new Error('A ballot record is missing.');
    return new Uint8Array(
        await crypto.subtle.decrypt(
            {
                name: 'AES-GCM',
                iv: new Uint8Array(12),
                additionalData: new Uint8Array(
                    recordAssociatedData(session.records, kind, index, length),
                ),
            },
            await recordCipher(keys[index], 'decrypt'),
            new Uint8Array(await blob.arrayBuffer()),
        ),
    );
};

// The ballot records a state lists; the predecessor check opens each under
// its own key.
const ballotInventory = (session: BallotSession): ParticipantStoredRecord[] =>
    (
        [
            [journalKind, session.state.journalKeys],
            [bodyKind, session.state.bodyKeys],
        ] as const
    ).flatMap(([kind, keys]) =>
        keys.map((key, index) => {
            const length = recordLength(
                session.contribution.context.descriptor,
                session.state,
                kind,
                index,
            );
            return {
                store: 'ballot',
                key: [kind, index],
                byteLength: length + 16,
                encryption: {
                    key,
                    additionalData: recordAssociatedData(
                        session.records,
                        kind,
                        index,
                        length,
                    ),
                },
            };
        }),
    );

type BallotTransition = Readonly<{
    generation: number;
    state: BallotState;
    // A record written with the root.
    added?: SealedRecord;
    // Completion removes the journal with the root that stops listing it.
    retireJournal?: boolean;
}>;

const commitBallot = async (
    session: BallotSession,
    transition: BallotTransition,
) => {
    const { contribution } = session;
    const { context, root } = contribution;
    const encoded = encodeBallotState(transition.generation, transition.state);
    if (encoded.length > context.descriptor.ballot.maximumStateBytes)
        throw new Error('The ballot state exceeds its bound.');
    contribution.root = await commitRoot(
        context.database,
        context.runtime,
        context.descriptor,
        root,
        {
            generation: transition.generation,
            manifest: {
                ...root.manifest,
                suffixes: { ...root.manifest.suffixes, ballot: encoded },
            },
            predecessorRecords: [
                ...dataRecordInventory(root.manifest),
                ...contributionRecords(contribution),
                ...ballotInventory(session),
            ],
            write: (transaction) => {
                const store = transaction.objectStore('ballot');
                if (transition.added !== undefined)
                    store.add(
                        new Blob([new Uint8Array(transition.added.ciphertext)]),
                        [transition.added.kind, transition.added.index],
                    );
                if (transition.retireJournal === true)
                    store.delete(
                        IDBKeyRange.bound(
                            [journalKind],
                            [bodyKind],
                            false,
                            true,
                        ),
                    );
            },
        },
    );
    session.state = transition.state;
    if (transition.added !== undefined)
        (
            await openRecord(
                session,
                transition.added.kind,
                transition.added.index,
            )
        ).fill(0);
};

const recordContext = async (
    contribution: ContributionSession,
): Promise<RecordContext> => ({
    poll: contribution.root.manifest.poll,
    runtime: contribution.context.runtime,
    inventory: (await openedInventory(contribution)).identity,
    position: contribution.records.position,
});

// Locks a ballot attempt: the scores and the ballot time enter the root
// before any journal randomness exists.
export const beginBallot = async (
    contribution: ContributionSession,
    scores: Uint8Array,
): Promise<BallotSession> => {
    const { context, root } = contribution;
    const { descriptor } = context;
    if (root.head.generation !== phase.locked - 1)
        throw new Error('No verified setup awaits a ballot.');
    if (!validScores(descriptor, scores))
        throw new Error('The scores are invalid.');
    const estimate = await navigator.storage.estimate();
    if (
        estimate.quota === undefined ||
        estimate.usage === undefined ||
        estimate.quota - estimate.usage < descriptor.ballot.requiredStorageBytes
    )
        throw new StoragePending('The origin lacks room for a ballot.');
    const session: BallotSession = {
        contribution,
        records: await recordContext(contribution),
        state: {
            scores: scores.slice(),
            ballotTime: BigInt(Date.now()),
            journalKeys: [],
            bodyLength: 0,
            bodyKeys: [],
            envelope: new Uint8Array(),
            coins: new Uint8Array(),
            signature: new Uint8Array(),
        },
    };
    contribution.root = await commitRoot(
        context.database,
        context.runtime,
        descriptor,
        root,
        {
            generation: phase.locked,
            manifest: {
                ...root.manifest,
                suffixes: {
                    ...root.manifest.suffixes,
                    ballot: encodeBallotState(phase.locked, session.state),
                },
            },
            predecessorRecords: [
                ...dataRecordInventory(root.manifest),
                ...contributionRecords(contribution),
            ],
        },
    );
    return session;
};

// Decodes the retained ballot. Every listed record must be stored and
// nothing else.
export const resumeBallot = async (
    contribution: ContributionSession,
): Promise<BallotSession> => {
    const { context, root } = contribution;
    const bytes = root.manifest.suffixes.ballot;
    if (
        root.head.generation < phase.locked ||
        root.head.generation > phase.signed ||
        bytes === undefined
    )
        throw new Error('No ballot is retained.');
    const records = await recordContext(contribution);
    const state = decodeBallotState(
        context.descriptor,
        records,
        root.head.generation,
        bytes,
    );
    const snapshot = await snapshotParticipant(context.database);
    if (
        snapshot.counts.ballot !==
        state.journalKeys.length + state.bodyKeys.length
    )
        throw new Error('The ballot records changed.');
    return { contribution, records, state };
};

const ballotCommand = (
    context: ParticipantContext,
    operation: number,
    argument = 0,
    input: Uint8Array = new Uint8Array(),
) => {
    const { kernel } = context;
    sessionInput(context, input);
    if (
        kernel.participant_ballot_command(operation, argument, input.length) !==
        0
    )
        throw new Error(
            'The ballot module refused operation ' + String(operation) + '.',
        );
    return readKernel(
        kernel,
        kernel.contribution_output_pointer(),
        kernel.contribution_output_length(),
    );
};

// Starts the module's ballot work from the retained poll, opening and setup
// reference, and delivers both encryption keys from the final public
// aggregate. The module checks each key against the retained reference, so
// an unavailable or refused key leaves the participant pending.
const startBallotWork = async (session: BallotSession) => {
    const { contribution } = session;
    const { context } = contribution;
    const { database, kernel } = context;
    const { manifest } = contribution.root;
    const definition = await readDataKind(
        database,
        manifest,
        dataKind.pollDefinition,
    );
    const definitionSignature = await readDataKind(
        database,
        manifest,
        dataKind.pollSignature,
    );
    const reference = await readDataKind(
        database,
        manifest,
        dataKind.setupReference,
    );
    const opening = await storedOpening(contribution);
    const packet = concatenate(
        unsigned32(opening.body.length),
        opening.body,
        opening.signature,
    );
    ballotCommand(
        context,
        0,
        0,
        concatenate(
            manifest.poll,
            context.runtime,
            unsigned32(definition.length),
            definition,
            definitionSignature,
            session.records.inventory,
            unsigned32(packet.length),
            packet,
            reference,
        ),
    );
    for (let ordinal = 0; ordinal < ballotKeys; ordinal++) {
        const index = kernel.participant_ballot_key_index(ordinal) >>> 0;
        ballotCommand(context, 1, index);
        try {
            await readFinalAggregate(context, index, (offset, bytes) => {
                ballotCommand(context, 2, offset, bytes);
            });
            ballotCommand(context, 3);
        } catch (error) {
            if (error instanceof PublicInputFailure) throw error;
            throw new PublicInputFailure(
                'A ballot key was refused: ' + describe(error),
            );
        }
    }
};

// Appends the journal's original random bytes one record at a time; the
// append of the final record enters the ready phase.
const prepareJournal = async (session: BallotSession) => {
    const layout = journalLayout(session.contribution.context.descriptor);
    while (session.contribution.root.head.generation === phase.locked) {
        const index = session.state.journalKeys.length;
        const bytes = new Uint8Array(layout[index].length);
        let added: SealedRecord;
        try {
            for (let offset = 0; offset < bytes.length;)
                offset += crypto.getRandomValues(
                    bytes.subarray(offset, offset + randomRequestBytes),
                ).length;
            added = await sealRecord(
                session.records,
                journalKind,
                index,
                bytes,
            );
        } finally {
            bytes.fill(0);
        }
        const journalKeys = [...session.state.journalKeys, added.key];
        await commitBallot(session, {
            generation:
                journalKeys.length === layout.length
                    ? phase.ready
                    : phase.locked,
            state: { ...session.state, journalKeys },
            added,
        });
    }
};

// Serves the module's encryption and proof randomness from the journal's
// two banks in order and clears what it consumed; exhaustion refuses.
const journalRandomness = async (session: BallotSession) => {
    const { descriptor } = session.contribution.context;
    const { recordBytes, randomBudgets } = descriptor.ballot;
    const banks: Uint8Array[][] = randomBudgets.map(() => []);
    for (const [index, entry] of journalLayout(descriptor).entries())
        banks[entry.bank].push(await openRecord(session, journalKind, index));
    const used = banks.map(() => 0);
    const serve = (bank: number, target: Uint8Array) => {
        if (target.length > randomBudgets[bank] - used[bank])
            throw new Error(
                'The ballot journal is exhausted in its ' +
                    (bank === 0 ? 'encryption' : 'proof') +
                    ' bank.',
            );
        for (let filled = 0; filled < target.length;) {
            const record = banks[bank][Math.floor(used[bank] / recordBytes)];
            const inside = used[bank] % recordBytes;
            const count = Math.min(
                target.length - filled,
                record.length - inside,
            );
            target.set(record.subarray(inside, inside + count), filled);
            record.fill(0, inside, inside + count);
            filled += count;
            used[bank] += count;
        }
    };
    const random: NonNullable<KernelHandlers['random']> = (source, target) => {
        if (source === 'ballot') serve(0, target);
        else if (source === 'proof') serve(1, target);
        else throw new Error('The ballot requested other randomness.');
    };
    return {
        random,
        clear: () => {
            for (const bank of banks) for (const record of bank) record.fill(0);
        },
    };
};

// Creates the ballot from the locked scores, ballot time and journal.
const createBallot = async (session: BallotSession) => {
    const { context } = session.contribution;
    const randomness = await journalRandomness(session);
    const input = concatenate(
        unsigned64(session.state.ballotTime),
        session.state.scores,
    );
    context.handlers.random = randomness.random;
    try {
        ballotCommand(context, 4, 0, input);
    } finally {
        context.handlers.random = undefined;
        randomness.clear();
        input.fill(0);
    }
    return ballotCommand(context, 10);
};

// Retains the created body record by record, each append with its root.
const retainBody = async (session: BallotSession) => {
    const { context } = session.contribution;
    const { recordBytes } = context.descriptor.ballot;
    const count = Math.ceil(session.state.bodyLength / recordBytes);
    while (session.state.bodyKeys.length < count) {
        const index = session.state.bodyKeys.length;
        const offset = index * recordBytes;
        const length = Math.min(recordBytes, session.state.bodyLength - offset);
        const bytes = ballotCommand(context, 11, offset, unsigned32(length));
        let added: SealedRecord;
        try {
            if (bytes.length !== length)
                throw new Error('A ballot body record is incomplete.');
            added = await sealRecord(session.records, bodyKind, index, bytes);
        } finally {
            bytes.fill(0);
        }
        await commitBallot(session, {
            generation: phase.body,
            state: {
                ...session.state,
                bodyKeys: [...session.state.bodyKeys, added.key],
            },
            added,
        });
    }
};

// Imports the complete retained body; the module verifies it against the
// keys and must reproduce the retained envelope.
const importBody = async (session: BallotSession) => {
    const { context } = session.contribution;
    ballotCommand(context, 5, 0, session.state.envelope);
    let offset = 0;
    for (let index = 0; index < session.state.bodyKeys.length; index++) {
        const bytes = await openRecord(session, bodyKind, index);
        try {
            ballotCommand(context, 6, offset, bytes);
            offset += bytes.length;
        } finally {
            bytes.fill(0);
        }
    }
    if (offset !== session.state.bodyLength)
        throw new Error('The retained ballot body is incomplete.');
    ballotCommand(context, 7);
    if (!equalBytes(ballotCommand(context, 10), session.state.envelope))
        throw new Error('The verified ballot changed its envelope.');
};

// Carries a retained ballot to its signed completion. A replay before the
// body is complete must reproduce the retained envelope before appending.
export const completeBallot = async (session: BallotSession) => {
    const { contribution } = session;
    const { context } = contribution;
    const generation = () => contribution.root.head.generation;
    if (generation() >= phase.signed) return;
    await startBallotWork(session);
    await prepareJournal(session);
    const bodyRecords = Math.ceil(
        session.state.bodyLength / context.descriptor.ballot.recordBytes,
    );
    if (
        generation() === phase.ready ||
        (generation() === phase.body &&
            session.state.bodyKeys.length < bodyRecords)
    ) {
        const envelope = await createBallot(session);
        if (generation() === phase.ready) {
            const bodyLength = Number(readUnsigned64(envelope, 142));
            if (
                envelope.length !== context.descriptor.ballot.envelopeBytes ||
                !envelopeMatches(
                    envelope,
                    session.records,
                    bodyLength,
                    session.state.ballotTime,
                )
            )
                throw new Error('The created envelope has another context.');
            await commitBallot(session, {
                generation: phase.body,
                state: { ...session.state, bodyLength, envelope },
            });
        } else if (!equalBytes(envelope, session.state.envelope))
            throw new Error('The replayed ballot differs from its envelope.');
        await retainBody(session);
    } else await importBody(session);
    if (generation() === phase.body)
        await commitBallot(session, {
            generation: phase.signing,
            state: {
                ...session.state,
                coins: crypto.getRandomValues(new Uint8Array(coinBytes)),
            },
        });
    const control = concatenate(session.state.envelope, session.state.coins);
    try {
        ballotCommand(context, 8, 0, control);
    } finally {
        control.fill(0);
    }
    const signature = ballotCommand(context, 12);
    if (signature.length !== context.descriptor.registration.signatureBytes)
        throw new Error('The ballot signature is incomplete.');
    await commitBallot(session, {
        generation: phase.signed,
        state: {
            ...session.state,
            scores: new Uint8Array(),
            ballotTime: 0n,
            journalKeys: [],
            coins: new Uint8Array(),
            signature,
        },
        retireJournal: true,
    });
};

const ballotDirectory = (position: number) =>
    'ballot-' + String(position) + '/';

// Delivers the signed ballot from its authenticated records.
export const publishBallot = async (
    session: BallotSession,
    relay: PublicRelay,
) => {
    if (session.contribution.root.head.generation !== phase.signed)
        throw new Error('No signed ballot is retained.');
    const directory = ballotDirectory(session.records.position);
    await publishRecord(
        relay,
        directory + 'envelope.bin',
        session.state.envelope,
    );
    await publishRecord(
        relay,
        directory + 'signature.bin',
        session.state.signature,
    );
    let offset = 0;
    for (let index = 0; index < session.state.bodyKeys.length; index++) {
        const bytes = await openRecord(session, bodyKind, index);
        try {
            await publishChunk(relay, directory + 'body.bin', offset, bytes);
            offset += bytes.length;
        } finally {
            bytes.fill(0);
        }
    }
};
