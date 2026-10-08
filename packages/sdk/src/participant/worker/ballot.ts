import {
    ballotEnvelopeMatches,
    ballotRecordAssociatedData,
    ballotRecordInventory,
    ballotRecordLength,
    decodeBallotState,
    encodeBallotState,
    validBallotScores,
} from './ballot-state.js';
import type { BallotState } from './ballot-state.js';
import type { ParticipantProfile } from './bounds.js';
import {
    concatenate,
    equalBytes,
    readUnsigned64,
    unsigned32,
    unsigned64,
} from './bytes.js';
import { closeRecordInventory, decodeCloseState } from './close-state.js';
import { describe, PublicInputFailure, sessionInput } from './context.js';
import type { ProfileContext } from './context.js';
import { contributionRecords } from './contribution.js';
import type { ParticipantSession } from './contribution.js';
import { openDelivery } from './delivery.js';
import {
    operationSeedBytes,
    readKernel,
    ResourceFailure,
    seededRandomness,
} from './kernel.js';
import type { ParticipantStoredRecord } from './predecessor.js';
import { createCandidatePublication } from './public.js';
import type { PublicRelay } from './public.js';
import { openRecord, recordContext, sealRecord } from './records.js';
import type { RecordContext } from './records.js';
import { ballotPhase } from './root-generation.js';
import {
    commitRoot,
    dataKind,
    dataRecordInventory,
    readDataKind,
} from './root.js';
import {
    deliverFinalAggregate,
    ensureFinalAggregate,
    readFinalAggregate,
} from './setup.js';
import { snapshotParticipant, StoragePending } from './storage.js';

// Creates, retains, signs and delivers a participant's ballot through the
// phases the ballot state records.

export type BallotSession = {
    readonly participant: ParticipantSession;
    readonly records: RecordContext;
    state: BallotState;
    // The proof-stream bytes the module drew, when this visit created the
    // ballot.
    proofRandomBytes?: number;
};

// The ordered scores a request supplies, or undefined when they are not one
// valid score per option.
export const parseBallotScores = (
    profile: ParticipantProfile,
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
        validBallotScores(profile, scores)
        ? scores
        : undefined;
};

type SealedRecord = Readonly<{
    index: number;
    key: Uint8Array;
    ciphertext: Uint8Array;
}>;

const sealBallotRecord = async (
    context: RecordContext,
    index: number,
    bytes: Uint8Array,
): Promise<SealedRecord> => ({
    index,
    ...(await sealRecord(
        ballotRecordAssociatedData(context, index, bytes.length),
        bytes,
    )),
});

const openBallotRecord = (session: BallotSession, index: number) => {
    const { context } = session.participant;
    const length = ballotRecordLength(context.profile, session.state, index);
    return openRecord(
        context.database,
        'ballot',
        index,
        {
            key: session.state.bodyKeys[index],
            additionalData: ballotRecordAssociatedData(
                session.records,
                index,
                length,
            ),
        },
        length,
    );
};

// The ballot a root retains: none at generation twelve or without a ballot,
// the attempt's phase through generation seventeen, and the signed ballot
// after it.
const retainedBallotState = (
    participant: ParticipantSession,
    records: RecordContext,
): BallotState | undefined => {
    const { root, context } = participant;
    const bytes = root.manifest.suffixes.ballot;
    if (bytes === undefined) throw new Error('The ballot suffix is missing.');
    if (bytes.length === 0) {
        if (
            root.head.generation >= ballotPhase.locked &&
            root.head.generation <= ballotPhase.signed
        )
            throw new Error('A ballot phase retains no ballot.');
        return undefined;
    }
    return decodeBallotState(
        context.profile,
        records,
        Math.min(root.head.generation, ballotPhase.signed),
        bytes,
    );
};

// The ballot records the current root lists.
export const retainedBallotRecords = (
    participant: ParticipantSession,
    records: RecordContext,
): ParticipantStoredRecord[] => {
    const state = retainedBallotState(participant, records);
    return state === undefined
        ? []
        : ballotRecordInventory(participant.context.profile, records, state);
};

// The close records the root lists while a ballot is pending; the close log
// only collects through the ballot phases.
const collectedCloseRecords = (
    participant: ParticipantSession,
    records: RecordContext,
) => {
    const { root, context } = participant;
    const bytes = root.manifest.suffixes.close;
    if (bytes === undefined) throw new Error('The close suffix is missing.');
    return closeRecordInventory(
        context.profile,
        records,
        decodeCloseState(context.profile, root.head.generation, false, bytes),
    );
};

type BallotTransition = Readonly<{
    generation: number;
    state: BallotState;
    // The records written with the root.
    added?: readonly SealedRecord[];
}>;

const commitBallot = async (
    session: BallotSession,
    transition: BallotTransition,
) => {
    const { participant } = session;
    const { context, root } = participant;
    const encoded = encodeBallotState(transition.generation, transition.state);
    if (encoded.length > context.profile.ballot.maximumStateBytes)
        throw new Error('The ballot state exceeds its bound.');
    participant.root = await commitRoot(context, root, {
        generation: transition.generation,
        manifest: {
            ...root.manifest,
            suffixes: { ...root.manifest.suffixes, ballot: encoded },
        },
        predecessorRecords: [
            ...dataRecordInventory(root.manifest),
            ...contributionRecords(participant),
            ...ballotRecordInventory(
                context.profile,
                session.records,
                session.state,
            ),
            ...collectedCloseRecords(participant, session.records),
        ],
        write: (transaction) => {
            const store = transaction.objectStore('ballot');
            for (const record of transition.added ?? [])
                store.add(
                    new Blob([new Uint8Array(record.ciphertext)]),
                    record.index,
                );
        },
    });
    session.state = transition.state;
    for (const record of transition.added ?? [])
        (await openBallotRecord(session, record.index)).fill(0);
};

// Locks a ballot attempt: the scores and the ballot time enter the root
// before any ballot randomness exists.
export const beginBallot = async (
    participant: ParticipantSession,
    scores: Uint8Array,
): Promise<BallotSession> => {
    const { context, root } = participant;
    const { profile } = context;
    if (root.head.generation !== ballotPhase.locked - 1)
        throw new Error('No verified setup awaits a ballot.');
    if (!validBallotScores(profile, scores))
        throw new Error('The scores are invalid.');
    const estimate = await navigator.storage.estimate();
    if (
        estimate.quota === undefined ||
        estimate.usage === undefined ||
        estimate.quota - estimate.usage < profile.ballot.requiredStorageBytes
    )
        throw new StoragePending('The origin lacks room for a ballot.');
    const records = await recordContext(participant);
    const session: BallotSession = {
        participant,
        records,
        state: {
            scores: scores.slice(),
            ballotTime: BigInt(Date.now()),
            seed: new Uint8Array(),
            bodyLength: 0,
            bodyKeys: [],
            envelope: new Uint8Array(),
            signature: new Uint8Array(),
        },
    };
    participant.root = await commitRoot(context, root, {
        generation: ballotPhase.locked,
        manifest: {
            ...root.manifest,
            suffixes: {
                ...root.manifest.suffixes,
                ballot: encodeBallotState(ballotPhase.locked, session.state),
            },
        },
        predecessorRecords: [
            ...dataRecordInventory(root.manifest),
            ...contributionRecords(participant),
            ...collectedCloseRecords(participant, records),
        ],
    });
    return session;
};

// Decodes the retained ballot, or undefined when the root retains none.
// Every listed record must be stored and nothing else.
export const resumeBallot = async (
    participant: ParticipantSession,
): Promise<BallotSession | undefined> => {
    const { context } = participant;
    const records = await recordContext(participant);
    const state = retainedBallotState(participant, records);
    const snapshot = await snapshotParticipant(context.database);
    if (snapshot.counts.ballot !== (state?.bodyKeys.length ?? 0))
        throw new Error('The ballot records changed.');
    return state === undefined ? undefined : { participant, records, state };
};

// Ballot and close authority binds the original member to its verified setup.
export const ballotWorkInput = async (
    participant: ParticipantSession,
    inventory: Uint8Array,
) => {
    const { context } = participant;
    const { manifest } = participant.root;
    const definition = await readDataKind(
        context,
        manifest,
        dataKind.pollDefinition,
    );
    const definitionSignature = await readDataKind(
        context,
        manifest,
        dataKind.pollSignature,
    );
    const reference = await readDataKind(
        context,
        manifest,
        dataKind.setupReference,
    );
    return concatenate(
        manifest.poll,
        participant.context.runtime,
        unsigned32(definition.length),
        definition,
        definitionSignature,
        inventory,
        reference,
    );
};

const ballotCommand = (
    context: ProfileContext,
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
// reference, and delivers the FHE key from the final public aggregate.
// The module derives the fixed auxiliary pair and checks the FHE reference, so
// an unavailable or refused key leaves the participant pending.
const startBallotWork = async (session: BallotSession) => {
    const { participant } = session;
    const { context } = participant;
    const { kernel } = context;
    ballotCommand(
        context,
        0,
        0,
        await ballotWorkInput(participant, session.records.inventory),
    );
    const index = kernel.participant_ballot_key_index() >>> 0;
    ballotCommand(context, 1, index);
    try {
        await deliverFinalAggregate(context, async () => {
            await readFinalAggregate(context, index, (offset, bytes) => {
                ballotCommand(context, 2, offset, bytes);
            });
            ballotCommand(context, 3);
        });
    } catch (error) {
        if (
            error instanceof PublicInputFailure ||
            error instanceof ResourceFailure
        )
            throw error;
        throw new PublicInputFailure(
            'A ballot key was refused: ' + describe(error),
        );
    }
};

// Creates the ballot from the locked scores and ballot time. Its encryption
// and proof randomness come only from the retained seed, so a replay draws
// the same bytes.
const createBallot = (session: BallotSession) => {
    const { context } = session.participant;
    const randomness = seededRandomness(
        context.kernel,
        'ballot',
        session.state.seed,
        'ballot',
    );
    const input = concatenate(
        unsigned64(session.state.ballotTime),
        session.state.scores,
    );
    context.handlers.random = randomness.random;
    try {
        ballotCommand(context, 4, 0, input);
        session.proofRandomBytes = randomness.proofDrawn();
    } finally {
        context.handlers.random = undefined;
        input.fill(0);
        randomness.discard();
    }
    return ballotCommand(context, 10);
};

// Creates the ballot from the seed and retains its envelope and complete body
// with one root, retiring the seed.
const retainBallot = async (session: BallotSession) => {
    const { context } = session.participant;
    const { envelopeBytes, recordBytes } = context.profile.ballot;
    const envelope = createBallot(session);
    const bodyLength = Number(readUnsigned64(envelope, 142));
    if (
        envelope.length !== envelopeBytes ||
        !ballotEnvelopeMatches(
            envelope,
            session.records,
            bodyLength,
            session.state.ballotTime,
        )
    )
        throw new Error('The created envelope has another context.');
    const added: SealedRecord[] = [];
    for (let offset = 0; offset < bodyLength; offset += recordBytes) {
        const length = Math.min(recordBytes, bodyLength - offset);
        const bytes = ballotCommand(context, 11, offset, unsigned32(length));
        try {
            if (bytes.length !== length)
                throw new Error('A ballot body record is incomplete.');
            added.push(
                await sealBallotRecord(session.records, added.length, bytes),
            );
        } finally {
            bytes.fill(0);
        }
    }
    await commitBallot(session, {
        generation: ballotPhase.body,
        state: {
            ...session.state,
            seed: new Uint8Array(),
            bodyLength,
            bodyKeys: added.map((record) => record.key),
            envelope,
        },
        added,
    });
};

// Imports the complete retained body; the module verifies it against the
// keys and must reproduce the retained envelope.
const importBody = async (session: BallotSession) => {
    const { context } = session.participant;
    ballotCommand(context, 5, 0, session.state.envelope);
    let offset = 0;
    await readBallotBody(session, (bytes) => {
        ballotCommand(context, 6, offset, bytes);
        offset += bytes.length;
    });
    ballotCommand(context, 7);
    if (!equalBytes(ballotCommand(context, 10), session.state.envelope))
        throw new Error('The verified ballot changed its envelope.');
};

// Carries a retained ballot to its signed completion. Its keys come from the
// final aggregate, which the setup is verified again to rewrite when the
// cache no longer holds it.
export const completeBallot = async (
    session: BallotSession,
    relay: PublicRelay,
) => {
    const { participant } = session;
    const { context } = participant;
    const generation = () => participant.root.head.generation;
    if (generation() >= ballotPhase.signed) return;
    await ensureFinalAggregate(participant, relay);
    await startBallotWork(session);
    if (generation() === ballotPhase.locked)
        await commitBallot(session, {
            generation: ballotPhase.ready,
            state: {
                ...session.state,
                seed: crypto.getRandomValues(
                    new Uint8Array(operationSeedBytes),
                ),
            },
        });
    if (generation() === ballotPhase.ready) await retainBallot(session);
    else await importBody(session);
    ballotCommand(context, 8, 0, session.state.envelope);
    const signature = ballotCommand(context, 12);
    if (signature.length !== context.profile.registration.signatureBytes)
        throw new Error('The ballot signature is incomplete.');
    await commitBallot(session, {
        generation: ballotPhase.signed,
        state: {
            ...session.state,
            scores: new Uint8Array(),
            ballotTime: 0n,
            signature,
        },
    });
};

// Every complete carrier for an author's submissions remains discoverable.
// The owning verifier authenticates the author and envelope identity.
export const ballotCandidateKey = (author: number) =>
    'ballot-' + String(author);

// Streams the retained body record by record, clearing each after use.
export const readBallotBody = async (
    session: BallotSession,
    consume: (bytes: Uint8Array) => void | Promise<void>,
) => {
    let offset = 0;
    for (let index = 0; index < session.state.bodyKeys.length; index++) {
        const bytes = await openBallotRecord(session, index);
        try {
            await consume(bytes);
            offset += bytes.length;
        } finally {
            bytes.fill(0);
        }
    }
    if (offset !== session.state.bodyLength)
        throw new Error('The retained ballot body is incomplete.');
};

// Whether the retained ballot is signed.
export const isSignedBallot = (session: BallotSession) =>
    session.state.signature.length > 0;

// Delivers one complete signed ballot candidate from its authenticated
// records, inspecting retained authority around every transfer.
export const publishBallot = async (
    session: BallotSession,
    relay: PublicRelay,
) => {
    if (!isSignedBallot(session))
        throw new Error('No signed ballot is retained.');
    const { context, root } = session.participant;
    const { position } = session.records;
    const delivery = await openDelivery(context, root);
    const publication = createCandidatePublication(
        relay,
        ballotCandidateKey(position),
        delivery,
    );
    await publication.addBytes('envelope.bin', session.state.envelope);
    await publication.addBytes('signature.bin', session.state.signature);
    await publication.addStream(
        'body.bin',
        session.state.bodyLength,
        async (accept) => {
            await readBallotBody(session, accept);
        },
    );
    await publication.finish();
};
