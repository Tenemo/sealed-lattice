import { ballotCandidateKey, retainedBallotRecords } from './ballot.js';
import {
    concatenate,
    equalBytes,
    hexadecimal,
    readUnsigned32,
    unsigned32,
} from './bytes.js';
import { completedClosePhase } from './close-state.js';
import {
    closeProposalCandidateKey,
    closureBodyFile,
    closureResponseFile,
    closureSubmissionFile,
    completedCloseRecords,
    heldBallotBody,
    heldResponses,
    heldSubmissions,
    isListedSubmission,
    isResponsePacket,
    proposalResponses,
    responseIdentity,
    responseListing,
    restoreCompletedClose,
} from './close.js';
import type { CloseSession } from './close.js';
import { PublicInputFailure, sessionInput } from './context.js';
import type {
    ProfileContext,
    PublicContext,
    PublicProfileContext,
} from './context.js';
import { contributionRecords } from './contribution.js';
import { openDelivery } from './delivery.js';
import {
    ModuleFailure,
    readKernel,
    ResourceFailure,
    writeBufferInput,
} from './kernel.js';
import type { ParticipantKernel } from './kernel.js';
import {
    createCandidatePublication,
    findCandidate,
    readCandidateFile,
    readCandidates,
    streamCandidateFile,
    transferChunkBytes,
} from './public.js';
import type { CandidateView, PublicRelay } from './public.js';
import { targetPhase } from './root-generation.js';
import { chunkBytes, commitRoot, dataRecordInventory } from './root.js';
import { deliverFinalAggregate, readFinalAggregate } from './setup.js';
import {
    awaitLater,
    evaluatedTargetName,
    namespacedName,
    publicEvaluationName,
} from './storage.js';
import {
    ballotStatuses,
    decodeTargetState,
    encodeTargetState,
} from './target-state.js';
import type { TargetState } from './target-state.js';

// A participant's target signing. It verifies the organizer's close barrier
// from the public close records, classifies each usable ballot, evaluates
// the public ranking target and retains the exact target body and the own
// ballot's status in it before its target vote
// exists. An interrupted signing
// evaluates again and must reproduce the retained body. The values the
// evaluation spills and the records of its keys are public work in their own
// database, which each evaluation clears first; the engine checks every value
// and record it reads back.
// The evaluated target, keyed to the credential, lives in another database
// of the participant's origin, from which release and result restore it
// instead of evaluating again; a missing or refused copy only means
// evaluating again. A verifier without participant state verifies the
// barrier, classifies and evaluates from the public records alone, in its
// own working storage, and retains nothing.

const unusedWord = 0xff_ff_ff_ff;
export const targetVoteCandidateKey = (position: number) =>
    'target-vote-' + String(position);
const evaluationStore = 'values';
const evaluatedTargetStore = 'target';
// The evaluation's working storage keeps each spilled value in chunks of
// whole coefficients within a mebibyte.
const evaluationStoreChunkBytes = 1 << 20;

// The largest input the worker writes at once into the module's close,
// classifier, evaluation and certificate buffers: a relay transfer chunk, a
// retained record chunk, a cached aggregate chunk or an evaluation store
// chunk. Every whole record and concatenation it writes there is smaller at
// every supported profile.
export const largestBufferInputBytes = (kernel: ParticipantKernel) =>
    Math.max(
        transferChunkBytes,
        chunkBytes,
        kernel.setup_chunk_capacity(),
        evaluationStoreChunkBytes,
    );

const words = (bytes: Uint8Array) => {
    if (bytes.length % 4 !== 0)
        throw new Error('The evaluation returned partial words.');
    return Array.from({ length: bytes.length / 4 }, (_unused, index) =>
        readUnsigned32(bytes, 4 * index),
    );
};

// A usable slot's authenticated submission and its envelope identity, which
// addresses its body, and the route of the body copy the barrier accepted,
// or none for this root's custody.
type UsableSlot = Readonly<{
    submission: Uint8Array;
    identity: Uint8Array;
    source?: Readonly<{ candidate: CandidateView; name: string }>;
}>;

// Reads a public record, or undefined when the relay lacks it.
const readCandidate = async (
    relay: PublicRelay,
    candidate: CandidateView,
    name: string,
    maximum: number,
) => {
    try {
        return await readCandidateFile(relay, candidate, name, maximum);
    } catch (error) {
        if (error instanceof PublicInputFailure) return undefined;
        throw error;
    }
};

// The close records a barrier verification reads, beside the copies of
// them that a participant's close log holds, which it takes before their
// public routes. A verifier without participant state holds none.
export type CloseRecordSource = Readonly<{
    context: PublicProfileContext;
    heldResponses: () => Promise<ReadonlyMap<number, Uint8Array>>;
    heldSubmissions: () => Promise<ReadonlyMap<string, Uint8Array>>;
    heldBody: (
        author: number,
        identity: Uint8Array,
    ) => ReturnType<typeof heldBallotBody>;
}>;

const participantCloseRecords = (session: CloseSession): CloseRecordSource => ({
    context: session.participant.context,
    heldResponses: () => heldResponses(session),
    heldSubmissions: () => heldSubmissions(session),
    heldBody: (author, identity) => heldBallotBody(session, author, identity),
});

export const publicCloseRecords = (
    context: PublicProfileContext,
): CloseRecordSource => ({
    context,
    heldResponses: () => Promise.resolve(new Map()),
    heldSubmissions: () => Promise.resolve(new Map()),
    heldBody: () => Promise.resolve(undefined),
});

// Reads a usable body from its held copy, or from a route.
const readBody = async (
    records: CloseRecordSource,
    relay: PublicRelay,
    author: number,
    identity: Uint8Array,
    source: UsableSlot['source'],
    consume: (bytes: Uint8Array) => void | Promise<void>,
) => {
    if (source !== undefined)
        return streamCandidateFile(
            relay,
            source.candidate,
            source.name,
            records.context.profile.ballot.maximumBodyBytes,
            consume,
        );
    const held = await records.heldBody(author, identity);
    if (held === undefined) throw new Error('The held ballot body is gone.');
    return held(consume);
};

const barrierCommand = (
    context: PublicProfileContext,
    operation: number,
    input: Uint8Array = new Uint8Array(),
) => {
    const { kernel } = context;
    writeBufferInput(kernel, 'close', input);
    return kernel.close_command(operation, input.length) === 0;
};

const requireBarrier = (
    context: PublicProfileContext,
    operation: number,
    input: Uint8Array,
    reason: string,
) => {
    if (!barrierCommand(context, operation, input))
        throw new PublicInputFailure(reason);
};

// The response a proposal names: from its held copy, the organizer's
// closure or the responder's own route, the first copy whose body has the
// named identity.
const namedResponse = async (
    context: PublicProfileContext,
    relay: PublicRelay,
    held: ReadonlyMap<number, Uint8Array>,
    responder: number,
    identity: Uint8Array,
    publication: CandidateView,
) => {
    const { profile } = context;
    const maximum =
        4 +
        profile.close.maximumResponseBodyBytes +
        profile.registration.signatureBytes;
    for (const candidate of [
        () => Promise.resolve(held.get(responder)),
        () =>
            readCandidate(
                relay,
                publication,
                closureResponseFile(identity),
                maximum,
            ),
    ]) {
        const response = await candidate();
        if (
            response !== undefined &&
            isResponsePacket(profile, response) &&
            equalBytes(responseIdentity(context, response), identity)
        )
            return response;
    }
    throw new PublicInputFailure('A named close response is unavailable.');
};

// An envelope a named response lists, with its signature: from its held
// copy, the organizer's closure or the author's own route, the first copy of
// that author's envelope with the listed identity.
const listedSubmission = async (
    context: PublicProfileContext,
    relay: PublicRelay,
    held: ReadonlyMap<string, Uint8Array>,
    author: number,
    identity: Uint8Array,
    publication: CandidateView,
) => {
    const { profile } = context;
    for (const candidate of [
        () => Promise.resolve(held.get(hexadecimal(identity))),
        () =>
            readCandidate(
                relay,
                publication,
                closureSubmissionFile(identity),
                profile.close.submissionBytes,
            ),
    ]) {
        const submission = await candidate();
        if (
            submission !== undefined &&
            isListedSubmission(context, submission, author, identity)
        )
            return submission;
    }
    throw new PublicInputFailure('A listed envelope is unavailable.');
};

// Authenticates a usable slot's body from its held copy, the organizer's
// closure or the author's own route, restarting the body verifier after a
// refused or interrupted copy. Returns the accepted copy's route, or none
// for the held copy.
const verifyUsableBody = async (
    records: CloseRecordSource,
    relay: PublicRelay,
    author: number,
    identity: Uint8Array,
    publication: CandidateView,
) => {
    const { context } = records;
    const sources = async function* () {
        if ((await records.heldBody(author, identity)) !== undefined)
            yield undefined;
        yield { candidate: publication, name: closureBodyFile(identity) };
        for await (const candidate of readCandidates(
            relay,
            ballotCandidateKey(author),
        ))
            yield { candidate, name: 'body.bin' };
    };
    for await (const source of sources()) {
        requireBarrier(context, 4, identity, 'A usable body was refused.');
        try {
            await readBody(
                records,
                relay,
                author,
                identity,
                source,
                (bytes) => {
                    requireBarrier(
                        context,
                        5,
                        bytes,
                        'A usable body was refused.',
                    );
                },
            );
            if (barrierCommand(context, 6)) return source;
        } catch (error) {
            if (!(error instanceof PublicInputFailure)) throw error;
        }
        barrierCommand(context, 10);
    }
    throw new PublicInputFailure('A usable body was refused.');
};

// Verifies the organizer's close barrier from the close records: the intent,
// the proposal's named responses with every envelope they list, and the body
// of each usable slot, each record from its held copy, the organizer's
// closure or its author's route. Returns each usable slot by its author.
const verifyCloseBarrier = async (
    records: CloseRecordSource,
    relay: PublicRelay,
) => {
    const { context } = records;
    const { profile, kernel } = context;
    const { close, registration } = profile;
    const { signatureBytes } = registration;
    return findCandidate(
        relay,
        closeProposalCandidateKey,
        async (publication) => {
            if (!barrierCommand(context, 1))
                throw new Error('The close verifier has no verified setup.');
            requireBarrier(
                context,
                2,
                await readCandidateFile(
                    relay,
                    publication,
                    'intent.bin',
                    4 + close.intentBodyBytes + signatureBytes,
                ),
                'The close intent was refused.',
            );
            const proposal = await readCandidateFile(
                relay,
                publication,
                'proposal.bin',
                4 + close.proposalBodyBytes + signatureBytes,
            );
            if (
                proposal.length !==
                4 + close.proposalBodyBytes + signatureBytes
            )
                throw new PublicInputFailure(
                    'The close proposal is incomplete.',
                );
            const responses = await records.heldResponses();
            const submissions = await records.heldSubmissions();
            const listed = new Map<
                string,
                { author: number; submission: Uint8Array }
            >();
            for (const { responder, identity } of proposalResponses(
                profile,
                proposal,
            )) {
                const response = await namedResponse(
                    context,
                    relay,
                    responses,
                    responder,
                    identity,
                    publication,
                );
                for (const entry of responseListing(profile, response)) {
                    const key = hexadecimal(entry.identity);
                    if (listed.has(key)) continue;
                    const submission = await listedSubmission(
                        context,
                        relay,
                        submissions,
                        entry.author,
                        entry.identity,
                        publication,
                    );
                    requireBarrier(
                        context,
                        3,
                        submission,
                        'A listed envelope was refused.',
                    );
                    listed.set(key, { author: entry.author, submission });
                }
                requireBarrier(
                    context,
                    7,
                    response,
                    'A close response was refused.',
                );
            }
            // Before any body is delivered, the usable-slot bodies the proposal still
            // needs are all of them.
            requireBarrier(
                context,
                8,
                proposal,
                'The close proposal was refused.',
            );
            const missing = readKernel(
                kernel,
                kernel.close_missing_pointer(),
                kernel.close_missing_count() * 64,
            );
            const usable = new Map<number, UsableSlot>();
            for (let offset = 0; offset < missing.length; offset += 64) {
                const identity = missing.subarray(offset, offset + 64);
                const slot = listed.get(hexadecimal(identity));
                if (slot === undefined)
                    throw new Error(
                        'The close verifier needs an unlisted body.',
                    );
                usable.set(slot.author, {
                    submission: slot.submission,
                    identity: identity.slice(),
                    source: await verifyUsableBody(
                        records,
                        relay,
                        slot.author,
                        identity,
                        publication,
                    ),
                });
            }
            requireBarrier(
                context,
                9,
                proposal,
                'The close barrier was refused.',
            );
            return usable;
        },
    );
};

const classifierInput = (context: PublicProfileContext, bytes: Uint8Array) => {
    const { kernel } = context;
    writeBufferInput(kernel, 'ballotBody', bytes);
    return bytes.length;
};

// Starts the owning signed-ballot classifier on a usable submission and its
// body header, and delivers its FHE key from the verified aggregate when
// the body relation needs it. The module derives the fixed auxiliary pair.
const beginClassification = async (
    context: PublicProfileContext,
    submission: Uint8Array,
    header: Uint8Array,
) => {
    const { kernel } = context;
    if (
        kernel.ballot_classification_begin(
            classifierInput(context, concatenate(submission, header)),
        ) !== 0
    )
        throw new PublicInputFailure('A usable ballot was refused.');
    if (kernel.ballot_classification_requires_key() === 1) {
        const index = kernel.ballot_classification_key_index() >>> 0;
        if (
            index === unusedWord ||
            kernel.ballot_classification_key_begin(index) !== 0
        )
            throw new Error('The ballot classifier refused its key.');
        await deliverFinalAggregate(context, async () => {
            await readFinalAggregate(context, index, (_offset, bytes) => {
                if (
                    kernel.ballot_classification_key_chunk(
                        classifierInput(context, bytes),
                    ) !== 0
                )
                    throw new PublicInputFailure('A ballot key was refused.');
            });
            if (kernel.ballot_classification_key_finish() !== 0)
                throw new PublicInputFailure('A ballot key was refused.');
        });
    }
};

// Classifies one usable ballot as valid or invalid. The body must be the one
// the barrier authenticated, or the classifier refuses it.
const classifyBallot = async (
    records: CloseRecordSource,
    relay: PublicRelay,
    author: number,
    slot: UsableSlot,
) => {
    const { context } = records;
    const { kernel, profile } = context;
    const { headerBytes } = profile.ballot;
    let header: Uint8Array = new Uint8Array();
    await readBody(
        records,
        relay,
        author,
        slot.identity,
        slot.source,
        async (bytes) => {
            let rest = bytes;
            if (header.length < headerBytes) {
                const taken = rest.subarray(0, headerBytes - header.length);
                header = concatenate(header, taken);
                rest = rest.subarray(taken.length);
                if (header.length < headerBytes) return;
                await beginClassification(context, slot.submission, header);
            }
            if (
                rest.length > 0 &&
                kernel.ballot_classification_chunk(
                    classifierInput(context, rest),
                ) !== 0
            )
                throw new PublicInputFailure('A usable ballot was refused.');
        },
    );
    const classification =
        header.length === headerBytes
            ? kernel.ballot_classification_finish()
            : 0;
    if (classification === 0)
        throw new PublicInputFailure('A usable ballot changed.');
    return classification === 1;
};

const tryEvaluationCommand = (
    context: PublicProfileContext,
    operation: number,
    argument = 0,
    input: Uint8Array = new Uint8Array(),
) => {
    const { kernel } = context;
    writeBufferInput(kernel, 'evaluationTarget', input);
    if (
        kernel.evaluation_target_command(operation, argument, input.length) !==
        0
    )
        return undefined;
    return readKernel(
        kernel,
        kernel.evaluation_target_output_pointer(),
        kernel.evaluation_target_output_length(),
    );
};

const evaluationCommand = (
    context: PublicProfileContext,
    operation: number,
    argument = 0,
    input: Uint8Array = new Uint8Array(),
) => {
    const output = tryEvaluationCommand(context, operation, argument, input);
    if (output === undefined)
        throw new Error(
            'The evaluation refused operation ' + String(operation) + '.',
        );
    return output;
};

// Delivers one incoming evaluation input in chunks and finishes it. A refusal
// means the bytes are not the ones the engine expects.
const deliverEvaluationInput = async (
    context: PublicProfileContext,
    produce: (accept: (bytes: Uint8Array) => void) => Promise<unknown>,
    reason: string,
) => {
    await produce((bytes) => {
        if (tryEvaluationCommand(context, 12, 0, bytes) === undefined)
            throw new PublicInputFailure(reason);
    });
    if (tryEvaluationCommand(context, 13) === undefined)
        throw new PublicInputFailure(reason);
};

const request = <Value>(value: IDBRequest<Value>) =>
    new Promise<Value>((resolve, reject) => {
        value.onsuccess = () => resolve(value.result);
        value.onerror = () =>
            reject(new PublicInputFailure('The evaluation storage failed.'));
    });

const completion = (transaction: IDBTransaction) =>
    new Promise<void>((resolve, reject) => {
        transaction.oncomplete = () => resolve();
        transaction.onabort = () =>
            reject(new PublicInputFailure('The evaluation storage failed.'));
    });

const openEvaluationStorage = async (namespace: string) => {
    const opened = indexedDB.open(
        namespacedName(publicEvaluationName, namespace),
        1,
    );
    opened.onupgradeneeded = () =>
        opened.result.createObjectStore(evaluationStore);
    return request(opened);
};

// Writes the evaluation's public work in one transaction, which a write that
// throws aborts.
const writeEvaluationStorage = async (
    storage: IDBDatabase,
    write: (store: IDBObjectStore) => void,
) => {
    const transaction = storage.transaction(evaluationStore, 'readwrite');
    const done = completion(transaction);
    try {
        write(transaction.objectStore(evaluationStore));
    } catch (error) {
        done.catch(() => undefined);
        transaction.abort();
        throw error;
    }
    await done;
};

// Runs one request on the evaluated-target store in its own transaction.
const evaluatedTargetRequest = async <Value>(
    namespace: string,
    mode: IDBTransactionMode,
    run: (store: IDBObjectStore) => IDBRequest<Value>,
) => {
    const opened = indexedDB.open(
        namespacedName(evaluatedTargetName, namespace),
        1,
    );
    opened.onupgradeneeded = () =>
        opened.result.createObjectStore(evaluatedTargetStore);
    const database = await request(opened);
    try {
        const transaction = database.transaction(evaluatedTargetStore, mode);
        // Observe completion before creating the request: a synchronous
        // factory failure can still be followed by a transaction abort.
        const done = awaitLater(completion(transaction));
        const [value] = await Promise.all([
            request(run(transaction.objectStore(evaluatedTargetStore))),
            done,
        ]);
        return value;
    } finally {
        database.close();
    }
};

// Retains the target this instance evaluated, keyed to the credential.
export const retainEvaluation = async (context: ProfileContext) => {
    const { kernel } = context;
    if (kernel.retain_evaluation() !== 0)
        throw new Error('The credential refused the evaluated target.');
    const pointer = kernel.contribution_output_pointer() >>> 0;
    const length = kernel.contribution_output_length();
    const parts: Blob[] = [];
    for (let offset = 0; offset < length; offset += chunkBytes)
        // Blob snapshots this bounded view synchronously. No Wasm call or
        // awaited work changes the encoded target while its parts are copied.
        parts.push(
            new Blob([
                new Uint8Array(
                    kernel.memory.buffer,
                    pointer + offset,
                    Math.min(chunkBytes, length - offset),
                ),
            ]),
        );
    const copy = new Blob(parts);
    parts.length = 0;
    await evaluatedTargetRequest(context.namespace, 'readwrite', (store) =>
        store.put(copy, 0),
    );
};

// Discards the retained evaluated target, so that the next visit evaluates
// the target again.
export const discardEvaluation = async (context: PublicContext) => {
    await evaluatedTargetRequest(context.namespace, 'readwrite', (store) =>
        store.clear(),
    );
};

// Restores the target this participant evaluated earlier from its retained
// copy, for the verified setup live in this instance. A copy that cannot be
// read, that the module refuses or on which the module fails is discarded,
// so a later visit evaluates the target again. Returns whether the target
// was restored.
export const restoreEvaluation = async (context: ProfileContext) => {
    try {
        return await restoreEvaluationCopy(context);
    } catch (error) {
        if (error instanceof ModuleFailure)
            // A public-cache cleanup failure cannot turn a terminal module
            // failure into a different local-state outcome.
            await discardEvaluation(context).catch(() => undefined);
        throw error;
    }
};

const restoreEvaluationCopy = async (context: ProfileContext) => {
    const value = await evaluatedTargetRequest<unknown>(
        context.namespace,
        'readonly',
        (store) => store.get(0),
    );
    if (!(value instanceof Blob)) return false;
    const length = value.size;
    // Wasm usize is u32. A wider host length must not wrap into a valid
    // profile-sized allocation before the owning Rust bound is checked.
    if (!Number.isSafeInteger(length) || length < 0 || length > 0xffff_ffff) {
        await discardEvaluation(context);
        return false;
    }
    // The module bounds the copy's length before any of it is read, and its
    // last step ends the copy it began whether or not the copy restores.
    const { kernel } = context;
    let restored = kernel.restore_evaluation(0, length) === 0;
    if (restored) {
        let terminal = false;
        try {
            for (
                let offset = 0;
                restored && offset < length;
                offset += chunkBytes
            ) {
                // Every slice belongs to the immutable Blob snapshot read
                // above, even if another connection replaces its stored key.
                const buffer = await value
                    .slice(offset, offset + chunkBytes)
                    .arrayBuffer()
                    .catch((error: unknown) => {
                        if (
                            error instanceof ModuleFailure ||
                            error instanceof ResourceFailure
                        )
                            throw error;
                        return undefined;
                    });
                if (buffer === undefined) {
                    restored = false;
                    break;
                }
                const chunk = new Uint8Array(buffer);
                sessionInput(context, chunk);
                restored = kernel.restore_evaluation(1, chunk.length) === 0;
            }
        } catch (error) {
            terminal =
                error instanceof ModuleFailure ||
                error instanceof ResourceFailure;
            throw error;
        } finally {
            // Finish consumes an incomplete copy too. Terminally failed
            // instances cannot be entered again, including for cleanup.
            if (!terminal)
                restored = kernel.restore_evaluation(2, 0) === 0 && restored;
        }
    }
    if (!restored) await discardEvaluation(context);
    return restored;
};

// The stored blobs of the keys, in one transaction.
const readStoredBlobs = async (
    storage: IDBDatabase,
    keys: readonly IDBValidKey[],
) => {
    const transaction = storage.transaction(evaluationStore, 'readonly');
    const done = completion(transaction);
    const store = transaction.objectStore(evaluationStore);
    const values = await Promise.all(
        keys.map((key) => request<unknown>(store.get(key))),
    );
    await done;
    return values;
};

// A key's record modulo a prime sorts after every stored value's chunk.
const keyRecord = (ordinal: number, prime: number) => ['key', ordinal, prime];

// The stored records modulo a prime of the keys from the first ordinal, in
// one transaction.
const readStoredRecords = async (
    storage: IDBDatabase,
    first: number,
    count: number,
    prime: number,
    inputCapacity: number,
) => {
    const values = await readStoredBlobs(
        storage,
        Array.from({ length: count }, (_unused, index) =>
            keyRecord(first + index, prime),
        ),
    );
    return Promise.all(
        values.map(async (value) => {
            if (!(value instanceof Blob) || 4 + value.size > inputCapacity)
                throw new PublicInputFailure(
                    'A stored evaluation key is missing.',
                );
            return new Uint8Array(await value.arrayBuffer());
        }),
    );
};

// Runs the public ranking evaluation from the closed inventory. The engine
// names each step's keys, ballot input, and values to spill or reload; a
// spilled value is read back through the engine before it leaves memory. A
// ballot input is the body of the barrier's usable slot of its author. Each
// loaded key leaves its records in storage, and a product or rotation
// requests them back one key group and prime at a time.
const evaluate = async (
    source: CloseRecordSource,
    relay: PublicRelay,
    usable: ReadonlyMap<number, UsableSlot>,
) => {
    const { context } = source;
    const { kernel, profile } = context;
    const { polynomialDegree, storedCoefficientBytes } = profile.evaluation;
    const coefficients = 2 * polynomialDegree;
    const inputCapacity = kernel.evaluation_target_input_capacity();
    const chunkCoefficients = Math.floor(
        evaluationStoreChunkBytes / storedCoefficientBytes,
    );
    const chunks = (node: number) =>
        Array.from(
            { length: Math.ceil(coefficients / chunkCoefficients) },
            (_unused, index) => {
                const offset = index * chunkCoefficients;
                return {
                    node,
                    offset,
                    count: Math.min(chunkCoefficients, coefficients - offset),
                };
            },
        );
    const storage = await openEvaluationStorage(context.namespace);
    try {
        await writeEvaluationStorage(storage, (store) => store.clear());
        // Delivers a stored value's chunks, whose blobs one transaction
        // finds, reading one chunk's bytes at a time.
        const deliverStored = (operation: number, node: number) => {
            evaluationCommand(context, operation, node);
            return deliverEvaluationInput(
                context,
                async (accept) => {
                    const valueChunks = chunks(node);
                    const blobs = await readStoredBlobs(
                        storage,
                        valueChunks.map((chunk) => [chunk.node, chunk.offset]),
                    );
                    for (const [index, chunk] of valueChunks.entries()) {
                        const blob = blobs[index];
                        if (
                            !(blob instanceof Blob) ||
                            blob.size !== chunk.count * storedCoefficientBytes
                        )
                            throw new PublicInputFailure(
                                'A stored evaluation value is missing.',
                            );
                        accept(new Uint8Array(await blob.arrayBuffer()));
                    }
                },
                'A stored evaluation value changed.',
            );
        };
        // Stores the records of the key just loaded, which the module hands
        // over one prime at a time.
        const storeKeyRecords = async (ordinal: number) => {
            const records: Uint8Array[] = [];
            for (
                let output = evaluationCommand(context, 22);
                output.length > 0;
                output = evaluationCommand(context, 22)
            )
                records.push(output);
            await writeEvaluationStorage(storage, (store) => {
                for (const output of records)
                    store.put(
                        new Blob([output.slice(4)]),
                        keyRecord(ordinal, readUnsigned32(output, 0)),
                    );
            });
        };
        // The values spilled and not yet retired, whose chunks storage holds.
        const spilled = new Set<number>();
        evaluationCommand(context, 2);
        while (
            kernel.evaluation_target_body_length() === 0 &&
            kernel.evaluation_target_finished() !== 1
        ) {
            const required = words(evaluationCommand(context, 10));
            const [, loaded, keyCount, spillCount, reloadCount, author] =
                required;
            if (required.length !== 7 + spillCount + reloadCount)
                throw new Error('The evaluation requirements are malformed.');
            for (const node of required.slice(7, 7 + spillCount)) {
                spilled.add(node);
                await writeEvaluationStorage(storage, (store) => {
                    for (const chunk of chunks(node)) {
                        const bytes = evaluationCommand(
                            context,
                            16,
                            node,
                            concatenate(
                                unsigned32(chunk.offset),
                                unsigned32(chunk.count),
                            ),
                        );
                        if (
                            bytes.length !==
                            chunk.count * storedCoefficientBytes
                        )
                            throw new Error(
                                'An evaluation spill is incomplete.',
                            );
                        store.put(new Blob([new Uint8Array(bytes)]), [
                            node,
                            chunk.offset,
                        ]);
                    }
                });
                await deliverStored(17, node);
            }
            for (const node of required.slice(7 + spillCount))
                await deliverStored(18, node);
            // A new cache replaces the earlier cache's records.
            if (loaded === 0 && keyCount > 0)
                await writeEvaluationStorage(storage, (store) =>
                    store.delete(IDBKeyRange.bound(['key'], ['key', []])),
                );
            for (let ordinal = loaded; ordinal < keyCount; ordinal++) {
                const [index] = words(evaluationCommand(context, 11));
                if (index !== unusedWord)
                    await deliverFinalAggregate(context, () =>
                        deliverEvaluationInput(
                            context,
                            (accept) =>
                                readFinalAggregate(
                                    context,
                                    index,
                                    (_offset, bytes) => accept(bytes),
                                ),
                            'An evaluation key was refused.',
                        ),
                    );
                await storeKeyRecords(ordinal);
            }
            if (author !== unusedWord) {
                const [length] = words(evaluationCommand(context, 14, author));
                const slot = usable.get(author);
                if (length > 0 && slot === undefined)
                    throw new Error('The evaluation needs an unusable ballot.');
                if (length > 0 && slot !== undefined)
                    await deliverEvaluationInput(
                        context,
                        (accept) =>
                            readBody(
                                source,
                                relay,
                                author,
                                slot.identity,
                                slot.source,
                                accept,
                            ),
                        'An accepted ballot changed.',
                    );
            }
            // The step ends with the values whose last use it was, or asks
            // for key records first, naming the requests that follow, whose
            // records are read while earlier ones are delivered and while a
            // helper's job the step awaits runs.
            const ahead = new Map<string, Promise<Uint8Array[]>>();
            for (;;) {
                const [status, ...rest] = words(evaluationCommand(context, 15));
                if (status === 0) {
                    // Only a value spilled earlier leaves records to delete.
                    const retired = rest.filter((node) => spilled.delete(node));
                    if (retired.length > 0)
                        await writeEvaluationStorage(storage, (store) => {
                            for (const node of retired)
                                store.delete(
                                    IDBKeyRange.bound(
                                        [node],
                                        [node + 1],
                                        false,
                                        true,
                                    ),
                                );
                        });
                    break;
                }
                if (status === 2)
                    throw new PublicInputFailure(
                        'A stored evaluation key changed.',
                    );
                if (status === 3) {
                    if (rest.length !== 1)
                        throw new Error('The evaluation step is malformed.');
                    await context.parallel.whenEnded(rest[0]);
                    continue;
                }
                if (status !== 1 || rest.length === 0 || rest.length % 3 !== 0)
                    throw new Error('The evaluation step is malformed.');
                const requests = Array.from(
                    { length: rest.length / 3 },
                    (_unused, index) => rest.slice(3 * index, 3 * index + 3),
                );
                const read = ([first, count, prime]: readonly number[]) => {
                    const records = readStoredRecords(
                        storage,
                        first,
                        count,
                        prime,
                        inputCapacity,
                    );
                    // A read that no request takes fails silently.
                    records.catch(() => undefined);
                    return records;
                };
                const pending =
                    ahead.get(requests[0].join()) ?? read(requests[0]);
                const named = new Map(
                    requests.slice(1).map((following) => {
                        const key = following.join();
                        return [
                            key,
                            ahead.get(key) ?? read(following),
                        ] as const;
                    }),
                );
                ahead.clear();
                for (const [key, records] of named) ahead.set(key, records);
                const [[first, count, prime]] = requests;
                const records = await pending;
                // With helpers, the records go to the helpers' shared memory
                // at once rather than through the module's.
                if (context.parallel.count > 0) {
                    const length = records.reduce(
                        (sum, record) => sum + record.length,
                        0,
                    );
                    const handle = context.parallel.shareRecords(records);
                    if (
                        tryEvaluationCommand(
                            context,
                            23,
                            handle,
                            concatenate(
                                ...[first, count, prime, length].map((value) =>
                                    unsigned32(value),
                                ),
                            ),
                        ) === undefined
                    )
                        throw new PublicInputFailure(
                            'A stored evaluation key changed.',
                        );
                } else
                    for (const [index, record] of records.entries())
                        if (
                            tryEvaluationCommand(
                                context,
                                21,
                                first + index,
                                concatenate(unsigned32(prime), record),
                            ) === undefined
                        )
                            throw new PublicInputFailure(
                                'A stored evaluation key changed.',
                            );
            }
        }
        if (kernel.evaluation_target_body_length() === 0)
            evaluationCommand(context, 19);
        await writeEvaluationStorage(storage, (store) => store.clear());
    } finally {
        storage.close();
    }
    return readKernel(
        kernel,
        kernel.evaluation_target_body_pointer(),
        kernel.evaluation_target_body_length(),
    );
};

const finalityCommand = (
    context: ProfileContext,
    operation: number,
    input: Uint8Array = new Uint8Array(),
) => {
    const { kernel } = context;
    sessionInput(context, input);
    if (kernel.participant_finality_command(operation, input.length) !== 0)
        throw new Error(
            'The finality work refused operation ' + String(operation) + '.',
        );
    return readKernel(
        kernel,
        kernel.contribution_output_pointer(),
        kernel.contribution_output_length(),
    );
};

// The own ballot's status in the target this instance certified, which the
// finality work reads for a participant that signed no target of its own.
export const certifiedBallotStatus = (context: ProfileContext) => {
    const output = finalityCommand(context, 3);
    if (output.length !== 1 || output[0] >= ballotStatuses.length)
        throw new Error('The finality work reported no ballot status.');
    return ballotStatuses[output[0]];
};

// The retained target signing state, or undefined before it begins.
export const resumeTarget = (close: CloseSession): TargetState | undefined => {
    const { root, context } = close.participant;
    if (root.head.generation < targetPhase.intent) return undefined;
    const bytes = root.manifest.suffixes.target;
    if (bytes === undefined) throw new Error('No target state is retained.');
    return decodeTargetState(
        context.profile,
        root.head.generation,
        close.organizer,
        bytes,
    );
};

const commitTarget = async (
    close: CloseSession,
    generation: number,
    state: TargetState,
) => {
    const { participant } = close;
    const { context, root } = participant;
    const encoded = encodeTargetState(generation, state);
    if (encoded.length > context.profile.target.maximumStateBytes)
        throw new Error('The target state exceeds its bound.');
    participant.root = await commitRoot(context, root, {
        generation,
        manifest: {
            ...root.manifest,
            suffixes: { ...root.manifest.suffixes, target: encoded },
        },
        predecessorRecords: [
            ...dataRecordInventory(root.manifest),
            ...contributionRecords(participant),
            ...retainedBallotRecords(participant, close.records),
            ...completedCloseRecords(close),
        ],
    });
};

// Verifies the close barrier, classifies each usable ballot and evaluates
// the target in this instance. Returns the target body, how many slots were
// usable and how many usable ballots were valid. The owning setup verifier
// must have verified the complete setup in this instance first, and a
// participant must have restored its completed close.
export const evaluateClosedTarget = async (
    records: CloseRecordSource,
    relay: PublicRelay,
) => {
    const { context } = records;
    const usable = await verifyCloseBarrier(records, relay);
    evaluationCommand(context, 0);
    let validBallots = 0;
    for (let author = 0; author < context.profile.participantCount; author++) {
        const slot = usable.get(author);
        if (
            slot !== undefined &&
            (await classifyBallot(records, relay, author, slot))
        )
            validBallots++;
        // Each slot takes the classification just made, or none.
        evaluationCommand(context, 1);
    }
    return {
        body: await evaluate(records, relay, usable),
        usableBallots: usable.size,
        validBallots,
    };
};

// Ends a worker whose operation retained the target it evaluated before its
// other work, so that a fresh worker restores it for the rest of the
// operation.
export class EvaluationRetained extends Error {}

// The target this participant evaluated earlier, restored from its retained
// copy, or else the target evaluated now from the public close records and
// retained, which ends a separately evaluating worker. The completed close
// and the verified setup must be restored in this instance first. Returns
// the target body and whether it was restored.
export const restoreOrEvaluateTarget = async (
    close: CloseSession,
    relay: PublicRelay,
) => {
    const { context } = close.participant;
    if (await restoreEvaluation(context)) {
        const { kernel } = context;
        return {
            body: readKernel(
                kernel,
                kernel.evaluation_target_body_pointer(),
                kernel.evaluation_target_body_length(),
            ),
            restored: true,
        };
    }
    const { body } = await evaluateClosedTarget(
        participantCloseRecords(close),
        relay,
    );
    await retainEvaluation(context);
    if (context.separateEvaluation)
        throw new EvaluationRetained('The evaluated target is retained.');
    return { body, restored: false };
};

// Evaluates the target from the public close records and signs this
// participant's target vote. The owning setup verifier must have verified
// the complete setup in this instance first. The signing state retains the
// own ballot's status in the target. Returns how many slots were usable and
// how many usable ballots were valid.
export const signTarget = async (close: CloseSession, relay: PublicRelay) => {
    const { participant } = close;
    const { context } = participant;
    await restoreCompletedClose(close);
    const { body, usableBallots, validBallots } = await evaluateClosedTarget(
        participantCloseRecords(close),
        relay,
    );
    await retainEvaluation(context);
    const finality = finalityCommand(context, 0);
    if (!equalBytes(finality.subarray(1), body))
        throw new Error('The finality work names another target.');
    const code = finality[0];
    if (code >= ballotStatuses.length)
        throw new Error('The finality work reported no ballot status.');
    const ballotStatus = ballotStatuses[code];
    let state = resumeTarget(close);
    if (state === undefined) {
        state = {
            predecessor: completedClosePhase(close.organizer),
            ballotStatus,
            body,

            vote: new Uint8Array(),
        };
        await commitTarget(close, targetPhase.intent, state);
    } else if (!equalBytes(state.body, body))
        throw new PublicInputFailure(
            'The public close records name another target.',
        );
    else if (state.ballotStatus !== ballotStatus)
        throw new Error('The finality work reported another ballot status.');
    const vote = finalityCommand(context, 1, state.body);
    await commitTarget(close, targetPhase.signed, {
        ...state,

        vote,
    });
    return { usableBallots, validBallots };
};

// Delivers the signed target vote, and the organizer the target body,
// inspecting the retained authority around every transfer.
export const publishTarget = async (
    close: CloseSession,
    relay: PublicRelay,
) => {
    const state = resumeTarget(close);
    const { context, root } = close.participant;
    if (state === undefined || root.head.generation < targetPhase.signed)
        return;
    const delivery = await openDelivery(context, root);
    const publication = createCandidatePublication(
        relay,
        targetVoteCandidateKey(close.records.position),
        delivery,
    );
    await publication.addBytes('vote.bin', state.vote);
    if (close.organizer) await publication.addBytes('target.bin', state.body);
    await publication.finish();
};
