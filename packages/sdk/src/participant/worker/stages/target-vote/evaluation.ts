import { writeModuleInput } from '../../module/context.js';
import type {
    ParticipantProfileContext,
    PublicContext,
    PublicProfileContext,
} from '../../module/context.js';
import {
    readModuleMemory,
    writeBufferInput,
} from '../../module/participant-module.js';
import { chunkBytes } from '../../module/runtime-bounds.js';
import type { PublicRelay } from '../../relay/relay.js';
import { concatenate, readUnsigned32, unsigned32 } from '../../shared/bytes.js';
import {
    ModuleFailure,
    PublicInputFailure,
    ResourceFailure,
} from '../../shared/failures.js';
import {
    awaitLater,
    evaluatedTargetName,
    namespacedName,
    publicEvaluationName,
    requestResult,
    transactionCompletion,
} from '../../storage/database.js';
import {
    deliverFinalAggregate,
    readFinalAggregate,
} from '../setup/setup-cache.js';

import {
    CloseRecordSource,
    UsableSlot,
    classifyBallot,
    readBody,
    unusedWord,
    verifyCloseBarrier,
} from './close-barrier.js';

// The public ranking evaluation of a verified close. The values it spills
// and the records of its keys are public work in their own database, which
// each evaluation clears first; the engine checks every value and record it
// reads back. The evaluated target, keyed to the credential, lives in another
// database of the participant's origin, from which release and result
// restore it instead of evaluating again; a missing or refused copy only
// means evaluating again.

const evaluationStore = 'values';

const evaluatedTargetStore = 'target';

// The evaluation's working storage keeps each spilled value in chunks of
// whole coefficients within a mebibyte.
export const evaluationStoreChunkBytes = 1 << 20;

const words = (bytes: Uint8Array) => {
    if (bytes.length % 4 !== 0)
        throw new Error('The evaluation returned partial words.');
    return Array.from({ length: bytes.length / 4 }, (_unused, index) =>
        readUnsigned32(bytes, 4 * index),
    );
};

// The evaluation's operations, as its command numbers them.
const evaluationOperation = {
    begin: 0,
    takeClassification: 1,
    start: 2,
    requirements: 10,
    nextKey: 11,
    // Incoming bytes of a key, ballot input or stored value.
    pushInput: 12,
    finishInput: 13,
    beginBallotInput: 14,
    execute: 15,
    readValue: 16,
    readBack: 17,
    reload: 18,
    finish: 19,
    keyRecord: 21,
    takeKeyRecord: 22,
    sharedKeyRecords: 23,
} as const;

// The steps of restoring a retained evaluated target: begin a copy of its
// length, push its bytes, and finish.
const evaluationRestore = { begin: 0, push: 1, finish: 2 } as const;

const tryEvaluationCommand = (
    context: PublicProfileContext,
    operation: number,
    argument = 0,
    input: Uint8Array = new Uint8Array(),
) => {
    const { module } = context;
    writeBufferInput(module, 'evaluationTarget', input);
    if (
        module.evaluation_target_command(operation, argument, input.length) !==
        0
    )
        return undefined;
    return readModuleMemory(
        module,
        module.evaluation_target_output_pointer(),
        module.evaluation_target_output_length(),
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
        if (
            tryEvaluationCommand(
                context,
                evaluationOperation.pushInput,
                0,
                bytes,
            ) === undefined
        )
            throw new PublicInputFailure(reason);
    });
    if (
        tryEvaluationCommand(context, evaluationOperation.finishInput) ===
        undefined
    )
        throw new PublicInputFailure(reason);
};

// The evaluation storage holds only public work, so its failure leaves the
// participant pending, like any other public input.
const evaluationStorageFailure = () =>
    new PublicInputFailure('The evaluation storage failed.');

const openEvaluationStorage = async (namespace: string) => {
    const opened = indexedDB.open(
        namespacedName(publicEvaluationName, namespace),
        1,
    );
    opened.onupgradeneeded = () =>
        opened.result.createObjectStore(evaluationStore);
    return requestResult(opened, evaluationStorageFailure);
};

// Writes the evaluation's public work in one transaction, which a write that
// throws aborts.
const writeEvaluationStorage = async (
    storage: IDBDatabase,
    write: (store: IDBObjectStore) => void,
) => {
    const transaction = storage.transaction(evaluationStore, 'readwrite');
    const done = transactionCompletion(transaction, evaluationStorageFailure);
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
    const database = await requestResult(opened, evaluationStorageFailure);
    try {
        const transaction = database.transaction(evaluatedTargetStore, mode);
        // Observe completion before creating the request: a synchronous
        // factory failure can still be followed by a transaction abort.
        const done = awaitLater(
            transactionCompletion(transaction, evaluationStorageFailure),
        );
        const [value] = await Promise.all([
            requestResult(
                run(transaction.objectStore(evaluatedTargetStore)),
                evaluationStorageFailure,
            ),
            done,
        ]);
        return value;
    } finally {
        database.close();
    }
};

// Retains the target this instance evaluated, keyed to the credential.
export const retainEvaluation = async (context: ParticipantProfileContext) => {
    const { module } = context;
    if (module.retain_evaluation() !== 0)
        throw new Error('The credential refused the evaluated target.');
    const pointer = module.contribution_output_pointer() >>> 0;
    const length = module.contribution_output_length();
    const parts: Blob[] = [];
    for (let offset = 0; offset < length; offset += chunkBytes)
        // Blob snapshots this bounded view synchronously. No Wasm call or
        // awaited work changes the encoded target while its parts are copied.
        parts.push(
            new Blob([
                new Uint8Array(
                    module.memory.buffer,
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

// Discards the retained evaluated target, so that the next operation evaluates
// the target again.
export const discardEvaluation = async (context: PublicContext) => {
    await evaluatedTargetRequest(context.namespace, 'readwrite', (store) =>
        store.clear(),
    );
};

// Restores the target this participant evaluated earlier from its retained
// copy, for the verified setup live in this instance. A copy that cannot be
// read, that the module refuses or on which the module fails is discarded,
// so a later operation evaluates the target again. Returns whether the target
// was restored.
export const restoreEvaluation = async (context: ParticipantProfileContext) => {
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

const restoreEvaluationCopy = async (context: ParticipantProfileContext) => {
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
    const { module } = context;
    let restored =
        module.restore_evaluation(evaluationRestore.begin, length) === 0;
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
                writeModuleInput(context, chunk);
                restored =
                    module.restore_evaluation(
                        evaluationRestore.push,
                        chunk.length,
                    ) === 0;
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
                restored =
                    module.restore_evaluation(evaluationRestore.finish, 0) ===
                        0 && restored;
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
    const done = transactionCompletion(transaction, evaluationStorageFailure);
    const store = transaction.objectStore(evaluationStore);
    const values = await Promise.all(
        keys.map((key) =>
            requestResult<unknown>(store.get(key), evaluationStorageFailure),
        ),
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
    const { module, profile } = context;
    const { polynomialDegree, storedCoefficientBytes } = profile.evaluation;
    const coefficients = 2 * polynomialDegree;
    const inputCapacity = module.evaluation_target_input_capacity();
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
                let output = evaluationCommand(
                    context,
                    evaluationOperation.takeKeyRecord,
                );
                output.length > 0;
                output = evaluationCommand(
                    context,
                    evaluationOperation.takeKeyRecord,
                )
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
        evaluationCommand(context, evaluationOperation.start);
        while (
            module.evaluation_target_body_length() === 0 &&
            module.evaluation_target_finished() !== 1
        ) {
            const required = words(
                evaluationCommand(context, evaluationOperation.requirements),
            );
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
                            evaluationOperation.readValue,
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
                await deliverStored(evaluationOperation.readBack, node);
            }
            for (const node of required.slice(7 + spillCount))
                await deliverStored(evaluationOperation.reload, node);
            // A new cache replaces the earlier cache's records.
            if (loaded === 0 && keyCount > 0)
                await writeEvaluationStorage(storage, (store) =>
                    store.delete(IDBKeyRange.bound(['key'], ['key', []])),
                );
            for (let ordinal = loaded; ordinal < keyCount; ordinal++) {
                const [index] = words(
                    evaluationCommand(context, evaluationOperation.nextKey),
                );
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
                const [length] = words(
                    evaluationCommand(
                        context,
                        evaluationOperation.beginBallotInput,
                        author,
                    ),
                );
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
                const [status, ...rest] = words(
                    evaluationCommand(context, evaluationOperation.execute),
                );
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
                            evaluationOperation.sharedKeyRecords,
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
                                evaluationOperation.keyRecord,
                                first + index,
                                concatenate(unsigned32(prime), record),
                            ) === undefined
                        )
                            throw new PublicInputFailure(
                                'A stored evaluation key changed.',
                            );
            }
        }
        if (module.evaluation_target_body_length() === 0)
            evaluationCommand(context, evaluationOperation.finish);
        await writeEvaluationStorage(storage, (store) => store.clear());
    } finally {
        storage.close();
    }
    return readModuleMemory(
        module,
        module.evaluation_target_body_pointer(),
        module.evaluation_target_body_length(),
    );
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
    evaluationCommand(context, evaluationOperation.begin);
    let acceptedBallots = 0;
    for (let author = 0; author < context.profile.participantCount; author++) {
        const slot = usable.get(author);
        if (
            slot !== undefined &&
            (await classifyBallot(records, relay, author, slot))
        )
            acceptedBallots++;
        // Each slot takes the classification just made, or none.
        evaluationCommand(context, evaluationOperation.takeClassification);
    }
    return {
        body: await evaluate(records, relay, usable),
        usableSubmissions: usable.size,
        acceptedBallots,
    };
};
