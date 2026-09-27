import {
    concatenate,
    equalBytes,
    readUnsigned32,
    unsigned16,
    unsigned32,
} from './bytes.js';
import { collectingCloseState, encodeCloseState } from './close-state.js';
import { isSetupContributor, PublicInputFailure } from './context.js';
import type { ProfileContext } from './context.js';
import {
    contributionDirectory,
    contributionRecords,
    isContributionSession,
    openedInventory,
    polynomialFile,
    readConfirmations,
} from './contribution.js';
import type { ParticipantSession } from './contribution.js';
import { readKernel, writeSetupInput } from './kernel.js';
import { readPublic, streamPublic } from './public.js';
import type { PublicRelay } from './public.js';
import {
    chunkBytes,
    commitRoot,
    dataKind,
    dataRecordInventory,
    readDataKind,
    referenceData,
} from './root.js';
import type { AuthenticatedRoot } from './root.js';
import { proposalRecordIds, streamRegistrations } from './roster.js';
import { awaitLater, namespacedName } from './storage.js';

// Verifies the complete setup from public records in the participant's own
// module: the poll and every registration again, the organizer's proposal
// signature, every participant's confirmation, and every setup contributor's
// opening with its body and proof. A contributor verifies the confirmations
// it opened; any other participant, once its own confirmation is signed,
// first verifies the published ones, which every contributor's opening must
// name, and then retains them. The running
// public aggregate lives in an origin-local cache between contributions, and
// the module checks every chunk it reads back. Only the complete verified
// setup lets the module emit the retained setup reference.

const cacheName = 'sealed-lattice-setup';
const cacheStore = 'aggregate';

const cacheRequest = <Value>(request: IDBRequest<Value>) =>
    new Promise<Value>((resolve, reject) => {
        request.onsuccess = () => resolve(request.result);
        request.onerror = () =>
            reject(request.error ?? new Error('A setup cache request failed.'));
    });

const cacheCompletion = (transaction: IDBTransaction) =>
    new Promise<void>((resolve, reject) => {
        transaction.oncomplete = () => resolve();
        transaction.onabort = () =>
            reject(
                transaction.error ??
                    new Error('A setup cache transaction aborted.'),
            );
    });

// The aggregate cache holds only public bytes; a cache failure leaves the
// participant pending, like any other public input.
const openSetupCache = async (namespace: string) => {
    const opened = indexedDB.open(namespacedName(cacheName, namespace), 1);
    opened.onupgradeneeded = () => opened.result.createObjectStore(cacheStore);
    try {
        return await cacheRequest(opened);
    } catch {
        throw new PublicInputFailure('The setup cache is unavailable.');
    }
};

const writeCache = async (
    cache: IDBDatabase,
    write: (store: IDBObjectStore) => void,
) => {
    try {
        const transaction = cache.transaction(cacheStore, 'readwrite', {
            durability: 'strict',
        });
        const done = cacheCompletion(transaction);
        write(transaction.objectStore(cacheStore));
        await done;
    } catch {
        throw new PublicInputFailure('The setup cache refused a write.');
    }
};

// The chunk capacity of one body polynomial, as setup verification streams
// and caches its aggregate: the whole coefficients that fit the module's
// setup chunk capacity.
const aggregateCapacity = (
    context: ProfileContext,
    polynomial: Readonly<{ bytes: number; coefficients: number }>,
) => {
    const width = polynomial.bytes / polynomial.coefficients;
    return Math.floor(context.kernel.setup_chunk_capacity() / width) * width;
};

// The chunks of an aggregate of the given length: each but the last fills
// the capacity.
type AggregateChunk = Readonly<{ offset: number; length: number }>;
const aggregateChunks = (capacity: number, bytes: number) => {
    const chunks: AggregateChunk[] = [];
    for (let offset = 0; offset < bytes; offset += capacity)
        chunks.push({ offset, length: Math.min(capacity, bytes - offset) });
    return chunks;
};

// Reads one body polynomial's aggregate after the given count of accepted
// contributions, every chunk in one transaction.
const readCachedAggregate = async (
    cache: IDBDatabase,
    accepted: number,
    expandedIndex: number,
    chunks: readonly AggregateChunk[],
) => {
    let values: unknown[];
    try {
        const transaction = cache.transaction(cacheStore, 'readonly');
        const store = transaction.objectStore(cacheStore);
        [values] = await Promise.all([
            Promise.all(
                chunks.map(({ offset }) =>
                    cacheRequest<unknown>(
                        store.get([accepted, expandedIndex, offset]),
                    ),
                ),
            ),
            cacheCompletion(transaction),
        ]);
    } catch {
        throw new PublicInputFailure('The setup cache refused a read.');
    }
    return Promise.all(
        values.map(async (value, index) => {
            if (!(value instanceof Blob) || value.size !== chunks[index].length)
                throw new PublicInputFailure(
                    'A cached aggregate chunk is missing.',
                );
            return new Uint8Array(await value.arrayBuffer());
        }),
    );
};

// Streams the final public aggregate of one body polynomial from the cache
// in the whole-coefficient chunks setup verification wrote. The consumer
// checks the bytes against the retained setup reference.
export const readFinalAggregate = async (
    context: ProfileContext,
    expandedIndex: number,
    consume: (offset: number, bytes: Uint8Array) => void,
) => {
    const { profile } = context;
    const polynomial = profile.contribution.polynomials.find(
        (value) => value.expandedIndex === expandedIndex,
    );
    if (polynomial === undefined)
        throw new Error('No body polynomial has this index.');
    const chunks = aggregateChunks(
        aggregateCapacity(context, polynomial),
        polynomial.bytes,
    );
    const cache = await openSetupCache(context.namespace);
    try {
        const values = await readCachedAggregate(
            cache,
            profile.setupContributorCount - 1,
            expandedIndex,
            chunks,
        );
        for (const [index, { offset }] of chunks.entries())
            consume(offset, values[index]);
    } finally {
        cache.close();
    }
};

// Verifies one opening, streams its body polynomials in whole-coefficient
// chunks against the running aggregate, and then its proof.
const verifyContribution = async (
    context: ProfileContext,
    relay: PublicRelay,
    cache: IDBDatabase,
    position: number,
) => {
    const { kernel, profile } = context;
    const bounds = profile.contribution;
    const directory = contributionDirectory(position);
    const opening = await readPublic(
        relay,
        directory + 'opening.bin',
        bounds.openingBodyBytes,
    );
    const openingSignature = await readPublic(
        relay,
        directory + 'opening-signature.bin',
        profile.registration.signatureBytes,
    );
    const header = await readPublic(
        relay,
        directory + 'body-header.bin',
        bounds.bodyHeaderBytes,
    );
    const proof = await readPublic(
        relay,
        directory + 'proof.bin',
        bounds.maximumProofBytes,
    );
    if (
        header.length !== bounds.bodyHeaderBytes ||
        proof.length < bounds.proofHeaderBytes
    )
        throw new PublicInputFailure('A contribution body is incomplete.');
    const packet = concatenate(
        unsigned32(opening.length),
        opening,
        openingSignature,
    );
    const control = concatenate(
        unsigned32(packet.length),
        packet,
        header,
        proof.subarray(0, bounds.proofHeaderBytes),
    );
    writeSetupInput(kernel, control);
    const accepted = kernel.setup_accepted();
    if (kernel.setup_begin_opening(control.length) !== 0)
        throw new PublicInputFailure('An opening was refused.');
    const chunk = kernel.setup_chunk_capacity();
    // Each polynomial's previous aggregate is read while the polynomial
    // before it is verified, and its new aggregate is written while the one
    // after it is verified. The cache's transactions run in the order they
    // start, so a read follows every write started before it.
    const readPrevious = (index: number) => {
        const polynomial = bounds.polynomials[index];
        return accepted === 0 || polynomial === undefined
            ? undefined
            : awaitLater(
                  readCachedAggregate(
                      cache,
                      accepted - 1,
                      polynomial.expandedIndex,
                      aggregateChunks(
                          aggregateCapacity(context, polynomial),
                          polynomial.bytes,
                      ),
                  ),
              );
    };
    let reading = readPrevious(0);
    let writing: Promise<void> | undefined;
    for (const [index, polynomial] of bounds.polynomials.entries()) {
        const previous = await reading;
        reading = readPrevious(index + 1);
        const capacity = aggregateCapacity(context, polynomial);
        const pending = new Uint8Array(capacity);
        const written: { offset: number; bytes: Uint8Array }[] = [];
        let used = 0;
        let offset = 0;
        const absorb = (incoming: Uint8Array) => {
            const prior =
                previous === undefined
                    ? new Uint8Array(incoming.length)
                    : previous[written.length];
            if (prior?.length !== incoming.length)
                throw new PublicInputFailure(
                    'A cached aggregate chunk is missing.',
                );
            writeSetupInput(kernel, incoming);
            writeSetupInput(kernel, prior, chunk);
            if (
                kernel.setup_polynomial(
                    polynomial.expandedIndex,
                    offset,
                    incoming.length,
                ) !== 0
            )
                throw new PublicInputFailure(
                    'A contribution polynomial was refused.',
                );
            written.push({
                offset,
                bytes: readKernel(
                    kernel,
                    kernel.setup_input_pointer() + chunk,
                    incoming.length,
                ),
            });
            offset += incoming.length;
        };
        await streamPublic(
            relay,
            directory + polynomialFile(polynomial.expandedIndex),
            polynomial.bytes,
            (bytes) => {
                for (let start = 0; start < bytes.length;) {
                    const count = Math.min(
                        bytes.length - start,
                        capacity - used,
                    );
                    pending.set(bytes.subarray(start, start + count), used);
                    start += count;
                    used += count;
                    if (used === capacity) {
                        absorb(pending.subarray(0, used));
                        used = 0;
                    }
                }
            },
        );
        if (used > 0) absorb(pending.subarray(0, used));
        if (offset !== polynomial.bytes)
            throw new PublicInputFailure(
                'A contribution polynomial is incomplete.',
            );
        await writing;
        writing = awaitLater(
            writeCache(cache, (store) => {
                for (const value of written)
                    store.put(new Blob([new Uint8Array(value.bytes)]), [
                        accepted,
                        polynomial.expandedIndex,
                        value.offset,
                    ]);
            }),
        );
    }
    for (let offset = 0; offset < proof.length; offset += chunkBytes) {
        const bytes = proof.subarray(offset, offset + chunkBytes);
        writeSetupInput(kernel, bytes);
        if (kernel.setup_proof(offset, bytes.length) !== 0)
            throw new PublicInputFailure('A contribution proof was refused.');
    }
    await writing;
    if (
        kernel.setup_finish_contribution() !== 1 ||
        kernel.setup_accepted() !== accepted + 1
    )
        throw new PublicInputFailure('A contribution was refused.');
    if (accepted > 0)
        await writeCache(cache, (store) =>
            store.delete(
                IDBKeyRange.bound([accepted - 1], [accepted], false, true),
            ),
        );
};

// The confirmation inventory a verification reads: the participant count
// and every participant's packet. Retained bytes are authenticated state, so
// their refusal stops the participant; published ones leave it pending.
type SetupInventory = Readonly<{ bytes: Uint8Array; retained: boolean }>;

// Verifies the complete setup behind the given confirmations and has the
// original credential emit its retained setup reference. A first
// verification starts from an empty aggregate cache; a later one overwrites
// each chunk in place, so an interrupted verification keeps the final
// aggregate a pending ballot reads.
const verifyCompleteSetup = async (
    session: ParticipantSession,
    relay: PublicRelay,
    clearCache: boolean,
    inventory: SetupInventory,
): Promise<Uint8Array> => {
    const { context } = session;
    const { kernel, profile } = context;
    const { manifest } = session.root;
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
    const recordIds = proposalRecordIds(
        await readDataKind(context, manifest, dataKind.proposal),
    );
    const begin = concatenate(
        manifest.poll,
        context.runtime,
        unsigned16(recordIds.length),
        unsigned32(definition.length),
        definition,
        definitionSignature,
    );
    writeSetupInput(kernel, begin);
    if (kernel.setup_roster_begin(begin.length) !== 0)
        throw new Error('The setup verifier refused the retained poll.');
    await streamRegistrations(
        relay,
        recordIds,
        profile.registration,
        kernel.roster_open_records(),
        (operation, position, bytes) => {
            writeSetupInput(kernel, bytes);
            return (
                kernel.setup_roster_record(
                    operation,
                    position,
                    bytes.length,
                ) === 0
            );
        },
    );
    const proposalSignature = await readDataKind(
        context,
        manifest,
        dataKind.proposalSignature,
    );
    writeSetupInput(kernel, proposalSignature);
    // The retained proposal and signature are authenticated, so a refusal
    // means the relay served other valid registrations under their names.
    if (kernel.setup_roster_finish(proposalSignature.length) !== 1)
        throw new PublicInputFailure(
            'The published registrations are not the retained roster.',
        );
    const refuse = (message: string) =>
        inventory.retained
            ? new Error(message)
            : new PublicInputFailure(message);
    const participants = profile.participantCount;
    const packetBytes = profile.contribution.confirmationPacketBytes;
    if (
        inventory.bytes.length !== profile.root.setupInventoryBytes ||
        readUnsigned32(inventory.bytes, 0) !== participants
    )
        throw refuse('The confirmation inventory is incomplete.');
    for (let position = 0; position < participants; position++) {
        const confirmation = inventory.bytes.subarray(
            4 + position * packetBytes,
            4 + (position + 1) * packetBytes,
        );
        writeSetupInput(kernel, confirmation);
        if (kernel.setup_confirmation(confirmation.length) !== 0)
            throw refuse('The setup verifier refused a confirmation.');
    }
    if (kernel.setup_inventory_finish() !== 1)
        throw refuse('The setup verifier refused the inventory.');
    const cache = await openSetupCache(context.namespace);
    try {
        if (clearCache) await writeCache(cache, (store) => store.clear());
        for (
            let position = 0;
            position < profile.setupContributorCount;
            position++
        )
            await verifyContribution(context, relay, cache, position);
    } finally {
        cache.close();
    }
    if (kernel.setup_finish() !== 1)
        throw new PublicInputFailure('The complete setup was refused.');
    if (kernel.retain_setup() !== 0)
        throw new Error('The credential refused the verified setup.');
    const reference = readKernel(
        kernel,
        kernel.contribution_output_pointer(),
        kernel.contribution_output_length(),
    );
    if (reference.length !== profile.root.setupReferenceBytes)
        throw new Error('The setup reference has another length.');
    return reference;
};

export type VerifiedSetup = Readonly<{
    reference: Uint8Array;
    inventory: Uint8Array;
}>;

// A setup reference names the inventory identity after its marker.
const referenceInventory = (reference: Uint8Array) =>
    reference.subarray(4, 4 + 64);

// Verifies the setup once: a setup contributor behind its opening, any other
// participant behind the published confirmations once its own is signed.
export const verifySetup = async (
    session: ParticipantSession,
    relay: PublicRelay,
): Promise<VerifiedSetup> => {
    if (!isSetupContributor(session.context)) {
        if (session.root.head.generation !== 9)
            throw new Error(
                'No signed roster confirmation awaits setup verification.',
            );
        const inventory = await readConfirmations(session, relay);
        return {
            reference: await verifyCompleteSetup(session, relay, true, {
                bytes: inventory,
                retained: false,
            }),
            inventory,
        };
    }
    if (!isContributionSession(session) || session.root.head.generation !== 11)
        throw new Error('No opened contribution awaits setup verification.');
    const opened = await openedInventory(session);
    const reference = await verifyCompleteSetup(session, relay, true, {
        bytes: opened.inventory,
        retained: true,
    });
    if (!equalBytes(referenceInventory(reference), opened.identity))
        throw new Error(
            'The verified setup differs from the opened inventory.',
        );
    return { reference, inventory: opened.inventory };
};

// Verifies the complete setup again in this instance, from the retained
// confirmation inventory, for work that needs the verified setup itself. It
// must reproduce the retained setup reference.
export const reverifySetup = async (
    session: ParticipantSession,
    relay: PublicRelay,
) => {
    if (session.root.head.generation < 12)
        throw new Error('No setup reference is retained.');
    const { context, root } = session;
    const reference = await verifyCompleteSetup(session, relay, false, {
        bytes: await readDataKind(
            context,
            root.manifest,
            dataKind.setupInventory,
        ),
        retained: true,
    });
    if (
        !equalBytes(
            reference,
            await readDataKind(context, root.manifest, dataKind.setupReference),
        )
    )
        throw new Error('The verified setup differs from the retained one.');
};

// The identity of the confirmation inventory the retained setup names.
export const retainedSetupInventory = async (session: ParticipantSession) =>
    referenceInventory(
        await readDataKind(
            session.context,
            session.root.manifest,
            dataKind.setupReference,
        ),
    ).slice();

// Retains the setup reference and the confirmation inventory it was
// verified against. The ballot suffix starts empty and the close log
// collects from here on; the contribution suffix keeps what it lists.
export const retainSetup = async (
    session: ParticipantSession,
    verified: VerifiedSetup,
): Promise<AuthenticatedRoot> => {
    const { context, root } = session;
    const added = [
        { kind: dataKind.setupReference, bytes: verified.reference },
        { kind: dataKind.setupInventory, bytes: verified.inventory },
    ];
    return commitRoot(context, root, {
        generation: 12,
        manifest: {
            ...root.manifest,
            references: [
                ...root.manifest.references,
                ...referenceData(context, added),
            ],
            suffixes: {
                ...root.manifest.suffixes,
                ballot: new Uint8Array(),
                close: encodeCloseState(12, false, collectingCloseState()),
            },
        },
        predecessorRecords: [
            ...dataRecordInventory(root.manifest),
            ...contributionRecords(session),
        ],
        addedData: added,
    });
};
