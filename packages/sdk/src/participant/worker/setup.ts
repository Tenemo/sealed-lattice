import { concatenate, equalBytes, unsigned16, unsigned32 } from './bytes.js';
import { collectingCloseState, encodeCloseState } from './close-state.js';
import { PublicInputFailure } from './context.js';
import type { ProfileContext } from './context.js';
import {
    contributionDirectory,
    contributionRecords,
    openedInventory,
    polynomialFile,
} from './contribution.js';
import type { ContributionSession } from './contribution.js';
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
import {
    proposalRecordIds,
    registrationFile,
    registrationPath,
} from './roster.js';
import { namespacedName } from './storage.js';

// Verifies the complete setup from public records in the participant's own
// module: the poll and every registration again, the organizer's proposal
// signature, the confirmations this participant opened, and every opening
// with its body and proof. The running public aggregate lives in an
// origin-local cache between contributions, and the module checks every
// chunk it reads back. Only the complete verified setup lets the module emit
// the retained setup reference.

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

const readCachedChunk = async (
    cache: IDBDatabase,
    key: readonly number[],
    length: number,
) => {
    let value: unknown;
    try {
        const transaction = cache.transaction(cacheStore, 'readonly');
        const done = cacheCompletion(transaction);
        value = await cacheRequest<unknown>(
            transaction.objectStore(cacheStore).get([...key]),
        );
        await done;
    } catch {
        throw new PublicInputFailure('The setup cache refused a read.');
    }
    if (!(value instanceof Blob) || value.size !== length)
        throw new PublicInputFailure('A cached aggregate chunk is missing.');
    return new Uint8Array(await value.arrayBuffer());
};

// Streams the final public aggregate of one body polynomial from the cache
// in the whole-coefficient chunks setup verification wrote. The consumer
// checks the bytes against the retained setup reference.
export const readFinalAggregate = async (
    context: ProfileContext,
    expandedIndex: number,
    consume: (offset: number, bytes: Uint8Array) => void,
) => {
    const { kernel, profile } = context;
    const polynomial = profile.contribution.polynomials.find(
        (value) => value.expandedIndex === expandedIndex,
    );
    if (polynomial === undefined)
        throw new Error('No body polynomial has this index.');
    const width = polynomial.bytes / polynomial.coefficients;
    const capacity = Math.floor(kernel.setup_chunk_capacity() / width) * width;
    const cache = await openSetupCache(context.namespace);
    try {
        for (let offset = 0; offset < polynomial.bytes; offset += capacity)
            consume(
                offset,
                await readCachedChunk(
                    cache,
                    [profile.participantCount - 1, expandedIndex, offset],
                    Math.min(capacity, polynomial.bytes - offset),
                ),
            );
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
    for (const polynomial of bounds.polynomials) {
        const width = polynomial.bytes / polynomial.coefficients;
        const capacity = Math.floor(chunk / width) * width;
        const pending = new Uint8Array(capacity);
        let used = 0;
        let offset = 0;
        const absorb = async (incoming: Uint8Array) => {
            const previous =
                accepted === 0
                    ? new Uint8Array(incoming.length)
                    : await readCachedChunk(
                          cache,
                          [accepted - 1, polynomial.expandedIndex, offset],
                          incoming.length,
                      );
            writeSetupInput(kernel, incoming);
            writeSetupInput(kernel, previous, chunk);
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
            const aggregate = readKernel(
                kernel,
                kernel.setup_input_pointer() + chunk,
                incoming.length,
            );
            await writeCache(cache, (store) =>
                store.put(new Blob([new Uint8Array(aggregate)]), [
                    accepted,
                    polynomial.expandedIndex,
                    offset,
                ]),
            );
            offset += incoming.length;
        };
        await streamPublic(
            relay,
            directory + polynomialFile(polynomial.expandedIndex),
            polynomial.bytes,
            async (bytes) => {
                for (let start = 0; start < bytes.length;) {
                    const count = Math.min(
                        bytes.length - start,
                        capacity - used,
                    );
                    pending.set(bytes.subarray(start, start + count), used);
                    start += count;
                    used += count;
                    if (used === capacity) {
                        await absorb(pending.subarray(0, used));
                        used = 0;
                    }
                }
            },
        );
        if (used > 0) await absorb(pending.subarray(0, used));
        if (offset !== polynomial.bytes)
            throw new PublicInputFailure(
                'A contribution polynomial is incomplete.',
            );
    }
    for (let offset = 0; offset < proof.length; offset += chunkBytes) {
        const bytes = proof.subarray(offset, offset + chunkBytes);
        writeSetupInput(kernel, bytes);
        if (kernel.setup_proof(offset, bytes.length) !== 0)
            throw new PublicInputFailure('A contribution proof was refused.');
    }
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

// Verifies the complete setup behind this participant's opening and has the
// original credential emit its retained setup reference. A first
// verification starts from an empty aggregate cache; a later one overwrites
// each chunk in place, so an interrupted verification keeps the final
// aggregate a pending ballot reads.
const verifyCompleteSetup = async (
    session: ContributionSession,
    relay: PublicRelay,
    clearCache: boolean,
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
    const registration = profile.registration;
    for (const [position, id] of recordIds.entries()) {
        const header = await readPublic(
            relay,
            registrationPath(id, registrationFile.header),
            registration.maximumHeaderBytes,
        );
        const signature = await readPublic(
            relay,
            registrationPath(id, registrationFile.signature),
            registration.signatureBytes,
        );
        const record = concatenate(
            unsigned16(position),
            unsigned32(header.length),
            header,
            signature,
        );
        writeSetupInput(kernel, record);
        if (kernel.setup_roster_record(0, record.length) !== 0)
            throw new PublicInputFailure('A registration header was refused.');
        await streamPublic(
            relay,
            registrationPath(id, registrationFile.publicKey),
            registration.publicKeyBytes,
            (bytes) => {
                writeSetupInput(kernel, bytes);
                if (kernel.setup_roster_record(1, bytes.length) !== 0)
                    throw new PublicInputFailure(
                        'A registration key was refused.',
                    );
            },
        );
        if (kernel.setup_roster_record(2, 0) !== 0)
            throw new PublicInputFailure('A registration key is incomplete.');
        await streamPublic(
            relay,
            registrationPath(id, registrationFile.proof),
            registration.maximumProofBytes,
            (bytes) => {
                writeSetupInput(kernel, bytes);
                if (kernel.setup_roster_record(3, bytes.length) !== 0)
                    throw new PublicInputFailure(
                        'A registration proof was refused.',
                    );
            },
        );
        if (kernel.setup_roster_record(4, 0) !== 0)
            throw new PublicInputFailure('A registration record was refused.');
    }
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
    // The confirmations are the ones this participant's opening signed.
    const opened = await openedInventory(session);
    const packetBytes = profile.contribution.confirmationPacketBytes;
    for (let position = 0; position < profile.participantCount; position++) {
        const confirmation = opened.inventory.subarray(
            4 + position * packetBytes,
            4 + (position + 1) * packetBytes,
        );
        writeSetupInput(kernel, confirmation);
        if (kernel.setup_confirmation(confirmation.length) !== 0)
            throw new Error('The setup verifier refused a confirmation.');
    }
    if (kernel.setup_inventory_finish() !== 1)
        throw new Error('The setup verifier refused the inventory.');
    const cache = await openSetupCache(context.namespace);
    try {
        if (clearCache) await writeCache(cache, (store) => store.clear());
        for (let position = 0; position < profile.participantCount; position++)
            await verifyContribution(context, relay, cache, position);
    } finally {
        cache.close();
    }
    if (kernel.setup_finish() !== 1)
        throw new PublicInputFailure('The complete setup was refused.');
    if (
        !equalBytes(
            readKernel(kernel, kernel.setup_inventory_pointer(), 64),
            opened.identity,
        )
    )
        throw new Error(
            'The verified setup differs from the opened inventory.',
        );
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

export const verifySetup = (
    session: ContributionSession,
    relay: PublicRelay,
): Promise<Uint8Array> => {
    if (session.root.head.generation !== 11)
        throw new Error('No opened contribution awaits setup verification.');
    return verifyCompleteSetup(session, relay, true);
};

// Verifies the complete setup again in this instance for work that needs the
// verified setup itself. It must reproduce the retained setup reference.
export const reverifySetup = async (
    session: ContributionSession,
    relay: PublicRelay,
) => {
    if (session.root.head.generation < 12)
        throw new Error('No setup reference is retained.');
    const reference = await verifyCompleteSetup(session, relay, false);
    if (
        !equalBytes(
            reference,
            await readDataKind(
                session.context,
                session.root.manifest,
                dataKind.setupReference,
            ),
        )
    )
        throw new Error('The verified setup differs from the retained one.');
};

// Retains the setup reference. The ballot suffix starts empty and the close
// log collects from here on.
export const retainSetup = async (
    session: ContributionSession,
    reference: Uint8Array,
): Promise<AuthenticatedRoot> => {
    const { context, root } = session;
    const added = [{ kind: dataKind.setupReference, bytes: reference }];
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
