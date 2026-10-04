import { readParticipantProfile } from './bounds.js';
import {
    concatenate,
    equalBytes,
    readUnsigned16,
    tupleFields,
    unsigned32,
} from './bytes.js';
import { collectingCloseState, encodeCloseState } from './close-state.js';
import { PublicInputFailure, sessionInput } from './context.js';
import type { PublicContext, PublicProfileContext } from './context.js';
import {
    contributionDirectory,
    contributionRecords,
    polynomialFile,
} from './contribution.js';
import type { ParticipantSession, SignedPacket } from './contribution.js';
import { openDelivery } from './delivery.js';
import { readKernel, ResourceFailure, writeSetupInput } from './kernel.js';
import { encodePreparationState } from './preparation-state.js';
import { publishRecord, readPublic, streamPublic } from './public.js';
import type { PublicRelay } from './public.js';
import {
    addedReferences,
    commitRoot,
    dataKind,
    dataRecordInventory,
    readDataKind,
} from './root.js';
import type { AuthenticatedRoot } from './root.js';
import {
    proposalRecordIds,
    rosterBegin,
    streamRegistrations,
    validRecordIds,
} from './roster.js';
import { awaitLater, namespacedName, setupCacheName } from './storage.js';

// The owning Rust verifiers authenticate the roster, complete selected offers,
// organizer proposal and endorsement certificate. The public aggregate cache
// supplies only bytes that Rust checks against those exact predecessors.

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
    const opened = indexedDB.open(namespacedName(setupCacheName, namespace), 1);
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
    context: PublicProfileContext,
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

// Discards every cached aggregate. The next visit that needs the setup then
// verifies it again, which rewrites the cache.
const discardSetupCache = async (namespace: string) => {
    const cache = await openSetupCache(namespace);
    try {
        await writeCache(cache, (store) => store.clear());
    } finally {
        cache.close();
    }
};

// Whether the cache holds a chunk of the final aggregate at every offset
// setup verification writes one. Each consumer checks the bytes it reads
// against the retained setup reference.
const holdsFinalAggregate = async (context: PublicProfileContext) => {
    const { profile } = context;
    const accepted = profile.setupContributorCount - 1;
    const expected = new Set<string>();
    for (const polynomial of profile.contribution.polynomials)
        for (const { offset } of aggregateChunks(
            aggregateCapacity(context, polynomial),
            polynomial.bytes,
        ))
            expected.add(
                String(polynomial.expandedIndex) + ':' + String(offset),
            );
    const cache = await openSetupCache(context.namespace);
    try {
        const transaction = cache.transaction(cacheStore, 'readonly');
        const range = IDBKeyRange.bound(
            [accepted],
            [accepted + 1],
            false,
            true,
        );
        const [keys] = await Promise.all([
            cacheRequest(transaction.objectStore(cacheStore).getAllKeys(range)),
            cacheCompletion(transaction),
        ]);
        return (
            keys.length === expected.size &&
            keys.every((key) => {
                if (!Array.isArray(key) || key.length !== 3) return false;
                const [, index, offset] = key as unknown[];
                return expected.has(String(index) + ':' + String(offset));
            })
        );
    } catch {
        throw new PublicInputFailure('The setup cache refused a read.');
    } finally {
        cache.close();
    }
};

// Delivers cached final aggregate bytes into the module. Missing or refused
// bytes are not the ones the retained setup reference names, so the cache
// is discarded and the next visit verifies the setup again, which rewrites
// it.
export const deliverFinalAggregate = async (
    context: PublicProfileContext,
    deliver: () => Promise<void>,
) => {
    try {
        await deliver();
    } catch (error) {
        if (!(error instanceof ResourceFailure))
            await discardSetupCache(context.namespace);
        throw error;
    }
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
    context: PublicProfileContext,
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

export type SelectedOffer = Readonly<{
    position: number;
    identity: Uint8Array;
}>;
type SetupSelection = Readonly<{
    identity: Uint8Array;
    offers: readonly SelectedOffer[];
}>;

const offerDirectory = (offer: SelectedOffer) =>
    contributionDirectory(offer.position, offer.identity);

// These getters describe only a selection already authenticated by Rust.
const selectedSetup = (context: PublicProfileContext): SetupSelection => {
    const { kernel, profile } = context;
    const count = kernel.setup_selection_count();
    const pointer = kernel.setup_selection_identity_pointer();
    if (count !== profile.setupContributorCount || pointer === 0)
        throw new PublicInputFailure(
            'No authenticated setup selection is available.',
        );
    const identity = readKernel(kernel, pointer, 64);
    const offers = Array.from({ length: count }, (_, ordinal) => {
        const position = kernel.setup_selection_position(ordinal) >>> 0;
        const bodyIdentityPointer =
            kernel.setup_selection_body_identity_pointer(ordinal);
        if (
            position >= profile.eligibleContributorCount ||
            bodyIdentityPointer === 0
        )
            throw new PublicInputFailure(
                'The setup selection has an invalid author.',
            );
        return {
            position,
            identity: readKernel(kernel, bodyIdentityPointer, 64),
        };
    });
    return { identity, offers };
};

export const setupOutput = (context: PublicContext) =>
    readKernel(
        context.kernel,
        context.kernel.setup_output_pointer(),
        context.kernel.setup_output_length(),
    );

export const authenticateSelection = (
    context: PublicProfileContext,
    packet: SignedPacket,
    retained = false,
) => {
    const bytes = concatenate(
        unsigned32(packet.body.length),
        packet.body,
        packet.signature,
    );
    writeSetupInput(context.kernel, bytes);
    if (context.kernel.setup_selection_begin(bytes.length) !== 0)
        throw retained
            ? new Error('The retained setup selection was refused.')
            : new PublicInputFailure('The setup selection was refused.');
    return selectedSetup(context);
};

export const readSelection = async (
    context: PublicProfileContext,
    relay: PublicRelay,
): Promise<SignedPacket> => ({
    body: await readPublic(
        relay,
        'selection.bin',
        context.profile.preparation.selectionBodyBytes,
    ),
    signature: await readPublic(
        relay,
        'selection-signature.bin',
        context.profile.registration.signatureBytes,
    ),
});

// A bounded lookahead only. The later complete proof stream must reproduce
// these bytes inside Rust; an interrupted fetch supplies no verified record.
const readProofPrefix = async (
    relay: PublicRelay,
    name: string,
    maximum: number,
    length: number,
) => {
    const prefix = new Uint8Array(length);
    const complete = new Error('The bounded proof lookahead is complete.');
    let used = 0;
    try {
        await streamPublic(relay, name, maximum, (bytes) => {
            const count = Math.min(bytes.length, length - used);
            prefix.set(bytes.subarray(0, count), used);
            used += count;
            if (used === length) throw complete;
        });
    } catch (error) {
        if (error !== complete) throw error;
    }
    if (used !== length)
        throw new PublicInputFailure('A contribution proof is incomplete.');
    return prefix;
};

// Discovery never supplies verification authority. Complete named reads from
// the relay published store and the owning proof verifier establish the exact
// published dependency. Retention preserves those records; no receipt or
// arbitrary local buffer substitutes for that completed read and verification.
export const verifyOffer = async (
    context: PublicProfileContext,
    relay: PublicRelay,
    offer: SelectedOffer,
) => {
    const { kernel, profile } = context;
    const bounds = profile.contribution;
    writeSetupInput(kernel, offer.identity);
    if (
        kernel.setup_offer_available(offer.position, offer.identity.length) ===
        1
    )
        return;
    const directory = offerDirectory(offer);
    const envelope = await readPublic(
        relay,
        directory + 'offer.bin',
        bounds.offerEnvelopeBytes,
    );
    const signature = await readPublic(
        relay,
        directory + 'offer-signature.bin',
        profile.registration.signatureBytes,
    );
    const header = await readPublic(
        relay,
        directory + 'body-header.bin',
        bounds.bodyHeaderBytes,
    );
    const proofPrefix = await readProofPrefix(
        relay,
        directory + 'proof.bin',
        bounds.maximumProofBytes,
        bounds.proofHeaderBytes,
    );
    if (header.length !== bounds.bodyHeaderBytes)
        throw new PublicInputFailure('A contribution offer is incomplete.');
    const control = concatenate(
        unsigned32(envelope.length),
        envelope,
        signature,
        header,
        proofPrefix,
    );
    writeSetupInput(kernel, control);
    if (kernel.setup_offer_begin(control.length) !== 0)
        throw new PublicInputFailure('A contribution offer was refused.');
    // Check the authenticated envelope's transport destination before its
    // proof can replace any author in the module's verified-offer pool.
    const fields = tupleFields(envelope);
    if (
        readUnsigned16(fields[2], 0) !== offer.position ||
        !equalBytes(fields[4], offer.identity)
    )
        throw new PublicInputFailure(
            'The offer route names another body or author.',
        );
    for (const polynomial of bounds.polynomials) {
        let offset = 0;
        const length = await streamPublic(
            relay,
            directory + polynomialFile(polynomial.expandedIndex),
            polynomial.bytes,
            (bytes) => {
                writeSetupInput(kernel, bytes);
                if (
                    kernel.setup_offer_polynomial(
                        polynomial.expandedIndex,
                        offset,
                        bytes.length,
                    ) !== 0
                )
                    throw new PublicInputFailure(
                        'A contribution offer polynomial was refused.',
                    );
                offset += bytes.length;
            },
        );
        if (length !== polynomial.bytes)
            throw new PublicInputFailure(
                'A contribution offer polynomial is incomplete.',
            );
    }
    let proofOffset = 0;
    await streamPublic(
        relay,
        directory + 'proof.bin',
        bounds.maximumProofBytes,
        (bytes) => {
            writeSetupInput(kernel, bytes);
            if (kernel.setup_offer_proof(proofOffset, bytes.length) !== 0)
                throw new PublicInputFailure(
                    'A contribution offer proof was refused.',
                );
            proofOffset += bytes.length;
        },
    );
    if (kernel.setup_offer_finish() !== 1)
        throw new PublicInputFailure('A contribution offer was refused.');
    writeSetupInput(kernel, offer.identity);
    if (
        kernel.setup_offer_available(offer.position, offer.identity.length) !==
        1
    )
        throw new PublicInputFailure(
            'The verified offer differs from its advertised identity.',
        );
};

const aggregateOffer = async (
    context: PublicProfileContext,
    relay: PublicRelay,
    cache: IDBDatabase,
    offer: SelectedOffer,
) => {
    const { kernel, profile } = context;
    const bounds = profile.contribution;
    const directory = offerDirectory(offer);
    const accepted = kernel.setup_accepted();
    if (kernel.setup_begin_selected_offer(offer.position) !== 0)
        throw new PublicInputFailure('A selected verified offer was refused.');
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
    await writing;
    if (
        kernel.setup_finish_selected_offer() !== 1 ||
        kernel.setup_accepted() !== accepted + 1
    )
        throw new PublicInputFailure(
            'A selected contribution aggregate was refused.',
        );
    if (accepted > 0)
        await writeCache(cache, (store) =>
            store.delete(
                IDBKeyRange.bound([accepted - 1], [accepted], false, true),
            ),
        );
};

const aggregateSelection = async (
    context: PublicProfileContext,
    relay: PublicRelay,
    selection: SetupSelection,
) => {
    const { kernel } = context;
    if (kernel.setup_selection_aggregate() !== 1)
        throw new PublicInputFailure(
            'Complete selected offers are unavailable.',
        );
    const cache = await openSetupCache(context.namespace);
    try {
        await writeCache(cache, (store) => store.clear());
        for (const offer of selection.offers)
            await aggregateOffer(context, relay, cache, offer);
    } finally {
        cache.close();
    }
    if (kernel.setup_selection_finish() !== 1)
        throw new PublicInputFailure('The selected aggregate was refused.');
};

// Each operation owns one Rust module; this records only whether that module
// has already restored the roster, never whether an offer or setup is valid.
const preparedRosters = new WeakSet<object>();

export const verifySetupRoster = async (
    session: ParticipantSession,
    relay: PublicRelay,
) => {
    const { context } = session;
    const { kernel, profile } = context;
    if (preparedRosters.has(kernel)) return;
    const { manifest } = session.root;
    const proposal = await readDataKind(context, manifest, dataKind.proposal);
    const definition = await readDataKind(
        context,
        manifest,
        dataKind.pollDefinition,
    );
    const pollSignature = await readDataKind(
        context,
        manifest,
        dataKind.pollSignature,
    );
    const recordIds = proposalRecordIds(proposal);
    const begin = rosterBegin(
        context,
        manifest.poll,
        definition,
        pollSignature,
        recordIds.length,
    );
    // The verified registrations are restored from the retained roster and
    // the published headers and keys.
    const input = concatenate(
        begin,
        await readDataKind(context, manifest, dataKind.retainedRoster),
    );
    sessionInput(context, input);
    if (kernel.setup_roster_begin_retained(begin.length, input.length) !== 0)
        throw new Error('The setup verifier refused the retained roster.');
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
        true,
    );
    const proposalSignature = await readDataKind(
        context,
        manifest,
        dataKind.proposalSignature,
    );
    writeSetupInput(kernel, proposalSignature);
    // The retained roster, proposal and signature are authenticated, so a
    // refusal means the relay served other headers or keys under their
    // names.
    if (kernel.setup_roster_finish(proposalSignature.length) !== 1)
        throw new PublicInputFailure(
            'The published registrations are not the retained roster.',
        );
    preparedRosters.add(kernel);
};

export const verifySelectionInputs = async (
    session: ParticipantSession,
    relay: PublicRelay,
    packet: SignedPacket,
    retained = false,
) => {
    await verifySetupRoster(session, relay);
    const selection = authenticateSelection(session.context, packet, retained);
    for (const offer of selection.offers)
        await verifyOffer(session.context, relay, offer);
    await aggregateSelection(session.context, relay, selection);
    return selection;
};

const authenticateCertificate = (
    context: PublicProfileContext,
    bytes: Uint8Array,
    retained = false,
) => {
    writeSetupInput(context.kernel, bytes);
    if (context.kernel.setup_certificate(bytes.length) !== 0)
        throw retained
            ? new Error('The retained setup certificate was refused.')
            : new PublicInputFailure('The setup certificate was refused.');
    return selectedSetup(context);
};

export const endorsementPath = (position: number) =>
    'selection-endorsement-' + String(position) + '.bin';

// A published complete certificate takes precedence over discovery or the
// participant's own endorsement. Otherwise collect independently authenticated
// endorsements of the organizer's proposal; invalid public entries are ignored.
const readSetupCertificate = async (
    context: PublicProfileContext,
    relay: PublicRelay,
) => {
    try {
        const bytes = await readPublic(
            relay,
            'setup-certificate.bin',
            context.profile.preparation.certificateBytes,
        );
        authenticateCertificate(context, bytes);
        return bytes;
    } catch (error) {
        if (!(error instanceof PublicInputFailure)) throw error;
    }
    authenticateSelection(context, await readSelection(context, relay));
    for (
        let position = 0;
        position < context.profile.participantCount;
        position++
    ) {
        try {
            const bytes = await readPublic(
                relay,
                endorsementPath(position),
                context.profile.preparation.endorsementPacketBytes,
            );
            writeSetupInput(context.kernel, bytes);
            if (context.kernel.setup_endorsement(bytes.length) !== 0) continue;
        } catch (error) {
            if (!(error instanceof PublicInputFailure)) throw error;
        }
    }
    if (context.kernel.setup_certificate_build() !== 0)
        throw new PublicInputFailure(
            'A complete setup endorsement quorum is unavailable.',
        );
    const certificate = setupOutput(context);
    authenticateCertificate(context, certificate);
    return certificate;
};

const verifyCertificateInputs = async (
    context: PublicProfileContext,
    relay: PublicRelay,
    certificate: Uint8Array,
    retained = false,
) => {
    const selection = authenticateCertificate(context, certificate, retained);
    for (const offer of selection.offers)
        await verifyOffer(context, relay, offer);
    await aggregateSelection(context, relay, selection);
    if (context.kernel.setup_finish_certificate() !== 1)
        throw new PublicInputFailure(
            'The complete certified setup was refused.',
        );
    return selection;
};

const retainedReference = (context: PublicProfileContext) => {
    if (context.kernel.retain_setup() !== 0)
        throw new Error('The credential refused the verified setup.');
    const reference = readKernel(
        context.kernel,
        context.kernel.contribution_output_pointer(),
        context.kernel.contribution_output_length(),
    );
    if (reference.length !== context.profile.root.setupReferenceBytes)
        throw new Error('The setup reference has another length.');
    return reference;
};

export type VerifiedSetup = Readonly<{
    reference: Uint8Array;
    inventory: Uint8Array;
}>;

const referenceInventory = (reference: Uint8Array) => reference.subarray(4, 68);

const certifyRetainedSelection = (
    session: ParticipantSession,
    certificate: Uint8Array,
) => {
    const retained = session.preparation.endorsement;
    if (retained === undefined) return undefined;
    const selection = authenticateCertificate(session.context, certificate);
    const original = authenticateSelection(
        session.context,
        retained.selection,
        true,
    );
    sessionInput(session.context, retained.reference);
    if (
        session.context.kernel.restore_selection_inputs(
            retained.reference.length,
        ) !== 0
    )
        throw new Error(
            'The original selection verification could not be restored.',
        );
    // Installing a different winning proposal discards the losing inputs in
    // Rust. Equality preserves the credential-keyed original verified inputs.
    authenticateCertificate(session.context, certificate);
    if (!equalBytes(original.identity, selection.identity)) return undefined;
    if (session.context.kernel.setup_finish_certificate() !== 1)
        throw new PublicInputFailure(
            'The certificate does not match the verified selection.',
        );
    return selection;
};

export const verifySetup = async (
    session: ParticipantSession,
    relay: PublicRelay,
): Promise<VerifiedSetup> => {
    if (session.root.head.generation !== 4)
        throw new Error('No confirmed roster awaits setup activation.');
    await verifySetupRoster(session, relay);
    let inventory = await readSetupCertificate(session.context, relay);
    const delivery = await openDelivery(session.context, session.root);
    const selection =
        certifyRetainedSelection(session, inventory) ??
        (await verifyCertificateInputs(session.context, relay, inventory));
    // Concurrent publishers may store different valid carriers of the same
    // setup. Completed named readback, not a successful HTTP response alone,
    // establishes which new certificate and selector entered the public store.
    try {
        await delivery.transfer(() =>
            publishRecord(relay, 'setup-certificate.bin', inventory),
        );
    } catch (error) {
        if (!(error instanceof PublicInputFailure)) throw error;
    }
    await delivery.transfer(async () => {
        inventory = await readPublic(
            relay,
            'setup-certificate.bin',
            session.context.profile.preparation.certificateBytes,
        );
    });
    const accepted = authenticateCertificate(session.context, inventory);
    if (
        !equalBytes(accepted.identity, selection.identity) ||
        session.context.kernel.setup_finish_certificate() !== 1
    )
        throw new PublicInputFailure(
            'The published certificate names another setup.',
        );
    try {
        await delivery.transfer(() =>
            publishRecord(relay, 'setup-identity.bin', selection.identity),
        );
    } catch (error) {
        if (!(error instanceof PublicInputFailure)) throw error;
    }
    await delivery.transfer(async () => {
        const stored = await readPublic(
            relay,
            'setup-identity.bin',
            selection.identity.length,
        );
        if (!equalBytes(stored, selection.identity))
            throw new PublicInputFailure(
                'The published setup identity changed.',
            );
    });
    const reference = retainedReference(session.context);
    if (!equalBytes(referenceInventory(reference), selection.identity))
        throw new Error('The retained setup names another selection.');
    return { reference, inventory };
};

export const ensureFinalAggregate = async (
    session: ParticipantSession,
    relay: PublicRelay,
) => {
    if (session.root.head.generation < 12)
        throw new Error('No setup reference is retained.');
    if (await holdsFinalAggregate(session.context)) return false;
    // A cache loss can also occur after certification in this same visit.
    // Rebuild from fresh owning verification, not an existing aggregate flag.
    preparedRosters.delete(session.context.kernel);
    await verifySetupRoster(session, relay);
    const certificate = await readDataKind(
        session.context,
        session.root.manifest,
        dataKind.setupInventory,
    );
    await verifyCertificateInputs(session.context, relay, certificate, true);
    if (
        !equalBytes(
            retainedReference(session.context),
            await readDataKind(
                session.context,
                session.root.manifest,
                dataKind.setupReference,
            ),
        )
    )
        throw new Error('The verified setup differs from the retained one.');
    return true;
};

export const restoreSetup = async (
    session: ParticipantSession,
    relay: PublicRelay,
) => {
    if (await ensureFinalAggregate(session, relay)) return;
    await verifySetupRoster(session, relay);
    const { context, root } = session;
    authenticateCertificate(
        context,
        await readDataKind(context, root.manifest, dataKind.setupInventory),
        true,
    );
    const reference = await readDataKind(
        context,
        root.manifest,
        dataKind.setupReference,
    );
    sessionInput(context, reference);
    if (context.kernel.restore_setup(reference.length) !== 0)
        throw new Error('The credential refused the retained setup.');
};

const publishedRecordIds = (context: PublicContext, proposal: Uint8Array) => {
    let recordIds: string[];
    try {
        recordIds = proposalRecordIds(proposal);
    } catch {
        throw new PublicInputFailure('The roster proposal is malformed.');
    }
    if (!validRecordIds(recordIds, context.limits))
        throw new PublicInputFailure('The roster proposal is malformed.');
    return recordIds;
};

export const verifyPublicSetup = async (
    context: PublicContext,
    relay: PublicRelay,
    poll: Uint8Array,
): Promise<PublicProfileContext> => {
    const { kernel, limits } = context;
    const { registration } = limits;
    const definition = await readPublic(
        relay,
        'poll-definition.bin',
        registration.maximumPollDefinitionBytes,
    );
    const pollSignature = await readPublic(
        relay,
        'poll-signature.bin',
        registration.signatureBytes,
    );
    const proposal = await readPublic(
        relay,
        'proposal.bin',
        registration.maximumProposalBytes,
    );
    const proposalSignature = await readPublic(
        relay,
        'proposal-signature.bin',
        registration.signatureBytes,
    );
    const recordIds = publishedRecordIds(context, proposal);
    const begin = rosterBegin(
        context,
        poll,
        definition,
        pollSignature,
        recordIds.length,
    );
    writeSetupInput(kernel, begin);
    if (kernel.setup_roster_begin(begin.length) !== 0)
        throw new PublicInputFailure('The poll was refused.');
    await streamRegistrations(
        relay,
        recordIds,
        registration,
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
    writeSetupInput(kernel, proposalSignature);
    if (kernel.setup_roster_finish(proposalSignature.length) !== 1)
        throw new PublicInputFailure('The roster proposal was refused.');
    const profile = readParticipantProfile(
        kernel,
        limits,
        recordIds.length,
        kernel.setup_option_count(),
    );
    if (profile === undefined || proposal.length !== profile.proposalBytes)
        throw new PublicInputFailure('The poll names no supported profile.');
    const profiled = { ...context, profile };
    preparedRosters.add(kernel);
    const certificate = await readSetupCertificate(profiled, relay);
    await verifyCertificateInputs(profiled, relay, certificate);
    return profiled;
};

export const retainedSetupInventory = async (session: ParticipantSession) =>
    referenceInventory(
        await readDataKind(
            session.context,
            session.root.manifest,
            dataKind.setupReference,
        ),
    ).slice();

export const retainSetup = async (
    session: ParticipantSession,
    verified: VerifiedSetup,
): Promise<AuthenticatedRoot> => {
    const { context, root } = session;
    const added = [
        { kind: dataKind.setupReference, bytes: verified.reference },
        { kind: dataKind.setupInventory, bytes: verified.inventory },
    ];
    const retainedKeys = root.manifest.dataKeys.slice(0, 64);
    const retainedReferences = root.manifest.references.filter(
        (reference) => reference.kind !== dataKind.sourceCapsule,
    );
    const retained = await commitRoot(context, root, {
        generation: 12,
        manifest: {
            ...root.manifest,
            dataKeys: retainedKeys,
            references: addedReferences(context, retainedReferences, added),
            suffixes: {
                ...root.manifest.suffixes,
                preparation: encodePreparationState({}),
                ballot: new Uint8Array(),
                close: encodeCloseState(12, false, collectingCloseState()),
            },
        },
        predecessorRecords: [
            ...dataRecordInventory(root.manifest),
            ...contributionRecords(session),
        ],
        addedData: added,
        write: (transaction) => {
            transaction.objectStore('data').delete([dataKind.sourceCapsule, 0]);
            transaction.objectStore('contribution').clear();
            transaction.objectStore('checkpoint').clear();
        },
    });
    // Both storage and live private sources retire only after the exact
    // predecessor and committed successor have authenticated.
    root.manifest.dataKeys.subarray(64).fill(0);
    root.plaintext.subarray(4 + 64, 4 + 96).fill(0);
    if (context.kernel.retire_contribution_sources() !== 0)
        throw new Error('The original key sources could not be retired.');
    session.root = retained;
    session.preparation = {};
    delete session.state;
    return retained;
};
