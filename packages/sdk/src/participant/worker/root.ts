import { participantDataKindMaximums } from './bounds.js';
import type { ParticipantLimits } from './bounds.js';
import {
    concatenate,
    encodeText,
    equalBytes,
    hexadecimal,
    readUnsigned32,
    unsigned32,
} from './bytes.js';
import { describe } from './context.js';
import type { ParticipantContext } from './context.js';
import { StoragePending } from './failures.js';
import {
    custodyIdentities,
    custodyIdentity,
    custodyPurpose,
} from './identity.js';
import type { ParticipantStoredRecord } from './predecessor.js';
import { validateParticipantPredecessor } from './predecessor.js';
import {
    isRootGeneration,
    lastRootGeneration,
    rootGeneration,
} from './root-generation.js';
import { commitParticipantState } from './state-transaction.js';
import {
    isParticipantHead,
    isRootKey,
    participantRecordStores,
    participantStores,
    readParticipantValue,
    snapshotParticipant,
} from './storage.js';
import type { ParticipantHead } from './storage.js';

// The encrypted root manifest. Its prefix retains the enrollment data keys,
// the poll and the ordered references of the public and private data records.
// Generation two appends the organizer's proposal intent. From generation four
// length-prefixed suffixes follow in a fixed order, each present from its
// first generation: preparation, then ballot and close together, then target
// signing, then release.
export const chunkBytes = 1 << 20;
const referenceBytes = 73;
export const requiresFheKeySources = (generation: number) =>
    generation < rootGeneration.setupRetained;
const dataKeyBytes = (generation: number) =>
    requiresFheKeySources(generation) ? 96 : 64;
const prefixBytes = (generation: number) =>
    4 + dataKeyBytes(generation) + 64 + 4;
const suffixStarts = {
    preparation: 4,
    ballot: 12,
    close: 12,
    target: 23,
    release: 25,
} as const;
type ManifestSuffix = keyof typeof suffixStarts;
const suffixOrder: readonly ManifestSuffix[] = [
    'preparation',
    'ballot',
    'close',
    'target',
    'release',
];

// Data record kinds, in manifest order.
export const dataKind = {
    publicKey: 0,
    header: 1,
    signature: 2,
    recipientCapsule: 3,
    signingCapsule: 4,
    pollDefinition: 5,
    pollSignature: 6,
    proposal: 7,
    proposalSignature: 8,
    setupReference: 9,
    // The setup certificate the setup was verified against.
    setupInventory: 10,
    // This participant's roster verification, keyed to its credential.
    retainedRoster: 11,
    // This participant's verification of its own registration, keyed to its
    // credential.
    retainedRegistration: 12,
    // Original private FHE family sources, retired with verified setup.
    sourceCapsule: 13,
} as const;

export type RecordReference = Readonly<{
    kind: number;
    offset: number;
    length: number;
    hash: Uint8Array;
}>;

export type ParticipantManifest = Readonly<{
    dataKeys: Uint8Array;
    poll: Uint8Array;
    references: readonly RecordReference[];
    suffixes: Readonly<Partial<Record<ManifestSuffix, Uint8Array>>>;
}>;

const presentSuffixes = (generation: number) =>
    suffixOrder.filter((name) => generation >= suffixStarts[name]);

// Roots before the contribution's intent retain only enrollment records,
// the proposal and its signature. A later root is bounded by the profile its
// retained roster names; before that profile is known, by the largest root
// of any supported profile.
const enrollmentRoot = (generation: number) =>
    generation < suffixStarts.preparation;

const provisionalRootBound = (limits: ParticipantLimits, generation: number) =>
    enrollmentRoot(generation)
        ? limits.root.maximumEnrollmentRootBytes
        : limits.root.maximumRootBytes;

export const rootBound = (context: ParticipantContext, generation: number) => {
    if (enrollmentRoot(generation))
        return context.limits.root.maximumEnrollmentRootBytes;
    if (context.profile === undefined)
        throw new Error('The participant profile is not known.');
    return context.profile.root.maximumRootBytes;
};

const encodeReference = (reference: RecordReference) => {
    const bytes = new Uint8Array(referenceBytes);
    const view = new DataView(bytes.buffer);
    view.setUint8(0, reference.kind);
    view.setUint32(1, reference.offset, true);
    view.setUint32(5, reference.length, true);
    bytes.set(reference.hash, 9);
    return bytes;
};

export const encodeManifest = (
    manifest: ParticipantManifest,
    generation: number,
) => {
    if (!isRootGeneration(generation))
        throw new Error('Invalid participant root generation.');
    const suffixes = presentSuffixes(generation).map((name) => {
        const bytes = manifest.suffixes[name];
        if (bytes === undefined)
            throw new Error('A participant root suffix is missing.');
        return concatenate(unsigned32(bytes.length), bytes);
    });
    if (
        manifest.dataKeys.length !== dataKeyBytes(generation) ||
        Object.keys(manifest.suffixes).length !== suffixes.length
    )
        throw new Error(
            'Participant root fields disagree with its generation.',
        );
    return concatenate(
        encodeText('ERM9'),
        manifest.dataKeys,
        manifest.poll,
        unsigned32(manifest.references.length),
        ...manifest.references.map(encodeReference),
        ...suffixes,
    );
};

// Checks the canonical reference inventory: ascending kinds, contiguous
// chunks of at most one mebibyte, only the last chunk of a kind shorter, and
// the complete records that the generation requires. The profile's exact
// proposal, retained roster, setup reference and setup inventory lengths are
// checked once it is known.
const checkReferences = (
    references: readonly RecordReference[],
    generation: number,
    limits: ParticipantLimits,
) => {
    const maximums = participantDataKindMaximums(limits);
    const lengths = maximums.map(() => 0);
    let previous: RecordReference | undefined;
    for (const reference of references) {
        if (
            reference.kind >= maximums.length ||
            (previous !== undefined && reference.kind < previous.kind) ||
            reference.offset !== lengths[reference.kind] ||
            reference.length === 0 ||
            reference.length > chunkBytes ||
            reference.length > maximums[reference.kind] - reference.offset ||
            (previous?.kind === reference.kind &&
                previous.length !== chunkBytes)
        )
            throw new Error('Noncanonical participant record inventory.');
        lengths[reference.kind] += reference.length;
        previous = reference;
    }
    const registration = limits.registration;
    const exact = (kind: number, length: number) => lengths[kind] === length;
    if (
        !exact(dataKind.publicKey, registration.publicKeyBytes) ||
        lengths[dataKind.header] === 0 ||
        !exact(dataKind.signature, registration.signatureBytes) ||
        !exact(dataKind.recipientCapsule, registration.recipientCapsuleBytes) ||
        !exact(dataKind.signingCapsule, registration.signingCapsuleBytes) ||
        requiresFheKeySources(generation) !==
            lengths[dataKind.sourceCapsule] > 0 ||
        lengths[dataKind.pollDefinition] === 0 ||
        !exact(dataKind.pollSignature, registration.signatureBytes) ||
        generation >= rootGeneration.rosterLocked !==
            lengths[dataKind.proposal] > 0 ||
        generation >= rootGeneration.rosterLocked !==
            lengths[dataKind.retainedRoster] > 0 ||
        !exact(
            dataKind.proposalSignature,
            generation >= rootGeneration.rosterSigned
                ? registration.signatureBytes
                : 0,
        ) ||
        generation >= rootGeneration.setupRetained !==
            lengths[dataKind.setupReference] > 0 ||
        generation >= rootGeneration.setupRetained !==
            lengths[dataKind.setupInventory] > 0
    )
        throw new Error('Participant records do not match the generation.');
};

const decodeManifest = (
    bytes: Uint8Array,
    generation: number,
    limits: ParticipantLimits,
): ParticipantManifest => {
    if (
        !isRootGeneration(generation) ||
        bytes.length < prefixBytes(generation) ||
        !equalBytes(bytes.subarray(0, 4), encodeText('ERM9'))
    )
        throw new Error('Invalid participant root manifest.');
    const prefix = prefixBytes(generation);
    const keysEnd = 4 + dataKeyBytes(generation);
    const count = readUnsigned32(bytes, prefix - 4);
    if (
        count > limits.root.maximumRecords ||
        bytes.length < prefix + referenceBytes * count
    )
        throw new Error('Invalid participant record inventory.');
    const references: RecordReference[] = [];
    for (let index = 0; index < count; index++) {
        const start = prefix + referenceBytes * index;
        const view = new DataView(
            bytes.buffer,
            bytes.byteOffset + start,
            referenceBytes,
        );
        references.push({
            kind: view.getUint8(0),
            offset: view.getUint32(1, true),
            length: view.getUint32(5, true),
            hash: bytes.slice(start + 9, start + referenceBytes),
        });
    }
    checkReferences(references, generation, limits);
    let offset = prefix + referenceBytes * count;
    const suffixes: Partial<Record<ManifestSuffix, Uint8Array>> = {};
    for (const name of presentSuffixes(generation)) {
        if (bytes.length - offset < 4)
            throw new Error('Missing participant root suffix.');
        const length = readUnsigned32(bytes, offset);
        if (length > bytes.length - offset - 4)
            throw new Error('Truncated participant root suffix.');
        suffixes[name] = bytes.slice(offset + 4, offset + 4 + length);
        offset += 4 + length;
    }
    if (offset !== bytes.length)
        throw new Error('Participant root manifest has trailing bytes.');
    return {
        dataKeys: bytes.slice(4, keysEnd),
        poll: bytes.slice(keysEnd, keysEnd + 64),
        references,
        suffixes,
    };
};

// The root nonce is the generation as a 96-bit big-endian counter; every
// root after the initial enrollment uses a fresh key, so a repeated
// generation never repeats a nonce under one key.
const rootNonce = (generation: number) => {
    const nonce = new Uint8Array(12);
    new DataView(nonce.buffer).setBigUint64(4, BigInt(generation));
    return nonce;
};

export const rootAssociatedData = (runtime: Uint8Array) =>
    concatenate(encodeText('POL1'), runtime);

export const createRootKey = () =>
    crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, [
        'encrypt',
        'decrypt',
    ]);

export const sealRoot = async (
    key: CryptoKey,
    generation: number,
    associatedData: Uint8Array,
    plaintext: Uint8Array,
) =>
    new Uint8Array(
        await crypto.subtle.encrypt(
            {
                name: 'AES-GCM',
                iv: rootNonce(generation),
                additionalData: new Uint8Array(associatedData),
            },
            key,
            new Uint8Array(plaintext),
        ),
    );

export const openRoot = async (
    key: CryptoKey,
    generation: number,
    associatedData: Uint8Array,
    sealed: Uint8Array,
) =>
    new Uint8Array(
        await crypto.subtle.decrypt(
            {
                name: 'AES-GCM',
                iv: rootNonce(generation),
                additionalData: new Uint8Array(associatedData),
            },
            key,
            new Uint8Array(sealed),
        ),
    );

// Validation of a predecessor is bounded by the foreground visit limit.
const validationMilliseconds = 15 * 60 * 1000;

export type AuthenticatedRoot = Readonly<{
    head: ParticipantHead;
    plaintext: Uint8Array;
    manifest: ParticipantManifest;
}>;

// Reads the stored key, root and head, authenticates the root under its
// generation and decodes the manifest. The data record count must match the
// manifest and no stop marker may exist.
export const authenticateRoot = async (
    context: ParticipantContext,
): Promise<AuthenticatedRoot> => {
    const { database, kernel, runtime, limits } = context;
    const snapshot = await snapshotParticipant(database);
    if (
        snapshot.counts.key !== 1 ||
        snapshot.counts.root !== 1 ||
        snapshot.counts.head !== 1 ||
        snapshot.counts.stopped !== 0 ||
        !isRootKey(snapshot.key) ||
        !(snapshot.root instanceof Uint8Array) ||
        !isParticipantHead(snapshot.head) ||
        snapshot.head.generation < rootGeneration.registered ||
        snapshot.head.generation > lastRootGeneration ||
        snapshot.head.runtime !== hexadecimal(runtime) ||
        snapshot.root.length >
            provisionalRootBound(limits, snapshot.head.generation) ||
        snapshot.head.hash !==
            hexadecimal(
                custodyIdentity(kernel, custodyPurpose.root, snapshot.root),
            )
    )
        throw new Error('Missing or inconsistent participant authority.');
    const plaintext = await openRoot(
        snapshot.key,
        snapshot.head.generation,
        rootAssociatedData(runtime),
        snapshot.root,
    );
    const manifest = decodeManifest(
        plaintext,
        snapshot.head.generation,
        limits,
    );
    if (manifest.references.length !== snapshot.counts.data)
        throw new Error('Participant data inventory changed.');
    return { head: snapshot.head, plaintext, manifest };
};

// Reads one data record and checks its reference hash.
export const readDataRecord = async (
    context: ParticipantContext,
    reference: RecordReference,
) => {
    const blob = await readParticipantValue(context.database, 'data', [
        reference.kind,
        reference.offset,
    ]);
    if (!(blob instanceof Blob) || blob.size !== reference.length)
        throw new Error('A participant data record is missing.');
    const bytes = new Uint8Array(await blob.arrayBuffer());
    if (
        !equalBytes(
            custodyIdentity(context.kernel, custodyPurpose.record, bytes),
            reference.hash,
        )
    )
        throw new Error('A participant data record changed.');
    return bytes;
};

// Reads every chunk of one data kind in order.
export const readDataKind = async (
    context: ParticipantContext,
    manifest: ParticipantManifest,
    kind: number,
) =>
    concatenate(
        ...(await Promise.all(
            manifest.references
                .filter((reference) => reference.kind === kind)
                .map((reference) => readDataRecord(context, reference)),
        )),
    );

export const dataRecordInventory = (
    manifest: ParticipantManifest,
): ParticipantStoredRecord[] =>
    manifest.references.map((reference) => ({
        store: 'data',
        key: [reference.kind, reference.offset],
        byteLength: reference.length,
        identity: reference.hash,
    }));

export type RootTransition = Readonly<{
    generation: number;
    manifest: ParticipantManifest;
    // Records of the predecessor, decoded from its authenticated manifest.
    predecessorRecords: readonly ParticipantStoredRecord[];
    // Already stored outputs that the successor will retain. They join
    // commit validation, but do not become original authority on rollback.
    stagedRecords?: readonly ParticipantStoredRecord[];
    // New data records to add, in manifest order after the existing ones.
    addedData?: readonly Readonly<{ kind: number; bytes: Uint8Array }>[];
    // Other synchronous writes that enter the same transaction.
    write?: (transaction: IDBTransaction) => void;
}>;

// A saved signing intent can resume without committing another root. Check
// its complete required predecessor before reinstating that authority too.
export const authenticateRecords = (
    context: ParticipantContext,
    root: AuthenticatedRoot,
    records: readonly ParticipantStoredRecord[],
) =>
    commitParticipantState({
        database: context.database,
        stores: participantStores,
        timeoutMilliseconds: validationMilliseconds,
        validate: (reader) =>
            validateParticipantPredecessor(reader, {
                head: root.head,
                manifest: root.plaintext,
                rootContext: rootAssociatedData(context.runtime),
                maximumRootBytes: rootBound(context, root.head.generation),
                recordStores: participantRecordStores,
                records,
                identities: custodyIdentities(context.kernel),
            }),
        write: () => undefined,
    });

const referenceData = (
    context: ParticipantContext,
    records: readonly Readonly<{ kind: number; bytes: Uint8Array }>[],
) => {
    const references: RecordReference[] = [];
    const offsets = new Map<number, number>();
    for (const record of records)
        for (
            let offset = 0;
            offset < record.bytes.length;
            offset += chunkBytes
        ) {
            const chunk = record.bytes.subarray(offset, offset + chunkBytes);
            const start = offsets.get(record.kind) ?? 0;
            references.push({
                kind: record.kind,
                offset: start,
                length: chunk.length,
                hash: custodyIdentity(
                    context.kernel,
                    custodyPurpose.record,
                    chunk,
                ),
            });
            offsets.set(record.kind, start + chunk.length);
        }
    return references;
};

// A successor's references: the predecessor's and those of the records it
// adds, whose kinds the predecessor lacks, in manifest order.
export const addedReferences = (
    context: ParticipantContext,
    references: readonly RecordReference[],
    records: readonly Readonly<{ kind: number; bytes: Uint8Array }>[],
) =>
    [...references, ...referenceData(context, records)].sort(
        (left, right) => left.kind - right.kind || left.offset - right.offset,
    );

// Seals the successor root under a fresh key and commits it with its added
// records only after the exact predecessor authenticates inside the same
// strict transaction; then reads the committed root back.
export const commitRoot = async (
    context: ParticipantContext,
    predecessor: AuthenticatedRoot,
    transition: RootTransition,
): Promise<AuthenticatedRoot> => {
    const { database, kernel, runtime } = context;
    const associatedData = rootAssociatedData(runtime);
    const plaintext = encodeManifest(
        transition.manifest,
        transition.generation,
    );
    if (plaintext.length + 16 > rootBound(context, transition.generation))
        throw new Error('The participant root exceeds its bound.');
    const key = await createRootKey();
    const sealed = await sealRoot(
        key,
        transition.generation,
        associatedData,
        plaintext,
    );
    const head: ParticipantHead = {
        generation: transition.generation,
        hash: hexadecimal(custodyIdentity(kernel, custodyPurpose.root, sealed)),
        runtime: hexadecimal(runtime),
    };
    const added = (transition.addedData ?? []).flatMap((record) => {
        const chunks = [];
        for (let offset = 0; offset < record.bytes.length; offset += chunkBytes)
            chunks.push({
                kind: record.kind,
                offset,
                bytes: record.bytes.subarray(offset, offset + chunkBytes),
            });
        return chunks;
    });
    const validate = (
        reader: Parameters<typeof validateParticipantPredecessor>[0],
        rollback = false,
    ) =>
        validateParticipantPredecessor(reader, {
            head: predecessor.head,
            manifest: predecessor.plaintext,
            rootContext: associatedData,
            maximumRootBytes: rootBound(context, predecessor.head.generation),
            recordStores: participantRecordStores,
            records: rollback
                ? transition.predecessorRecords
                : [
                      ...transition.predecessorRecords,
                      ...(transition.stagedRecords ?? []),
                  ],
            ...(rollback
                ? { provisionalRecords: transition.stagedRecords ?? [] }
                : {}),
            identities: custodyIdentities(kernel),
        });
    try {
        await commitParticipantState({
            database,
            stores: participantStores,
            timeoutMilliseconds: validationMilliseconds,
            validate,
            write: (transaction) => {
                transaction.objectStore('key').put(key, 0);
                for (const record of added)
                    transaction
                        .objectStore('data')
                        .add(new Blob([new Uint8Array(record.bytes)]), [
                            record.kind,
                            record.offset,
                        ]);
                transition.write?.(transaction);
                transaction.objectStore('root').put(sealed, 0);
                transaction.objectStore('head').put(head, 0);
            },
        });
    } catch (error) {
        // Rejection alone does not prove rollback: the exact predecessor
        // must authenticate again before the participant may stay pending.
        await commitParticipantState({
            database,
            stores: participantStores,
            timeoutMilliseconds: validationMilliseconds,
            validate: (reader) => validate(reader, true),
            write: () => undefined,
        });
        throw new StoragePending(
            'The participant root was not committed: ' + describe(error),
        );
    }
    const snapshot = await snapshotParticipant(database);
    if (
        !isRootKey(snapshot.key) ||
        !isParticipantHead(snapshot.head) ||
        snapshot.head.generation !== head.generation ||
        snapshot.head.hash !== head.hash ||
        snapshot.head.runtime !== head.runtime ||
        !(snapshot.root instanceof Uint8Array) ||
        !equalBytes(snapshot.root, sealed)
    )
        throw new Error('Participant root readback failed.');
    const reopened = await openRoot(
        snapshot.key,
        head.generation,
        associatedData,
        snapshot.root,
    );
    if (!equalBytes(reopened, plaintext))
        throw new Error('Participant root readback differs.');
    const manifest = transition.manifest;
    const addedKinds = new Set(added.map(({ kind }) => kind));
    for (const reference of manifest.references.filter(({ kind }) =>
        addedKinds.has(kind),
    ))
        await readDataRecord(context, reference);
    return { head, plaintext: reopened, manifest };
};
