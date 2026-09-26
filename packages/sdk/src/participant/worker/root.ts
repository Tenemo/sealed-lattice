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
import {
    custodyIdentities,
    custodyIdentity,
    custodyPurpose,
} from './identity.js';
import type { ParticipantStoredRecord } from './predecessor.js';
import { validateParticipantPredecessor } from './predecessor.js';
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
// Generation two appends the organizer's proposal coins. From generation four
// length-prefixed suffixes follow in a fixed order, each present from its
// first generation: contribution, then ballot and close together, then target
// signing, then release.
export const chunkBytes = 1 << 20;
const referenceBytes = 73;
const prefixBytes = 4 + 64 + 64 + 4;
const lastGeneration = 29;
const suffixStarts = {
    contribution: 4,
    ballot: 12,
    close: 12,
    target: 23,
    release: 25,
} as const;
type ManifestSuffix = keyof typeof suffixStarts;
const suffixOrder: readonly ManifestSuffix[] = [
    'contribution',
    'ballot',
    'close',
    'target',
    'release',
];

// Data record kinds, in manifest order.
export const dataKind = {
    publicKey: 0,
    proof: 1,
    header: 2,
    signature: 3,
    recipientCapsule: 4,
    signingCapsule: 5,
    pollDefinition: 6,
    pollSignature: 7,
    proposal: 8,
    proposalSignature: 9,
    setupReference: 10,
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
    proposalCoins?: Uint8Array;
    suffixes: Readonly<Partial<Record<ManifestSuffix, Uint8Array>>>;
}>;

const presentSuffixes = (generation: number) =>
    suffixOrder.filter((name) => generation >= suffixStarts[name]);

// Roots before the contribution's intent retain only enrollment records,
// the proposal and its signature. A later root is bounded by the profile its
// retained roster names; before that profile is known, by the largest root
// of any supported profile.
const enrollmentRoot = (generation: number) =>
    generation < suffixStarts.contribution;

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
    const suffixes = presentSuffixes(generation).map((name) => {
        const bytes = manifest.suffixes[name];
        if (bytes === undefined)
            throw new Error('A participant root suffix is missing.');
        return concatenate(unsigned32(bytes.length), bytes);
    });
    if (
        (generation === 2) !== (manifest.proposalCoins !== undefined) ||
        Object.keys(manifest.suffixes).length !== suffixes.length
    )
        throw new Error(
            'Participant root fields disagree with its generation.',
        );
    return concatenate(
        encodeText('ERM5'),
        manifest.dataKeys,
        manifest.poll,
        unsigned32(manifest.references.length),
        ...manifest.references.map(encodeReference),
        manifest.proposalCoins ?? new Uint8Array(),
        ...suffixes,
    );
};

// Checks the canonical reference inventory: ascending kinds, contiguous
// chunks of at most one mebibyte, only the last chunk of a kind shorter, and
// the complete records that the generation requires. The profile's exact
// proposal and setup reference lengths are checked once it is known.
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
        lengths[dataKind.proof] === 0 ||
        lengths[dataKind.header] === 0 ||
        !exact(dataKind.signature, registration.signatureBytes) ||
        !exact(dataKind.recipientCapsule, registration.recipientCapsuleBytes) ||
        !exact(dataKind.signingCapsule, registration.signingCapsuleBytes) ||
        lengths[dataKind.pollDefinition] === 0 ||
        !exact(dataKind.pollSignature, registration.signatureBytes) ||
        generation >= 2 !== lengths[dataKind.proposal] > 0 ||
        !exact(
            dataKind.proposalSignature,
            generation >= 3 ? registration.signatureBytes : 0,
        ) ||
        generation >= 12 !== lengths[dataKind.setupReference] > 0
    )
        throw new Error('Participant records do not match the generation.');
};

const decodeManifest = (
    bytes: Uint8Array,
    generation: number,
    limits: ParticipantLimits,
): ParticipantManifest => {
    if (
        !Number.isSafeInteger(generation) ||
        generation < 1 ||
        generation > lastGeneration ||
        bytes.length < prefixBytes ||
        !equalBytes(bytes.subarray(0, 4), encodeText('ERM5'))
    )
        throw new Error('Invalid participant root manifest.');
    const count = readUnsigned32(bytes, 132);
    if (
        count > limits.root.maximumRecords ||
        bytes.length < prefixBytes + referenceBytes * count
    )
        throw new Error('Invalid participant record inventory.');
    const references: RecordReference[] = [];
    for (let index = 0; index < count; index++) {
        const start = prefixBytes + referenceBytes * index;
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
    let offset = prefixBytes + referenceBytes * count;
    let proposalCoins: Uint8Array | undefined;
    if (generation === 2) {
        if (bytes.length - offset < 32)
            throw new Error('Missing proposal signing coins.');
        proposalCoins = bytes.slice(offset, offset + 32);
        offset += 32;
    }
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
        dataKeys: bytes.slice(4, 68),
        poll: bytes.slice(68, 132),
        references,
        ...(proposalCoins === undefined ? {} : { proposalCoins }),
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

const openRoot = async (
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

// A failed transition whose exact predecessor still authenticates leaves the
// participant pending; any other failure is local state loss.
export class StoragePending extends Error {}

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
        snapshot.head.generation < 1 ||
        snapshot.head.generation > lastGeneration ||
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
    // New data records to add, in manifest order after the existing ones.
    addedData?: readonly Readonly<{ kind: number; bytes: Uint8Array }>[];
    // Other synchronous writes that enter the same transaction.
    write?: (transaction: IDBTransaction) => void;
}>;

export const referenceData = (
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
    ) =>
        validateParticipantPredecessor(reader, {
            head: predecessor.head,
            manifest: predecessor.plaintext,
            rootContext: associatedData,
            maximumRootBytes: rootBound(context, predecessor.head.generation),
            recordStores: participantRecordStores,
            records: transition.predecessorRecords,
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
            validate,
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
    for (const reference of manifest.references.slice(
        predecessor.manifest.references.length,
    ))
        await readDataRecord(context, reference);
    return { head, plaintext: reopened, manifest };
};
