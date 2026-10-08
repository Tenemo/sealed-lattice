import type { ParticipantTransactionReader } from './state-transaction.js';

// A required record is authenticated either by the key the worker sealed it
// under and its associated data, or by its listed ciphertext hash, as a
// checkpoint record the module seals and a data record are.
export type ParticipantStoredRecord = Readonly<{
    store: string;
    key: number | number[];
    byteLength: number;
}> &
    (
        | Readonly<{ identity: Uint8Array; encryption?: undefined }>
        | Readonly<{
              identity?: undefined;
              encryption: Readonly<{
                  key: Uint8Array;
                  additionalData: Uint8Array;
              }>;
          }>
    );

// The most records, and the most of their bytes, that one batch of the
// predecessor check reads and authenticates at once.
const checkedRecords = 64;
const checkedBytes = 8_388_608;
// No listed record may be longer: every record the worker retains is at most
// one chunk and its tag.
const maximumListedRecordBytes = 1_572_864;

// The identities the caller derives for a sealed root and a stored record.
export type ParticipantIdentities = Readonly<{
    root: (bytes: Uint8Array) => Uint8Array | Promise<Uint8Array>;
    record: (bytes: Uint8Array) => Uint8Array | Promise<Uint8Array>;
}>;

// The expected manifest is the immutable authenticated predecessor, never the
// next manifest after retired records have been removed. This check
// runs inside commitParticipantState's protected readwrite transaction.
export async function validateParticipantPredecessor(
    reader: ParticipantTransactionReader,
    expected: Readonly<{
        head: Readonly<{ generation: number; hash: string; runtime: string }>;
        manifest: Uint8Array;
        rootContext: Uint8Array;
        maximumRootBytes: number;
        recordStores: readonly string[];
        records: readonly ParticipantStoredRecord[];
        // Rollback may leave only these unreferenced new keys, whose values
        // are not authority and need not have survived. Every other record
        // and the exact original root still authenticate before continuation.
        provisionalRecords?: readonly Pick<
            ParticipantStoredRecord,
            'store' | 'key'
        >[];
        identities: ParticipantIdentities;
    }>,
): Promise<void> {
    const equal = (left: Uint8Array, right: Uint8Array) =>
        left.length === right.length &&
        left.every((value, index) => value === right[index]);
    const hexadecimal = (bytes: Uint8Array) =>
        Array.from(bytes, (value) => value.toString(16).padStart(2, '0')).join(
            '',
        );
    // The root nonce is the generation as a 96-bit big-endian counter, so it
    // never repeats under one root key.
    if (
        !Number.isSafeInteger(expected.head.generation) ||
        expected.head.generation < 0
    )
        throw new Error('Invalid predecessor generation.');
    const counts = new Map<string, number>();
    for (const store of expected.recordStores) counts.set(store, 0);
    const keys = new Set<string>();
    // Record encryption uses a zero nonce, which is safe only while every
    // record key encrypts exactly one record.
    const encryptionKeys = new Set<string>();
    for (const record of expected.records) {
        const identity = `${record.store}:${JSON.stringify(record.key)}`;
        const encryptionKey =
            record.encryption === undefined
                ? undefined
                : hexadecimal(record.encryption.key);
        if (
            !counts.has(record.store) ||
            keys.has(identity) ||
            !Number.isSafeInteger(record.byteLength) ||
            record.byteLength <= 0 ||
            record.byteLength > maximumListedRecordBytes ||
            (record.identity === undefined) ===
                (record.encryption === undefined) ||
            (record.identity !== undefined && record.identity.length !== 64) ||
            (record.encryption !== undefined &&
                (record.encryption.key.length !== 32 ||
                    record.byteLength <= 16)) ||
            (encryptionKey !== undefined && encryptionKeys.has(encryptionKey))
        )
            throw new Error('Invalid predecessor record description.');
        keys.add(identity);
        if (encryptionKey !== undefined) encryptionKeys.add(encryptionKey);
        counts.set(record.store, counts.get(record.store)! + 1);
    }
    for (const record of expected.provisionalRecords ?? []) {
        const identity = `${record.store}:${JSON.stringify(record.key)}`;
        if (!counts.has(record.store) || keys.has(identity))
            throw new Error('Invalid provisional record description.');
        keys.add(identity);
        counts.set(
            record.store,
            counts.get(record.store)! +
                (await reader.count(record.store, record.key)),
        );
    }
    for (const [store, count] of [
        ['head', 1],
        ['root', 1],
        ['key', 1],
        ['stopped', 0],
        ...counts,
    ] as const)
        if ((await reader.count(store)) !== count)
            throw new Error('Participant predecessor inventory changed.');
    const head = await reader.get('head', 0),
        root = await reader.get('root', 0),
        key = await reader.get('key', 0);
    if (
        head === null ||
        typeof head !== 'object' ||
        Array.isArray(head) ||
        !('generation' in head) ||
        !('hash' in head) ||
        !('runtime' in head) ||
        Object.keys(head).length !== 3 ||
        head.generation !== expected.head.generation ||
        head.hash !== expected.head.hash ||
        head.runtime !== expected.head.runtime ||
        !(root instanceof Uint8Array) ||
        root.length > expected.maximumRootBytes ||
        !(key instanceof CryptoKey) ||
        key.type !== 'secret' ||
        key.extractable ||
        key.algorithm.name !== 'AES-GCM' ||
        !('length' in key.algorithm) ||
        key.algorithm.length !== 256 ||
        key.usages.slice().sort().join(',') !== 'decrypt,encrypt' ||
        hexadecimal(await expected.identities.root(root)) !== expected.head.hash
    )
        throw new Error('Participant predecessor authority changed.');
    const nonce = new Uint8Array(12);
    new DataView(nonce.buffer).setBigUint64(
        4,
        BigInt(expected.head.generation),
    );
    const manifest = new Uint8Array(
        await crypto.subtle.decrypt(
            {
                name: 'AES-GCM',
                iv: nonce,
                additionalData: new Uint8Array(expected.rootContext),
            },
            key,
            new Uint8Array(root),
        ),
    );
    try {
        if (!equal(manifest, expected.manifest))
            throw new Error('Participant predecessor plaintext changed.');
    } finally {
        manifest.fill(0);
    }
    const check = async (record: ParticipantStoredRecord) => {
        const blob = await reader.get(record.store, record.key);
        if (!(blob instanceof Blob) || blob.size !== record.byteLength)
            throw new Error('Required predecessor record is missing.');
        const bytes = new Uint8Array(await blob.arrayBuffer());
        try {
            const { encryption, identity } = record;
            if (encryption !== undefined) {
                const recordKey = await crypto.subtle.importKey(
                    'raw',
                    new Uint8Array(encryption.key),
                    'AES-GCM',
                    false,
                    ['decrypt'],
                );
                const plaintext = new Uint8Array(
                    await crypto.subtle.decrypt(
                        {
                            name: 'AES-GCM',
                            iv: new Uint8Array(12),
                            additionalData: new Uint8Array(
                                encryption.additionalData,
                            ),
                        },
                        recordKey,
                        bytes,
                    ),
                );
                plaintext.fill(0);
            } else if (
                identity === undefined ||
                !equal(await expected.identities.record(bytes), identity)
            )
                throw new Error('Predecessor record bytes changed.');
        } finally {
            bytes.fill(0);
        }
    };
    // Records authenticate in batches whose reads and checks overlap. Every
    // check of a batch settles before the next batch starts, and the first
    // failure in record order is reported, as checking the records one at a
    // time reports it.
    for (let start = 0; start < expected.records.length;) {
        let end = start + 1;
        let bytes = expected.records[start].byteLength;
        while (
            end < expected.records.length &&
            end - start < checkedRecords &&
            bytes + expected.records[end].byteLength <= checkedBytes
        )
            bytes += expected.records[end++].byteLength;
        const results = await Promise.allSettled(
            expected.records.slice(start, end).map(check),
        );
        for (const result of results)
            if (result.status === 'rejected') throw result.reason;
        start = end;
    }
}
