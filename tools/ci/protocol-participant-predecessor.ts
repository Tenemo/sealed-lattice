import type { ParticipantTransactionReader } from './protocol-participant-state-transaction.js';

export type ParticipantStoredRecord = Readonly<{
    store: string;
    key: number | number[];
    byteLength: number;
    sha512?: Uint8Array;
    encryption?: Readonly<{
        key: Uint8Array;
        additionalData: Uint8Array;
    }>;
}>;

// The expected manifest is the immutable authenticated predecessor, never the
// next manifest after journals/checkpoints have been removed. This check
// runs inside commitParticipantState's protected readwrite transaction.
export async function validateParticipantPredecessor(
    reader: ParticipantTransactionReader,
    expected: Readonly<{
        head: Readonly<{ generation: number; hash: string }>;
        manifest: Uint8Array;
        rootContext: Uint8Array;
        maximumRootBytes: number;
        recordStores: readonly string[];
        records: readonly ParticipantStoredRecord[];
    }>,
): Promise<void> {
    const equal = (left: Uint8Array, right: Uint8Array) =>
        left.length === right.length &&
        left.every((value, index) => value === right[index]);
    const digest = async (bytes: Uint8Array) =>
        new Uint8Array(
            await crypto.subtle.digest('SHA-512', new Uint8Array(bytes)),
        );
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
            record.byteLength > 1_572_864 ||
            (record.sha512 === undefined && record.encryption === undefined) ||
            (record.sha512 !== undefined && record.sha512.length !== 64) ||
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
        head.generation !== expected.head.generation ||
        head.hash !== expected.head.hash ||
        !(root instanceof Uint8Array) ||
        root.length > expected.maximumRootBytes ||
        !(key instanceof CryptoKey) ||
        key.type !== 'secret' ||
        key.extractable ||
        key.algorithm.name !== 'AES-GCM' ||
        !('length' in key.algorithm) ||
        key.algorithm.length !== 256 ||
        key.usages.slice().sort().join(',') !== 'decrypt,encrypt' ||
        hexadecimal(await digest(root)) !== expected.head.hash
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
    for (const record of expected.records) {
        const blob = await reader.get(record.store, record.key);
        if (!(blob instanceof Blob) || blob.size !== record.byteLength)
            throw new Error('Required predecessor record is missing.');
        const bytes = new Uint8Array(await blob.arrayBuffer());
        try {
            if (record.sha512 !== undefined) {
                if (!equal(await digest(bytes), record.sha512))
                    throw new Error('Predecessor record bytes changed.');
            }
            if (record.encryption !== undefined) {
                const encryption = record.encryption;
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
            }
        } finally {
            bytes.fill(0);
        }
    }
}
