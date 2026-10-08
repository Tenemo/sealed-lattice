import type { ParticipantSession } from './contribution.js';
import { recordKeyBytes, tagBytes } from './runtime-bounds.js';
import { readParticipantValue } from './storage.js';
import type { ParticipantStore } from './storage.js';

// Every private record beneath the authenticated root is sealed once under its
// own fresh AES-256-GCM key with the zero nonce.

// What a private record after setup verification is bound to besides its
// coordinates: the poll, the runtime, the setup identity and the
// participant.
export type RecordContext = Readonly<{
    poll: Uint8Array;
    runtime: Uint8Array;
    setupIdentity: Uint8Array;
    position: number;
}>;

export const recordContext = (
    session: ParticipantSession,
    setupIdentity: Uint8Array,
): RecordContext => ({
    poll: session.root.manifest.poll,
    runtime: session.context.runtime,
    setupIdentity,
    position: session.records.position,
});

const recordCipher = (key: Uint8Array, usage: 'encrypt' | 'decrypt') =>
    crypto.subtle.importKey('raw', new Uint8Array(key), 'AES-GCM', false, [
        usage,
    ]);

export const sealRecord = async (
    additionalData: Uint8Array,
    bytes: Uint8Array,
) => {
    const key = crypto.getRandomValues(new Uint8Array(recordKeyBytes));
    const ciphertext = new Uint8Array(
        await crypto.subtle.encrypt(
            {
                name: 'AES-GCM',
                iv: new Uint8Array(12),
                additionalData: new Uint8Array(additionalData),
            },
            await recordCipher(key, 'encrypt'),
            new Uint8Array(bytes),
        ),
    );
    return { key, ciphertext };
};

export const sealedLength = (length: number) => length + tagBytes;

// A record sealed under a fresh key at its index among the records its
// stage lists, written with the root that lists it.
export type SealedRecord = Readonly<{
    index: number;
    key: Uint8Array;
    ciphertext: Uint8Array;
}>;

// Opens a record's ciphertext under its listed key and associated data.
export const openSealedRecord = async (
    key: Uint8Array,
    additionalData: Uint8Array,
    ciphertext: Uint8Array<ArrayBuffer>,
) =>
    new Uint8Array(
        await crypto.subtle.decrypt(
            {
                name: 'AES-GCM',
                iv: new Uint8Array(12),
                additionalData: new Uint8Array(additionalData),
            },
            await recordCipher(key, 'decrypt'),
            ciphertext,
        ),
    );

// Reads one record at its store key and opens it under its listed key.
export const openRecord = async (
    database: IDBDatabase,
    store: ParticipantStore,
    storeKey: IDBValidKey,
    record: Readonly<{ key: Uint8Array; additionalData: Uint8Array }>,
    length: number,
) => {
    const blob = await readParticipantValue(database, store, storeKey);
    if (!(blob instanceof Blob) || blob.size !== sealedLength(length))
        throw new Error('A private participant record is missing.');
    return openSealedRecord(
        record.key,
        record.additionalData,
        new Uint8Array(await blob.arrayBuffer()),
    );
};
