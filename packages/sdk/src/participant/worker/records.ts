import type { ParticipantSession } from './contribution.js';
import { retainedSetupInventory } from './setup.js';
import { readParticipantValue } from './storage.js';
import type { ParticipantStore } from './storage.js';

// Private records beneath the authenticated root after setup verification.
// Each is sealed once under its own fresh AES-256-GCM key with the zero
// nonce; its associated data binds the poll, the runtime, the setup
// inventory, the participant and the record's coordinates.
export type RecordContext = Readonly<{
    poll: Uint8Array;
    runtime: Uint8Array;
    inventory: Uint8Array;
    position: number;
}>;

export const recordKeyBytes = 32;
const tagBytes = 16;

export const recordContext = async (
    session: ParticipantSession,
): Promise<RecordContext> => ({
    poll: session.root.manifest.poll,
    runtime: session.context.runtime,
    inventory: await retainedSetupInventory(session),
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

// Reads one record at its store key and opens it under its listed key.
export const openRecord = async (
    database: IDBDatabase,
    store: ParticipantStore,
    storeKey: IDBValidKey,
    record: Readonly<{ key: Uint8Array; additionalData: Uint8Array }>,
    length: number,
) => {
    const blob = await readParticipantValue(database, store, storeKey);
    if (!(blob instanceof Blob) || blob.size !== length + tagBytes)
        throw new Error('A private participant record is missing.');
    return new Uint8Array(
        await crypto.subtle.decrypt(
            {
                name: 'AES-GCM',
                iv: new Uint8Array(12),
                additionalData: new Uint8Array(record.additionalData),
            },
            await recordCipher(record.key, 'decrypt'),
            new Uint8Array(await blob.arrayBuffer()),
        ),
    );
};

export const sealedLength = (length: number) => length + tagBytes;
