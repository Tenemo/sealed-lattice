import { equalBytes, hexadecimal } from './bytes.js';
import type { ParticipantContext } from './context.js';
import { custodyIdentity, custodyPurpose } from './identity.js';
import { openRoot, rootAssociatedData } from './root.js';
import type { AuthenticatedRoot } from './root.js';
import {
    isParticipantHead,
    isRootKey,
    participantStores,
    snapshotParticipant,
} from './storage.js';
import type { ParticipantHead, ParticipantStore } from './storage.js';

// Delivery of a completed message's retained, already signed parts. The
// participant's retained authority is inspected before the first transfer
// and after every transfer, whether the transfer succeeded or failed: the
// stored key must still open exactly the root this operation holds, the stored
// head must name it, no stop marker may exist, and every store must hold as
// many records as when the delivery began. A failed inspection ends the
// delivery before any further read or transfer and takes precedence over the
// transfer's own failure. A plaintext copy read for a transfer is cleared
// before the inspection that follows it, and each inspection clears the
// root plaintext it opened.

export type RetainedAuthority = Readonly<{
    head: ParticipantHead;
    plaintext: Uint8Array;
    rootContext: Uint8Array;
    counts: Readonly<Record<ParticipantStore, number>>;
}>;

const changed = () =>
    new Error('The participant authority changed during delivery.');

export const inspectRetainedAuthority = async (
    database: IDBDatabase,
    expected: RetainedAuthority,
    rootIdentity: (bytes: Uint8Array) => Uint8Array | Promise<Uint8Array>,
) => {
    const snapshot = await snapshotParticipant(database);
    if (
        !isRootKey(snapshot.key) ||
        !(snapshot.root instanceof Uint8Array) ||
        !isParticipantHead(snapshot.head) ||
        snapshot.head.generation !== expected.head.generation ||
        snapshot.head.hash !== expected.head.hash ||
        snapshot.head.runtime !== expected.head.runtime ||
        participantStores.some(
            (store) => snapshot.counts[store] !== expected.counts[store],
        ) ||
        hexadecimal(await rootIdentity(snapshot.root)) !== expected.head.hash
    )
        throw changed();
    let plaintext: Uint8Array;
    try {
        plaintext = await openRoot(
            snapshot.key,
            snapshot.head.generation,
            expected.rootContext,
            snapshot.root,
        );
    } catch {
        throw changed();
    }
    try {
        if (!equalBytes(plaintext, expected.plaintext)) throw changed();
    } finally {
        plaintext.fill(0);
    }
};

export type Delivery = Readonly<{
    transfer: (
        send: () => Promise<void>,
        plaintext?: Uint8Array,
    ) => Promise<void>;
}>;

// Inspects once before the first transfer and returns the guarded transfer.
export const guardDelivery = async (
    inspect: () => Promise<void>,
): Promise<Delivery> => {
    await inspect();
    return {
        transfer: async (send, plaintext) => {
            let failed = false;
            let failure: unknown;
            try {
                await send();
            } catch (error) {
                failed = true;
                failure = error;
            }
            plaintext?.fill(0);
            await inspect();
            if (failed) throw failure;
        },
    };
};

// Opens a delivery under the root this operation holds. Its stores must hold the
// root's own data records and the record counts the caller requires.
export const openDelivery = async (
    context: ParticipantContext,
    root: AuthenticatedRoot,
    required: Readonly<Partial<Record<ParticipantStore, number>>> = {},
): Promise<Delivery> => {
    const { counts } = await snapshotParticipant(context.database);
    if (
        counts.key !== 1 ||
        counts.root !== 1 ||
        counts.head !== 1 ||
        counts.stopped !== 0 ||
        counts.data !== root.manifest.references.length ||
        participantStores.some(
            (store) =>
                required[store] !== undefined &&
                counts[store] !== required[store],
        )
    )
        throw new Error('Missing or inconsistent participant authority.');
    const expected: RetainedAuthority = {
        head: root.head,
        plaintext: root.plaintext,
        rootContext: rootAssociatedData(context.runtime),
        counts,
    };
    return guardDelivery(() =>
        inspectRetainedAuthority(context.database, expected, (bytes) =>
            custodyIdentity(context.module, custodyPurpose.root, bytes),
        ),
    );
};
