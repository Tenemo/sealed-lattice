import { chunkBytes } from '../../module/runtime-bounds.js';
import type { ParticipantProfile } from '../../module/runtime-bounds.js';
import { encodeText, equalBytes, readUnsigned64 } from '../../shared/bytes.js';

export type ProofBounds = Pick<
    ParticipantProfile['contribution'],
    'minimumProofBytes' | 'maximumProofBytes' | 'bodyHeaderBytes'
>;
export type ProofSlot = Readonly<{ offset: number; length: number }>;

// The private record plan depends only on the authenticated profile. The
// final slot has the profile's remainder, even when the proof ends earlier.
export const proofRecordLayout = (bounds: ProofBounds): ProofSlot[] =>
    Array.from(
        { length: Math.ceil(bounds.maximumProofBytes / chunkBytes) },
        (_unused, index) => ({
            offset: index * chunkBytes,
            length: Math.min(
                chunkBytes,
                bounds.maximumProofBytes - index * chunkBytes,
            ),
        }),
    );

const checkProofLength = (bounds: ProofBounds, length: number) => {
    if (
        bounds.bodyHeaderBytes !== 4 + 8 + 64 ||
        !Number.isSafeInteger(length) ||
        length < bounds.minimumProofBytes ||
        length > bounds.maximumProofBytes
    )
        throw new Error('The contribution proof has an invalid length.');
};

// This fixed-width authenticated body header is the only retained carrier
// of the actual proof length. Physical record lengths always follow the plan.
export const proofLength = (bounds: ProofBounds, header: Uint8Array) => {
    if (
        bounds.bodyHeaderBytes !== 4 + 8 + 64 ||
        header.length !== bounds.bodyHeaderBytes ||
        !equalBytes(header.subarray(0, 4), encodeText('SCB2'))
    )
        throw new Error('The contribution body header is malformed.');
    const length = readUnsigned64(header, 4);
    if (
        length < BigInt(bounds.minimumProofBytes) ||
        length > BigInt(bounds.maximumProofBytes)
    )
        throw new Error('The retained proof has an invalid length.');
    return Number(length);
};

export const createProofWriter = (
    bounds: ProofBounds,
    store: (slot: ProofSlot, bytes: Uint8Array) => Promise<void>,
) => {
    const slots = proofRecordLayout(bounds);
    const buffer = new Uint8Array(chunkBytes);
    let next = 0;
    let used = 0;
    let length = 0;
    let closed = false;
    const close = () => {
        closed = true;
        buffer.fill(0);
    };
    const appendSlot = async () => {
        const slot = slots[next];
        if (slot === undefined || used > slot.length)
            throw new Error('The contribution proof exceeds its record plan.');
        buffer.fill(0, used, slot.length);
        await store(slot, buffer.subarray(0, slot.length));
        buffer.fill(0);
        next++;
        used = 0;
    };
    return {
        append: async (bytes: Uint8Array) => {
            if (closed)
                throw new Error('The contribution proof writer is closed.');
            try {
                if (bytes.length > bounds.maximumProofBytes - length)
                    throw new Error('The proof exceeds its bound.');
                length += bytes.length;
                for (let offset = 0; offset < bytes.length;) {
                    const slot = slots[next];
                    if (slot === undefined)
                        throw new Error('The proof exceeds its record plan.');
                    const count = Math.min(
                        bytes.length - offset,
                        slot.length - used,
                    );
                    buffer.set(bytes.subarray(offset, offset + count), used);
                    used += count;
                    offset += count;
                    if (used === slot.length) await appendSlot();
                }
            } catch (error) {
                close();
                throw error;
            }
        },
        finish: async () => {
            if (closed)
                throw new Error('The contribution proof writer is closed.');
            try {
                checkProofLength(bounds, length);
                while (next < slots.length) await appendSlot();
                return length;
            } finally {
                close();
            }
        },
        close,
    };
};

// Every planned slot is authenticated by the owning reader and checked for
// zero padding before this pass completes. Consumers receive only the
// framed proof prefix; commitment completion waits for the whole pass.
export const readProof = async (
    bounds: ProofBounds,
    header: Uint8Array,
    read: (slot: ProofSlot, index: number) => Promise<Uint8Array>,
    consume: (offset: number, bytes: Uint8Array) => void | Promise<void>,
) => {
    const length = proofLength(bounds, header);
    for (const [index, slot] of proofRecordLayout(bounds).entries()) {
        const bytes = await read(slot, index);
        try {
            if (bytes.length !== slot.length)
                throw new Error('A private proof record has another length.');
            const used = Math.min(
                slot.length,
                Math.max(0, length - slot.offset),
            );
            if (bytes.subarray(used).some((value) => value !== 0))
                throw new Error('The private proof padding is nonzero.');
            if (used > 0) await consume(slot.offset, bytes.subarray(0, used));
        } finally {
            bytes.fill(0);
        }
    }
};
