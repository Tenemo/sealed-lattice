import { chunkBytes } from '../../module/runtime-bounds.js';
import type { ParticipantProfile } from '../../module/runtime-bounds.js';
import { readUnsigned64 } from '../../shared/bytes.js';

type ProofBounds = Pick<
    ParticipantProfile['contribution'],
    'minimumProofBytes' | 'maximumProofBytes' | 'bodyHeaderBytes'
>;
type ProofSlot = Readonly<{ offset: number; length: number }>;

// Completed records are determined by the authenticated proof length.
export const proofRecordLayout = (
    bounds: ProofBounds,
    length: number,
): ProofSlot[] => {
    checkProofLength(bounds, length);
    return Array.from(
        { length: Math.ceil(length / chunkBytes) },
        (_unused, index) => ({
            offset: index * chunkBytes,
            length: Math.min(chunkBytes, length - index * chunkBytes),
        }),
    );
};

const checkProofLength = (bounds: ProofBounds, length: number) => {
    if (
        bounds.bodyHeaderBytes !== 8 + 64 ||
        !Number.isSafeInteger(length) ||
        length < bounds.minimumProofBytes ||
        length > bounds.maximumProofBytes
    )
        throw new Error('The contribution proof has an invalid length.');
};

// The existing authenticated body header remains the sole length carrier.
export const proofLength = (bounds: ProofBounds, header: Uint8Array) => {
    if (
        bounds.bodyHeaderBytes !== 8 + 64 ||
        header.length !== bounds.bodyHeaderBytes
    )
        throw new Error('The contribution body header is malformed.');
    const length = readUnsigned64(header, 0);
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
    const buffer = new Uint8Array(chunkBytes);
    let stored = 0;
    let used = 0;
    let length = 0;
    let closed = false;
    const close = () => {
        closed = true;
        buffer.fill(0);
    };
    const appendSlot = async () => {
        if (used === 0) return;
        await store({ offset: stored, length: used }, buffer.subarray(0, used));
        stored += used;
        buffer.fill(0);
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
                    const count = Math.min(
                        bytes.length - offset,
                        chunkBytes - used,
                    );
                    buffer.set(bytes.subarray(offset, offset + count), used);
                    used += count;
                    offset += count;
                    if (used === chunkBytes) await appendSlot();
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
                await appendSlot();
                return length;
            } finally {
                close();
            }
        },
        close,
    };
};

// Every required slot is authenticated by the owning reader. Completion
// waits for the complete exact-length proof, including its final record.
export const readProof = async (
    bounds: ProofBounds,
    header: Uint8Array,
    read: (slot: ProofSlot, index: number) => Promise<Uint8Array>,
    consume: (offset: number, bytes: Uint8Array) => void | Promise<void>,
) => {
    const length = proofLength(bounds, header);
    for (const [index, slot] of proofRecordLayout(bounds, length).entries()) {
        const bytes = await read(slot, index);
        try {
            if (bytes.length !== slot.length)
                throw new Error('A private proof record has another length.');
            await consume(slot.offset, bytes);
        } finally {
            bytes.fill(0);
        }
    }
};
