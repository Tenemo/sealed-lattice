import {
    littleEndian,
    word32,
    protocolHash,
} from '#tests/word-proof-reference/transcript.js';

export const merkleLeaf = (
    role: Uint8Array,
    stage: number,
    position: number,
    salt: Uint8Array,
    data: Uint8Array,
) =>
    protocolHash('bounded-proof/leaf', [
        role,
        word32(stage),
        word32(position),
        salt,
        data,
    ]);

export const merkleNode = (
    role: Uint8Array,
    stage: number,
    level: number,
    left: Uint8Array,
    right: Uint8Array,
) =>
    protocolHash('bounded-proof/node', [
        role,
        word32(stage),
        word32(level),
        left,
        right,
    ]);

// A Merkle tree over one stage's leaves, numbered as a heap: the root is
// node one and leaf i is node L+i.
export const merkleTree = (
    role: Uint8Array,
    stage: number,
    leaves: readonly Uint8Array[],
    salts: readonly Uint8Array[],
) => {
    const length = leaves.length;
    const nodes = new Array<Buffer>(2 * length);
    leaves.forEach((data, index) => {
        nodes[length + index] = merkleLeaf(
            role,
            stage,
            index,
            salts[index],
            data,
        );
    });
    for (let node = length - 1, level = 1, start = length / 2; node >= 1;) {
        nodes[node] = merkleNode(
            role,
            stage,
            level,
            nodes[2 * node],
            nodes[2 * node + 1],
        );
        node--;
        if (node < start) {
            level++;
            start /= 2;
        }
    }
    // Openings of the sorted positions with the sibling labels the verifier
    // does not yet hold.
    const open = (positions: readonly number[]) => {
        const authenticated = new Set<number>();
        const parts: Uint8Array[] = [word32(positions.length)];
        for (const position of positions) {
            parts.push(word32(position), leaves[position], salts[position]);
            for (
                let node = length + position;
                node > 1 && !authenticated.has(node);
                node >>= 1
            ) {
                authenticated.add(node);
                if (!authenticated.has(node ^ 1)) {
                    parts.push(nodes[node ^ 1]);
                    authenticated.add(node ^ 1);
                }
            }
        }
        return Buffer.concat(parts);
    };
    return { root: nodes[1], open };
};

export const encodeBase = (value: bigint) => littleEndian(value, 16);
