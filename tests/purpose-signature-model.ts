import { createHash } from 'node:crypto';

import { protocolHashPrefix } from '#tests/word-proof-reference/transcript.js';

// An independent model of the plain Winternitz purpose signature on Node's
// FIPS 202 SHAKE256. Every hash is the fixed-length protocol digest of a
// literal domain followed by its unframed fixed-layout parts.
const digestBytes = 64;
const base = 16;
const largestDigit = base - 1;
const messageDigits = (8 * digestBytes) / Math.log2(base);
const checksumDigits = (() => {
    let digits = 0;
    for (let value = messageDigits * largestDigit; value > 0; value >>= 4)
        digits += 1;
    return digits;
})();

export const purposeSignatureContexts = [
    'poll-definition',
    'registration',
    'roster-proposal',
    'contribution-offer',
    'setup-selection-proposal',
    'setup-selection-endorsement',
    'ballot-envelope',
    'close-intent',
    'close-response',
    'close-proposal',
    'target-certification',
    'release-envelope',
].map((name) => `sealed-lattice/${name}`);
const leaves = 2 ** Math.ceil(Math.log2(purposeSignatureContexts.length));
const treeLevels = Math.log2(leaves);

export const purposeSignatureChains = messageDigits + checksumDigits;
export const purposeSignatureBytes =
    2 + (purposeSignatureChains + treeLevels) * digestBytes;

const hash = (domain: string, ...parts: Uint8Array[]) =>
    createHash('shake256', { outputLength: digestBytes })
        .update(protocolHashPrefix)
        .update(domain, 'ascii')
        .update(Buffer.concat(parts))
        .digest();

const chain = (value: Buffer, steps: number) => {
    for (let step = 0; step < steps; step++)
        value = hash('purpose-wots/chain/v1', value);
    return value;
};

const chainStart = (seed: Uint8Array, purpose: number, index: number) => {
    const position = Buffer.alloc(2);
    position.writeUInt16LE(index);
    return hash(
        'purpose-wots/secret/v1',
        seed,
        Uint8Array.of(purpose),
        position,
    );
};

const encodedDigits = (representative: Uint8Array) => {
    const digits = [...representative].flatMap((byte) => [
        byte >> 4,
        byte & 15,
    ]);
    let checksum = digits.reduce((sum, digit) => sum + largestDigit - digit, 0);
    const tail: number[] = [];
    for (let index = 0; index < checksumDigits; index++) {
        tail.unshift(checksum % base);
        checksum = Math.floor(checksum / base);
    }
    return [...digits, ...tail];
};

const representativeOf = (
    root: Uint8Array,
    purpose: number,
    message: Uint8Array,
) => {
    const length = Buffer.alloc(8);
    length.writeBigUInt64LE(BigInt(message.length));
    return hash(
        'purpose-wots/message/v1',
        root,
        Uint8Array.of(purpose),
        length,
        message,
    );
};

const leaf = (purpose: number, publicKey: Uint8Array) =>
    hash('purpose-wots/leaf/v1', Uint8Array.of(purpose), publicKey);

const parent = (level: number, left: Uint8Array, right: Uint8Array) =>
    hash('purpose-wots/node/v1', Uint8Array.of(level), left, right);

const chainEnds = (seed: Uint8Array, purpose: number) =>
    Buffer.concat(
        Array.from({ length: purposeSignatureChains }, (_, index) =>
            chain(chainStart(seed, purpose, index), largestDigit),
        ),
    );

const leafLayer = (seed: Uint8Array) =>
    Array.from({ length: leaves }, (_, purpose) =>
        purpose >= purposeSignatureContexts.length
            ? hash('purpose-wots/unused/v1', Uint8Array.of(purpose))
            : leaf(purpose, chainEnds(seed, purpose)),
    );

const treeLayers = (seed: Uint8Array) => {
    const layers = [leafLayer(seed)];
    for (let level = 0; level < treeLevels; level++) {
        const below = layers[level];
        layers.push(
            Array.from({ length: below.length / 2 }, (_, index) =>
                parent(level, below[2 * index], below[2 * index + 1]),
            ),
        );
    }
    return layers;
};

export const purposeSignatureRoot = (seed: Uint8Array) =>
    treeLayers(seed)[treeLevels][0];

export const signPurpose = (
    seed: Uint8Array,
    purpose: number,
    message: Uint8Array,
) => {
    if (
        !Number.isInteger(purpose) ||
        purpose < 0 ||
        purpose >= purposeSignatureContexts.length
    )
        throw new Error('The purpose has no signing context.');
    const layers = treeLayers(seed);
    const representative = representativeOf(
        layers[treeLevels][0],
        purpose,
        message,
    );
    const values = encodedDigits(representative).map((digit, index) =>
        chain(chainStart(seed, purpose, index), digit),
    );
    const path = layers
        .slice(0, treeLevels)
        .map((layer, level) => layer[(purpose >> level) ^ 1]);
    return Buffer.concat([Uint8Array.of(1, purpose), ...values, ...path]);
};

export const verifyPurpose = (
    root: Uint8Array,
    purpose: number,
    message: Uint8Array,
    signature: Uint8Array,
) => {
    if (
        !Number.isInteger(purpose) ||
        purpose < 0 ||
        purpose >= purposeSignatureContexts.length ||
        signature.length !== purposeSignatureBytes ||
        signature[0] !== 1 ||
        signature[1] !== purpose
    )
        return false;
    const value = (index: number) =>
        Buffer.from(
            signature.subarray(
                2 + index * digestBytes,
                2 + (index + 1) * digestBytes,
            ),
        );
    const publicKey = Buffer.concat(
        encodedDigits(representativeOf(root, purpose, message)).map(
            (digit, index) => chain(value(index), largestDigit - digit),
        ),
    );
    let node = leaf(purpose, publicKey);
    for (let level = 0; level < treeLevels; level++) {
        const sibling = value(purposeSignatureChains + level);
        node =
            ((purpose >> level) & 1) === 0
                ? parent(level, node, sibling)
                : parent(level, sibling, node);
    }
    return node.equals(root);
};
