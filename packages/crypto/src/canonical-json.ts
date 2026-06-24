import { shake256 } from '@noble/hashes/sha3.js';
import { bytesToHex } from '@noble/hashes/utils.js';

const textEncoder = new TextEncoder();
const hash512PreimagePrefix = textEncoder.encode('sealed.vote/v1/hash512');

const isCanonicalInteger = (value: number): boolean =>
    Number.isSafeInteger(value) && !Object.is(value, -0);

const isPlainObject = (
    value: unknown,
): value is Readonly<Record<string, unknown>> =>
    typeof value === 'object' &&
    value !== null &&
    !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype;

const hasOwnProperty = (value: object, key: PropertyKey): boolean =>
    Object.prototype.hasOwnProperty.call(value, key);

const containsLoneSurrogate = (value: string): boolean => {
    for (let index = 0; index < value.length; index += 1) {
        const codeUnit = value.charCodeAt(index);
        if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
            const nextCodeUnit = value.charCodeAt(index + 1);
            if (
                index + 1 >= value.length ||
                nextCodeUnit < 0xdc00 ||
                nextCodeUnit > 0xdfff
            ) {
                return true;
            }
            index += 1;
        } else if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {
            return true;
        }
    }

    return false;
};

const normalizeCanonicalString = (value: string): string => {
    // Canonical strings must be surrogate-free and NFC-normalized so that
    // byte-different-but-equivalent inputs cannot collide under the hash.
    if (containsLoneSurrogate(value)) {
        throw new TypeError(
            'Canonical strings cannot contain lone UTF-16 surrogates.',
        );
    }

    return value.normalize('NFC');
};

const serializeCanonicalValue = (value: unknown): string => {
    if (value === null) {
        return 'null';
    }
    if (typeof value === 'string') {
        return JSON.stringify(normalizeCanonicalString(value));
    }
    if (typeof value === 'boolean') {
        return value ? 'true' : 'false';
    }
    if (typeof value === 'number') {
        if (!isCanonicalInteger(value)) {
            throw new TypeError(
                'Canonical numeric fields must be safe integers.',
            );
        }

        return JSON.stringify(value);
    }
    if (Array.isArray(value)) {
        const serializedItems: string[] = [];
        for (let index = 0; index < value.length; index += 1) {
            if (!hasOwnProperty(value, index)) {
                throw new TypeError('Canonical arrays cannot be sparse.');
            }
            serializedItems.push(serializeCanonicalValue(value[index]));
        }

        return `[${serializedItems.join(',')}]`;
    }
    if (isPlainObject(value)) {
        const serializedEntries: {
            readonly key: string;
            readonly value: string;
        }[] = [];
        for (const key of Object.keys(value)) {
            const normalizedKey = normalizeCanonicalString(key);
            if (
                serializedEntries.some((entry) => entry.key === normalizedKey)
            ) {
                throw new TypeError(
                    'Canonical object keys must be unique after NFC normalization.',
                );
            }
            const entry = value[key];
            if (entry === undefined) {
                throw new TypeError(
                    'Canonical objects cannot contain undefined.',
                );
            }
            serializedEntries.push({
                key: normalizedKey,
                value: serializeCanonicalValue(entry),
            });
        }
        // Keys sorted by UTF-16 code-unit comparison (`<`/`>` on JS strings),
        // not code-point or locale order. This ordering is part of the hash
        // contract and must byte-match the Rust kernel.
        serializedEntries.sort((left, right) =>
            left.key < right.key ? -1 : left.key > right.key ? 1 : 0,
        );

        return `{${serializedEntries
            .map((entry) => `${JSON.stringify(entry.key)}:${entry.value}`)
            .join(',')}}`;
    }

    throw new TypeError('Unsupported canonical value.');
};

export const canonicalJson = (value: unknown): string =>
    serializeCanonicalValue(value);

const appendVarUintToHash = (
    hash: ReturnType<typeof shake256.create>,
    value: number,
): void => {
    if (!Number.isSafeInteger(value) || value < 0) {
        throw new TypeError(
            'Varuint values must be non-negative safe integers.',
        );
    }

    // LEB128 unsigned varint. Used as a length prefix so every hashed part is
    // framed (length ‖ bytes); this makes the preimage injective and prevents
    // length-extension / concatenation ambiguity across parts.
    const encodedBytes: number[] = [];
    let remainingValue = value;
    for (;;) {
        let byte = remainingValue & 0x7f;
        remainingValue = Math.floor(remainingValue / 128);
        if (remainingValue !== 0) {
            byte |= 0x80;
        }
        encodedBytes.push(byte);
        if (remainingValue === 0) {
            break;
        }
    }

    hash.update(Uint8Array.from(encodedBytes));
};

const appendBytesToHash = (
    hash: ReturnType<typeof shake256.create>,
    value: Uint8Array,
): void => {
    appendVarUintToHash(hash, value.byteLength);
    hash.update(value);
};

const hash512 = (domain: string, parts: readonly Uint8Array[]): Uint8Array => {
    const hash = shake256.create({ dkLen: 64 });

    try {
        // Security-critical anti-collision preimage layout that every protocol
        // hash relies on, and that must byte-match the Rust kernel:
        //   prefix ‖ len(domain) ‖ domain ‖ count(parts) ‖ (len(part) ‖ part)*
        // The varint length prefixes make the layout unambiguous/injective.
        hash.update(hash512PreimagePrefix);
        appendBytesToHash(hash, textEncoder.encode(domain));
        appendVarUintToHash(hash, parts.length);
        for (const part of parts) {
            appendBytesToHash(hash, part);
        }

        return hash.digest();
    } finally {
        hash.destroy();
    }
};

export const hash512Hex = (
    domain: string,
    parts: readonly Uint8Array[],
): string => bytesToHex(hash512(domain, parts));

export const setupProofMaterialFullObjectHashHex = (
    proofFamily: string,
    totalByteLength: number,
    chunks: readonly Uint8Array[],
): string => {
    if (!Number.isSafeInteger(totalByteLength) || totalByteLength < 0) {
        throw new TypeError(
            'setup proof material totalByteLength must be a non-negative safe integer.',
        );
    }
    if (chunks.length === 0) {
        throw new TypeError(
            'setup proof material full-object hash requires at least one chunk.',
        );
    }

    const hash = shake256.create({ dkLen: 64 });
    try {
        hash.update(hash512PreimagePrefix);
        appendBytesToHash(
            hash,
            textEncoder.encode(
                'sealed-lattice/setup/proof-material/full-object-v1',
            ),
        );
        appendBytesToHash(hash, textEncoder.encode(proofFamily));
        appendVarUintToHash(hash, totalByteLength);
        for (const chunk of chunks) {
            hash.update(chunk);
        }

        return bytesToHex(hash.digest());
    } finally {
        hash.destroy();
    }
};

export type SetupVssMaterialFullObjectHasher = Readonly<{
    update: (chunk: Uint8Array) => void;
    digestHex: () => string;
}>;

// Chunks are concatenated unframed; the digest is injective only because all non-final chunks are exactly the fixed transport chunk size, so totalByteLength recovers the boundaries. Do not call with variable-size chunks.
export const createSetupVssMaterialFullObjectHasher = (
    totalByteLength: number,
): SetupVssMaterialFullObjectHasher => {
    if (!Number.isSafeInteger(totalByteLength) || totalByteLength < 0) {
        throw new TypeError(
            'setup VSS material totalByteLength must be a non-negative safe integer.',
        );
    }

    const hash = shake256.create({ dkLen: 64 });
    let finalized = false;
    hash.update(hash512PreimagePrefix);
    appendBytesToHash(
        hash,
        textEncoder.encode(
            'sealed-lattice/setup/vss-coefficient-commitment-material/full-object-v1',
        ),
    );
    appendVarUintToHash(hash, 1);
    appendVarUintToHash(hash, totalByteLength);

    return {
        update: (chunk: Uint8Array): void => {
            if (finalized) {
                throw new Error(
                    'setup VSS material full-object hash is already finalized.',
                );
            }
            hash.update(chunk);
        },
        digestHex: (): string => {
            if (finalized) {
                throw new Error(
                    'setup VSS material full-object hash is already finalized.',
                );
            }
            finalized = true;

            try {
                return bytesToHex(hash.digest());
            } finally {
                hash.destroy();
            }
        },
    };
};

export const setupVssMaterialFullObjectHashHex = (
    totalByteLength: number,
    chunks: readonly Uint8Array[],
): string => {
    if (!Number.isSafeInteger(totalByteLength) || totalByteLength < 0) {
        throw new TypeError(
            'setup VSS material totalByteLength must be a non-negative safe integer.',
        );
    }
    if (chunks.length === 0) {
        throw new TypeError(
            'setup VSS material full-object hash requires at least one chunk.',
        );
    }

    const hasher = createSetupVssMaterialFullObjectHasher(totalByteLength);
    for (const chunk of chunks) {
        hasher.update(chunk);
    }

    return hasher.digestHex();
};
