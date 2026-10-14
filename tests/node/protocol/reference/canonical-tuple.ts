import {
    readRustSource,
    rustEnumCodes,
    rustIntegerConstant,
} from '#tests/node/rust-source.js';

// An encoder of the canonical tuple format for test fixtures. It shares no
// code with the models or the participant module. Only the item type codes
// and the tuple header are read from the production codec, so fixtures carry
// the bytes the real hashes absorb.

const codec = 'crates/protocol-research/protocol-foundations/src/foundation/';
const itemCodes = rustEnumCodes(
    await readRustSource(codec + 'canonical-tuple/value.rs'),
    'CanonicalItemType',
);
const tupleConstants = await readRustSource(codec + 'canonical-tuple.rs');

const itemCode = (name: string) => {
    if (!(name in itemCodes))
        throw new Error(`The codec defines no item type ${name}.`);
    return itemCodes[name];
};

export const itemType = {
    rawBytes: itemCode('RawBytes'),
    ascii: itemCode('Ascii'),
    unsigned16: itemCode('Unsigned16'),
    unsigned64: itemCode('Unsigned64'),
    hash512: itemCode('Hash512'),
} as const;

const schemaIdentifier = rustIntegerConstant(
    tupleConstants,
    'CANONICAL_TUPLE_SCHEMA_IDENTIFIER',
);

// The little-endian encoding of a nonnegative integer in exactly this many
// bytes. A value that does not fit is refused.
export const unsigned = (value: bigint | number, byteCount: number): Buffer => {
    let remaining = BigInt(value);
    if (remaining < 0n) throw new RangeError(`${String(value)} is negative.`);
    const encoded = Buffer.alloc(byteCount);
    for (let index = 0; index < byteCount; index++) {
        encoded[index] = Number(remaining & 255n);
        remaining >>= 8n;
    }
    if (remaining !== 0n)
        throw new RangeError(
            `${String(value)} does not fit in ${String(byteCount)} bytes.`,
        );
    return encoded;
};

// A value after its four-byte length.
export const variable = (value: Uint8Array): Buffer =>
    Buffer.concat([unsigned(value.length, 4), value]);

// One item: its two-byte type code, the four-byte length of its value, and
// the value.
export const item = (type: number, value: Uint8Array): Buffer =>
    Buffer.concat([unsigned(type, 2), unsigned(value.length, 4), value]);

// An ASCII item. Text outside printable ASCII is refused.
export const ascii = (text: string): Buffer => {
    if (!/^[\x20-\x7e]*$/u.test(text))
        throw new RangeError(`Not printable ASCII: ${text}`);
    return item(itemType.ascii, variable(Buffer.from(text, 'ascii')));
};

// A tuple: the schema identifier and the item count, then the items.
export const tuple = (items: readonly Uint8Array[]): Buffer =>
    Buffer.concat([
        unsigned(schemaIdentifier, 2),
        unsigned(items.length, 4),
        ...items,
    ]);
