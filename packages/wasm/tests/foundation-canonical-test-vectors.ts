const unsigned16LittleEndian = (value: number): Uint8Array => {
    const bytes = new Uint8Array(2);
    new DataView(bytes.buffer).setUint16(0, value, true);
    return bytes;
};

const unsigned32LittleEndian = (value: number): Uint8Array => {
    const bytes = new Uint8Array(4);
    new DataView(bytes.buffer).setUint32(0, value, true);
    return bytes;
};

const concatenateBytes = (...chunks: readonly Uint8Array[]): Uint8Array => {
    const byteLength = chunks.reduce(
        (total, chunk) => total + chunk.byteLength,
        0,
    );
    const bytes = new Uint8Array(byteLength);
    let offset = 0;
    for (const chunk of chunks) {
        bytes.set(chunk, offset);
        offset += chunk.byteLength;
    }
    return bytes;
};

const canonicalItem = (
    itemType: number,
    canonicalBytes: Uint8Array,
): Uint8Array =>
    concatenateBytes(
        unsigned16LittleEndian(itemType),
        unsigned32LittleEndian(canonicalBytes.byteLength),
        canonicalBytes,
    );

const variableBytes = (bytes: Uint8Array): Uint8Array =>
    concatenateBytes(unsigned32LittleEndian(bytes.byteLength), bytes);

const textEncoder = new TextEncoder();

const ballotOptionDefinition = (displayTextBytes: Uint8Array): Uint8Array =>
    concatenateBytes(
        unsigned16LittleEndian(0x0111),
        unsigned16LittleEndian(1),
        unsigned32LittleEndian(3),
        canonicalItem(0x03, unsigned16LittleEndian(0)),
        canonicalItem(
            0x02,
            variableBytes(textEncoder.encode('canonical-option')),
        ),
        canonicalItem(0x0c, variableBytes(displayTextBytes)),
    );

export type FoundationDisplayTextVector = {
    readonly name: string;
    readonly canonicalBytes: Uint8Array;
};

const validDisplayText = (
    name: string,
    value: string,
): FoundationDisplayTextVector => ({
    name,
    canonicalBytes: ballotOptionDefinition(textEncoder.encode(value)),
});

const invalidDisplayText = (
    name: string,
    bytes: Uint8Array,
): FoundationDisplayTextVector => ({
    name,
    canonicalBytes: ballotOptionDefinition(bytes),
});

/**
 * Canonical Unicode 17 vectors shared verbatim by the real-WASM Node and
 * browser suites. Canonical-object verification validates stabilized NFC; it
 * never normalizes producer bytes.
 */
export const validFoundationDisplayTextVectors = [
    validDisplayText('ASCII', 'Canonical label'),
    validDisplayText('precomposed Latin', 'Caf\u00e9'),
    validDisplayText('precomposed Hangul', '\uac00'),
    validDisplayText('ordered combining marks', '\u1ea1\u0301'),
    validDisplayText('assigned supplementary scalar', '\u{10000}'),
    validDisplayText('assigned emoji', '\u{1fae9}'),
    validDisplayText('basic private use', 'label-\ue000'),
    validDisplayText('supplementary private use', 'label-\u{10fffd}'),
] as const satisfies readonly FoundationDisplayTextVector[];

export const invalidFoundationDisplayTextVectors = [
    invalidDisplayText(
        'decomposed Latin is not NFC',
        textEncoder.encode('Cafe\u0301'),
    ),
    invalidDisplayText(
        'decomposed Hangul is not NFC',
        textEncoder.encode('\u1100\u1161'),
    ),
    invalidDisplayText(
        'canonically decomposable Angstrom sign is not NFC',
        textEncoder.encode('\u212b'),
    ),
    invalidDisplayText(
        'Unicode 17 unassigned scalar',
        textEncoder.encode('\u0378'),
    ),
    invalidDisplayText(
        'basic multilingual plane noncharacter',
        textEncoder.encode('\ufdd0'),
    ),
    invalidDisplayText(
        'supplementary noncharacter',
        textEncoder.encode('\u{10ffff}'),
    ),
    invalidDisplayText(
        'UTF-8 surrogate encoding',
        Uint8Array.from([0xed, 0xa0, 0x80]),
    ),
    invalidDisplayText(
        'overlong UTF-8 encoding',
        Uint8Array.from([0xc0, 0xaf]),
    ),
    invalidDisplayText(
        'truncated UTF-8 encoding',
        Uint8Array.from([0xe2, 0x82]),
    ),
] as const satisfies readonly FoundationDisplayTextVector[];
