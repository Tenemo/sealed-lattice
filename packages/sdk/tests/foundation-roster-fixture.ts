// Independent canonical-wire fixture. These are structural public-key bytes,
// not generated signing/encryption keys and not protocol participation evidence.
const join = (parts: readonly Uint8Array[]): Uint8Array => {
    const output = new Uint8Array(
        parts.reduce((size, part) => size + part.length, 0),
    );
    let offset = 0;
    for (const part of parts) {
        output.set(part, offset);
        offset += part.length;
    }
    return output;
};
const unsigned = (value: number, width: 2 | 4): Uint8Array => {
    const output = new Uint8Array(width);
    const view = new DataView(output.buffer);
    if (width === 2) view.setUint16(0, value, true);
    else view.setUint32(0, value, true);
    return output;
};
const tuple = (
    schema: number,
    items: readonly (readonly [number, Uint8Array])[],
) =>
    join([
        unsigned(schema, 2),
        unsigned(1, 2),
        unsigned(items.length, 4),
        ...items.map(([type, value]) =>
            join([unsigned(type, 2), unsigned(value.length, 4), value]),
        ),
    ]);

export const createFoundationRosterFixture = (
    participantCount: number,
): Uint8Array => {
    const entries = Array.from({ length: participantCount }, (_, position) => {
        const signingKey = new Uint8Array(1952);
        signingKey[0] = position + 1;
        const mailboxKey = new Uint8Array(1184);
        mailboxKey[1152] = position + 1;
        return tuple(0x0114, [
            [3, unsigned(position, 2)],
            [1, signingKey],
            [1, mailboxKey],
        ]);
    });
    return tuple(0x0115, [
        [14, join([unsigned(9, 2), unsigned(participantCount, 4), ...entries])],
    ]);
};
