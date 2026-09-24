import { describe, expect, it } from 'vitest';

import { decodeTerminalOutput } from '#tools/ci/protocol-terminal-output.js';

const word = (value: number) => {
    const bytes = Buffer.alloc(4);
    bytes.writeUInt32LE(value);
    return bytes;
};
const encode = (identifiers: readonly string[]) =>
    Buffer.concat([
        word(identifiers.length),
        ...identifiers.flatMap((identifier) => {
            const bytes = Buffer.from(identifier, 'utf8');
            return [word(bytes.length), bytes];
        }),
    ]);

describe('owning-kernel terminal output framing', () => {
    it('preserves short, complete and empty outputs without inventing omitted ranks', () => {
        for (const identifiers of [
            [],
            ['option-7'],
            ['option-4', 'option-1', 'option-8'],
            Array.from({ length: 20 }, (_, index) => `option-${index}`),
            ['wybór-ż', '選択'],
            ['\ufeffoption-4', 'option-\ufeff7'],
        ]) {
            const bytes = encode(identifiers);
            // Decode a nonzero-offset view as well as a complete buffer.
            const framed = Buffer.concat([Buffer.from([123]), bytes]);
            expect(decodeTerminalOutput(framed.subarray(1))).toEqual(
                identifiers,
            );
        }
    });

    it('refuses truncated, oversized, empty-identifier and non-UTF8 encodings', () => {
        const valid = encode(['option-2', 'option-0']);
        for (const bytes of [
            Buffer.alloc(3),
            Buffer.alloc(1_048_577),
            word(0xffff_ffff),
            valid.subarray(0, valid.length - 1),
            Buffer.concat([valid, Buffer.from([0])]),
            Buffer.concat([word(1), word(0)]),
            Buffer.concat([word(1), word(0xffff_ffff), Buffer.from([65])]),
            Buffer.concat([word(1), word(2), Buffer.from([0xc0, 0xaf])]),
        ])
            expect(() => decodeTerminalOutput(bytes)).toThrow();
    });
});
