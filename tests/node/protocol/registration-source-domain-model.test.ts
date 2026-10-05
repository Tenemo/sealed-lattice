import { expect, it } from 'vitest';

import {
    compileOracleMaskRouting,
    runOracleSliceRouting,
} from '#tests/compressed-oracle-model.js';
import { compileRegistrationSetupBindingScreen } from '#tests/registration-setup-binding-model.js';
import {
    registrationSourceMask,
    registrationSourceSliceMask,
} from '#tests/registration-source-domain-model.js';
import { compileRegistrationSourceRandomness } from '#tests/registration-source-randomness-model.js';

const uint = (width: number, value: number | bigint) => {
    const bytes = Buffer.alloc(width);
    if (width === 2) bytes.writeUInt16LE(Number(value));
    else if (width === 4) bytes.writeUInt32LE(Number(value));
    else bytes.writeBigUInt64LE(BigInt(value));
    return bytes;
};
const field = (type: number, bytes: Buffer) =>
    Buffer.concat([uint(2, type), uint(4, bytes.length), bytes]);
const variable = (bytes: Buffer) =>
    Buffer.concat([uint(4, bytes.length), bytes]);
const frame = (
    owner: Buffer,
    modulus: Buffer,
    sampleBits: bigint,
    coordinate: Buffer,
) =>
    Buffer.concat([
        Buffer.from('0100010008000000', 'hex'),
        field(2, variable(Buffer.from('sealed-lattice/registered-fhe-key/v1'))),
        field(1, owner),
        field(1, Buffer.alloc(64, 3)),
        field(6, Buffer.alloc(64, 5)),
        field(6, Buffer.alloc(64, 7)),
        field(1, variable(modulus)),
        field(4, uint(8, sampleBits)),
        field(1, variable(coordinate)),
    ]);

it('routes raw source families and salts without reordering or aliasing their oracle inputs', () => {
    const owner = Buffer.alloc(1952, 11);
    const modulus = Buffer.from([253, 1]);
    const otherModulus = Buffer.from([251, 1]);
    const degree = 4;
    const first = registrationSourceMask(owner, modulus, 128n, degree);
    const second = registrationSourceMask(owner, otherModulus, 128n, degree);
    const masks = [first, second].map((source) =>
        registrationSourceSliceMask(source, Buffer.alloc(64, 3)),
    );
    expect(masks[0].positions.length).toBe(Number(first.comparedRawBits) + 512);
    const capacity = masks[0].inputLength + 8;
    const compiled = compileOracleMaskRouting(capacity, 2, masks);
    const coordinate = Buffer.alloc(degree * 3, 19);
    const original = frame(owner, modulus, 128n, coordinate);
    const run = (bytes: Buffer, requested = 2) => {
        const data = Uint8Array.from(
            { length: capacity },
            (_, bit) => ((bytes[Math.floor(bit / 8)] ?? 0) >> (bit % 8)) & 1,
        );
        return runOracleSliceRouting(
            compiled,
            data,
            bytes.length * 8,
            requested,
        );
    };
    expect(run(original)).toEqual([0, 2, 0]);
    // Identical owner and salt are still disjoint because the family fields
    // after the salt belong to the exact predicate.
    expect(run(frame(owner, otherModulus, 128n, coordinate))).toEqual([
        0, 0, 2,
    ]);
    expect(run(frame(owner, Buffer.from([249, 1]), 128n, coordinate))).toEqual([
        2, 0, 0,
    ]);
    const changedSalt = Buffer.from(original);
    changedSalt[first.saltOffset] ^= 1;
    expect(run(changedSalt)).toEqual([2, 0, 0]);
    const malformed = Buffer.from(original);
    malformed[0] ^= 1;
    expect(run(malformed)).toEqual([2, 0, 0]);
    expect(run(Buffer.concat([original, Buffer.of(0)]))).toEqual([2, 0, 0]);
    expect(run(original.subarray(0, original.length - 1))).toEqual([2, 0, 0]);
    // Raw-domain membership leaves payload validity to the protocol verifier.
    expect(
        run(frame(owner, modulus, 128n, Buffer.alloc(degree * 3, 255))),
    ).toEqual([0, 2, 0]);
    expect(run(original, 3)).toEqual([0, 0, 0]);
});

// An independent length-delimited decoder, not the mask's offsets.
const decode = (bytes: Buffer, degree: number) => {
    if (
        bytes.length < 8 ||
        bytes.readUInt16LE() !== 1 ||
        bytes.readUInt16LE(2) !== 1 ||
        bytes.readUInt32LE(4) !== 8
    )
        return undefined;
    let offset = 8;
    const fields: { type: number; bytes: Buffer }[] = [];
    for (let index = 0; index < 8; index++) {
        if (offset + 6 > bytes.length) return undefined;
        const type = bytes.readUInt16LE(offset),
            length = bytes.readUInt32LE(offset + 2);
        offset += 6;
        if (offset + length > bytes.length) return undefined;
        fields.push({ type, bytes: bytes.subarray(offset, offset + length) });
        offset += length;
    }
    if (
        offset !== bytes.length ||
        fields.some(
            (value, index) => value.type !== [2, 1, 1, 6, 6, 1, 4, 1][index],
        )
    )
        return undefined;
    const unwrap = (value: Buffer) =>
        value.length >= 4 && value.readUInt32LE() === value.length - 4
            ? value.subarray(4)
            : undefined;
    const domain = unwrap(fields[0].bytes),
        modulus = unwrap(fields[5].bytes),
        coordinate = unwrap(fields[7].bytes);
    if (
        domain?.toString() !== 'sealed-lattice/registered-fhe-key/v1' ||
        fields[1].bytes.length !== 1952 ||
        fields[2].bytes.length !== 64 ||
        fields[3].bytes.length !== 64 ||
        fields[4].bytes.length !== 64 ||
        fields[6].bytes.length !== 8 ||
        modulus === undefined ||
        coordinate?.length !== degree * (modulus.length + 1)
    )
        return undefined;
    return {
        owner: fields[1].bytes,
        modulus,
        sampleBits: fields[6].bytes.readBigUInt64LE(),
    };
};

it('matches an independent raw decoder including every framing and owner bit, malformed inputs and unvalidated coordinate payloads', () => {
    const owner = Buffer.alloc(1952, 11),
        modulus = Buffer.from([253, 1]),
        sampleBits = 128n,
        degree = 4;
    const bytes = frame(
        owner,
        modulus,
        sampleBits,
        Buffer.alloc(degree * (modulus.length + 1), 255),
    );
    const mask = registrationSourceMask(owner, modulus, sampleBits, degree);
    const expected = (value: Buffer) => {
        const decoded = decode(value, degree);
        return (
            decoded !== undefined &&
            decoded.owner.equals(owner) &&
            decoded.modulus.equals(modulus) &&
            decoded.sampleBits === sampleBits
        );
    };
    expect(mask.matches(bytes)).toBe(true);
    for (let index = 0; index < bytes.length; index++) {
        for (let bit = 0; bit < 8; bit++) {
            bytes[index] ^= 1 << bit;
            expect(
                mask.matches(bytes),
                `byte ${String(index)}, bit ${String(bit)}`,
            ).toBe(expected(bytes));
            bytes[index] ^= 1 << bit;
        }
    }
    for (const value of [
        bytes.subarray(0, bytes.length - 1),
        Buffer.concat([bytes, Buffer.of(0)]),
        Buffer.alloc(0),
        Buffer.from(bytes).reverse(),
    ]) {
        expect(mask.matches(value)).toBe(false);
        expect(expected(value)).toBe(false);
    }
    expect(mask.comparedRawBits).toBe(
        BigInt(bytes.length - 64 - 128 - degree * (modulus.length + 1)) * 8n,
    );
    expect(mask.comparedCellBits).toBe(
        mask.comparedRawBits +
            mask.inputClassUpper +
            1n -
            8n * BigInt(bytes.length),
    );
});

it('derives source-mask operands from the independently modeled complete registration families', () => {
    for (const [maximum, options] of [
        [3, 2],
        [10, 10],
        [20, 20],
    ]) {
        const inventory = compileRegistrationSetupBindingScreen(
            maximum,
            options,
        );
        const work = compileRegistrationSourceRandomness(maximum, options);
        for (const [index, family] of inventory.fhe.entries()) {
            const hex = family.modulus
                .toString(16)
                .padStart(
                    2 * Math.ceil(family.modulus.toString(16).length / 2),
                    '0',
                );
            const modulus = Buffer.from(hex, 'hex').reverse();
            const mask = registrationSourceMask(
                Buffer.alloc(1952),
                modulus,
                BigInt(family.sampleBits),
                65536,
            );
            expect(BigInt(mask.inputBytes)).toBe(
                work.families[index].commitmentInputBytes,
            );
            expect(mask.comparedRawBits).toBe(
                8n *
                    (work.families[index].commitmentInputBytes -
                        192n -
                        family.publicCoordinateBytes),
            );
            expect(mask.inputClassUpper).toBeGreaterThanOrEqual(
                8n * BigInt(mask.inputBytes),
            );
            expect(mask.inputClassUpper / 2n).toBeLessThan(
                8n * BigInt(mask.inputBytes),
            );
        }
    }
});

// DFMS21 Definition 4.1 maximizes over the complete extraction function,
// including malformed inputs and targets the protocol never requests.
const extractionMultiplicities = (
    inputs: readonly string[],
    outputBits: number,
    image: (input: string, output: number) => string,
) => {
    const outputs = Array.from(
        { length: 2 ** outputBits },
        (_, index) => index,
    );
    let maximumFibre = 0;
    let maximumOtherInputFibre = 0;
    for (const input of inputs) {
        for (const referenceInput of inputs) {
            for (const referenceOutput of outputs) {
                const target = image(referenceInput, referenceOutput);
                const count = outputs.filter(
                    (output) => image(input, output) === target,
                ).length;
                maximumFibre = Math.max(maximumFibre, count);
                if (input !== referenceInput)
                    maximumOtherInputFibre = Math.max(
                        maximumOtherInputFibre,
                        count,
                    );
            }
        }
    }
    return { maximumFibre, maximumOtherInputFibre };
};

it.each([1, 2, 3])(
    'preserves extraction ratios for a %i-bit prefix with independent unused tails',
    (prefixBits) => {
        const sources = new Map([
            ['first coordinate', ['owner-a', 'family-a']],
            ['second coordinate', ['owner-a', 'family-a']],
            ['other owner', ['owner-b', 'family-a']],
            ['other family', ['owner-a', 'family-b']],
        ]);
        const inputs = [...sources.keys(), 'truncated input', 'unknown family'];
        for (const tailBits of [0, 1, 2]) {
            const image = (input: string, output: number) => {
                const prefix = output >>> tailBits;
                const source = sources.get(input);
                return JSON.stringify(
                    source
                        ? ['source', ...source, prefix]
                        : ['other', input, prefix],
                );
            };
            const actual = extractionMultiplicities(
                inputs,
                prefixBits + tailBits,
                image,
            );
            // Distinct coordinates of the same original owner/family attain
            // the cross-input maximum. A raw complement input retains its
            // own disjoint target label, including the requested prefix.
            expect(actual).toEqual({
                maximumFibre: 2 ** tailBits,
                maximumOtherInputFibre: 2 ** tailBits,
            });
            // An unused constant bottom target is unsafe even if extraction
            // never requests it: both source maxima range over that target.
            const constantBottom = extractionMultiplicities(
                inputs,
                prefixBits + tailBits,
                (input, output) =>
                    sources.has(input) ? image(input, output) : 'bottom',
            );
            expect(constantBottom).toEqual({
                maximumFibre: 2 ** (prefixBits + tailBits),
                maximumOtherInputFibre: 2 ** (prefixBits + tailBits),
            });
        }
    },
);
