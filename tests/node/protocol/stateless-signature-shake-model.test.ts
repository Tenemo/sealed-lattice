import { describe, expect, it } from 'vitest';

import {
    authenticationContext,
    pureSignatureFrame,
} from '#tests/authentication-work-model.js';
import {
    compileStatelessSignatureShakeWork,
    labelledSignatureContext,
    labelledSignaturePrfRoute,
} from '#tests/stateless-signature-shake-model.js';

describe('Stateless signature SHAKE screen', () => {
    it('routes actual byte fields to one public label without reading the secret', () => {
        const publicSeed = Uint8Array.from(
                { length: 32 },
                (_, index) => index * 13 + 7,
            ),
            secret = Buffer.alloc(32, 23),
            randomizer = Buffer.alloc(32, 19);
        for (const role of compileStatelessSignatureShakeWork().roles) {
            const context = labelledSignatureContext(role.purpose, publicSeed);
            const message = Buffer.alloc(
                Number(role.frameBytes) - 2 - context.length,
                11,
            );
            const frame = pureSignatureFrame(context, message),
                input = Buffer.concat([secret, randomizer, frame]);
            const expected = {
                kind: 'message-randomization',
                publicSeed,
                secretOffset: 0,
            };
            expect(labelledSignaturePrfRoute(input)).toEqual(expected);
            const changed = Uint8Array.from(input);
            changed[0] ^= 1;
            expect(labelledSignaturePrfRoute(changed)).toEqual(expected);
            const malformed = Uint8Array.from(input);
            malformed[65] ^= 1;
            expect(labelledSignaturePrfRoute(malformed)).toBeUndefined();
            expect(
                labelledSignaturePrfRoute(
                    Buffer.concat([input, Buffer.from([0])]),
                ),
            ).toBeUndefined();
            const hashInput = Buffer.concat([
                randomizer,
                publicSeed,
                Buffer.alloc(32, 31),
                frame,
            ]);
            expect(labelledSignaturePrfRoute(hashInput)).toBeUndefined();
        }
        for (const type of [5, 6]) {
            const address = Buffer.alloc(32);
            address.writeUInt32BE(type, 16);
            const input = Buffer.concat([publicSeed, address, secret]);
            expect(labelledSignaturePrfRoute(input)).toEqual({
                kind: 'secret-element',
                publicSeed,
                secretOffset: 64,
            });
            input[64] ^= 1;
            expect(labelledSignaturePrfRoute(input)?.publicSeed).toEqual(
                publicSeed,
            );
            input.writeUInt32BE(3, 48);
            expect(labelledSignaturePrfRoute(input)).toBeUndefined();
        }
    });
    it('counts the complete input padding for each fixed function and actual frame', () => {
        const value = compileStatelessSignatureShakeWork();
        for (const work of [
            ...Object.values(value.fixed),
            ...value.roles.flatMap((role) => [
                role.randomization,
                role.messageHash,
            ]),
        ]) {
            const bytes = Array<number>(Number(work.inputBytes)).fill(0);
            bytes.push(0x1f);
            while (bytes.length % 136 !== 0) bytes.push(0);
            bytes[bytes.length - 1] |= 0x80;
            expect(work.permutations).toBe(BigInt(bytes.length / 136));
            expect(work.outputBytes).toBeLessThan(136n);
        }
        expect(value.keyGeneration.permutations).toBe(17439n);
        expect(value.roles[0].signingUpper.permutations).toBe(350180n);
        expect(value.roles[5].signingUpper.permutations).toBe(350182n);
        expect(value.roles[0].verificationUpper.permutations).toBe(17803n);
        expect(value.roles[5].verificationUpper.permutations).toBe(17804n);
        expect(value.ordinaryScreenUpper.permutations).toBe(2225340n);
    });
    it('separates currently emitted message roles and fixed address domains', () => {
        const value = compileStatelessSignatureShakeWork();
        const fixed = Object.values(value.fixed);
        for (let left = 0; left < fixed.length; left++)
            for (let right = left + 1; right < fixed.length; right++) {
                expect(
                    fixed[left].inputBytes !== fixed[right].inputBytes ||
                        fixed[left].addressTypes.every(
                            (type) => !fixed[right].addressTypes.includes(type),
                        ),
                ).toBe(true);
            }
        const randomizationLengths = new Set(
            value.roles.map((role) => role.randomization.inputBytes),
        );
        const hashLengths = new Set(
            value.roles.map((role) => role.messageHash.inputBytes),
        );
        expect(
            [...randomizationLengths].filter((length) =>
                hashLengths.has(length),
            ),
        ).toEqual([]);
        for (const work of fixed) {
            expect(randomizationLengths.has(work.inputBytes)).toBe(false);
            expect(hashLengths.has(work.inputBytes)).toBe(false);
        }
    });
    it('does not extend that length-separation claim to unrestricted messages', () => {
        const publicSeed = Buffer.alloc(32, 9),
            context = labelledSignatureContext('registration', publicSeed);
        const compressionBytes = Number(
            compileStatelessSignatureShakeWork().fixed.forestCompression
                .inputBytes,
        );
        const frame = pureSignatureFrame(
            context,
            new Uint8Array(compressionBytes - 64 - 2 - context.length),
        );
        const first = Buffer.alloc(32, 9),
            address = Buffer.alloc(32);
        address.writeUInt32BE(4, 16);
        // An unrestricted valid message frame can occupy the complete forest
        // root-vector input. This is a domain-overlap witness, not a forgery.
        const messageRandomization = Buffer.concat([first, address, frame]);
        const compression = new Uint8Array(compressionBytes);
        compression.set(first);
        new DataView(compression.buffer).setUint32(48, 4, false);
        compression.set(frame, 64);
        expect(messageRandomization.equals(compression)).toBe(true);
        expect(BigInt(messageRandomization.length)).toBe(
            compileStatelessSignatureShakeWork().fixed.forestCompression
                .inputBytes,
        );
    });
    it('derives a bounded context from the public key and preserves exact framing', () => {
        const seed = Uint8Array.from(
            { length: 32 },
            (_, index) => index * 7 + 3,
        );
        const context = labelledSignatureContext('registration', seed);
        const prefix = Buffer.from(authenticationContext('registration'));
        expect(context.subarray(0, prefix.length)).toEqual(prefix);
        expect(context[prefix.length]).toBe(0);
        expect(context.subarray(prefix.length + 1)).toEqual(Buffer.from(seed));
        expect(context.length).toBeLessThanOrEqual(255);
        const frame = pureSignatureFrame(context, new Uint8Array(64));
        expect(frame.subarray(0, 2)).toEqual(Buffer.from([0, context.length]));
        expect(BigInt(frame.length)).toBe(
            compileStatelessSignatureShakeWork().roles[1].frameBytes,
        );
        const changed = seed.slice();
        changed[31] ^= 1;
        expect(labelledSignatureContext('registration', changed)).not.toEqual(
            context,
        );
        expect(() =>
            labelledSignatureContext('registration', seed.subarray(1)),
        ).toThrow(RangeError);
    });
});
