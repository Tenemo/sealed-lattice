import { describe, expect, it } from 'vitest';

import {
    authenticationContext,
    pureSignatureFrame,
} from '#tests/authentication-work-model.js';
import { compileStatelessSignatureShakeWork } from '#tests/stateless-signature-shake-model.js';

describe('Stateless signature SHAKE screen', () => {
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
        const emptyFrame = pureSignatureFrame(
            Buffer.from(authenticationContext('registration')),
            new Uint8Array(),
        );
        expect(emptyFrame.length).toBe(32);
        const first = Buffer.alloc(32, 9),
            address = Buffer.alloc(32);
        address.writeUInt32BE(5, 16);
        // In the general byte domains an empty-message frame can occupy the
        // secret-input position of another hash role. This is an overlap
        // witness, not a forgery or an assertion about an honest sampled key.
        const messageRandomization = Buffer.concat([
            first,
            address,
            emptyFrame,
        ]);
        const secretElementFunction = new Uint8Array(96);
        secretElementFunction.set(first);
        new DataView(secretElementFunction.buffer).setUint32(48, 5, false);
        secretElementFunction.set(emptyFrame, 64);
        expect(messageRandomization.equals(secretElementFunction)).toBe(true);
        expect(BigInt(messageRandomization.length)).toBe(
            compileStatelessSignatureShakeWork().fixed.pseudorandomFunction
                .inputBytes,
        );
    });
});
