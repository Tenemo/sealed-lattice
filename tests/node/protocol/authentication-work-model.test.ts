import { describe, expect, it } from 'vitest';

import {
    authenticationContext,
    authenticationPurposes,
    compileAuthenticationFrameWork,
    compileCompletedAuthenticationCensus,
    pureSignatureFrame,
} from '#tests/authentication-work-model.js';

describe('Authentication frame accounting', () => {
    it('preserves the FIPS pure-mode prefix and unambiguous context boundary', () => {
        expect(pureSignatureFrame(Buffer.from('ab'), Buffer.from('c'))).toEqual(
            Buffer.from([0, 2, 97, 98, 99]),
        );
        expect(pureSignatureFrame(Buffer.from('a'), Buffer.from('bc'))).toEqual(
            Buffer.from([0, 1, 97, 98, 99]),
        );
        expect(pureSignatureFrame(new Uint8Array(), new Uint8Array())).toEqual(
            Buffer.from([0, 0]),
        );
        expect(
            pureSignatureFrame(new Uint8Array(255), Buffer.from([9])),
        ).toHaveLength(258);
        expect(() =>
            pureSignatureFrame(new Uint8Array(256), new Uint8Array()),
        ).toThrow(RangeError);
    });

    it('accounts for the actual digest and envelope message paths separately', () => {
        const roles = compileAuthenticationFrameWork();
        expect(roles.map((role) => role.messageBytes)).toEqual([
            64n,
            64n,
            64n,
            64n,
            64n,
            206n,
        ]);
        for (const role of roles) {
            const frame = pureSignatureFrame(
                Buffer.from(role.context),
                Buffer.alloc(Number(role.messageBytes), 7),
            );
            expect(role.frameBytes).toBe(BigInt(frame.length));
            const input = 64 + frame.length;
            // Count complete rate blocks, including the mandatory padded block.
            let blocks = 1;
            for (let remaining = input; remaining >= 136; remaining -= 136)
                blocks++;
            expect(role.representativePermutations).toBe(BigInt(blocks));
        }
        const frames = authenticationPurposes.map((purpose) =>
            pureSignatureFrame(
                Buffer.from(authenticationContext(purpose)),
                Buffer.alloc(64),
            ).toString('hex'),
        );
        expect(new Set(frames).size).toBe(authenticationPurposes.length);
    });

    it('enumerates signatures without equating the enrollment set with the roster', () => {
        for (let participants = 3; participants <= 20; participants++) {
            for (const extraRegistrations of [0, 1, 21]) {
                for (const ballots of [0, 1, participants]) {
                    const records = ['poll-definition', 'roster-proposal'];
                    for (
                        let position = 0;
                        position < participants + extraRegistrations;
                        position++
                    )
                        records.push('registration');
                    for (let position = 0; position < participants; position++)
                        records.push('roster-confirmation', 'setup-opening');
                    for (let position = 0; position < ballots; position++)
                        records.push('ballot-envelope');
                    const census = compileCompletedAuthenticationCensus(
                        participants,
                        BigInt(participants + extraRegistrations),
                        ballots,
                    );
                    expect(census.signatures).toBe(BigInt(records.length));
                    for (const role of census.roles)
                        expect(role.messages).toBe(
                            BigInt(
                                records.filter(
                                    (record) => record === role.purpose,
                                ).length,
                            ),
                        );
                }
            }
        }
        expect(
            compileCompletedAuthenticationCensus(10, 10n, 10).signatures,
        ).toBe(42n);
        expect(
            compileCompletedAuthenticationCensus(10, 10n, 0).signatures,
        ).toBe(32n);
        for (const values of [
            [2, 2n, 0],
            [21, 21n, 0],
            [10, 9n, 0],
            [10, 10n, -1],
            [10, 10n, 11],
            [10, 10n, 0.5],
        ] as const)
            expect(() =>
                compileCompletedAuthenticationCensus(
                    values[0],
                    values[1],
                    values[2],
                ),
            ).toThrow(RangeError);
    });
});
