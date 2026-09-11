import { describe, expect, it } from 'vitest';

import {
    authenticationContext,
    authenticationPurposes,
    compileAuthenticationFrameWork,
    compileCompletedAuthenticationCensus,
    compileCurrentCredentialIntentBounds,
    compileCurrentSignatureHashInputs,
    compileCurrentSignatureSamplingBounds,
    compileSignatureCounterBoundary,
    compileBallotSignatureHashWork,
    pureSignatureFrame,
} from '#tests/authentication-work-model.js';
import { compileContributionBodyCensus } from '#tests/contribution-body-model.js';
import {
    framedProofHashBytes,
    proofHashProfiles,
} from '#tests/proof-hash-work-model.js';
import { compileFixedSpongeInitializationCensus } from '#tests/sponge-initialization-model.js';
import { compileWideChallengeCompilerCensus } from '#tests/wide-challenge-compiler-model.js';

describe('Authentication frame accounting', () => {
    it('derives the checked counter boundary by enumerating nonce blocks', () => {
        const boundary = compileSignatureCounterBoundary();
        let full = 0n,
            partial = 0n;
        for (let start = 0n; start < 65536n; start += 5n) {
            let used = 0n;
            for (
                let position = 0n;
                position < 5n && start + position < 65536n;
                position++
            )
                used++;
            if (used === 5n) full++;
            else partial = used;
        }
        expect(boundary.fullIterations).toBe(full);
        expect(boundary.partialMaskCalls).toBe(partial);
        expect(full * boundary.masksPerIteration + partial).toBe(
            boundary.nonceCapacity,
        );
        const work = compileBallotSignatureHashWork(full, partial);
        expect(
            work.rows.find((row) => row.purpose === 'Mask expansion')?.calls,
        ).toBe(65536n);
        expect(
            work.rows.find(
                (row) => row.purpose === 'Matrix polynomial sampling',
            )?.calls,
        ).toBe(60n);
        expect(work.hashCalls).toBe(75n + 7n * full + partial);
        expect(compileBallotSignatureHashWork(2n).hashCalls).toBe(89n);
        expect(() => compileBallotSignatureHashWork(full + 1n)).toThrow();
        expect(() =>
            compileBallotSignatureHashWork(full, partial + 1n),
        ).toThrow();
        expect(() => compileBallotSignatureHashWork(-1n)).toThrow();
    });
    it('bounds all seed inputs before adaptive selection without a lifetime invocation cap', () => {
        const rows = compileCurrentSignatureSamplingBounds();
        expect(rows.map((row) => row.outputBytes)).toEqual([
            1536n,
            1024n,
            520n,
        ]);
        for (const row of rows) {
            expect(row.inputCount).toBe(1n << (8n * row.inputBytes));
            expect(row.requiredRejections).toBe(
                row.candidatePositions - row.requiredSuccesses + 1n,
            );
            expect(row.numerator << 80n).toBeLessThan(
                1n << row.denominatorBits,
            );
        }
    });
    it('checks the fixed-threshold domination for the increasing challenge sampler', () => {
        for (let tape = 0; tape < 8 ** 5; tape++) {
            let encoded = tape,
                actualSuccesses = 0,
                fixedSuccesses = 0;
            for (let draw = 0; draw < 5; draw++) {
                const value = encoded % 8;
                encoded = Math.floor(encoded / 8);
                if (value <= 5) fixedSuccesses++;
                if (actualSuccesses < 3 && value <= 5 + actualSuccesses)
                    actualSuccesses++;
            }
            expect(actualSuccesses).toBeGreaterThanOrEqual(
                Math.min(3, fixedSuccesses),
            );
        }
    });
    it('keeps exact standard hash-input shapes and leaves unbounded sampler output explicit', () => {
        const signature = compileCurrentSignatureHashInputs();
        expect(signature.highBitEncodingBytes).toBe(768n);
        expect(
            signature.rows.slice(0, 8).map((value) => value.inputBytes),
        ).toEqual([34n, 1952n, 128n, 832n, 48n, 66n, 66n, 34n]);
        expect(
            signature.rows
                .filter((value) => value.outputBytes === null)
                .map((value) => value.purpose),
        ).toEqual([
            'Challenge polynomial sampling',
            'Secret polynomial sampling',
            'Matrix polynomial sampling',
        ]);
        expect(signature.maximumInputBytes).toBeLessThan(
            compileContributionBodyCensus().senderPrefixBytes,
        );
        const messageBytes = BigInt(
            compileWideChallengeCompilerCensus().challengeBytes,
        );
        for (const profile of proofHashProfiles())
            expect(signature.maximumInputBytes).toBeLessThan(
                framedProofHashBytes('bounded-proof/verifier-message', [
                    profile.roleBytes,
                    64n,
                    messageBytes,
                    4n,
                ]),
            );
    });
    it('retains literal matrix-input overlap with the standard challenge sampler', () => {
        const signature = compileCurrentSignatureHashInputs(),
            challenge = signature.rows.find(
                (value) => value.purpose === 'Challenge polynomial sampling',
            )!;
        const aliases = compileFixedSpongeInitializationCensus().seeds.filter(
            (seed) => BigInt(seed.message.length) === challenge.inputBytes,
        );
        expect(aliases.map((seed) => seed.label)).toEqual(
            Array.from({ length: 6 }, (_, gadget) =>
                ['a', 'u', 'k'].map((role) => `common-fhe-${role}-${gadget}`),
            ).flat(),
        );
        expect(challenge.family).toBe('SHAKE256');
        // These are permitted sampler inputs. This does not produce a valid
        // signature or make the common matrices independent oracle functions.
    });
    it('bounds first-evaluated intents separately from delivered ballot counts', () => {
        const [organizer, participant] = compileCurrentCredentialIntentBounds();
        expect(organizer.firstEvaluatedIntentBound).toBe(6n);
        expect(participant.firstEvaluatedIntentBound).toBe(4n);
        expect(participant.purposes).toEqual([
            'registration',
            'roster-confirmation',
            'setup-opening',
            'ballot-envelope',
        ]);
        for (let count = 3; count <= 20; count++) {
            const intentBound =
                organizer.firstEvaluatedIntentBound +
                BigInt(count - 1) * participant.firstEvaluatedIntentBound;
            expect(
                compileCompletedAuthenticationCensus(
                    count,
                    BigInt(count),
                    count,
                ).signatures,
            ).toBe(intentBound);
            // An evaluated ballot signature may never be delivered. The bound
            // cannot be reduced to the accepted or published ballot count.
            expect(
                compileCompletedAuthenticationCensus(count, BigInt(count), 0)
                    .signatures,
            ).toBeLessThan(intentBound);
        }
    });
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
