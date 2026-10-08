import { readFile } from 'node:fs/promises';

import { describe, expect, it } from 'vitest';

import {
    authenticationContext,
    authenticationPurposes,
    compileAuthenticationFrameWork,
    compileCompleteAuthenticationFrameWork,
    compileCompleteCredentialIntentBounds,
    compileCompletedAuthenticationCensus,
    compileCurrentCredentialIntentBounds,
    compileCurrentSignatureHashInputs,
    compileCurrentSignatureSamplingBounds,
    compileSignatureCounterBoundary,
    compileBallotSignatureHashWork,
    pureSignatureFrame,
} from '#tests/authentication-work-model.js';
import {
    framedProofHashBytes,
    proofHashProfiles,
} from '#tests/proof-hash-work-model.js';
import { compileSetupSelectionCensus } from '#tests/setup-selection-model.js';
import { compileFixedSpongeInitializationCensus } from '#tests/sponge-initialization-model.js';
import {
    completionProfile,
    completionProfileCounts,
} from '#tests/supported-profile-model.js';
import { compileWideChallengeCompilerCensus } from '#tests/wide-challenge-compiler-model.js';

describe('authentication frame accounting', () => {
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
        expect(signature.maximumInputBytes).toBe(1952n);
        const messageBytes = BigInt(
            compileWideChallengeCompilerCensus(completionProfile())
                .challengeBytes,
        );
        for (const profile of proofHashProfiles(completionProfile()))
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
        const aliases = compileFixedSpongeInitializationCensus(
            completionProfile(),
        ).seeds.filter(
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
        expect(organizer.firstEvaluatedIntentBound).toBe(7n);
        expect(participant.firstEvaluatedIntentBound).toBe(4n);
        expect(participant.purposes).toEqual([
            'registration',
            'contribution-offer',
            'setup-selection-endorsement',
            'ballot-envelope',
        ]);
        for (let count = 3; count <= 20; count++) {
            const intentBound =
                organizer.firstEvaluatedIntentBound +
                BigInt(count - 1) * participant.firstEvaluatedIntentBound -
                BigInt(
                    count - compileSetupSelectionCensus(count).eligibleCount,
                );
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
            64n,
            214n,
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
                    const records = [
                        'poll-definition',
                        'roster-proposal',
                        'setup-selection-proposal',
                    ];
                    for (
                        let position = 0;
                        position < participants + extraRegistrations;
                        position++
                    )
                        records.push('registration');
                    for (let position = 0; position < participants; position++)
                        records.push('setup-selection-endorsement');
                    for (
                        let position = 0;
                        position <
                        compileSetupSelectionCensus(participants).eligibleCount;
                        position++
                    )
                        records.push('contribution-offer');
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
        ).toBe(40n);
        expect(
            compileCompletedAuthenticationCensus(10, 10n, 0).signatures,
        ).toBe(30n);
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

describe('complete participant authentication accounting', () => {
    it('keeps all actual signature purposes in the current hash-input inventory', () => {
        expect(
            compileCurrentSignatureHashInputs()
                .rows.slice(8)
                .map((row) => row.purpose),
        ).toEqual([
            'poll-definition',
            'registration',
            'roster-proposal',
            'contribution-offer',
            'setup-selection-proposal',
            'setup-selection-endorsement',
            'ballot-envelope',
            'close-intent',
            'close-response',
            'close-proposal',
            'target-certification',
            'release-envelope',
        ]);
    });

    it('frames the complete release envelope and the other late purpose identities', () => {
        const roles = compileCompleteAuthenticationFrameWork();
        expect(roles.map((role) => role.messageBytes)).toEqual([
            64n,
            64n,
            64n,
            64n,
            64n,
            64n,
            214n,
            64n,
            64n,
            64n,
            64n,
            270n,
        ]);
        for (const role of roles.slice(7)) {
            const context = Buffer.from(role.context);
            const message = Buffer.alloc(
                role.purpose === 'release-envelope' ? 270 : 64,
                7,
            );
            const expected = Buffer.concat([
                Buffer.from([0, context.length]),
                context,
                message,
            ]);
            expect(pureSignatureFrame(context, message)).toEqual(expected);
            expect(role.frameBytes).toBe(BigInt(expected.length));
            expect(role.representativeInputBytes).toBe(
                BigInt(64 + expected.length),
            );
            let permutations = 1n;
            for (
                let remaining = 64 + expected.length;
                remaining >= 136;
                remaining -= 136
            )
                permutations++;
            expect(role.representativePermutations).toBe(permutations);
        }
    });

    it('counts an optional ballot and one close response under the retained-state locks', () => {
        const rows = compileCompleteCredentialIntentBounds(
            completionProfileCounts.participantCount,
        );
        // Organizer: six setup purposes, three close purposes, then target
        // and release as the branch allows. Others: three setup purposes and
        // one close response. Each row adds the optional ballot.
        expect(rows.map((row) => row.firstEvaluatedIntentBound)).toEqual([
            12n,
            7n,
            11n,
            6n,
            11n,
            6n,
        ]);
        for (const row of rows) {
            expect(row.participantCount).toBe(10);
            expect(row.optionalPurposes).toEqual(['ballot-envelope']);
            expect(row.fixedPurposes).not.toContain('ballot-envelope');
            expect(
                row.fixedPurposes.filter(
                    (purpose) => purpose === 'close-response',
                ),
            ).toHaveLength(1);
            for (const purpose of ['close-intent', 'close-proposal'] as const)
                expect(row.fixedPurposes.includes(purpose)).toBe(
                    row.role === 'organizer',
                );
            expect(new Set(row.fixedPurposes).size).toBe(
                row.fixedPurposes.length,
            );
        }
    });

    it('omits release for no result and permits release without an own target vote', () => {
        const rows = compileCompleteCredentialIntentBounds(
            completionProfileCounts.participantCount,
        );
        for (const row of rows.filter(
            (candidate) => candidate.branch === 'No result',
        )) {
            expect(row.fixedPurposes).not.toContain('release-envelope');
            expect(row.fixedPurposes).toContain('target-certification');
        }
        for (const row of rows.filter(
            (candidate) =>
                candidate.branch ===
                'Encrypted release without own target vote',
        )) {
            expect(row.fixedPurposes).not.toContain('target-certification');
            expect(row.fixedPurposes).toContain('release-envelope');
        }
    });

    it('preserves the separate through-ballot census used by retained prefix evidence', () => {
        expect(compileAuthenticationFrameWork()).toHaveLength(7);
        expect(
            compileCurrentCredentialIntentBounds().map(
                (row) => row.firstEvaluatedIntentBound,
            ),
        ).toEqual([7n, 4n]);
    });
    it('matches the original poll, registration and clear-preparation signature contexts', async () => {
        const roles = compileCompleteAuthenticationFrameWork();
        for (const [purpose, file, name] of [
            ['poll-definition', 'poll.rs', 'POLL_SIGNATURE_CONTEXT'],
            ['registration', 'lib.rs', 'REGISTRATION_SIGNATURE_CONTEXT'],
            [
                'roster-proposal',
                'roster-authentication.rs',
                'ROSTER_SIGNATURE_CONTEXT',
            ],
            ['contribution-offer', 'contribution-offer.rs', 'OFFER_PURPOSE'],
            [
                'setup-selection-proposal',
                'setup-selection.rs',
                'PROPOSAL_CONTEXT',
            ],
            [
                'setup-selection-endorsement',
                'setup-selection.rs',
                'ENDORSEMENT_PURPOSE',
            ],
        ] as const) {
            const source = await readFile(
                new URL(
                    '../../../crates/protocol-research/protocol-foundations/src/' +
                        file,
                    import.meta.url,
                ),
                'utf8',
            );
            const actual = source.match(
                new RegExp('pub const ' + name + ': [^=]+ = b?"([^"]+)";', 'u'),
            );
            expect(actual).not.toBeNull();
            expect(
                roles.find((role) => role.purpose === purpose)!.context,
            ).toBe(actual![1]);
        }
        expect(roles[0].context).toBe('sealed-lattice/poll-definition/v2');
        expect(roles[1].context).toBe('sealed-lattice/registration/v1');
    });
});
