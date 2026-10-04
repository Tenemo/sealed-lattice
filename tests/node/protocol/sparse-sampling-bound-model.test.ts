import { readFile } from 'node:fs/promises';

import { describe, expect, it } from 'vitest';

import {
    boundSparseSupportSampling,
    compileSparseSupportSamplingCensus,
} from '#tests/sparse-sampling-bound-model.js';
import { completionProfile } from '#tests/supported-profile-model.js';

// Exact occupancy recurrence: each unselected label advances the state; every
// already selected label repeats it. Completed paths absorb all later draws.
const incompleteTapes = (degree: number, support: number, draws: number) => {
    let counts = Array<bigint>(support + 1).fill(0n);
    counts[0] = 1n;
    for (let draw = 0; draw < draws; draw++) {
        const next = Array<bigint>(support + 1).fill(0n);
        for (let selected = 0; selected <= support; selected++) {
            if (selected === support)
                next[selected] += counts[selected] * BigInt(degree);
            else {
                next[selected] += counts[selected] * BigInt(selected);
                next[selected + 1] +=
                    counts[selected] * BigInt(degree - selected);
            }
        }
        counts = next;
    }
    return counts.slice(0, support).reduce((sum, count) => sum + count, 0n);
};

describe('bounded sparse-support sampling comparison', () => {
    it('matches the independently maintained browser reader and sampling call sites', async () => {
        const read = (name: string) =>
            readFile(
                new URL(
                    '../../../crates/protocol-research/' + name,
                    import.meta.url,
                ),
                'utf8',
            );
        const [reader, source, contribution, registration, shared] =
            await Promise.all([
                read('setup-witness/src/browser_random.rs'),
                read('setup-witness/src/lib.rs'),
                read('setup-witness/src/contribution.rs'),
                read('setup-witness/src/registration.rs'),
                read('supported-profile/src/lib.rs'),
            ]);
        const profile = completionProfile();
        const rows = compileSparseSupportSamplingCensus(profile);
        const bufferBytes = BigInt(
            reader.match(/vec!\[0; ([\d_]+)\]/u)![1].replace(/_/gu, ''),
        );
        expect(
            rows.every((value) => value.browserBufferBytes === bufferBytes),
        ).toBe(true);
        expect(source).toContain('let mut bytes = [0; 4];');
        expect(source).toContain('u32::from_le_bytes(bytes) as usize % degree');
        expect(source).toContain('if selected < support / 2 { 1 } else { -1 }');
        // Degrees and supports are named constants of the shared profile
        // crate.
        const constant = (name: string) =>
            BigInt(
                shared
                    .match(
                        new RegExp(
                            'pub const ' + name + ': usize = ([\\d_]+);',
                            'u',
                        ),
                    )![1]
                    .replace(/_/gu, ''),
            );
        expect(
            rows
                .slice(0, 3)
                .every((value) => value.degree === constant('DEGREE')),
        ).toBe(true);
        expect(rows[3].degree).toBe(constant('AUXILIARY_DEGREE'));
        expect(contribution.match(/witness\.sparse\(/gu)).toHaveLength(4);
        expect(registration.match(/witness\.sparse\(/gu)).toHaveLength(1);
        const support = (code: string, label: string) =>
            constant(
                code.match(
                    new RegExp(
                        'witness\\.sparse\\(\\s*"' +
                            label +
                            '",\\s*[A-Z_]+,\\s*([A-Z_]+),',
                        'u',
                    ),
                )![1],
            );
        expect(support(registration, 'registration-secret')).toBe(
            rows[0].support,
        );
        // The standalone new() constructor still samples its own original
        // key. Active enrollment supplies it through from_source instead.
        expect(support(contribution, 'fhe-secret')).toBe(rows[1].support);
        expect(contribution).toContain(
            'witness.sparse_from_values(values, &plan)',
        );
        expect(rows[1].callsPerOperation).toBe(1n);
        expect(support(contribution, 'fhe-auxiliary')).toBe(rows[1].support);
        expect(support(contribution, 'auxiliary-secret')).toBe(rows[3].support);
        // One share-encryption ephemeral per roster position.
        const ephemerals = contribution.match(
            /\(0\.\.profile\.participants\(\)\)\s*\.map\(\|index\| \{\s*witness\.sparse\(\s*&format!\("share-ephemeral-\{index\}"\),\s*DEGREE,\s*([A-Z_]+),/u,
        )!;
        expect(rows[2].callsPerOperation).toBe(
            BigInt(profile.participantCount),
        );
        expect(constant(ephemerals[1])).toBe(rows[2].support);
    });

    it('bounds exact occupancy tails across small and dense alphabets', () => {
        for (const degree of [2, 4, 8, 16])
            for (let support = 2; support <= degree; support += 2) {
                const value = boundSparseSupportSampling(
                    BigInt(degree),
                    BigInt(support),
                );
                const failures = incompleteTapes(degree, support, 2 * support);
                const tapes = BigInt(degree) ** BigInt(2 * support);
                expect(failures * value.denominator).toBeLessThanOrEqual(
                    value.numerator * tapes,
                );
                expect(value.numerator).toBeLessThanOrEqual(value.denominator);
            }
    });

    it('preserves uniform balanced signs among completed finite tapes', () => {
        const degree = 4,
            support = 2,
            draws = 4;
        const completed = new Map<string, number>();
        let unfinished = 0;
        for (let tape = 0; tape < degree ** draws; tape++) {
            let digits = tape;
            const positions: number[] = [];
            for (let draw = 0; draw < draws; draw++) {
                const position = digits % degree;
                digits = Math.floor(digits / degree);
                if (positions.length < support && !positions.includes(position))
                    positions.push(position);
            }
            if (positions.length < support) unfinished++;
            else {
                const signed = Array<number>(degree).fill(0);
                positions.forEach((position, index) => {
                    signed[position] = index < support / 2 ? 1 : -1;
                });
                const key = signed.join(',');
                completed.set(key, (completed.get(key) ?? 0) + 1);
            }
        }
        expect(unfinished).toBe(4);
        expect(completed.size).toBe(12);
        expect([...completed.values()]).toEqual(Array(12).fill(21));
    });

    it('charges full browser fills and independently recomputes the emitted bounds', () => {
        const rows = compileSparseSupportSamplingCensus(completionProfile());
        expect(
            rows.map((value) => [
                value.degree,
                value.support,
                value.callsPerOperation,
            ]),
        ).toEqual([
            [65_536n, 256n, 1n],
            [65_536n, 1024n, 1n],
            [65_536n, 256n, 10n],
            [4096n, 256n, 1n],
        ]);
        for (const [index, bits] of [1536n, 4096n, 1536n, 512n].entries()) {
            const value = rows[index];
            expect(value.numerator << bits).toBeLessThan(value.denominator);
            expect(value.maximumExaminedBytes).toBeLessThan(65_520n);
            expect(value.maximumBrowserRandomBytes).toBe(65_520n);
        }
        expect(
            boundSparseSupportSampling(65_536n, 16_384n)
                .maximumBrowserRandomBytes,
        ).toBe(196_560n);
    });

    it.each([
        [3n, 2n],
        [8n, 3n],
        [4n, 6n],
        [4n, 0n],
        [1n << 33n, 2n],
    ])(
        'refuses degree %s and support %s when modulo or balanced support would differ',
        (degree, support) => {
            expect(() => boundSparseSupportSampling(degree, support)).toThrow();
        },
    );
});
