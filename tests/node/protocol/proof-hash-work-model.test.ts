import { describe, expect, it } from 'vitest';

import {
    byteAlignedSpongePermutations,
    compileProofHashWork,
    framedProofHashBytes,
    proofHashProfiles,
} from '#tests/proof-hash-work-model.js';

describe('proof hash work', () => {
    it('matches explicit suffix padding and block-by-block squeezing', () => {
        for (const rate of [72, 136])
            for (let input = 0; input <= 2 * rate + 1; input++)
                for (const output of [
                    0,
                    1,
                    rate - 1,
                    rate,
                    rate + 1,
                    2 * rate + 1,
                ]) {
                    const padded = Array<number>(input).fill(0);
                    padded.push(rate === 72 ? 0x06 : 0x1f);
                    while (padded.length % rate !== 0) padded.push(0);
                    padded[padded.length - 1] |= 0x80;
                    let expected = padded.length / rate;
                    for (
                        let produced = rate;
                        produced < output;
                        produced += rate
                    )
                        expected++;
                    expect(
                        byteAlignedSpongePermutations(
                            BigInt(input),
                            BigInt(output),
                            BigInt(rate),
                        ),
                    ).toBe(BigInt(expected));
                }
    });

    it('includes every part length, including empty parts', () => {
        expect(framedProofHashBytes('d', [3n, 0n, 5n])).toBe(25n);
        expect(() => framedProofHashBytes('d', [1n << 32n])).toThrow();
        expect(() => byteAlignedSpongePermutations(-1n, 64n, 72n)).toThrow();
    });

    it('matches the deployed per-role layouts while retaining the shared query bound', () => {
        const profiles = proofHashProfiles();
        expect(
            profiles.map((value) => [
                value.role,
                value.firstWidth,
                value.secondWidth,
                value.parameterBytes,
                value.statementBytes,
            ]),
        ).toEqual([
            ['registration', 144n, 288n, 180n, 2752540n],
            ['setup', 5904n, 18240n, 7788n, 342737041n],
            ['ballot', 576n, 1632n, 776n, 28672136n],
            ['release', 1072n, 3504n, 1596n, 8782022n],
        ]);
        expect(profiles.map((value) => value.roleBytes)).toEqual([
            282n,
            272n,
            266n,
            40n,
        ]);
        for (const profile of profiles) {
            const costs = compileProofHashWork(profile);
            expect(costs.verifierCore.queries).toBe(97827n);
            expect(costs.proverCore.queries).toBe(2097187n);
            expect(costs.proverCore.permutations).toBeGreaterThan(
                costs.proverCore.queries,
            );
            expect(costs.verifierCore.permutations).toBeGreaterThan(
                costs.verifierCore.queries,
            );
            expect(
                compileProofHashWork(profile, 1024n).proverCore.permutations,
            ).toBeGreaterThan(costs.proverCore.permutations);
        }
    });

    it('preserves distinct hash inputs even when only their common prefix grows', () => {
        const profile = proofHashProfiles()[0];
        const short = compileProofHashWork(profile, 64n);
        const long = compileProofHashWork(profile, 282n);
        expect(long.proverCore.queries).toBe(short.proverCore.queries);
        expect(long.proverCore.inputBytes).toBeGreaterThan(
            short.proverCore.inputBytes,
        );
        expect(long.proverCore.permutations).toBeGreaterThan(
            short.proverCore.permutations,
        );
        expect(() => compileProofHashWork(profile, 0n)).toThrow();
        expect(() => compileProofHashWork(profile, 1025n)).toThrow();
    });

    it('charges cached prefix initialization while preserving logical queries and inputs', () => {
        const values = proofHashProfiles().map((profile) =>
            compileProofHashWork(profile),
        );
        expect(
            values.map(
                (value) =>
                    value.proverCoreWithoutPrefixReuse.permutations -
                    value.proverCore.permutations,
            ),
        ).toEqual([8387600n, 8387600n, 8387600n, 2096900n]);
        for (const value of values) {
            expect(value.proverCore.queries).toBe(
                value.proverCoreWithoutPrefixReuse.queries,
            );
            expect(value.proverCore.inputBytes).toBe(
                value.proverCoreWithoutPrefixReuse.inputBytes,
            );
            expect(value.proverCore.outputBytes).toBe(
                value.proverCoreWithoutPrefixReuse.outputBytes,
            );
            expect(
                value.groups.reduce(
                    (sum, group) => sum + group.prefixReuse.initializations,
                    0n,
                ),
            ).toBe(225n);
            expect(
                value.groups.reduce(
                    (sum, group) => sum + group.prefixReuse.stateClones,
                    0n,
                ),
            ).toBe(2097125n);
        }
    });
});
