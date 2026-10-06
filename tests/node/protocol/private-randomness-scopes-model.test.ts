import { readFile } from 'node:fs/promises';

import { describe, expect, it } from 'vitest';

import { compilePrivateRandomnessScopes } from '#tests/operation-seed-model.js';

// Enumerate original seed identities and their consumers independently of
// the census formulas. Replaying one identity does not create another seed.
const enumerate = (
    sources: number,
    contributions: number,
    ballots: number,
    releases: number,
    replay: boolean,
) => {
    const seeds = new Set<string>(),
        initialized = new Set<string>(),
        read = new Set<string>();
    const root = (identity: string, domains: readonly [string, boolean][]) => {
        seeds.add(identity);
        for (const [domain, used] of domains) {
            initialized.add(`${identity}:${domain}`);
            if (used) read.add(`${identity}:${domain}`);
        }
    };
    const proof = (identity: string) => {
        // Three initial trees, then one after each fold except the terminal
        // constant. Derive the fold tree schedule from the native domain.
        for (const name of ['first', 'second', 'linear'])
            root(`${identity}:${name}`, [['salt', true]]);
        for (let domain = 262144 / 2; domain > 2; domain /= 2)
            root(`${identity}:fold:${domain}`, [['salt', true]]);
    };
    for (let visit = 0; visit < (replay ? 3 : 1); visit++) {
        for (let source = 0; source < sources; source++)
            root(`source:${source}`, [['source', true]]);
        for (let author = 0; author < contributions; author++) {
            root(`contribution:${author}:generation`, [
                ['witness', true],
                ['proof', true],
            ]);
            root(`contribution:${author}:continuation`, [
                ['witness', false],
                ['proof', true],
            ]);
            proof(`contribution:${author}`);
        }
        for (let author = 0; author < ballots; author++) {
            root(`ballot:${author}`, [
                ['encryption', true],
                ['proof', true],
            ]);
            proof(`ballot:${author}`);
        }
        for (let author = 0; author < releases; author++) {
            root(`release:${author}`, [['proof', true]]);
            proof(`release:${author}`);
        }
    }
    return { seeds, initialized, read };
};

describe('Original private-randomness scope populations', () => {
    it('separates seed draws, read domains and unused continuation domains', () => {
        for (const values of [
            [0, 0, 0, 0],
            [1, 0, 0, 0],
            [5, 2, 0, 0],
            [11, 0, 4, 0],
            [13, 3, 7, 4],
        ] as const) {
            const [sources, contributions, ballots, releases] = values;
            const actual = compilePrivateRandomnessScopes(
                BigInt(sources),
                BigInt(contributions),
                BigInt(ballots),
                BigInt(releases),
            );
            const original = enumerate(
                    sources,
                    contributions,
                    ballots,
                    releases,
                    false,
                ),
                replayed = enumerate(
                    sources,
                    contributions,
                    ballots,
                    releases,
                    true,
                );
            expect(BigInt(original.seeds.size)).toBe(actual.maximumSeedDraws);
            expect(BigInt(original.initialized.size)).toBe(
                actual.maximumInitializedScopes,
            );
            expect(BigInt(original.read.size)).toBe(actual.maximumReadScopes);
            expect(replayed).toEqual(original);
            expect(
                actual.maximumInitializedScopes - actual.maximumReadScopes,
            ).toBe(BigInt(contributions));
            let pairs = 0n;
            const identities = [...original.seeds];
            for (let first = 0; first < identities.length; first++)
                for (
                    let second = first + 1;
                    second < identities.length;
                    second++
                )
                    pairs++;
            expect(actual.seedCollisionPairs).toBe(pairs);
            expect(actual.seedCollisionDenominator).toBe(2n ** 512n);
        }
        expect(() => compilePrivateRandomnessScopes(0n, -1n, 0n, 0n)).toThrow(
            'Negative',
        );
    });

    it('includes unopened original registrations without using a completed-roster denominator', () => {
        const registered = 1n << 28n,
            sources = 7n * registered;
        const worst = compilePrivateRandomnessScopes(
            sources,
            registered,
            registered,
            registered,
        );
        const noOffers = compilePrivateRandomnessScopes(sources, 0n, 0n, 0n);
        expect(noOffers.maximumReadScopes).toBe(sources);
        expect(noOffers.maximumSeedDraws).toBe(sources);
        expect(worst.maximumSeedDraws).toBe(
            sources + 4n * registered + 3n * 19n * registered,
        );
        expect(worst.maximumReadScopes).toBe(
            sources + 6n * registered + 3n * 19n * registered,
        );
        expect(worst.maximumReadScopes).toBeGreaterThan(worst.maximumSeedDraws);
    });

    it('binds the domain and seed-width operands to the current source owners', async () => {
        const operation = await readFile(
            'crates/protocol-research/registration-enrollment/src/operation-random.rs',
            'utf8',
        );
        const source = await readFile(
            'crates/protocol-research/registration-enrollment/src/fhe-sources.rs',
            'utf8',
        );
        const tree = await readFile(
            'crates/protocol-research/word-proof/src/tree.rs',
            'utf8',
        );
        const rows = compilePrivateRandomnessScopes(1n, 1n, 1n, 1n).domains;
        expect(operation).toContain('const SEED_BYTES: usize = 64;');
        expect(source).toContain('const SEED_BYTES: usize = 64;');
        expect(tree).toContain('pub const SALT_SEED_BYTES: usize = 64;');
        expect(source).toContain(`"${rows[0].domain}"`);
        for (const row of rows.slice(1, -1))
            expect(operation).toContain(`"${row.domain}"`);
        expect(tree).toContain(`b"${rows[rows.length - 1].domain}"`);
        const restore = await readFile(
            'crates/protocol-research/word-proof/src/first-checkpoint.rs',
            'utf8',
        );
        expect(restore).toContain('tree: Tree::with_seed(');
    });
});
