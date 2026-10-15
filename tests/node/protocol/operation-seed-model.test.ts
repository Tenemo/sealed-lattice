import { describe, expect, it } from 'vitest';

import {
    readRustSource,
    rustIntegerConstant,
    rustFunctionBody,
} from '#tests/node/rust-source.js';
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
            root(`source:${source}`, [
                ['source-generation', true],
                ['source-encryption', true],
            ]);
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

describe('original private-randomness scope populations', () => {
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
        expect(noOffers.maximumReadScopes).toBe(2n * sources);
        expect(noOffers.maximumSeedDraws).toBe(sources);
        expect(worst.maximumSeedDraws).toBe(
            sources + 4n * registered + 3n * 19n * registered,
        );
        expect(worst.maximumReadScopes).toBe(
            2n * sources + 6n * registered + 3n * 19n * registered,
        );
        expect(worst.maximumReadScopes).toBeGreaterThan(worst.maximumSeedDraws);
    });

    it('binds the domain and seed-width operands to their source owners', async () => {
        const operation = await readRustSource(
            'crates/protocol-research/participant-module/src/operation-random.rs',
        );
        const source = await readRustSource(
            'crates/protocol-research/protocol-foundations/src/source-seeds.rs',
        );
        const tree = await readRustSource(
            'crates/protocol-research/word-proof/src/tree.rs',
        );
        const rows = compilePrivateRandomnessScopes(1n, 1n, 1n, 1n).domains;
        expect(rustIntegerConstant(operation, 'SEED_BYTES')).toBe(64n);
        expect(rustIntegerConstant(source, 'SEED_BYTES')).toBe(64n);
        expect(rustIntegerConstant(tree, 'SALT_SEED_BYTES')).toBe(64n);
        const encryptedSource = await readRustSource(
            'crates/protocol-research/setup-witness/src/encrypted-source.rs',
        );
        const sourceReader = rustFunctionBody(encryptedSource, 'from_seed');
        expect(sourceReader).toContain(`b"${rows[0].domain}"`);
        expect(sourceReader).toContain('state.update(&[purpose]);');
        expect(sourceReader).toContain('state.update(seed.as_ref());');
        expect(
            [...sourceReader.matchAll(/reader\((\d+)\)/gu)].map((match) =>
                Number(match[1]),
            ),
        ).toEqual([0, 1]);
        for (const row of rows.slice(1, -1))
            expect(operation).toContain(`"${row.domain}"`);
        expect(tree).toContain(`b"${rows[rows.length - 1].domain}"`);
        const restore = await readRustSource(
            'crates/protocol-research/word-proof/src/first-oracle-checkpoint.rs',
        );
        expect(restore).toContain('tree: Tree::with_seed(');
    });
});
