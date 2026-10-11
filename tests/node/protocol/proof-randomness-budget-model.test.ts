import { readFile } from 'node:fs/promises';

import { describe, expect, it } from 'vitest';

import {
    bufferedFieldPrefixLaw,
    bufferedFieldSamplingFailure,
    bufferedFieldWaitingLaw,
    compileFirstOracleReadVariation,
    compileProofRandomnessBudgets,
    rejectionSubsetBound,
} from '#tests/proof-randomness-budget-model.js';
import {
    completionProfile,
    deriveSupportedProfile,
} from '#tests/supported-profile-model.js';

describe('bounded randomness for complete proof simulation', () => {
    it('keeps unfinished read prefixes independent of the latent complete mask', () => {
        for (const [alphabet, accepted, required, batch, maximumReads] of [
            [3, 2, 3, 2, 3],
            [4, 3, 2, 1, 4],
            [2, 2, 3, 2, 2],
            [3, 1, 2, 2, 2],
        ] as const) {
            for (let reads = 0; reads <= maximumReads; reads++) {
                const length = reads * batch;
                const counts = new Map<number, Map<string, bigint>>();
                for (let encoded = 0; encoded < alphabet ** length; encoded++) {
                    let remaining = encoded;
                    const prefix: number[] = [];
                    for (let position = 0; position < length; position++) {
                        const word = remaining % alphabet;
                        remaining = Math.floor(remaining / alphabet);
                        if (word < accepted) prefix.push(word);
                    }
                    if (prefix.length >= required) continue;
                    const group =
                        counts.get(prefix.length) ?? new Map<string, bigint>();
                    const key = prefix.join(',');
                    group.set(key, (group.get(key) ?? 0n) + 1n);
                    counts.set(prefix.length, group);
                }
                for (
                    let found = 0;
                    found < Math.min(required, length + 1);
                    found++
                ) {
                    const law = bufferedFieldPrefixLaw(
                        BigInt(alphabet),
                        BigInt(accepted),
                        BigInt(required),
                        BigInt(reads),
                        BigInt(batch),
                        BigInt(found),
                    );
                    const group =
                        counts.get(found) ?? new Map<string, bigint>();
                    const total = [...group.values()].reduce(
                        (sum, count) => sum + count,
                        0n,
                    );
                    expect(total).toBe(law.historyNumerator);
                    expect(law.denominator).toBe(
                        BigInt(alphabet) ** BigInt(length),
                    );
                    expect(BigInt(group.size)).toBe(
                        total === 0n ? 0n : law.prefixVectors,
                    );
                    expect(new Set(group.values())).toEqual(
                        new Set(total === 0n ? [] : [law.prefixNumerator]),
                    );
                    // Complete any unfinished mask from its independent
                    // latent suffix. Every full vector has the same mass
                    // within this read/acceptance-count history.
                    expect(law.prefixVectors * law.latentSuffixVectors).toBe(
                        BigInt(accepted) ** BigInt(required),
                    );
                    expect(
                        law.prefixNumerator *
                            BigInt(accepted) ** BigInt(required) *
                            law.denominator,
                    ).toBe(
                        law.historyNumerator *
                            law.completedVectorJointDenominator,
                    );
                }
            }
        }
        expect(() => bufferedFieldPrefixLaw(3n, 2n, 2n, 1n, 2n, 2n)).toThrow(
            'unfinished',
        );
        expect(() => bufferedFieldPrefixLaw(3n, 2n, 2n, 0n, 2n, 1n)).toThrow(
            'unfinished',
        );
    });

    it('preserves failed prefixes on replay and conditions later work only on the read history', () => {
        const alphabet = 3;
        const accepted = 2;
        const required = 2;
        const batch = 2;
        const maximumReads = 3;
        const length = batch * maximumReads + 1;
        const run = (
            tape: readonly number[],
            fail: (read: number, prefix: readonly number[]) => boolean,
        ) => {
            const output: number[] = [];
            const events: string[] = [];
            let cursor = 0;
            for (let read = 1; read <= maximumReads; read++) {
                events.push(`read:${read}`);
                if (fail(read, output))
                    return {
                        output,
                        cursor,
                        events: [...events, 'failed'],
                        completed: false,
                    };
                const end = cursor + batch;
                while (cursor < end && output.length < required) {
                    const value = tape[cursor++];
                    if (value < accepted) output.push(value);
                }
                cursor = end;
                if (output.length === required)
                    return {
                        output,
                        cursor,
                        events: [...events, 'completed'],
                        completed: true,
                    };
            }
            return {
                output,
                cursor,
                events: [...events, 'unfinished'],
                completed: false,
            };
        };
        const groups = new Map<string, Map<string, number>>();
        const valueDependentGroups = new Map<string, Set<string>>();
        let interruptedThenCompleted = 0;
        for (let encoded = 0; encoded < alphabet ** length; encoded++) {
            let remaining = encoded;
            const tape = Array.from({ length }, () => {
                const word = remaining % alphabet;
                remaining = Math.floor(remaining / alphabet);
                return word;
            });
            const first = run(tape, (read) => read === 2);
            const repeated = first.completed
                ? first
                : run(tape, (read) => read === 3);
            const final = repeated.completed
                ? repeated
                : run(tape, () => false);
            if (!final.completed) continue;
            if (!first.completed) interruptedThenCompleted++;
            const history = [first.events, repeated.events, final.events]
                .map((events) => events.join(','))
                .join('|');
            const result = `${final.output.join(',')}|${tape[final.cursor]}`;
            const group = groups.get(history) ?? new Map<string, number>();
            group.set(result, (group.get(result) ?? 0) + 1);
            groups.set(history, group);

            // A private-value-dependent failure is outside the coupling:
            // an otherwise identical provider can disclose the first mask.
            const revealing = run(
                tape,
                (read, prefix) => read === 2 && prefix[0] === 0,
            );
            if (revealing.events[revealing.events.length - 1] === 'failed') {
                const observed = revealing.events.join(',');
                const outputs =
                    valueDependentGroups.get(observed) ?? new Set<string>();
                outputs.add(final.output.join(','));
                valueDependentGroups.set(observed, outputs);
            }
        }
        expect(interruptedThenCompleted).toBeGreaterThan(0);
        expect(groups.size).toBeGreaterThan(1);
        for (const group of groups.values()) {
            expect(group.size).toBe(accepted ** required * alphabet);
            expect(new Set(group.values()).size).toBe(1);
        }
        expect(valueDependentGroups.size).toBeGreaterThan(0);
        expect(
            [...valueDependentGroups.values()].some(
                (outputs) => outputs.size < accepted ** required,
            ),
        ).toBe(true);

        // Repeated failure at the same boundary is one original event.
        // Enumerate fresh second tapes independently to demonstrate why
        // counting replay as a new sampling trial gives a different law.
        let failedPrefixes = 0n;
        let twoFreshFailures = 0n;
        const unfinished = (encoded: number) =>
            Number(encoded % alphabet < accepted) +
                Number(Math.floor(encoded / alphabet) < accepted) <
            required;
        for (let first = 0; first < alphabet ** batch; first++) {
            if (unfinished(first)) failedPrefixes++;
            for (let second = 0; second < alphabet ** batch; second++)
                if (unfinished(first) && unfinished(second)) twoFreshFailures++;
        }
        const originalPrefixMass = [0n, 1n].reduce(
            (sum, found) =>
                sum +
                bufferedFieldPrefixLaw(3n, 2n, 2n, 1n, 2n, found)
                    .historyNumerator,
            0n,
        );
        expect(failedPrefixes).toBe(originalPrefixMass);
        expect(failedPrefixes * BigInt(alphabet ** batch)).toBeGreaterThan(
            twoFreshFailures,
        );
    });

    it('separates batched read counts from accepted values and the next consumer’s words', () => {
        for (const [alphabet, accepted, required, batch, maximumReads] of [
            [4, 2, 2, 2, 3],
            [3, 2, 3, 2, 3],
            [4, 3, 1, 3, 2],
            [2, 2, 3, 2, 2],
        ] as const) {
            const futureWords = 2;
            const length = batch * maximumReads + futureWords;
            const groups = new Map<number, Map<string, number>>();
            for (let encoded = 0; encoded < alphabet ** length; encoded++) {
                let rest = encoded;
                const tape = Array.from({ length }, () => {
                    const word = rest % alphabet;
                    rest = Math.floor(rest / alphabet);
                    return word;
                });
                const output: number[] = [];
                let cursor = 0;
                let reads = 0;
                while (reads < maximumReads && output.length < required) {
                    const end = cursor + batch;
                    while (cursor < end && output.length < required) {
                        const word = tape[cursor++];
                        if (word < accepted) output.push(word);
                    }
                    cursor = end;
                    reads++;
                }
                if (output.length !== required) continue;
                const key =
                    output.join(',') +
                    '|' +
                    tape.slice(cursor, cursor + futureWords).join(',');
                const group = groups.get(reads) ?? new Map<string, number>();
                group.set(key, (group.get(key) ?? 0) + 1);
                groups.set(reads, group);
            }
            expect(groups.size).toBeGreaterThan(0);
            for (const group of groups.values()) {
                expect(group.size).toBe(
                    accepted ** required * alphabet ** futureWords,
                );
                expect(new Set(group.values()).size).toBe(1);
            }
        }
    });

    it('matches the exact waiting-tuple law while preserving discarded read tails', () => {
        for (const waiting of [
            [1n, 1n],
            [1n, 2n],
            [2n, 2n],
            [1n, 3n],
        ]) {
            const law = bufferedFieldWaitingLaw(4n, 3n, waiting, 3n);
            const words = Number(law.examinedWords);
            const counts = new Map<string, bigint>();
            for (let encoded = 0; encoded < 4 ** words; encoded++) {
                let rest = encoded;
                const output: number[] = [];
                const observed: bigint[] = [];
                let since = 0n;
                for (let index = 0; index < words; index++) {
                    const word = rest % 4;
                    rest = Math.floor(rest / 4);
                    since++;
                    if (word < 3) {
                        output.push(word);
                        observed.push(since);
                        since = 0n;
                    }
                }
                if (since !== 0n || observed.join() !== waiting.join())
                    continue;
                const key = output.join();
                counts.set(key, (counts.get(key) ?? 0n) + 1n);
            }
            expect(BigInt(counts.size)).toBe(law.outputVectors);
            expect(new Set(counts.values())).toEqual(
                new Set([law.jointNumerator]),
            );
            expect(
                [...counts.values()].reduce((sum, count) => sum + count, 0n),
            ).toBe(law.historyNumerator);
            expect(law.denominator).toBe(4n ** BigInt(words));
            expect(law.requestedWords % 3n).toBe(0n);
            expect(law.discardedWords).toBe(law.requestedWords - BigInt(words));
        }
        const noRejections = bufferedFieldWaitingLaw(4n, 4n, [1n, 1n], 3n);
        expect(noRejections.historyNumerator).toBe(noRejections.denominator);
        expect(noRejections.discardedWords).toBe(1n);
        expect(bufferedFieldWaitingLaw(4n, 4n, [2n], 3n).jointNumerator).toBe(
            0n,
        );
        expect(() => bufferedFieldWaitingLaw(4n, 3n, [0n], 3n)).toThrow();
    });

    it('keeps the native degree-mask read variation instead of treating the minimum as fixed', async () => {
        const source = await readFile(
            new URL(
                '../../../crates/protocol-research/supported-profile/src/relation.rs',
                import.meta.url,
            ),
            'utf8',
        );
        expect(source).toContain('pub const RANDOM_WORD_BYTES: usize = 16;');
        expect(source).toContain(
            'pub const RANDOM_READ_BYTES: usize = 65_536;',
        );
        const result = compileFirstOracleReadVariation();
        expect(result.requiredValues).toBe(3n * 2n * 65_536n);
        expect(result.bufferWords).toBe(65_536n / 16n);
        const rejected = 133n * (1n << 64n) - 1n;
        const alphabet = 1n << 128n;
        expect(result.rejectedValues).toBe(rejected);
        expect(result.lowerNumerator).toBe(
            result.requiredValues * rejected * alphabet -
                ((result.requiredValues * (result.requiredValues - 1n)) / 2n) *
                    rejected *
                    rejected,
        );
        expect(
            result.lowerNumerator << result.lowerProbabilityExponent,
        ).toBeGreaterThanOrEqual(result.denominator);
        expect(
            result.upperNumerator << result.upperProbabilityExponent,
        ).toBeLessThanOrEqual(result.denominator);
        // This work variation is not itself 2^-80-small. That comparison
        // gives no cost-normalized security verdict; the coupling retains
        // the actual request history without assigning it a privacy error.
        expect(result.lowerNumerator << 80n).toBeGreaterThan(
            result.denominator,
        );
    });

    it('programs the complete role-specific word without borrowing the setup width', () => {
        for (const [participants, options, setupBytes] of [
            [3, 2, 131072n],
            [10, 10, 262144n],
            [20, 20, 524288n],
        ] as const) {
            const budgets = compileProofRandomnessBudgets(
                deriveSupportedProfile(participants, options),
            );
            expect(
                budgets.map((value) => value.programmedMessageBytes),
            ).toEqual([setupBytes, 262144n, 262144n]);
            for (const budget of budgets)
                expect(
                    budget.simulatorBaselineBytes -
                        budget.ordinaryBaselineBytes,
                ).toBe(budget.programmedMessageBytes);
        }
    });
    it('bounds a stopping event by fixed rejected-position subsets', () => {
        const bound = rejectionSubsetBound({
            candidatePositions: 4n,
            requiredRejections: 3n,
            rejectedValues: 1n,
            sampleBits: 2n,
            inputCount: 1n,
        });
        let failures = 0n;
        for (let tape = 0; tape < 256; tape++) {
            let encoded = tape,
                rejections = 0;
            for (let index = 0; index < 4; index++) {
                if (encoded % 4 === 0) rejections++;
                encoded = Math.floor(encoded / 4);
            }
            if (rejections >= 3) failures++;
        }
        expect(failures).toBe(13n);
        expect(failures * (1n << bound.denominatorBits)).toBeLessThanOrEqual(
            bound.numerator * 256n,
        );
        expect(
            rejectionSubsetBound({
                candidatePositions: 4n,
                requiredRejections: 5n,
                rejectedValues: 1n,
                sampleBits: 2n,
                inputCount: 1n,
            }).numerator,
        ).toBe(0n);
        expect(() =>
            rejectionSubsetBound({
                candidatePositions: 4n,
                requiredRejections: 3n,
                rejectedValues: 5n,
                sampleBits: 2n,
                inputCount: 1n,
            }),
        ).toThrow();
    });

    it('bounds exact small-field rejection events without assuming independent stopping positions', () => {
        // Exhaust all three-byte tapes for a sampler accepting 255 values.
        // At least two rejections is the union of the three index pairs.
        const bound = bufferedFieldSamplingFailure({
            baselineBytes: 2n,
            bufferBytes: 1n,
            sampleBits: 8n,
            modulus: 255n,
            extraReads: 1n,
            invocations: 1n,
        });
        let failures = 0n;
        for (let first = 0; first < 256; first++)
            for (let second = 0; second < 256; second++)
                for (let third = 0; third < 256; third++)
                    failures += BigInt(
                        Number(first === 255) +
                            Number(second === 255) +
                            Number(third === 255) >=
                            2,
                    );
        expect(failures).toBe(766n);
        expect(failures * (1n << bound.denominatorBits)).toBeLessThanOrEqual(
            bound.numerator * 256n ** 3n,
        );
    });

    it('charges the complete role population and only adds enough read headroom', () => {
        const budgets = compileProofRandomnessBudgets(completionProfile());
        expect(budgets.map((value) => value.role)).toEqual([
            'setup contribution',
            'linked ballot',
            'linked release',
        ]);
        for (const value of budgets) {
            expect(value.simulatorBaselineBytes).toBe(
                value.ordinaryBaselineBytes + 262_144n,
            );
            expect(value.failure.numerator << 128n).toBeLessThanOrEqual(
                1n << value.failure.denominatorBits,
            );
            expect(value.invocationCap).toBe(1n << 28n);
            expect(value.extraReads).toBeGreaterThan(0n);
            const previousPositions =
                (value.simulatorBaselineBytes +
                    (value.extraReads - 1n) * 65_536n) /
                16n;
            let pairs = 1n;
            for (let index = 1n; index <= value.extraReads; index++)
                pairs = (pairs * (previousPositions - index + 1n)) / index;
            const rejectedWords = 133n * (1n << 64n) - 1n;
            expect(
                (value.invocationCap *
                    pairs *
                    rejectedWords ** value.extraReads) <<
                    128n,
            ).toBeGreaterThan(1n << (128n * value.extraReads));
        }
    });

    it('refuses misaligned budgets and accounts for a rejection-free alphabet', () => {
        const input = {
            baselineBytes: 32n,
            bufferBytes: 16n,
            sampleBits: 128n,
            modulus: 1n << 128n,
            extraReads: 0n,
            invocations: 1n,
        };
        expect(bufferedFieldSamplingFailure(input).numerator).toBe(0n);
        expect(() =>
            bufferedFieldSamplingFailure({ ...input, baselineBytes: 33n }),
        ).toThrow('Invalid');
        expect(() =>
            bufferedFieldSamplingFailure({ ...input, invocations: 0n }),
        ).toThrow('Invalid');
    });
});
