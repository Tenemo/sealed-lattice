import assert from 'node:assert/strict';

// An accurate marginal is insufficient when the same sample also exposes
// a public tail. These complete-view controls retain that counterexample.
export const excludedPrefixStreamControl = () => {
    const cases = [];
    for (const outputBits of [2, 3, 4])
        for (const sampleBits of [
            2 * outputBits + 4,
            2 * outputBits + 6,
            2 * outputBits + 8,
        ]) {
            const output = 2 ** outputBits,
                modulus = output - 1,
                samples = 2 ** sampleBits,
                tails = 2 ** (sampleBits - outputBits),
                counts = Array<number>(modulus).fill(0);
            let reusedSuccess = 0;
            for (let value = 0; value < samples; value++) {
                const prefix = value % modulus,
                    tail = Math.floor(value / output);
                counts[prefix]++;
                if (prefix === (tail * output) % modulus) reusedSuccess++;
            }
            let independentSuccess = 0;
            for (let tail = 0; tail < tails; tail++)
                independentSuccess += counts[(tail * output) % modulus];
            // Independent prefix sample and tail word have samples*tails equally
            // weighted outcomes. Reuse leaves only samples outcomes and correlates
            // them, despite a small marginal modulo imbalance.
            assert.equal(reusedSuccess * output, 2 * samples);
            const numerator = reusedSuccess * tails - independentSuccess,
                denominator = samples * tails;
            assert.ok(numerator > 0);
            assert.ok(
                BigInt(numerator) * BigInt(samples) >
                    BigInt(modulus) * BigInt(denominator),
            );
            const changedNumerator = counts.reduce(
                (sum, count) => sum + Math.max(0, samples - modulus * count),
                0,
            );
            assert.ok(changedNumerator <= modulus * modulus);
            for (const count of counts)
                assert.ok(Math.max(0, samples - modulus * count) <= modulus);
            // Applying any bijection from indices to outputs excluding the target
            // preserves the independent joint law and cannot return that target.
            for (const target of [0, 1, modulus])
                for (let index = 0; index < modulus; index++) {
                    const result = index < target ? index : index + 1;
                    assert.notEqual(result, target);
                    assert.ok(result >= 0 && result < output);
                }
            cases.push({
                outputBits,
                sampleBits,
                reusedSuccess,
                independentSuccess,
                denominator,
                samples,
                tails,
                distinguishing: { numerator, denominator },
                marginalVariation: {
                    numerator: changedNumerator,
                    denominator: modulus * samples,
                },
            });
        }
    return cases;
};

// Exact independent prefix/tail law and a direct two-Boolean-query XOR
// implementation. The length register may be coherent: agreement on each
// basis state, with no retained scratch, gives agreement by linearity.
export const fullXofPrefixControl = () => {
    const views = [];
    for (let target = 0; target < 4; target++) {
        const counts = Array<number>(16).fill(0);
        for (let searchCoin = 0; searchCoin < 4; searchCoin++)
            for (let index = 0; index < 3; index++)
                for (let tail = 0; tail < 4; tail++) {
                    const prefix =
                        searchCoin === 0
                            ? target
                            : index < target
                              ? index
                              : index + 1;
                    counts[prefix + 4 * tail]++;
                }
        assert.deepEqual(counts, Array<number>(16).fill(3));
        views.push({ target, counts });
    }
    let basisCases = 0;
    for (let table = 0; table < 16; table++)
        for (let input = 0; input < 4; input++)
            for (let length = 0; length <= 4; length++)
                for (let answer = 0; answer < 16; answer++) {
                    const target = (input + 1) % 4,
                        index = input % 3,
                        tail = (2 * input + 1) % 4,
                        forced = input === 0;
                    let scratch = 0,
                        queries = 0;
                    scratch ^= (table >> input) & 1;
                    queries++;
                    const prefix =
                        forced || scratch
                            ? target
                            : index < target
                              ? index
                              : index + 1;
                    const output =
                        answer ^ ((prefix + 4 * tail) & (2 ** length - 1));
                    scratch ^= (table >> input) & 1;
                    queries++;
                    assert.equal(scratch, 0);
                    assert.equal(queries, 2);
                    const expectedPrefix =
                        forced || (table >> input) & 1
                            ? target
                            : index < target
                              ? index
                              : index + 1;
                    assert.equal(
                        output,
                        answer ^
                            ((expectedPrefix + 4 * tail) & (2 ** length - 1)),
                    );
                    if (!forced && prefix === target)
                        assert.equal((table >> input) & 1, 1);
                    basisCases++;
                }
    return { views, basisCases, booleanQueriesPerXof: 2 };
};
