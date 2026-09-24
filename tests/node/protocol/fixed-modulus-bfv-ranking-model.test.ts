import { describe, expect, it } from 'vitest';

import { evaluateFixedModulusBfvRanking } from '#tests/fixed-modulus-bfv-ranking-model.js';

const prime = 65_537;
const reduce = (value: number): number => ((value % prime) + prime) % prime;
const inverse = (value: number): number => {
    let result = 1;
    let base = reduce(value);
    for (
        let exponent = prime - 2;
        exponent > 0;
        exponent = Math.floor(exponent / 2)
    ) {
        if (exponent % 2 === 1) result = reduce(result * base);
        base = reduce(base * base);
    }
    return result;
};

// Lagrange basis expansion is independent of the encrypted block schedule.
const interpolate = (
    points: readonly number[],
    values: readonly number[],
): number[] => {
    const output = Array.from({ length: points.length }, () => 0);
    for (let selected = 0; selected < points.length; selected++) {
        if (values[selected] === 0) continue;
        let polynomial = [1];
        let denominator = 1;
        for (let other = 0; other < points.length; other++) {
            if (other === selected) continue;
            const next = Array.from({ length: polynomial.length + 1 }, () => 0);
            polynomial.forEach((coefficient, degree) => {
                next[degree] = reduce(
                    next[degree] - coefficient * points[other],
                );
                next[degree + 1] = reduce(next[degree + 1] + coefficient);
            });
            polynomial = next;
            denominator = reduce(
                denominator * (points[selected] - points[other]),
            );
        }
        const weight = reduce(values[selected] * inverse(denominator));
        polynomial.forEach((coefficient, degree) => {
            output[degree] = reduce(output[degree] + weight * coefficient);
        });
    }
    return output;
};

describe('shared fixed-modulus BFV ranking schedule', () => {
    it.each([
        { participants: 3, options: 2, top: 1 },
        { participants: 10, options: 10, top: 10 },
        { participants: 20, options: 20, top: 3 },
    ])(
        'matches independent sorting for $participants participants and $options options',
        ({ participants, options, top }) => {
            const maximum = 18 * participants + 1;
            const points = Array.from(
                { length: maximum + 1 },
                (_, index) => -maximum + 2 * index,
            );
            const comparison = interpolate(
                points,
                points.map((value) => Number(value > 0)),
            );
            const equality = Array.from({ length: top }, (_rank, requested) =>
                interpolate(
                    Array.from({ length: options }, (_, index) => index),
                    Array.from({ length: options }, (_, index) =>
                        Number(index === requested),
                    ),
                ),
            );
            const window = 2 ** Math.ceil(Math.log2(options));
            const lanes = options * top * window;
            const mapPair = (
                left: readonly number[],
                right: readonly number[],
                multiply: boolean,
            ) =>
                left.map((value, index) =>
                    reduce(
                        multiply ? value * right[index] : value + right[index],
                    ),
                );
            for (const pattern of [0, 1, 2]) {
                const submitted = pattern === 2 ? 1 : participants;
                const ballots = Array.from(
                    { length: participants },
                    (_participant, participant) =>
                        participant >= submitted
                            ? null
                            : Array.from({ length: options }, (_, option) =>
                                  pattern === 0
                                      ? 1
                                      : 1 +
                                        ((participant * 7 +
                                            option * 3 +
                                            participant * (option % 2)) %
                                            10),
                              ),
                );
                const inputs = ballots.map((ballot) =>
                    Array.from({ length: lanes }, (_, index) => {
                        const option = Math.floor(index / (top * window)),
                            opponent = index % window;
                        return ballot && opponent < options
                            ? reduce(2 * (ballot[opponent] - ballot[option]))
                            : 0;
                    }),
                );
                const coefficient = (index: number, exponent: number) =>
                    index % window === 0
                        ? equality[Math.floor(index / window) % top][exponent]
                        : 0;
                const rankedSlots = evaluateFixedModulusBfvRanking(
                    inputs,
                    options,
                    16,
                    {
                        add: (left, right) => mapPair(left, right, false),
                        multiply: (left, right) => mapPair(left, right, true),
                        multiplyScalar: (input, exponent) =>
                            input.map((value) =>
                                reduce(value * comparison[exponent]),
                            ),
                        multiplyPlaintext: (input, exponent) =>
                            input.map((value, index) =>
                                reduce(value * coefficient(index, exponent)),
                            ),
                        addPlaintext: (input, purpose) =>
                            input.map((value, index) =>
                                reduce(
                                    value +
                                        (purpose === 'comparison-constant'
                                            ? comparison[0]
                                            : purpose === 'ranking-constant'
                                              ? coefficient(index, 0)
                                              : index % window <
                                                  Math.floor(
                                                      index / (top * window),
                                                  )
                                                ? 1
                                                : -1),
                                ),
                            ),
                        rotate: (input) => [...input.slice(1), input[0]],
                    },
                ).result;
                const totals = Array.from({ length: options }, (_, option) =>
                    ballots.reduce(
                        (sum, ballot) => sum + (ballot?.[option] ?? 0),
                        0,
                    ),
                );
                const ordered = Array.from(
                    { length: options },
                    (_, option) => option,
                )
                    .sort(
                        (left, right) =>
                            totals[right] - totals[left] || left - right,
                    )
                    .slice(0, top);
                expect(
                    rankedSlots.every((bit, index) =>
                        index % window === 0
                            ? bit === 0 || bit === 1
                            : bit === 0,
                    ),
                ).toBe(true);
                const selected = Array.from({ length: top }, (_rank, rank) =>
                    Array.from(
                        { length: options },
                        (_, option) => option,
                    ).filter(
                        (option) =>
                            rankedSlots[(option * top + rank) * window] === 1,
                    ),
                );
                expect(selected).toEqual(ordered.map((option) => [option]));
            }
        },
    );
});
