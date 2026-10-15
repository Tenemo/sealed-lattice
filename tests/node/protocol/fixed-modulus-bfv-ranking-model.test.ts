import { describe, expect, it } from 'vitest';

import { evaluateFixedModulusBfvRanking } from '#tests/fixed-modulus-bfv-ranking-model.js';

const prime = 12_289;
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

describe('compact fixed-modulus BFV ranking schedule', () => {
    it.each([
        { participants: 3, options: 2, top: 1 },
        { participants: 4, options: 3, top: 2 },
        { participants: 10, options: 10, top: 10 },
        { participants: 20, options: 20, top: 3 },
    ])(
        'matches independent sorting and clears every unused slot for $participants/$options/$top',
        ({ participants, options, top }) => {
            const activeSlots = 1024;
            const maximum = 18 * participants + 1;
            const points = Array.from(
                { length: maximum + 1 },
                (_, index) => -maximum + 2 * index,
            );
            const comparison = interpolate(
                points,
                points.map((value) => Number(value > 0)),
            );
            const equality = Array.from({ length: top }, (_rankSlot, rank) =>
                interpolate(
                    Array.from({ length: options }, (_, index) => index),
                    Array.from({ length: options }, (_, index) =>
                        Number(index === rank),
                    ),
                ),
            );
            const window = 2 ** Math.ceil(Math.log2(options));
            const combine = (
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
                const turnout = pattern === 2 ? 1 : participants;
                const ballots = Array.from(
                    { length: participants },
                    (_participantSlot, participant) =>
                        participant >= turnout
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
                    Array.from({ length: 2 * activeSlots }, (_, position) => {
                        if (!ballot) return 0;
                        if (position >= activeSlots)
                            return ballot[position - activeSlots] ?? 0;
                        const option = Math.floor(position / window),
                            opponent = position % window;
                        return option < options && opponent < options
                            ? reduce(2 * (ballot[opponent] - ballot[option]))
                            : 0;
                    }),
                );
                const coefficient = (position: number, exponent: number) => {
                    const rank = (window - (position % window)) % window;
                    return position < activeSlots && rank < top
                        ? equality[rank][exponent]
                        : 0;
                };
                const ranked = evaluateFixedModulusBfvRanking(
                    inputs,
                    options,
                    16,
                    {
                        add: (left, right) => combine(left, right, false),
                        multiply: (left, right) => combine(left, right, true),
                        multiplyScalar: (value, exponent) =>
                            value.map((item) =>
                                reduce(item * comparison[exponent]),
                            ),
                        multiplyPlaintext: (value, exponent) =>
                            value.map((item, position) =>
                                reduce(
                                    item *
                                        (exponent === -1
                                            ? Number(
                                                  position < activeSlots &&
                                                      position % window === 0,
                                              )
                                            : coefficient(position, exponent)),
                                ),
                            ),
                        addPlaintext: (value, purpose) =>
                            value.map((item, position) => {
                                const constant =
                                    purpose === 'comparison-constant'
                                        ? comparison[0]
                                        : purpose === 'ranking-constant'
                                          ? coefficient(position, 0)
                                          : purpose === 'padding-correction'
                                            ? -Number(
                                                  position < activeSlots &&
                                                      position % window === 0 &&
                                                      position / window >=
                                                          options,
                                              )
                                            : position >= activeSlots
                                              ? 0
                                              : position < options * window &&
                                                  position % window <
                                                      Math.floor(
                                                          position / window,
                                                      )
                                                ? 1
                                                : -1;
                                return reduce(item + constant);
                            }),
                        rotate: (value) =>
                            value.map(
                                (_, position) =>
                                    value[
                                        Math.floor(position / activeSlots) *
                                            activeSlots +
                                            ((position + 1) % activeSlots)
                                    ],
                            ),
                    },
                    top,
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
                const expected = new Array<number>(2 * activeSlots).fill(0);
                ordered.forEach(
                    (option, rank) =>
                        (expected[
                            (option * window - rank + activeSlots) % activeSlots
                        ] = 1),
                );
                expect(ranked).toEqual(expected);
            }
        },
    );
});
