// Exact finite-field counterexamples to query masking and table-to-polynomial
// compilation. These are research models, not proof or commitment verifiers.
const modulo = (value: number, prime: number): number =>
    ((value % prime) + prime) % prime;

const power = (base: number, exponent: number, prime: number): number => {
    let result = 1;
    for (let index = 0; index < exponent; index += 1) {
        result = modulo(result * base, prime);
    }
    return result;
};

// H={1,4,16,13} in F_17. A constant witness c has randomized encoding
// c+(X^4-1)r(X). Enumerating every mask gives its exact joint query law.
export const enumerateRandomizedEncodingViews = (
    constant: number,
    maskCoefficientCount: number,
    queryPoints: readonly number[],
): ReadonlyMap<string, number> => {
    const prime = 17;
    if (
        !Number.isInteger(constant) ||
        constant < 0 ||
        constant >= prime ||
        !Number.isInteger(maskCoefficientCount) ||
        maskCoefficientCount < 0 ||
        maskCoefficientCount > 3 ||
        queryPoints.some(
            (point) =>
                !Number.isInteger(point) ||
                point < 0 ||
                point >= prime ||
                power(point, 4, prime) === 1,
        )
    ) {
        throw new RangeError(
            'The bounded encoding experiment input is invalid.',
        );
    }
    const histogram = new Map<string, number>();
    for (
        let ordinal = 0;
        ordinal < prime ** maskCoefficientCount;
        ordinal += 1
    ) {
        const view = queryPoints
            .map((point) => {
                let mask = 0;
                for (let index = 0; index < maskCoefficientCount; index += 1) {
                    const coefficient =
                        Math.floor(ordinal / prime ** index) % prime;
                    mask = modulo(
                        mask + coefficient * power(point, index, prime),
                        prime,
                    );
                }
                return modulo(
                    constant + (power(point, 4, prime) - 1) * mask,
                    prime,
                );
            })
            .join(',');
        histogram.set(view, (histogram.get(view) ?? 0) + 1);
    }
    return histogram;
};

export const createFalseBinaryRelationTable = (): Readonly<{
    prime: number;
    claimedQuotientMaximumDegree: number;
    witnessValue: number;
    entries: readonly Readonly<{ point: number; quotient: number }>[];
}> => {
    const prime = 97;
    const witnessValue = 2;
    const entries = Array.from({ length: prime }, (_unused, point) => point)
        .filter((point) => power(point, 4, prime) !== 1)
        .map((point) => ({
            point,
            quotient: modulo(
                witnessValue *
                    (witnessValue - 1) *
                    power(
                        modulo(power(point, 4, prime) - 1, prime),
                        prime - 2,
                        prime,
                    ),
                prime,
            ),
        }));
    return { prime, claimedQuotientMaximumDegree: 4, witnessValue, entries };
};
