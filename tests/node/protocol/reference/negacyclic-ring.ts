// The product of two polynomials in Z[X]/(X^n + 1), multiplied term by term,
// where n is the length of both coefficient lists. X^n = -1, so a term whose
// exponent reaches n wraps around with its sign flipped.
export const negacyclicProduct = (
    left: readonly bigint[],
    right: readonly bigint[],
): bigint[] => {
    const degree = left.length;
    if (right.length !== degree)
        throw new RangeError('Both factors need the same ring degree.');
    const product = Array<bigint>(degree).fill(0n);
    for (let leftIndex = 0; leftIndex < degree; leftIndex++)
        for (let rightIndex = 0; rightIndex < degree; rightIndex++) {
            const exponent = leftIndex + rightIndex;
            product[exponent % degree] +=
                (exponent < degree ? 1n : -1n) *
                left[leftIndex] *
                right[rightIndex];
        }
    return product;
};
