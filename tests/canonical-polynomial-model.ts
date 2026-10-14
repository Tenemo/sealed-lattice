// Whether a polynomial has the degree's coefficients, each centered in the
// odd modulus: from -(modulus - 1) / 2 to (modulus - 1) / 2.
export const isCanonicalCenteredPolynomial = (
    coefficients: readonly bigint[],
    degree: number,
    modulus: bigint,
): boolean => {
    if (modulus % 2n !== 1n)
        throw new RangeError('A centered polynomial needs an odd modulus.');
    if (coefficients.length !== degree) return false;
    const maximum = modulus / 2n;
    for (let index = 0; index < degree; index++) {
        const coefficient = coefficients[index];
        if (
            typeof coefficient !== 'bigint' ||
            coefficient < -maximum ||
            coefficient > maximum
        )
            return false;
    }
    return true;
};
