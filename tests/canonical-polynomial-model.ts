export const isCanonicalCenteredPolynomial = (
    coefficients: readonly bigint[],
    degree: number,
    modulus: bigint,
): boolean => {
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
