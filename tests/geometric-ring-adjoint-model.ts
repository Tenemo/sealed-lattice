const modulo = (value: bigint, modulus: bigint): bigint =>
    ((value % modulus) + modulus) % modulus;

// Transpose of negacyclic convolution applied to (1, alpha, ..., alpha^(N-1)).
// This recurrence works in any commutative ring, including alpha=0 and roots
// of X^N+1; it neither divides by alpha nor materializes a dense matrix.
export const geometricNegacyclicAdjoint = (
    coefficients: readonly bigint[],
    alpha: bigint,
    modulus: bigint,
): readonly bigint[] => {
    if (coefficients.length === 0 || modulus < 2n)
        throw new RangeError('Invalid adjoint model dimensions.');
    let first = 0n,
        alphaToDegree = 1n;
    for (let index = coefficients.length - 1; index >= 0; index--)
        first = modulo(first * alpha + coefficients[index], modulus);
    for (let index = 0; index < coefficients.length; index++)
        alphaToDegree = modulo(alphaToDegree * alpha, modulus);
    const correction = modulo(alphaToDegree + 1n, modulus);
    const result: bigint[] = [];
    let current = first;
    for (let index = 0; index < coefficients.length; index++) {
        result.push(current);
        current = modulo(
            alpha * current -
                correction * coefficients[coefficients.length - 1 - index],
            modulus,
        );
    }
    if (current !== modulo(-first, modulus))
        throw new Error('The adjoint did not complete its negacyclic period.');
    return result;
};

export const fingerprintSignedLimbs = (
    value: bigint,
    radix: bigint,
    limbCount: number,
    limbWeight: bigint,
    modulus: bigint,
): bigint => {
    if (
        radix < 2n ||
        modulus < 2n ||
        !Number.isSafeInteger(limbCount) ||
        limbCount < 1
    )
        throw new RangeError('Invalid limb fingerprint.');
    const sign = value < 0n ? -1n : 1n;
    let remaining = value < 0n ? -value : value,
        result = 0n,
        weight = 1n;
    for (let limb = 0; limb < limbCount; limb++) {
        result = modulo(result + sign * (remaining % radix) * weight, modulus);
        remaining /= radix;
        weight = modulo(weight * limbWeight, modulus);
    }
    if (remaining !== 0n)
        throw new RangeError('The limb fingerprint omitted public digits.');
    return result;
};
