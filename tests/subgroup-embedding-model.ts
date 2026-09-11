const power = (value: bigint, exponent: bigint, prime: bigint): bigint => {
    let result = 1n;
    for (let remaining = exponent; remaining > 0n; remaining >>= 1n) {
        if ((remaining & 1n) !== 0n) result = (result * value) % prime;
        value = (value * value) % prime;
    }
    return result;
};

// Values on a subgroup occupy every stride-th position of the larger
// systematic domain; all other positions contain zero. Multiplying the
// smaller interpolant by this factor gives the larger interpolant.
export const subgroupEmbeddingFactor = (
    point: bigint,
    subgroupSize: number,
    systematicSize: number,
    prime: bigint,
): bigint => {
    if (
        !Number.isSafeInteger(subgroupSize) ||
        !Number.isSafeInteger(systematicSize) ||
        subgroupSize < 1 ||
        systematicSize < subgroupSize ||
        systematicSize % subgroupSize !== 0 ||
        prime <= BigInt(systematicSize) ||
        (prime - 1n) % BigInt(systematicSize) !== 0n
    )
        throw new RangeError('Invalid subgroup embedding.');
    const stride = systematicSize / subgroupSize;
    const step = power(
        ((point % prime) + prime) % prime,
        BigInt(subgroupSize),
        prime,
    );
    let sum = 0n,
        term = 1n;
    for (let index = 0; index < stride; index++) {
        sum = (sum + term) % prime;
        term = (term * step) % prime;
    }
    // The caller fixes a prime field, and stride is smaller than its characteristic.
    return (sum * power(BigInt(stride), prime - 2n, prime)) % prime;
};
