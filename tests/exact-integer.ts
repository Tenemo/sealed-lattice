// Exact integer helpers that the models share. Each refuses an input
// outside its domain instead of returning a value for it.

// The number of binary digits of a nonnegative integer; zero has none.
export const bitLength = (value: bigint): number => {
    if (value < 0n)
        throw new RangeError('A bit length needs a nonnegative integer.');
    return value === 0n ? 0 : value.toString(2).length;
};

// The number of bytes that hold a nonnegative integer; zero needs none.
export const byteLength = (value: bigint): number =>
    Math.ceil(bitLength(value) / 8);

// The least integer at or above a nonnegative numerator over a positive
// denominator.
export const ceilingDivide = (numerator: bigint, denominator: bigint) => {
    if (numerator < 0n || denominator <= 0n)
        throw new RangeError(
            'A ceiling division needs a nonnegative numerator and a positive denominator.',
        );
    return (numerator + denominator - 1n) / denominator;
};

export const absolute = (value: bigint): bigint =>
    value < 0n ? -value : value;

// The largest of one or more integers.
export const maximum = (values: readonly bigint[]): bigint => {
    if (values.length === 0) throw new RangeError('A maximum needs a value.');
    return values.reduce((largest, value) =>
        value > largest ? value : largest,
    );
};

// The number of `count`-element subsets of a `population`-element set.
export const binomial = (
    population: bigint | number,
    count: bigint | number,
): bigint => {
    const total = BigInt(population);
    let chosen = BigInt(count);
    if (total < 0n || chosen < 0n)
        throw new RangeError(
            'A binomial coefficient needs nonnegative arguments.',
        );
    if (chosen > total) return 0n;
    if (chosen > total - chosen) chosen = total - chosen;
    let result = 1n;
    for (let index = 1n; index <= chosen; index++)
        result = (result * (total - chosen + index)) / index;
    return result;
};

// A nonnegative integer as exactly `byteCount` little-endian bytes.
export const littleEndian = (value: bigint | number, byteCount: number) => {
    let remaining = BigInt(value);
    if (remaining < 0n || remaining >= 1n << BigInt(8 * byteCount))
        throw new RangeError('A value exceeds its little-endian width.');
    const bytes = Buffer.alloc(byteCount);
    for (let index = 0; index < byteCount; index++, remaining >>= 8n)
        bytes[index] = Number(remaining & 0xffn);
    return bytes;
};
