// SHAKE256's rate: 1088 bits, or 136 bytes (FIPS 202, Section 6.2).
export const shake256RateBytes = 136n;

// The Keccak-f[1600] permutations of one byte-aligned SHA-3 or SHAKE call at
// this rate, counted block by block. The domain suffix and the first padding
// bit share one byte after the input, and pad10*1 fills the block that byte
// opens. The permutation after the last absorbed block yields the first
// output block, and every further output block takes one more.
export const spongePermutations = (
    inputBytes: bigint | number,
    outputBytes: bigint | number,
    rateBytes: bigint | number,
): bigint => {
    const input = BigInt(inputBytes),
        output = BigInt(outputBytes),
        rate = BigInt(rateBytes);
    if (input < 0n || output < 0n || rate <= 0n)
        throw new RangeError(
            'A sponge call needs nonnegative lengths and a positive rate.',
        );
    let absorbed = input + 1n;
    while (absorbed % rate !== 0n) absorbed++;
    let permutations = absorbed / rate;
    for (let produced = rate; produced < output; produced += rate)
        permutations++;
    return permutations;
};
