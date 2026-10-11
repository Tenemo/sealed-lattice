// The transform field is an arithmetic carrier. Its centered representative
// identifies the integer convolution only while the complete norm bound fits.
export const integerLimbConvolutionMagnitudeBound = (
    radix: bigint,
    oneNorm: bigint,
    transformModulus: bigint,
): bigint => {
    if (
        radix < 2n ||
        oneNorm < 0n ||
        transformModulus < 3n ||
        transformModulus % 2n === 0n
    )
        throw new RangeError('Invalid integer-convolution parameters.');
    const bound = oneNorm * (radix - 1n);
    if (2n * bound >= transformModulus)
        throw new RangeError(
            'The transform modulus cannot identify every integer coefficient.',
        );
    return bound;
};
