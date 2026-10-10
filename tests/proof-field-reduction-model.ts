import { compileSmallLimbProofFieldCensus } from '#tests/small-limb-proof-field-model.js';

const reductionBounds = (radix: bigint, offset: bigint) => {
    const modulus = radix * radix - offset * radix + 1n;
    const maximumFirstHigh = offset * offset + offset - 1n;
    const maximumCarriedFinalHigh = offset * maximumFirstHigh + offset - 1n;
    if (
        radix < 2n ||
        (radix & (radix - 1n)) !== 0n ||
        offset < 1n ||
        2n * modulus <= radix * radix ||
        maximumCarriedFinalHigh >= radix
    )
        throw new RangeError('The reduction bounds do not hold.');
    const squareCoefficient = offset * offset - 1n;
    return {
        modulus,
        maximumFirstHigh,
        maximumSecondHigh: (radix - 1n + offset * maximumFirstHigh) / radix,
        maximumCarriedFinalHigh,
        maximumSmallFactor:
            squareCoefficient > offset ? squareCoefficient : offset,
    };
};

export const foldProofFieldLimbs = (
    limbs: readonly [bigint, bigint, bigint, bigint],
    radix: bigint,
    offset: bigint,
) => {
    const bounds = reductionBounds(radix, offset);
    if (limbs.some((value) => value < 0n || value >= radix))
        throw new RangeError('A product limb exceeds its radix.');
    const split = (value: bigint) => {
        const low = ((value % radix) + radix) % radix;
        return { low, high: (value - low) / radix };
    };
    const constant = split(limbs[0] - limbs[2] - offset * limbs[3]);
    const linear = split(
        limbs[1] +
            offset * limbs[2] +
            (offset * offset - 1n) * limbs[3] +
            constant.high,
    );
    const constantSecond = split(constant.low - linear.high);
    const linearSecond = split(
        linear.low + offset * linear.high + constantSecond.high,
    );
    const constantThird = split(constantSecond.low - linearSecond.high);
    const finalHigh =
        linearSecond.low + offset * linearSecond.high + constantThird.high;
    const unnormalized = finalHigh * radix + constantThird.low;
    return {
        value:
            unnormalized >= bounds.modulus
                ? unnormalized - bounds.modulus
                : unnormalized,
        firstHigh: linear.high,
        secondHigh: linearSecond.high,
        finalHigh,
    };
};

export const compileProofFieldReductionCensus = () => {
    const field = compileSmallLimbProofFieldCensus();
    return {
        radix: field.wordRadix,
        offset: field.reductionOffset,
        ...reductionBounds(field.wordRadix, field.reductionOffset),
    };
};
