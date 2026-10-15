// BCIKS20 Theorem 7.2, curve degree one, with the consistency weights of
// section 8.2.1 / Claim 8.5. This is conditional proof arithmetic, not a
// verifier or an efficient agreement-state computation.
export const compileWeightedFriBound = (
    domainSize: bigint,
    agreementNumerator: bigint,
    agreementDenominator: bigint,
    rateDenominator: 2n | 4n = 2n,
) => {
    if (
        domainSize < 4n ||
        (domainSize & (domainSize - 1n)) !== 0n ||
        agreementNumerator <= 0n ||
        agreementNumerator >= agreementDenominator
    )
        throw new RangeError(
            'Invalid weighted FRI domain or agreement threshold.',
        );
    const analysisParameter = 8n;
    // alpha >= sqrt(rate) * (1 + 1/(2m)), without square roots.
    const thresholdLeft =
        rateDenominator *
        (2n * analysisParameter) ** 2n *
        agreementNumerator ** 2n;
    const thresholdRight =
        (2n * analysisParameter + 1n) ** 2n * agreementDenominator ** 2n;
    if (thresholdLeft < thresholdRight)
        throw new RangeError('The weighted FRI agreement premise fails.');
    const folds = [];
    for (
        let sourceDomainSize = domainSize;
        sourceDomainSize > rateDenominator;
        sourceDomainSize /= 2n
    ) {
        const targetDomainSize = sourceDomainSize / 2n;
        const weightDenominator = domainSize / targetDomainSize;
        // At rate 1/2 use 1/(3*rate^(3/2)) < 1 and
        // 1/sqrt(rate) < 3/2; at rate 1/4 these are exactly 8/3 and 2.
        // In the second term M*|D_i| stays the original domain size: it
        // does not shrink merely because the next fold has fewer points.
        const first = {
            numerator:
                17n ** 7n *
                targetDomainSize ** 2n *
                (rateDenominator === 4n ? 8n : 1n),
            denominator: 128n * (rateDenominator === 4n ? 3n : 1n),
        };
        const second = {
            numerator:
                (rateDenominator === 4n ? 34n : 51n) *
                (weightDenominator * targetDomainSize + 1n),
            denominator: rateDenominator === 4n ? 1n : 2n,
        };
        const upper =
            first.numerator * second.denominator >=
            second.numerator * first.denominator
                ? first
                : second;
        folds.push({
            sourceDomainSize,
            targetDomainSize,
            weightDenominator,
            first,
            second,
            upper,
        });
    }
    const upper = folds.reduce(
        (maximum, fold) =>
            fold.upper.numerator * maximum.denominator >
            maximum.numerator * fold.upper.denominator
                ? fold.upper
                : maximum,
        folds[0].upper,
    );
    return {
        analysisParameter,
        rateNumerator: 1n,
        rateDenominator,
        domainSize,
        agreementNumerator,
        agreementDenominator,
        thresholdLeft,
        thresholdRight,
        folds,
        upper,
        ceiling: (upper.numerator + upper.denominator - 1n) / upper.denominator,
    };
};
