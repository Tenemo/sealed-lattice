const modulo = (value: bigint, modulus: bigint): bigint =>
    ((value % modulus) + modulus) % modulus;

export const separateProximityDegreeCounterexample = () => {
    const prime = 17n;
    const domain = Array.from({ length: 16 }, (_, index) => BigInt(index + 1));
    const commonRoots = [1n, 2n, 4n, 5n, 8n, 14n];
    // X^6-h(X) is the product over the listed roots, with both the X^5
    // and X^4 coefficients zero. Thus h is a valid degree-three codeword.
    const lowerPolynomial = [8n, 11n, 15n, 1n];
    const evaluate = (coefficients: readonly bigint[], point: bigint) =>
        coefficients.reduceRight(
            (value, coefficient) => modulo(value * point + coefficient, prime),
            0n,
        );
    const outside = domain.filter((point) => !commonRoots.includes(point));
    const originalAgreement = [...commonRoots, ...outside.slice(0, 5)];
    const raw = domain.map((point) =>
        originalAgreement.includes(point)
            ? point ** 3n % prime
            : (evaluate(lowerPolynomial, point) *
                  (point ** 3n % prime) ** 15n) %
              prime,
    );
    const shifted = raw.map(
        (value, index) => (value * domain[index] ** 3n) % prime,
    );
    const first = domain.map((point) => point ** 3n % prime);
    const second = domain.map((point) => evaluate(lowerPolynomial, point));
    const firstAgreement = raw.flatMap((value, index) =>
        value === first[index] ? [index] : [],
    );
    const secondAgreement = shifted.flatMap((value, index) =>
        value === second[index] ? [index] : [],
    );
    return {
        domain,
        raw,
        shifted,
        commonRoots,
        factorizationValues: domain.map((point) =>
            modulo(point ** 6n - evaluate(lowerPolynomial, point), prime),
        ),
        firstAgreement,
        secondAgreement,
        commonAgreement: firstAgreement.filter((index) =>
            secondAgreement.includes(index),
        ),
    };
};

export const compileCommonAgreementDegreeCensus = () => {
    const systematicSize = 65536;
    const queries = 432;
    const maskDimension = 2 * queries + 1;
    const witnessDegree = systematicSize + maskDimension - 1;
    const codeDimension = 2 * systematicSize;
    const maximumCodeDegree = codeDimension - 1;
    const domainSize = 4 * codeDimension;
    const distanceNumerator = 47;
    const distanceDenominator = 128;
    const minimumAgreementPoints = Math.ceil(
        (domainSize * (distanceDenominator - distanceNumerator)) /
            distanceDenominator,
    );
    const maximumShiftIdentityDegree = 2 * maximumCodeDegree;
    const maximumRelationIdentityDegree = Math.max(
        2 * witnessDegree,
        2 * systematicSize + maskDimension - 2,
    );
    if (
        minimumAgreementPoints <= maximumShiftIdentityDegree ||
        minimumAgreementPoints <= maximumRelationIdentityDegree ||
        2 * distanceNumerator * domainSize >
            distanceDenominator * (domainSize - codeDimension) ||
        2 * distanceNumerator * domainSize >=
            distanceDenominator * (domainSize - codeDimension + 1)
    )
        throw new Error('The direct common-agreement proof premises fail.');
    return {
        systematicSize,
        queries,
        maskDimension,
        witnessDegree,
        codeDimension,
        maximumCodeDegree,
        domainSize,
        distanceNumerator,
        distanceDenominator,
        minimumAgreementPoints,
        maximumShiftIdentityDegree,
        maximumRelationIdentityDegree,
    };
};
