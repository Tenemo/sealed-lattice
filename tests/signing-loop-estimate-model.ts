import { compileSignatureCounterBoundary } from '#tests/authentication-work-model.js';

// FIPS 204 Appendix C and NIST's potential updates dated 2026-07-31,
// Sheet1!C27:D27. Both statements use a geometric repetition estimate.
export const signingLoopSourceEstimates = [
    {
        source: 'FIPS 204 Appendix C',
        meanNumerator: 51n,
        meanDenominator: 10n,
        minimumIterations: 814n,
    },
    {
        source: 'NIST potential updates 2026-07-31',
        meanNumerator: 257n,
        meanDenominator: 50n,
        minimumIterations: 821n,
    },
] as const;

// Exact arithmetic within the stated source model; this function does not
// establish geometric domination for the implementation or adaptive callers.
export const signingLoopGeometricEstimate = (
    meanNumerator: bigint,
    meanDenominator: bigint,
    iterations: bigint,
) => {
    if (
        meanDenominator <= 0n ||
        meanNumerator <= meanDenominator ||
        iterations < 0n ||
        iterations > compileSignatureCounterBoundary().nonceCapacity
    )
        throw new RangeError('Invalid signing-loop estimate.');
    const numerator = (meanNumerator - meanDenominator) ** iterations;
    const denominator = meanNumerator ** iterations;
    let failureExponent = 0n;
    while (numerator << (failureExponent + 1n) <= denominator)
        failureExponent++;
    return { iterations, numerator, denominator, failureExponent };
};

export const compileSigningLoopSourceComparison = () => {
    const boundary = compileSignatureCounterBoundary();
    return signingLoopSourceEstimates.map((source) => ({
        ...source,
        atSourceLimit: signingLoopGeometricEstimate(
            source.meanNumerator,
            source.meanDenominator,
            source.minimumIterations,
        ),
        beforeSourceLimit: signingLoopGeometricEstimate(
            source.meanNumerator,
            source.meanDenominator,
            source.minimumIterations - 1n,
        ),
        atOriginalLimit: signingLoopGeometricEstimate(
            source.meanNumerator,
            source.meanDenominator,
            signingLoopSourceEstimates[0].minimumIterations,
        ),
        atCheckedCounter: signingLoopGeometricEstimate(
            source.meanNumerator,
            source.meanDenominator,
            boundary.fullIterations,
        ),
    }));
};
