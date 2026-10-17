import { compileCommonAgreementDegreeCensus } from '#tests/common-agreement-degree-model.js';
import { fixedModulusBfvInputs } from '#tests/fixed-modulus-bfv-model.js';
import { maximumSharedPathSiblings } from '#tests/merkle-path-sharing-model.js';
import {
    fheRadix,
    setupEquationWidths,
} from '#tests/setup-relation/equations.js';
import { compileSmallLimbProofFieldCensus } from '#tests/small-limb-proof-field-model.js';
import type { SupportedProfile } from '#tests/supported-profile-model.js';
import { compileWeightedFriBound } from '#tests/weighted-fri-bound-model.js';

export const committedOfferPolynomials = (profile: SupportedProfile) =>
    Array.from({ length: Number(profile.gadgetLength) }, (_, gadget) =>
        [1, 2, 4, 6].map((component) => 7 * gadget + component),
    )
        .flat()
        .filter((index) => index !== 1);

export const committedOfferColumns = (profile: SupportedProfile) =>
    committedOfferPolynomials(profile).length *
    Math.ceil(
        profile.ciphertext.modulus.toString(2).length /
            (fheRadix.toString(2).length - 1),
    );

// The least query count whose exact rational error is no larger than the
// existing word proof's. No floating-point logarithm selects this parameter.
const evaluationQueries = () => {
    const agreement = compileCommonAgreementDegreeCensus();
    const targetNumerator =
        BigInt(agreement.distanceDenominator - agreement.distanceNumerator) **
        BigInt(agreement.queries);
    const targetDenominator =
        BigInt(agreement.distanceDenominator) ** BigInt(agreement.queries);
    let numerator = 1n,
        denominator = 1n,
        queries = 0;
    while (numerator * targetDenominator > targetNumerator * denominator) {
        numerator *= 161n;
        denominator *= 256n;
        queries++;
    }
    return queries;
};

const signedBytes = (bound: bigint) =>
    BigInt(Math.ceil((bound.toString(2).length + 1) / 8));

export const compileCommittedOfferCensus = (profile: SupportedProfile) => {
    const agreement = compileCommonAgreementDegreeCensus();
    const field = compileSmallLimbProofFieldCensus();
    const degree = BigInt(agreement.systematicSize);
    const domain = BigInt(agreement.domainSize);
    const columns = BigInt(committedOfferColumns(profile));
    const contributors = BigInt(profile.setupContributorCount);
    const { quotientBits, fheCarryBits, errorBits } = setupEquationWidths;
    const digitBound =
        fixedModulusBfvInputs.secretSupportWeight * (fheRadix - 1n) +
        fheRadix -
        1n +
        (1n << BigInt(quotientBits)) * (fheRadix - 1n) +
        (1n << BigInt(fheCarryBits)) * fheRadix +
        (1n << BigInt(fheCarryBits)) +
        (1n << BigInt(errorBits));
    const aggregateBound = contributors * digitBound;
    const cleanLimbBytes = signedBytes(contributors * (fheRadix - 1n));
    const maximumLimbBytes = signedBytes(aggregateBound);
    const queries = evaluationQueries();
    const folds = Math.log2(Number(degree));
    const group = (length: number, width: bigint) => {
        const leaves = Math.min(2 * queries, length);
        return (
            4n +
            BigInt(leaves) * (4n + width) +
            64n * BigInt(maximumSharedPathSiblings(length, leaves))
        );
    };
    const evaluationHeaderBytes = 96n + BigInt(folds - 1) * 64n;
    let maximumEvaluationProofBytes =
        evaluationHeaderBytes + group(Number(domain), 16n * columns);
    for (let length = Number(domain / 2n); length > 4; length /= 2)
        maximumEvaluationProofBytes += group(length, 48n);
    const agreementPoints =
        (domain *
            BigInt(
                agreement.distanceDenominator - agreement.distanceNumerator,
            )) /
        BigInt(agreement.distanceDenominator);
    const minimumDegree = degree - 2n;
    const maximumDegree = 2n * degree - 1n;
    let evaluationMessageBytes = 1n;
    while (
        evaluationMessageBytes < 96n * (columns + 1n) ||
        evaluationMessageBytes < 4n * BigInt(queries)
    )
        evaluationMessageBytes *= 2n;
    const weightedFri = compileWeightedFriBound(domain, 161n, 256n, 4n);
    const fieldSize = field.modulus ** 3n;
    const nonbaseSpace = field.modulus ** 2n * (field.modulus - 1n);
    const pointError = {
        numerator: (degree - 1n) * fieldSize + nonbaseSpace,
        denominator: nonbaseSpace * fieldSize,
    };
    const foldError = {
        numerator: weightedFri.upper.numerator,
        denominator: weightedFri.upper.denominator * fieldSize,
    };
    const uniformAlgebraic =
        pointError.numerator * foldError.denominator >
        foldError.numerator * pointError.denominator
            ? pointError
            : foldError;
    const density = {
        numerator: 1n << 256n,
        denominator: (1n << 256n) - 3n * (columns + 1n) * field.modulus,
    };
    const sampledAlgebraic = {
        numerator: uniformAlgebraic.numerator * density.numerator,
        denominator: uniformAlgebraic.denominator * density.denominator,
    };
    const queryError = {
        numerator: 161n ** BigInt(queries),
        denominator: 256n ** BigInt(queries),
    };
    const queryDominates =
        queryError.numerator * sampledAlgebraic.denominator >=
        sampledAlgebraic.numerator * queryError.denominator;
    const roundError = queryDominates ? queryError : sampledAlgebraic;
    return {
        committedPolynomials: committedOfferPolynomials(profile),
        committedColumns: columns,
        publicOracleBytes: columns * domain * 16n,
        columnDegree: degree - 1n,
        evaluationQuotientDegree: degree - 2n,
        degreeShiftIdentityDegree: 2n * maximumDegree - minimumDegree,
        agreementPoints,
        committedDigitMagnitudeBound: digitBound,
        aggregateLimbMagnitudeBound: aggregateBound,
        proofFieldModulus: field.modulus,
        generatedAggregateLimbBytes: cleanLimbBytes,
        maximumAggregateLimbBytes: maximumLimbBytes,
        generatedAggregateBytes: columns * degree * cleanLimbBytes,
        maximumAggregateBytes: columns * degree * maximumLimbBytes,
        aggregateManifestBytes:
            1n + 64n * BigInt(committedOfferPolynomials(profile).length),
        evaluationQueries: queries,
        evaluationFolds: folds,
        evaluationMessageBytes,
        weightedFri,
        pointError,
        density,
        sampledAlgebraic,
        queryError,
        queryDominates,
        roundError,
        evaluationHeaderBytes,
        maximumEvaluationProofBytes,
        // A false evaluation quotient can agree with a degree-bounded
        // word only at the original oracle's exceptional positions or at
        // roots of its nonzero degree-N difference polynomial.
        falseQuotientAgreementNumerator:
            BigInt(agreement.distanceNumerator) * domain +
            degree * BigInt(agreement.distanceDenominator),
        falseQuotientAgreementDenominator:
            BigInt(agreement.distanceDenominator) * domain,
        evaluationDistanceNumerator: 95n,
        evaluationDistanceDenominator: 256n,
    };
};
