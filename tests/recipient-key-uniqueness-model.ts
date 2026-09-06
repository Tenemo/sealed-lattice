import { compileBoundedIntegerSharingPrivacyCensus } from '#tests/bounded-integer-sharing-privacy-model.js';
import { publicEncryptedSharingModelConstants } from '#tests/public-encrypted-sharing-model.js';

// For a uniform a in Z_p[X]/(X^N+1), p=1 mod 2N and N a power of two,
// union over every bounded difference (dx,de). The nonzero integer determinant
// of multiplication by dx is at most (2B*sqrt(N))^N by Hadamard. If its
// reduction has nullity z, p^z divides that determinant, so each equation
// a*dx=de has probability at most (2B*sqrt(N)/p)^N. This covers every public
// key simultaneously. It is a bad-matrix bound, not computational security.
export const compileRecipientKeyUniquenessBound = (): Readonly<{
    coefficientBound: bigint;
    differenceValueCount: bigint;
    polynomialModulusDegree: bigint;
    primeModulus: bigint;
    squaredFailureBaseNumerator: bigint;
    uniformMatrixFailureExponent: bigint;
}> => {
    const primeModulus =
        compileBoundedIntegerSharingPrivacyCensus().sharePlaintextModulus;
    const polynomialModulusDegree =
        publicEncryptedSharingModelConstants.productionPolynomialModulusDegree;
    const coefficientBound =
        publicEncryptedSharingModelConstants.maximumSmallCoefficientMagnitude;
    if (
        polynomialModulusDegree <= 0n ||
        primeModulus <= 2n * coefficientBound ||
        (polynomialModulusDegree & (polynomialModulusDegree - 1n)) !== 0n ||
        (primeModulus - 1n) % (2n * polynomialModulusDegree) !== 0n
    ) {
        throw new Error(
            'The uniqueness lemma requires a split power-of-two cyclotomic ring.',
        );
    }
    const differenceValueCount = 4n * coefficientBound + 1n;
    // Squaring avoids a floating-point square root in the probability bound.
    const squaredFailureBaseNumerator =
        differenceValueCount ** 4n *
        (2n * coefficientBound) ** 2n *
        polynomialModulusDegree;
    let exponentPerCoefficient = 0n;
    while (
        squaredFailureBaseNumerator << (2n * (exponentPerCoefficient + 1n)) <=
        primeModulus ** 2n
    ) {
        exponentPerCoefficient += 1n;
    }
    return {
        coefficientBound,
        differenceValueCount,
        polynomialModulusDegree,
        primeModulus,
        squaredFailureBaseNumerator,
        uniformMatrixFailureExponent:
            polynomialModulusDegree * exponentPerCoefficient,
    };
};
