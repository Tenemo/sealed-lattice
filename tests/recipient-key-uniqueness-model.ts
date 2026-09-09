import { compileRegistrationKeyRelationCensus } from '#tests/registration-key-relation-model.js';
import { compileSmallLimbProofFieldCensus } from '#tests/small-limb-proof-field-model.js';

// For a uniform a in Z_p[X]/(X^N+1), p=1 mod 2N and N a power of two,
// union over every bounded difference (dx,de). The nonzero integer determinant
// of multiplication by dx is at most (2S*sqrt(N))^N by Hadamard. If its
// reduction has nullity z, p^z divides that determinant, so each equation
// a*dx=de has probability at most (2S*sqrt(N)/p)^N. Secret and error
// coefficient bounds S and E are distinct. This covers every public key
// simultaneously. It is a bad-matrix bound, not computational security.
export const compileRecipientKeyUniquenessBound = (): Readonly<{
    secretCoefficientBound: bigint;
    errorCoefficientBound: bigint;
    secretDifferenceValueCount: bigint;
    errorDifferenceValueCount: bigint;
    polynomialModulusDegree: bigint;
    primeModulus: bigint;
    squaredFailureBaseNumerator: bigint;
    uniformMatrixFailureExponent: bigint;
}> => {
    const relation = compileRegistrationKeyRelationCensus();
    const primeModulus = compileSmallLimbProofFieldCensus().modulus;
    const polynomialModulusDegree = relation.degree;
    // The proved secret is the difference of disjoint Boolean columns. Its
    // sparse support is an additional constraint that this union overcounts.
    const secretCoefficientBound = 1n;
    const errorCoefficientBound = relation.error;
    if (
        polynomialModulusDegree <= 0n ||
        primeModulus <= 2n * secretCoefficientBound ||
        primeModulus <= 2n * errorCoefficientBound ||
        relation.modulus % primeModulus !== 0n ||
        (polynomialModulusDegree & (polynomialModulusDegree - 1n)) !== 0n ||
        (primeModulus - 1n) % (2n * polynomialModulusDegree) !== 0n
    ) {
        throw new Error(
            'The uniqueness lemma requires a split power-of-two cyclotomic ring.',
        );
    }
    const secretDifferenceValueCount = 4n * secretCoefficientBound + 1n;
    const errorDifferenceValueCount = 4n * errorCoefficientBound + 1n;
    // Squaring avoids a floating-point square root in the probability bound.
    const squaredFailureBaseNumerator =
        secretDifferenceValueCount ** 2n *
        errorDifferenceValueCount ** 2n *
        (2n * secretCoefficientBound) ** 2n *
        polynomialModulusDegree;
    let exponentPerCoefficient = 0n;
    while (
        squaredFailureBaseNumerator << (2n * (exponentPerCoefficient + 1n)) <=
        primeModulus ** 2n
    ) {
        exponentPerCoefficient += 1n;
    }
    return {
        secretCoefficientBound,
        errorCoefficientBound,
        secretDifferenceValueCount,
        errorDifferenceValueCount,
        polynomialModulusDegree,
        primeModulus,
        squaredFailureBaseNumerator,
        uniformMatrixFailureExponent:
            polynomialModulusDegree * exponentPerCoefficient,
    };
};
