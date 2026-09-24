import {
    candidateBgvParameterInputs,
    compileCandidateBgvParameterCensus,
} from '#tests/candidate-bgv-parameter-model.js';

// Direct integer embedding of the KLSW24 key equations over the candidate Q.
// This is distinct from HLS25's generation over p followed by modulus switching.
// It assumes ternary secrets/errors only; correctness and hardness are open.
export const compileFheKeyIntegerEmbeddingBounds = (): Readonly<{
    ciphertextModulus: bigint;
    maximumGadgetCoefficient: bigint;
    maximumNumeratorMagnitude: bigint;
    maximumQuotientMagnitude: bigint;
    minimumProofFieldModulus: bigint;
    quotientRingElementCountPerContributor: bigint;
}> => {
    const parameters = compileCandidateBgvParameterCensus();
    const ciphertextModulus = parameters.ciphertextModulus;
    const minimumPrime =
        candidateBgvParameterInputs.ciphertextModulusPrimeFactors.reduce(
            (minimum, prime) => (minimum < prime ? minimum : prime),
        );
    const maximumGadgetCoefficient = ciphertextModulus / minimumPrime;
    // Each coefficient contains one N-term negacyclic product of a centered
    // public residue and a ternary secret, one public output, a scalar gadget
    // times a ternary secret (except b), and one ternary error.
    const maximumNumeratorMagnitude =
        (parameters.polynomialModulusDegree + 1n) *
            ((ciphertextModulus - 1n) / 2n) +
        maximumGadgetCoefficient +
        1n;
    const maximumQuotientMagnitude =
        (maximumNumeratorMagnitude + ciphertextModulus - 1n) /
        ciphertextModulus;
    return {
        ciphertextModulus,
        maximumGadgetCoefficient,
        maximumNumeratorMagnitude,
        maximumQuotientMagnitude,
        minimumProofFieldModulus:
            maximumNumeratorMagnitude +
            ciphertextModulus * maximumQuotientMagnitude +
            1n,
        quotientRingElementCountPerContributor:
            4n * parameters.ciphertextModulusLimbCount,
    };
};
