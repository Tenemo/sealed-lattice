import { compileBoundedIntegerSharingPrivacyCensus } from '#tests/bounded-integer-sharing-privacy-model.js';
import { compileCandidateSetupProofFieldCensus } from '#tests/candidate-setup-proof-field-model.js';
import { publicEncryptedSharingModelConstants } from '#tests/public-encrypted-sharing-model.js';
import { compileThresholdKeyAggregationResourceLowerBound } from '#tests/threshold-key-aggregation-resource-model.js';

// AHIV22 Section 5.3 communication expression for its direct arithmetic
// circuit argument. The field-size factor below is the serialized field-element
// bit length from the preceding exact communication formula, not the field
// cardinality. The CMS19 exponent screen assumes at most 2^64 quantum random-
// oracle queries and allocates sixteen bits beyond the 80-bit end-to-end target
// to this component. Its asymptotic constant and fixed-hash encoding remain
// unknown.
const endToEndTargetSecurityBitLength = 80n;
const componentSecurityMarginBitLength = 16n;
const maximumQuantumRandomOracleQueryBitLength = 64n;
const ternaryConstraintMultiplicationCount = 2n;
const shareEncryptionKeyBoundedRingElementCount = 2n;
const shareEncryptionBoundedRingElementCountPerCiphertext = 3n;
const shareEncryptionEquationRingElementCountPerCiphertext = 2n;
const sharingPolynomialNonconstantCoefficientCount = 3n;

const ceilingDivide = (numerator: bigint, denominator: bigint): bigint =>
    (numerator + denominator - 1n) / denominator;

// The smallest exponent e with 2^e >= value, which is the authentication-path
// length of a binary Merkle tree over value leaves.
const ceilingLogarithmBaseTwo = (value: bigint): bigint => {
    let exponent = 0n;
    while (1n << exponent < value) exponent += 1n;
    return exponent;
};

const smallestPowerOfTwoAbove = (value: bigint): bigint => {
    let result = 1n;
    while (result <= value) result *= 2n;
    return result;
};

// The screen charges every Ligero column query a two-thirds survival
// probability. The smallest query count t with (2/3)^t <= 2^-lambda is the
// first t with 2^(lambda + t) <= 3^t, compared in exact integers.
export const minimumLigeroQueryCount = (
    interactiveSoundnessBitLength: bigint,
): bigint => {
    if (interactiveSoundnessBitLength < 0n) {
        throw new RangeError(
            'The interactive soundness bit length must be nonnegative.',
        );
    }
    let queryCount = 0n;
    let scaledPowerOfTwo = 1n << interactiveSoundnessBitLength;
    let powerOfThree = 1n;
    while (scaledPowerOfTwo > powerOfThree) {
        queryCount += 1n;
        scaledPowerOfTwo *= 2n;
        powerOfThree *= 3n;
    }
    return queryCount;
};

export type PublicEncryptedSharingProofResourceCensus = Readonly<{
    binaryDecompositionConstraintCountPerContributor: bigint;
    binaryEndpointConstraintCountPerContributor: bigint;
    binaryDecompositionRingElementCountPerContributor: bigint;
    boundedCoefficientCountPerContributor: bigint;
    boundedRingElementCountPerContributor: bigint;
    encodedProofOracleByteLengthPerContributor: bigint;
    encodedProofOracleFieldElementCountPerContributor: bigint;
    exceedsSetupStorageVarianceCeiling: boolean;
    expandedBoundedWitnessByteLengthPerContributor: bigint;
    fitsSetupProofBudgetBeforeFixedHashAndLiftingConstant: boolean;
    interactiveSoundnessBitLength: bigint;
    ligeroCodeDimension: bigint;
    ligeroCodeLength: bigint;
    ligeroMessageBlockLength: bigint;
    ligeroQueryCount: bigint;
    ligeroRepetitionCount: bigint;
    ligeroWitnessRowCount: bigint;
    linearConstraintCountPerContributor: bigint;
    optimisticCircuitConstraintCountPerContributor: bigint;
    optimisticLigeroProofByteLengthPerContributor: bigint;
    optimisticTenProofCorpusByteLength: bigint;
    proofFieldElementBitLength: bigint;
    proofBudgetRemainingByteLengthPerContributor: bigint;
    publicInputByteLengthPerContributor: bigint;
    publicInputPlusExpandedWitnessByteLengthPerContributor: bigint;
    randomOracleOutputBitLength: bigint;
    sharingCoefficientDecompositionBitLength: bigint;
    ternaryConstraintCountPerContributor: bigint;
    ternaryRingElementCountPerContributor: bigint;
}>;

export const compilePublicEncryptedSharingProofResourceCensus =
    (): PublicEncryptedSharingProofResourceCensus => {
        const resources = compileThresholdKeyAggregationResourceLowerBound();
        const setupProofField = compileCandidateSetupProofFieldCensus();
        const boundedIntegerSharing =
            compileBoundedIntegerSharingPrivacyCensus();
        const ringDegree =
            publicEncryptedSharingModelConstants.productionPolynomialModulusDegree;
        const participantCount =
            publicEncryptedSharingModelConstants.productionParticipantCount;
        const proofFieldElementBitLength = setupProofField.modulusBitLength;
        const componentSecurityBitLength =
            endToEndTargetSecurityBitLength + componentSecurityMarginBitLength;
        const interactiveSoundnessBitLength =
            componentSecurityBitLength +
            2n * maximumQuantumRandomOracleQueryBitLength;
        const randomOracleOutputBitLength =
            componentSecurityBitLength +
            3n * maximumQuantumRandomOracleQueryBitLength;

        // KLSW24 Section 4.1: two secrets and four error vectors; encryption
        // reuses the first b coordinate. Ternary errors are an HLS25-inspired
        // screening choice, not Lattigo's Gaussian errors or a KLSW theorem.
        const fheKeyBoundedRingElementCount =
            2n + 4n * resources.ciphertextModulusLimbCount;
        const ternaryRingElementCountPerContributor =
            fheKeyBoundedRingElementCount +
            shareEncryptionKeyBoundedRingElementCount +
            participantCount *
                shareEncryptionBoundedRingElementCountPerCiphertext;
        // Encode a centered coefficient a as a + R in [0, 2R]. The domain has
        // 2R+1 values, so when R is a power of two the endpoint needs one more
        // bit than R itself.
        const sharingCoefficientDecompositionBitLength = BigInt(
            (2n * boundedIntegerSharing.coefficientSamplingBound).toString(2)
                .length,
        );
        const binaryDecompositionRingElementCountPerContributor =
            sharingPolynomialNonconstantCoefficientCount *
            sharingCoefficientDecompositionBitLength;
        const boundedRingElementCountPerContributor =
            ternaryRingElementCountPerContributor +
            binaryDecompositionRingElementCountPerContributor;
        const boundedCoefficientCountPerContributor =
            boundedRingElementCountPerContributor * ringDegree;
        const ternaryConstraintCountPerContributor =
            ternaryConstraintMultiplicationCount *
            ternaryRingElementCountPerContributor *
            ringDegree;
        const binaryDecompositionConstraintCountPerContributor =
            binaryDecompositionRingElementCountPerContributor * ringDegree;
        // The highest shifted bit denotes exactly 2R. If it is one, all lower
        // bits must be zero; one component-wise product against their sum
        // enforces the endpoint without admitting values above 2R.
        const binaryEndpointConstraintCountPerContributor =
            sharingPolynomialNonconstantCoefficientCount * ringDegree;

        // The optimistic linear rows comprise every public KLSW key equation,
        // one share-encryption key equation, one sharing evaluation per
        // recipient, two share-encryption equations per recipient, and one
        // bit recomposition per decomposed sharing coefficient.
        const linearEquationRingElementCount =
            resources.publicKeyContributionRingElementCount +
            1n +
            participantCount +
            participantCount *
                shareEncryptionEquationRingElementCountPerCiphertext +
            sharingPolynomialNonconstantCoefficientCount;
        const linearConstraintCountPerContributor =
            linearEquationRingElementCount * ringDegree;
        const optimisticCircuitConstraintCountPerContributor =
            ternaryConstraintCountPerContributor +
            binaryDecompositionConstraintCountPerContributor +
            binaryEndpointConstraintCountPerContributor +
            linearConstraintCountPerContributor;

        const ligeroQueryCount = minimumLigeroQueryCount(
            interactiveSoundnessBitLength,
        );
        // Repeat the field-dependent checks until |F|^r >= 2^lambda. The
        // serialized bit length can exceed log2|F| by up to one bit, so the
        // comparison uses the modulus itself.
        let ligeroRepetitionCount = 1n;
        while (
            setupProofField.modulus ** ligeroRepetitionCount <
            1n << interactiveSoundnessBitLength
        ) {
            ligeroRepetitionCount += 1n;
        }
        let best:
            | Readonly<{
                  codeDimension: bigint;
                  codeLength: bigint;
                  messageBlockLength: bigint;
                  proofBitLength: bigint;
                  witnessRowCount: bigint;
              }>
            | undefined;
        for (let messageBlockLength = 1n; ; messageBlockLength += 1n) {
            const codeDimension = smallestPowerOfTwoAbove(
                messageBlockLength + ligeroQueryCount,
            );
            const codeDimensionFieldElementCount =
                (4n * codeDimension + messageBlockLength - 2n) *
                ligeroRepetitionCount;
            // Every proof term is nonnegative, and this term never decreases
            // as the message block grows. Once it alone reaches the best
            // proof, no longer block can be strictly smaller, so stopping
            // here keeps the search exhaustive.
            if (
                best !== undefined &&
                codeDimensionFieldElementCount * proofFieldElementBitLength >=
                    best.proofBitLength
            ) {
                break;
            }
            const codeLength = 3n * codeDimension;
            const witnessRowCount =
                optimisticCircuitConstraintCountPerContributor /
                    messageBlockLength +
                1n;
            const communicatedFieldElementCount =
                codeDimensionFieldElementCount +
                ligeroQueryCount *
                    (4n * witnessRowCount + 3n * ligeroRepetitionCount);
            const proofBitLength =
                communicatedFieldElementCount * proofFieldElementBitLength +
                ligeroQueryCount *
                    ceilingLogarithmBaseTwo(codeLength) *
                    randomOracleOutputBitLength;
            if (best === undefined || proofBitLength < best.proofBitLength) {
                best = {
                    codeDimension,
                    codeLength,
                    messageBlockLength,
                    proofBitLength,
                    witnessRowCount,
                };
            }
        }
        if (best === undefined) {
            throw new Error('The Ligero parameter search found no candidate.');
        }
        const optimisticLigeroProofByteLengthPerContributor = ceilingDivide(
            best.proofBitLength,
            8n,
        );

        const oneExpandedFieldElementByteLength = ceilingDivide(
            proofFieldElementBitLength,
            8n,
        );
        const expandedBoundedWitnessByteLengthPerContributor =
            (boundedCoefficientCountPerContributor +
                sharingPolynomialNonconstantCoefficientCount * ringDegree) *
            oneExpandedFieldElementByteLength;
        const publicInputByteLengthPerContributor =
            resources.onePublicKeyContributionByteLength +
            participantCount *
                resources.minimumPublicEncryptedShareCiphertextRingElementCount *
                resources.oneSerializedShareEncryptionRingElementByteLength +
            resources.oneSerializedShareEncryptionRingElementByteLength;
        const encodedProofOracleFieldElementCountPerContributor =
            (4n * best.witnessRowCount + 5n * ligeroRepetitionCount) *
            best.codeLength;
        const encodedProofOracleByteLengthPerContributor =
            encodedProofOracleFieldElementCountPerContributor *
            oneExpandedFieldElementByteLength;
        const setupStorageVarianceCeilingByteLength = 3_221_225_472n;

        return {
            binaryDecompositionConstraintCountPerContributor,
            binaryEndpointConstraintCountPerContributor,
            binaryDecompositionRingElementCountPerContributor,
            boundedCoefficientCountPerContributor,
            boundedRingElementCountPerContributor,
            encodedProofOracleByteLengthPerContributor,
            encodedProofOracleFieldElementCountPerContributor,
            exceedsSetupStorageVarianceCeiling:
                encodedProofOracleByteLengthPerContributor >
                setupStorageVarianceCeilingByteLength,
            expandedBoundedWitnessByteLengthPerContributor,
            fitsSetupProofBudgetBeforeFixedHashAndLiftingConstant:
                optimisticLigeroProofByteLengthPerContributor <=
                resources.availablePublicEncryptedSharingProofPerContributorByteLength,
            interactiveSoundnessBitLength,
            ligeroCodeDimension: best.codeDimension,
            ligeroCodeLength: best.codeLength,
            ligeroMessageBlockLength: best.messageBlockLength,
            ligeroQueryCount,
            ligeroRepetitionCount,
            ligeroWitnessRowCount: best.witnessRowCount,
            linearConstraintCountPerContributor,
            optimisticCircuitConstraintCountPerContributor,
            optimisticLigeroProofByteLengthPerContributor,
            optimisticTenProofCorpusByteLength:
                participantCount *
                optimisticLigeroProofByteLengthPerContributor,
            proofFieldElementBitLength,
            proofBudgetRemainingByteLengthPerContributor:
                resources.availablePublicEncryptedSharingProofPerContributorByteLength -
                optimisticLigeroProofByteLengthPerContributor,
            publicInputByteLengthPerContributor,
            publicInputPlusExpandedWitnessByteLengthPerContributor:
                publicInputByteLengthPerContributor +
                expandedBoundedWitnessByteLengthPerContributor,
            randomOracleOutputBitLength,
            sharingCoefficientDecompositionBitLength,
            ternaryConstraintCountPerContributor,
            ternaryRingElementCountPerContributor,
        };
    };
