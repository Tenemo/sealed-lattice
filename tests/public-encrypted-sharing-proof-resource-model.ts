import { compileBoundedIntegerSharingPrivacyCensus } from '#tests/bounded-integer-sharing-privacy-model.js';
import { compileCandidateBgvParameterCensus } from '#tests/candidate-bgv-parameter-model.js';
import { publicEncryptedSharingModelConstants } from '#tests/public-encrypted-sharing-model.js';
import { compileThresholdKeyAggregationResourceLowerBound } from '#tests/threshold-key-aggregation-resource-model.js';

// AHIV22 Section 5.3 communication expression for its direct arithmetic
// circuit argument. The field-size factor below is the serialized field-element
// bit length from the preceding exact communication formula, not the field
// cardinality. The CMS19 exponent screen assumes at most 2^64 quantum random-
// oracle queries and allocates sixteen bits beyond the 80-bit end-to-end target
// to this component. Its asymptotic constant and fixed-hash encoding remain
// unknown.
const endToEndTargetSecurityBitLength = 80;
const componentSecurityMarginBitLength = 16;
const maximumQuantumRandomOracleQueryBitLength = 64;
const ternaryConstraintMultiplicationCount = 2;
const shareEncryptionKeyBoundedRingElementCount = 2;
const shareEncryptionBoundedRingElementCountPerCiphertext = 3;
const shareEncryptionEquationRingElementCountPerCiphertext = 2;
const sharingPolynomialNonconstantCoefficientCount = 3n;

export type PublicEncryptedSharingProofResourceCensus = Readonly<{
    binaryDecompositionConstraintCountPerContributor: bigint;
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
        const candidateBgvParameters = compileCandidateBgvParameterCensus();
        const boundedIntegerSharing =
            compileBoundedIntegerSharingPrivacyCensus();
        const ringDegree =
            publicEncryptedSharingModelConstants.productionPolynomialModulusDegree;
        const participantCount =
            publicEncryptedSharingModelConstants.productionParticipantCount;
        const proofFieldElementBitLength = Number(
            candidateBgvParameters.ciphertextModulusBitLength + 1n,
        );
        const componentSecurityBitLength =
            endToEndTargetSecurityBitLength + componentSecurityMarginBitLength;
        const interactiveSoundnessBitLength =
            componentSecurityBitLength +
            2 * maximumQuantumRandomOracleQueryBitLength;
        const randomOracleOutputBitLength =
            componentSecurityBitLength +
            3 * maximumQuantumRandomOracleQueryBitLength;

        // One FHE secret, one auxiliary secret, one encryption-key error, three
        // relinearization-error vectors, and one automorphism-error vector.
        const fheKeyBoundedRingElementCount =
            3n + 4n * resources.ciphertextModulusLimbCount;
        const ternaryRingElementCountPerContributor =
            fheKeyBoundedRingElementCount +
            BigInt(shareEncryptionKeyBoundedRingElementCount) +
            participantCount *
                BigInt(shareEncryptionBoundedRingElementCountPerCiphertext);
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
            BigInt(ternaryConstraintMultiplicationCount) *
            ternaryRingElementCountPerContributor *
            ringDegree;
        const binaryDecompositionConstraintCountPerContributor =
            binaryDecompositionRingElementCountPerContributor * ringDegree;

        // The optimistic linear rows comprise every public KLSW key equation,
        // one share-encryption key equation, one sharing evaluation per
        // recipient, and two share-encryption equations per recipient.
        const linearEquationRingElementCount =
            resources.publicKeyContributionRingElementCount +
            1n +
            participantCount +
            participantCount *
                BigInt(shareEncryptionEquationRingElementCountPerCiphertext) +
            sharingPolynomialNonconstantCoefficientCount;
        const linearConstraintCountPerContributor =
            linearEquationRingElementCount * ringDegree;
        const optimisticCircuitConstraintCountPerContributor =
            ternaryConstraintCountPerContributor +
            binaryDecompositionConstraintCountPerContributor +
            linearConstraintCountPerContributor;

        const fieldBitLength = proofFieldElementBitLength;
        const ligeroQueryCount = Math.ceil(
            interactiveSoundnessBitLength / Math.log2(3 / 2),
        );
        const ligeroRepetitionCount = Math.max(
            1,
            Math.ceil(interactiveSoundnessBitLength / fieldBitLength),
        );
        const nextPowerOfTwoStrictlyGreater = (value: number): number => {
            let result = 1;
            while (result <= value) result *= 2;
            return result;
        };
        const circuitConstraintCount = Number(
            optimisticCircuitConstraintCountPerContributor,
        );
        const searchLimit = Math.ceil(
            2 * Math.sqrt(4 * ligeroQueryCount * circuitConstraintCount),
        );
        let best:
            | Readonly<{
                  codeDimension: number;
                  codeLength: number;
                  messageBlockLength: number;
                  proofBitLength: number;
                  witnessRowCount: number;
              }>
            | undefined;
        for (
            let messageBlockLength = 1;
            messageBlockLength <= searchLimit;
            messageBlockLength += 1
        ) {
            const codeDimension = nextPowerOfTwoStrictlyGreater(
                messageBlockLength + ligeroQueryCount,
            );
            const codeLength = 3 * codeDimension;
            const witnessRowCount =
                Math.floor(circuitConstraintCount / messageBlockLength) + 1;
            const communicatedFieldElementCount =
                (4 * codeDimension + messageBlockLength - 2) *
                    ligeroRepetitionCount +
                ligeroQueryCount *
                    (4 * witnessRowCount + 3 * ligeroRepetitionCount);
            const proofBitLength =
                communicatedFieldElementCount * fieldBitLength +
                ligeroQueryCount *
                    Math.ceil(Math.log2(codeLength)) *
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
        const optimisticLigeroProofByteLengthPerContributor = BigInt(
            Math.ceil(best.proofBitLength / 8),
        );

        const oneExpandedFieldElementByteLength = BigInt(
            Math.ceil(fieldBitLength / 8),
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
        const encodedProofOracleFieldElementCountPerContributor = BigInt(
            (4 * best.witnessRowCount + 5 * ligeroRepetitionCount) *
                best.codeLength,
        );
        const encodedProofOracleByteLengthPerContributor =
            encodedProofOracleFieldElementCountPerContributor *
            oneExpandedFieldElementByteLength;
        const setupStorageVarianceCeilingByteLength = 3_221_225_472n;

        return {
            binaryDecompositionConstraintCountPerContributor,
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
            interactiveSoundnessBitLength: BigInt(
                interactiveSoundnessBitLength,
            ),
            ligeroCodeDimension: BigInt(best.codeDimension),
            ligeroCodeLength: BigInt(best.codeLength),
            ligeroMessageBlockLength: BigInt(best.messageBlockLength),
            ligeroQueryCount: BigInt(ligeroQueryCount),
            ligeroRepetitionCount: BigInt(ligeroRepetitionCount),
            ligeroWitnessRowCount: BigInt(best.witnessRowCount),
            linearConstraintCountPerContributor,
            optimisticCircuitConstraintCountPerContributor,
            optimisticLigeroProofByteLengthPerContributor,
            optimisticTenProofCorpusByteLength:
                participantCount *
                optimisticLigeroProofByteLengthPerContributor,
            proofFieldElementBitLength: BigInt(fieldBitLength),
            proofBudgetRemainingByteLengthPerContributor:
                resources.availablePublicEncryptedSharingProofPerContributorByteLength -
                optimisticLigeroProofByteLengthPerContributor,
            publicInputByteLengthPerContributor,
            publicInputPlusExpandedWitnessByteLengthPerContributor:
                publicInputByteLengthPerContributor +
                expandedBoundedWitnessByteLengthPerContributor,
            randomOracleOutputBitLength: BigInt(randomOracleOutputBitLength),
            sharingCoefficientDecompositionBitLength,
            ternaryConstraintCountPerContributor,
            ternaryRingElementCountPerContributor,
        };
    };
