import {
    compileContributionGenerationResources,
    publicCoefficientAllowance,
} from '#tests/browser-word-prover-resource-model.js';
import { compileCommonMatrixSamplingCensus } from '#tests/common-matrix-sampling-model.js';
import { fixedModulusBfvInputs } from '#tests/fixed-modulus-bfv-model.js';
import { operationSeedBytes } from '#tests/operation-seed-model.js';
import { deriveSupportedProfile } from '#tests/supported-profile-model.js';

// One source and first gadget at the cheapest supported profile. This is a
// full-ring source-reproduction screen, not a proof, registration, private
// checkpoint, full family inventory run or preparation capability.
export const compileFheKeySourceScreenResources = () => {
    const participantCount = 3;
    const optionCount = 2;
    const profile = deriveSupportedProfile(participantCount, optionCount);
    const degree = fixedModulusBfvInputs.polynomialDegree;
    const modulus = profile.ciphertext.modulus;
    const magnitudeBytes = BigInt(Math.ceil(modulus.toString(2).length / 8));
    const coefficientBytes = 1n + magnitudeBytes;
    const commonSampleBits =
        compileCommonMatrixSamplingCensus(profile).fheBitsPerCoefficient;
    const samplePositions = [
        0,
        1,
        63,
        Number(degree / 4n - 1n),
        Number(degree / 4n),
        Number(degree / 2n),
        Number(degree - 2n),
        Number(degree - 1n),
    ];
    const reportBytes =
        4n +
        6n * 4n +
        2n * 64n +
        BigInt(samplePositions.length) * (4n + coefficientBytes);
    const outputCapacity = 1024n;
    const sourcePayloadBytes = degree * (1n + 16n);
    const limbs = BigInt(Math.ceil(modulus.toString(2).length / 96));
    const keyWitnessBytes = degree * 2n * (limbs + 1n);
    const publicWorkspaceBytes = 4n * degree * publicCoefficientAllowance;
    const privateWorkspaceBytes = 24n * degree * 16n;
    const planAndSparseTransformBytes = 3n * degree * 16n;
    const allocationAllowanceBytes = 64n * 1024n * 1024n;
    const retainedPublicSamples =
        BigInt(samplePositions.length) * publicCoefficientAllowance;
    const sourcePhaseBytes =
        sourcePayloadBytes +
        degree * 17n +
        keyWitnessBytes +
        publicWorkspaceBytes +
        privateWorkspaceBytes +
        planAndSparseTransformBytes +
        allocationAllowanceBytes;
    const continuationPhaseBytes =
        compileContributionGenerationResources(profile).generationAllowance +
        degree * 16n +
        retainedPublicSamples;
    // After the Contribution is dropped, one regenerated public common
    // vector and an independent sparse reference remain. Public samples
    // replace whole retained b[0] vectors; the error reference is streamed.
    const referencePhaseBytes =
        degree * publicCoefficientAllowance +
        degree +
        retainedPublicSamples +
        allocationAllowanceBytes;
    const maximumPhaseBytes = [
        sourcePhaseBytes,
        continuationPhaseBytes,
        referencePhaseBytes,
    ].reduce((maximum, value) => (value > maximum ? value : maximum), 0n);
    return {
        caseId: 0,
        participantCount,
        optionCount,
        degree,
        modulus,
        coefficientBytes,
        commonSampleBits,
        samplePositions,
        reportBytes,
        outputCapacity,
        sourcePayloadBytes,
        keyWitnessBytes,
        publicWorkspaceBytes,
        sourcePhaseBytes,
        continuationPhaseBytes,
        referencePhaseBytes,
        // The four-vector public allowance already covers native product
        // check clones. Use the same conservative screen for both hosts.
        nativePlanningBytes:
            maximumPhaseBytes + operationSeedBytes + 2n * outputCapacity,
        scalarPlanningBytes:
            maximumPhaseBytes + operationSeedBytes + 2n * outputCapacity,
    };
};
