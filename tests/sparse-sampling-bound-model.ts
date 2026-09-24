import { auxiliaryInputEncryptionParameters } from '#tests/auxiliary-input-encryption-parameters.js';
import { fixedModulusBfvInputs } from '#tests/fixed-modulus-bfv-model.js';
import { compileRegistrationKeyRelationCensus } from '#tests/registration-key-relation-model.js';
import { compileWideShareLiftingCensus } from '#tests/wide-share-lifting-model.js';

// Proof-only truncation of the existing sampler, coupled to the same random
// tape. This does not impose a new runtime limit or authorize another attempt.
export const boundSparseSupportSampling = (degree: bigint, support: bigint) => {
    if (
        degree < 2n ||
        degree > 1n << 32n ||
        (degree & (degree - 1n)) !== 0n ||
        support < 2n ||
        support > degree ||
        support % 2n !== 0n
    )
        throw new RangeError('Invalid uniform balanced-support sampler.');

    const maximumDraws = 2n * support;
    // Before completion, each conditional rejection probability is at most
    // (support - 1) / degree. Failure entails more than support rejections;
    // union over support positions and bound the binomial by 2^(2*support).
    const denominator = degree ** support;
    const unboundedNumerator = (4n * (support - 1n)) ** support;
    const numerator =
        unboundedNumerator < denominator ? unboundedNumerator : denominator;
    let failureBits = 0n;
    while (numerator << (failureBits + 1n) <= denominator) failureBits++;
    const maximumExaminedBytes = 4n * maximumDraws;
    const browserBufferBytes = 65_520n;
    const maximumBrowserRandomBytes =
        ((maximumExaminedBytes + browserBufferBytes - 1n) /
            browserBufferBytes) *
        browserBufferBytes;
    return {
        degree,
        support,
        maximumDraws,
        maximumExaminedBytes,
        browserBufferBytes,
        maximumBrowserRandomBytes,
        numerator,
        denominator,
        failureBits,
    };
};

export const compileSparseSupportSamplingCensus = () => {
    const registration = compileRegistrationKeyRelationCensus();
    const sharing = compileWideShareLiftingCensus();
    return [
        {
            role: 'Registration recipient secret',
            callsPerOperation: 1n,
            ...boundSparseSupportSampling(
                registration.degree,
                registration.support,
            ),
        },
        {
            role: 'Contribution FHE secrets',
            callsPerOperation: 2n,
            ...boundSparseSupportSampling(
                fixedModulusBfvInputs.polynomialDegree,
                fixedModulusBfvInputs.secretSupportWeight,
            ),
        },
        {
            role: 'Contribution recipient ephemerals',
            callsPerOperation: fixedModulusBfvInputs.participantCount,
            ...boundSparseSupportSampling(
                fixedModulusBfvInputs.polynomialDegree,
                sharing.encryptionSupportWeight,
            ),
        },
        {
            role: 'Contribution auxiliary secret',
            callsPerOperation: 1n,
            ...boundSparseSupportSampling(
                auxiliaryInputEncryptionParameters.degree,
                auxiliaryInputEncryptionParameters.support,
            ),
        },
    ];
};
