import { fixedModulusBfvInputs } from '#tests/fixed-modulus-bfv-model.js';
import { compileRecipientKeyCensus } from '#tests/recipient-key-model.js';
import type { SupportedProfile } from '#tests/supported-profile-model.js';
import { shareEncryptionParameters } from '#tests/wide-share-lifting-model.js';

// Joint law of one prescribed ordered distinct support and its complete
// waiting-count tuple on an independent uniform position stream. At stage j,
// each rejected draw has j choices; the prescribed next index has one.
export const sparseSupportWaitingLaw = (
    degree: bigint,
    waitingDraws: readonly bigint[],
) => {
    const support = BigInt(waitingDraws.length);
    if (
        degree < 2n ||
        degree > 1n << 32n ||
        (degree & (degree - 1n)) !== 0n ||
        support < 2n ||
        support > degree ||
        support % 2n !== 0n ||
        waitingDraws.some((draws) => draws < 1n)
    )
        throw new RangeError('Invalid balanced-support waiting history.');
    let orderedSupports = 1n;
    let jointNumerator = 1n;
    let draws = 0n;
    for (const [selected, waiting] of waitingDraws.entries()) {
        orderedSupports *= degree - BigInt(selected);
        jointNumerator *= BigInt(selected) ** (waiting - 1n);
        draws += waiting;
    }
    const denominator = degree ** draws;
    return {
        orderedSupports,
        jointNumerator,
        historyNumerator: orderedSupports * jointNumerator,
        denominator,
    };
};

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

export const compileSparseSupportSamplingCensus = (
    profile: SupportedProfile,
) => {
    const registration = compileRecipientKeyCensus();
    const sharing = shareEncryptionParameters;
    return [
        {
            role: 'Registration recipient secret',
            scope: 'registration',
            callsPerOperation: 1n,
            ...boundSparseSupportSampling(
                registration.degree,
                registration.support,
            ),
        },
        {
            role: 'Contribution FHE auxiliary secret',
            scope: 'contribution',
            // The original FHE secret is sampled separately for each
            // registration source family and supplied to from_source.
            callsPerOperation: 1n,
            ...boundSparseSupportSampling(
                fixedModulusBfvInputs.polynomialDegree,
                fixedModulusBfvInputs.secretSupportWeight,
            ),
        },
        {
            role: 'Contribution recipient ephemerals',
            scope: 'contribution',
            callsPerOperation: BigInt(profile.participantCount),
            ...boundSparseSupportSampling(
                fixedModulusBfvInputs.polynomialDegree,
                sharing.encryptionSupportWeight,
            ),
        },
    ];
};
