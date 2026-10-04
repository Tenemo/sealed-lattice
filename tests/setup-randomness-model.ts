import { auxiliaryInputEncryptionParameters } from '#tests/auxiliary-input-encryption-parameters.js';
import { fixedModulusBfvInputs } from '#tests/fixed-modulus-bfv-model.js';
import { compileRegistrationSetupBindingScreen } from '#tests/registration-setup-binding-model.js';
import type { SupportedProfile } from '#tests/supported-profile-model.js';

export const setupGaussianParameters = {
    sigmaNumerator: 16n,
    sigmaDenominator: 5n,
    sampleBits: 160n,
    minimum: -64,
    maximum: 63,
} as const;

// One roster's fresh enrollments and completed contributions. By default the
// original poll admits exactly this roster size; a larger poll maximum is a
// separate operand. This is not a population bound for abandoned credentials.
export const compileSetupRandomnessCensus = (
    profile: SupportedProfile,
    originalPollMaximumParticipants = profile.participantCount,
) => {
    if (originalPollMaximumParticipants < profile.participantCount)
        throw new RangeError('The poll maximum cannot exclude the roster.');
    const sourceFamilyCount = compileRegistrationSetupBindingScreen(
        originalPollMaximumParticipants,
        profile.optionCount,
    ).coordinateCount;
    const gadgetLength = profile.gadgetLength;
    const participants = BigInt(profile.participantCount);
    const contributors = BigInt(profile.setupContributorCount);
    const degree = fixedModulusBfvInputs.polynomialDegree;
    const samplesPerContribution =
        (4n * gadgetLength + 2n * participants - 1n) * degree +
        auxiliaryInputEncryptionParameters.degree;
    const samplesPerSourceFamily = degree;
    const samplesPerEnrollment = (1n + sourceFamilyCount) * degree;
    const samplesPerPreparation =
        contributors * samplesPerContribution +
        participants * samplesPerEnrollment;
    const thresholdCount = BigInt(
        setupGaussianParameters.maximum - setupGaussianParameters.minimum,
    );
    const quantizationNumerator = thresholdCount * samplesPerPreparation;
    const quantizationDenominator = 1n << setupGaussianParameters.sampleBits;
    let quantizationBits = 0;
    while (
        quantizationNumerator << BigInt(quantizationBits + 1) <=
        quantizationDenominator
    )
        quantizationBits++;
    const cutoff = BigInt(
        Math.min(
            -setupGaussianParameters.minimum + 1,
            setupGaussianParameters.maximum + 1,
        ),
    );
    const tailExponent =
        (cutoff * cutoff * setupGaussianParameters.sigmaDenominator ** 2n) /
        (2n * setupGaussianParameters.sigmaNumerator ** 2n);
    const ratioExponent =
        ((2n * cutoff + 1n) * setupGaussianParameters.sigmaDenominator ** 2n) /
        (2n * setupGaussianParameters.sigmaNumerator ** 2n);
    if (ratioExponent < 1n)
        throw new Error('The geometric tail bound does not apply.');
    // e > 2 bounds the omitted tails. Normalization cannot increase this
    // bound because the zero coefficient alone has weight one.
    const commonExponent =
        tailExponent > setupGaussianParameters.sampleBits
            ? tailExponent
            : setupGaussianParameters.sampleBits;
    const preparationVariationNumerator =
        samplesPerPreparation *
        ((thresholdCount <<
            (commonExponent - setupGaussianParameters.sampleBits)) +
            (4n << (commonExponent - tailExponent)));
    const preparationVariationDenominator = 1n << commonExponent;
    let preparationSamplingBits = 0;
    while (
        preparationVariationNumerator << BigInt(preparationSamplingBits + 1) <=
        preparationVariationDenominator
    )
        preparationSamplingBits++;
    return {
        originalPollMaximumParticipants,
        sourceFamilyCount,
        samplesPerSourceFamily,
        samplesPerEnrollment,
        samplesPerContribution,
        samplesPerPreparation,
        thresholdCount,
        encodedThresholdBytes:
            thresholdCount * (setupGaussianParameters.sampleBits / 8n),
        contributionSampleBytes:
            samplesPerContribution * (setupGaussianParameters.sampleBits / 8n),
        quantizationNumerator,
        quantizationDenominator,
        quantizationBits,
        tailExponent,
        preparationVariationNumerator,
        preparationVariationDenominator,
        preparationSamplingBits,
    };
};

// A radix-prefix quotient overestimates the true quotient by at most one
// whenever its value is smaller than the leading modulus digit.
export const reduceSignedDigitModel = (
    digits: readonly bigint[],
    radix: bigint,
    modulus: bigint,
) => {
    if (
        radix < 2n ||
        digits.length === 0 ||
        modulus < 2n ||
        modulus % 2n === 0n
    )
        throw new Error('Invalid reduction parameters.');
    const value = digits.reduceRight(
        (total, digit) => total * radix + digit,
        0n,
    );
    const scale = radix ** BigInt(digits.length - 1);
    const leading = modulus / scale;
    if (leading === 0n || leading >= radix)
        throw new Error('Invalid leading modulus digit.');
    const magnitude = value < 0n ? -value : value;
    const estimate = magnitude / scale / leading;
    if (estimate >= leading)
        throw new Error('The single-correction premise fails.');
    const correction = magnitude < estimate * modulus ? 1n : 0n;
    let quotient = estimate - correction;
    let remainder = magnitude - quotient * modulus;
    if (remainder > modulus / 2n) {
        remainder -= modulus;
        quotient++;
    }
    if (value < 0n) {
        remainder = -remainder;
        quotient = -quotient;
    }
    return { value, estimate, correction, remainder, quotient };
};
