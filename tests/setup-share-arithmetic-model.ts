import assert from 'node:assert/strict';

import { integerLimbConvolutionMagnitudeBound } from '#tests/exact-integer-convolution-model.js';
import { setupGaussianParameters } from '#tests/setup-randomness-model.js';
import type { SupportedProfile } from '#tests/supported-profile-model.js';
import { shareEncryptionParameters } from '#tests/wide-share-lifting-model.js';

// Both ciphertext components use arbitrary canonical centered public
// coefficients and a bounded sparse ephemeral. Only the constant component
// adds the signed monomial sharing evaluation. No recipient-key witness or
// public-coefficient distribution is assumed by these arithmetic bounds.
export const boundSetupShareArithmetic = (
    modulus: bigint,
    radix: bigint,
    support: bigint,
    errorBound: bigint,
    scale: bigint,
    sharingDegree: number,
    coefficientBits: number,
    withMessage: boolean,
) => {
    assert.ok(
        modulus > radix && modulus < radix * radix && modulus % 2n === 1n,
    );
    assert.ok(radix > 1n && (radix & (radix - 1n)) === 0n);
    assert.ok(
        support > 0n && errorBound >= 0n && errorBound < radix && scale > 0n,
    );
    const radixBits = radix.toString(2).length - 1;
    assert.ok(Number.isSafeInteger(sharingDegree) && sharingDegree > 0);
    assert.ok(
        Number.isSafeInteger(coefficientBits) &&
            coefficientBits > radixBits &&
            coefficientBits < 127,
    );
    const degree = BigInt(sharingDegree);
    const maximumMessage = 1n + degree * (1n << BigInt(coefficientBits - 1));
    const maximumLowSum = degree * (radix / 2n);
    const maximumHighSum =
        degree * (1n << BigInt(coefficientBits - radixBits - 1));
    const maximumOffset = scale * maximumLowSum;
    const maximumLimbProduct = support * (radix - 1n);
    const maximumScaledMessageLow = withMessage
        ? scale * (maximumMessage < radix ? maximumMessage : radix - 1n)
        : 0n;
    const maximumScaledMessageHigh = withMessage
        ? scale * (maximumMessage / radix)
        : 0n;
    const maximumRawLow =
        maximumLimbProduct + errorBound + maximumScaledMessageLow;
    const maximumRawHigh = maximumLimbProduct + maximumScaledMessageHigh;
    const maximumFirstNormalizationCarry = (maximumRawLow + radix - 1n) / radix;
    const maximumFinalNormalizationCarry =
        (maximumRawHigh + maximumFirstNormalizationCarry + radix - 1n) / radix;
    const maximumRawInteger =
        support * (modulus / 2n) +
        errorBound +
        (withMessage ? scale * maximumMessage : 0n);
    const leadingModulusDigit = modulus / radix;
    const maximumQuotientEstimate =
        maximumRawInteger / radix / leadingModulusDigit;
    const maximumQuotient = (maximumRawInteger + modulus / 2n) / modulus;
    const maximumSharedLow = withMessage
        ? (maximumOffset < radix ? maximumOffset : radix - 1n) +
          scale * (maximumLowSum + 1n)
        : 0n;
    const maximumSharedHigh = withMessage
        ? maximumOffset / radix + scale * maximumHighSum
        : 0n;
    const maximumWitnessLowRow =
        maximumLimbProduct +
        radix -
        1n +
        maximumSharedLow +
        errorBound +
        (modulus % radix) * maximumQuotient;
    // A genuine integer equation makes the low row divisible by the radix.
    const maximumWitnessCarry = maximumWitnessLowRow / radix;
    const maximumWitnessHighRow =
        maximumLimbProduct +
        radix -
        1n +
        maximumSharedHigh +
        leadingModulusDigit * maximumQuotient +
        maximumWitnessCarry;
    return {
        maximumMessage,
        maximumLowSum,
        maximumHighSum,
        maximumOffset,
        maximumLimbProduct,
        maximumScaledMessageLow,
        maximumScaledMessageHigh,
        maximumRawLow,
        maximumRawHigh,
        maximumFirstNormalizationCarry,
        maximumFinalNormalizationCarry,
        maximumRawInteger,
        leadingModulusDigit,
        maximumQuotientEstimate,
        maximumQuotient,
        maximumSharedLow,
        maximumSharedHigh,
        maximumWitnessLowRow,
        maximumWitnessCarry,
        maximumWitnessHighRow,
    };
};

export const compileSetupShareArithmeticBounds = (
    profile: SupportedProfile,
) => {
    const parameters = shareEncryptionParameters;
    const radix = 1n << BigInt(profile.shareLifting.limbBits);
    assert.ok(
        profile.shareLifting.limbBits >= 17 &&
            profile.shareLifting.limbBits <= 96,
    );
    assert.ok(
        setupGaussianParameters.minimum >= -64 &&
            setupGaussianParameters.maximum < 64,
    );
    return [true, false].map((withMessage) => {
        const row = boundSetupShareArithmetic(
            parameters.modulus,
            radix,
            parameters.encryptionSupportWeight,
            parameters.errorBound,
            parameters.scale,
            profile.releaseThreshold - 1,
            profile.shareLifting.sharingCoefficientBits,
            withMessage,
        );
        assert.equal(
            row.maximumLimbProduct,
            integerLimbConvolutionMagnitudeBound(
                radix,
                parameters.encryptionSupportWeight,
                parameters.proofPrime,
            ),
        );
        assert.ok(
            BigInt(-setupGaussianParameters.minimum) <= parameters.errorBound,
        );
        assert.ok(
            BigInt(setupGaussianParameters.maximum) <= parameters.errorBound,
        );
        assert.ok(row.leadingModulusDigit > 65536n);
        assert.ok(row.maximumQuotientEstimate < 1n << 16n);
        assert.ok(row.maximumQuotientEstimate < row.leadingModulusDigit);
        assert.ok(row.maximumQuotient < 1n << 15n);
        const carryBits = withMessage ? profile.shareLifting.carryBits : 16;
        assert.ok(row.maximumWitnessCarry < 1n << BigInt(carryBits - 1));
        const signedLimit = 1n << 127n;
        for (const bound of [
            row.maximumMessage,
            row.maximumLowSum + 1n,
            row.maximumHighSum,
            row.maximumOffset,
            row.maximumRawLow,
            row.maximumRawHigh + row.maximumFirstNormalizationCarry,
            (row.maximumFinalNormalizationCarry + 1n) * radix - 1n,
            ((1n << 16n) - 1n) * row.leadingModulusDigit,
            radix * row.maximumQuotientEstimate,
            row.maximumSharedLow,
            row.maximumSharedHigh,
            row.maximumWitnessLowRow,
            row.maximumWitnessHighRow,
        ])
            assert.ok(bound < signedLimit);
        return {
            component: withMessage ? 'constant' : 'linear',
            carryBits,
            ...row,
        };
    });
};
