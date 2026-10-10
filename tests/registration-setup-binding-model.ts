import { auxiliaryInputEncryptionParameters } from '#tests/auxiliary-input-encryption-parameters.js';
import { compileCommonMatrixSamplingCensus } from '#tests/common-matrix-sampling-model.js';
import { fixedModulusBfvInputs } from '#tests/fixed-modulus-bfv-model.js';
import { operationSeedBytes } from '#tests/operation-seed-model.js';
import { compileBoundedKeyUniqueness } from '#tests/recipient-key-uniqueness-model.js';
import {
    deriveSupportedProfile,
    supportedProfileRanges,
} from '#tests/supported-profile-model.js';

export const sourceOpeningSaltBytes = 64n;

// First-order screen for committing the FHE encryption-key coordinate
// before the roster exists. The existing proof ties b[0] to the FHE sharing
// constant. Registration commits to this public coordinate, not a private
// seed whose expansion the current proof does not check.
//
// Each distinct FHE common matrix/modulus needs an independent original
// seed. The honest participant later opens only the roster's chosen entry.
// No new modulus, larger-profile substitution or cross-modulus secret reuse
// is assumed. Hash digests and seed/salt lengths are payload subtotals;
// canonical framing, authentication and encrypted custody are not included.
export const compileRegistrationSetupBindingScreen = (
    maximumParticipants: number,
    optionCount: number,
) => {
    deriveSupportedProfile(maximumParticipants, optionCount);
    const { minimum } = supportedProfileRanges().participants;
    const profiles = Array.from(
        { length: maximumParticipants - minimum + 1 },
        (_unused, index) =>
            deriveSupportedProfile(minimum + index, optionCount),
    );
    const families = new Map<
        string,
        { modulus: bigint; sampleBits: number; profiles: number[] }
    >();
    for (const profile of profiles) {
        const sampleBits =
            compileCommonMatrixSamplingCensus(profile).fheBitsPerCoefficient;
        const identity = `${profile.ciphertext.modulus}:${sampleBits}`;
        const family = families.get(identity) ?? {
            modulus: profile.ciphertext.modulus,
            sampleBits,
            profiles: [],
        };
        family.profiles.push(profile.participantCount);
        families.set(identity, family);
    }
    const polynomialBytes = (degree: bigint, modulus: bigint) =>
        degree * (1n + BigInt(Math.ceil(modulus.toString(2).length / 8)));
    const fhe = [...families.values()].map((family) => ({
        ...family,
        publicCoordinateBytes: polynomialBytes(
            fixedModulusBfvInputs.polynomialDegree,
            family.modulus,
        ),
        uniqueness: compileBoundedKeyUniqueness(
            fixedModulusBfvInputs.polynomialDegree,
            family.modulus,
            1n,
            fixedModulusBfvInputs.errorBound,
        ),
    }));
    const auxiliaryPublicCoordinateBytes = polynomialBytes(
        auxiliaryInputEncryptionParameters.degree,
        auxiliaryInputEncryptionParameters.modulus,
    );
    // Real parties use two fixed uniform public coordinates and hold no
    // auxiliary key. Only a good-key proof game needs this decryption bound.
    const auxiliary = {
        publicCoordinateBytes: auxiliaryPublicCoordinateBytes,
        fixedPublicPairBytes: 2n * auxiliaryPublicCoordinateBytes,
        goodKeyPhaseError:
            (2n * auxiliaryInputEncryptionParameters.support + 1n) *
            fixedModulusBfvInputs.errorBound,
        scale: auxiliaryInputEncryptionParameters.scale,
    };
    const coordinateCount = BigInt(fhe.length);
    return {
        maximumParticipants,
        optionCount,
        fhe,
        auxiliary,
        coordinateCount,
        commitmentDigestPayloadBytes: coordinateCount * 64n,
        privateSeedAndSaltPayloadBytes:
            coordinateCount * (operationSeedBytes + sourceOpeningSaltBytes),
        generatedPublicCoordinateBytes: fhe.reduce(
            (sum, family) => sum + family.publicCoordinateBytes,
            0n,
        ),
        largestPublicCoordinateBytes: fhe.reduce(
            (largest, family) =>
                family.publicCoordinateBytes > largest
                    ? family.publicCoordinateBytes
                    : largest,
            0n,
        ),
    };
};
