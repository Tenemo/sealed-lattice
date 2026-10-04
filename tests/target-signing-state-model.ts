import { fixedModulusBfvInputs } from '#tests/fixed-modulus-bfv-model.js';
import { compileRegistrationEnrollmentCensus } from '#tests/registration-enrollment-model.js';
import type { SupportedProfile } from '#tests/supported-profile-model.js';

export const compileRetainedEvaluationResources = (
    profile: SupportedProfile,
) => {
    const targetBodyBytes = compileTargetSigningStateCensus().maximumBodyBytes;
    const coefficientBytes =
        1n + BigInt(Math.ceil(profile.release.modulus.toString(2).length / 8));
    const ciphertextBytes =
        2n * fixedModulusBfvInputs.polynomialDegree * coefficientBytes;
    // RET1 is unchanged: marker, body length, body, switched ciphertext and
    // original-credential tag. Bounded SDK slices do not shrink the Rust Vec
    // or the single stored Blob, nor establish allocator/physical storage.
    const maximumRetainedBytes =
        4n + 4n + targetBodyBytes + ciphertextBytes + 64n;
    const maximumSliceBytes = 1_048_576n;
    return {
        ciphertextBytes,
        maximumRetainedBytes,
        maximumSliceBytes,
        maximumSlices:
            (maximumRetainedBytes + maximumSliceBytes - 1n) / maximumSliceBytes,
    };
};

export const compileTargetSigningStateCensus = () => {
    const { signatureBytes } = compileRegistrationEnrollmentCensus();
    const maximumBodyBytes = 2048n;
    const packetBytes = 2n + 64n + signatureBytes;
    // The marker, the close phase, the own ballot's status and the body
    // length.
    const prefixBytes = 4n + 1n + 1n + 2n;
    const intentBytes = prefixBytes + maximumBodyBytes + 32n;
    const completionBytes = prefixBytes + maximumBodyBytes + packetBytes;
    return {
        maximumBodyBytes,
        packetBytes,
        prefixBytes,
        intentBytes,
        completionBytes,
        maximumStateBytes: completionBytes,
    };
};
