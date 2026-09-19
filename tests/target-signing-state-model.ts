import { compileRegistrationEnrollmentCensus } from '#tests/registration-enrollment-model.js';

export const compileTargetSigningStateCensus = () => {
    const { signatureBytes } = compileRegistrationEnrollmentCensus();
    const maximumBodyBytes = 2048n;
    const packetBytes = 2n + 64n + signatureBytes;
    const prefixBytes = 4n + 1n + 2n;
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
