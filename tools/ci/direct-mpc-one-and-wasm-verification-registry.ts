import { foundationProfile } from '#packages/types/src/foundation-contract.js';

const directMpcOneAndVerification = Object.freeze({
    evidenceClassification:
        'one-AND scalar WebAssembly positive-verifier development evidence',
    maximumRequestByteLength: foundationProfile.maximumCopiedBufferByteLength,
    maximumResponseByteLength: 4_096,
    maximumVerificationMilliseconds: 2 * 60 * 1_000,
    maximumWasmMemoryByteLength: foundationProfile.maximumWasmMemoryByteLength,
    verificationId: 'direct-mpc-one-and-positive-verifier',
});

type DirectMpcOneAndWasmVerification = typeof directMpcOneAndVerification;

const directMpcOneAndWasmVerificationRegistry = Object.freeze({
    [directMpcOneAndVerification.verificationId]: directMpcOneAndVerification,
});

export const resolveDirectMpcOneAndWasmVerification = (
    verificationId: string,
): DirectMpcOneAndWasmVerification => {
    const registeredVerificationIds = Object.keys(
        directMpcOneAndWasmVerificationRegistry,
    );
    if (registeredVerificationIds.length === 0) {
        throw new Error(
            'The direct-MPC one-AND verification registry is empty.',
        );
    }
    const verification = (
        directMpcOneAndWasmVerificationRegistry as Readonly<
            Record<string, DirectMpcOneAndWasmVerification>
        >
    )[verificationId];
    if (verification === undefined) {
        throw new Error(
            `No direct-MPC one-AND WebAssembly verification matches "${verificationId}". Registered verifications: ${registeredVerificationIds.join(', ')}.`,
        );
    }
    return verification;
};
