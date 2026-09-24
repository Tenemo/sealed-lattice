import { compileContributionBodyCensus } from '#tests/contribution-body-model.js';
import { compileFirstOracleCheckpointCensus } from '#tests/first-oracle-checkpoint-model.js';
import type { SupportedProfile } from '#tests/supported-profile-model.js';

export const compileCompletedContributionStateCensus = (
    profile: SupportedProfile,
) => {
    const body = compileContributionBodyCensus(profile);
    const checkpoint = compileFirstOracleCheckpointCensus(profile);
    const maximumProofRecords =
        (body.maximumProofBytes + (1n << 20n) - 1n) / (1n << 20n);
    const maximumPublicRecords =
        checkpoint.publicRecordCount + maximumProofRecords;
    const maximumRootPlaintextBytes = 80n + 106n * maximumPublicRecords;
    const maximumProofCiphertextBytes =
        body.maximumProofBytes + 16n * maximumProofRecords;
    return {
        maximumProofRecords,
        maximumPublicRecords,
        maximumRootPlaintextBytes,
        maximumProofCiphertextBytes,
        maximumRetainedPayloadBytes:
            checkpoint.publicCiphertextBytes +
            maximumProofCiphertextBytes +
            maximumRootPlaintextBytes +
            16n,
        maximumStagedPayloadBytes:
            checkpoint.maximumRetainedPayloadBytes +
            maximumProofCiphertextBytes +
            maximumRootPlaintextBytes +
            16n,
    };
};
