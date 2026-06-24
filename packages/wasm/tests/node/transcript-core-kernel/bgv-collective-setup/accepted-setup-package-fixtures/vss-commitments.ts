import {
    deterministicRandomBytes,
    firstProfileDecryptionThreshold,
    firstProfileParticipantCount,
    minimumSuccinctProofFixtureRingDegree,
} from '../setup-fixture-primitives.js';

import {
    createVssCoefficientCommitmentBundle,
    createVssSourceTrusteeCoefficientOpeningState,
    type VssCoefficientCommitmentBundle,
} from '#packages/protocol/src/setup/vss-coefficient-commitments';
import { type CollectiveBgvSetupContext } from '#packages/protocol/src/setup/vss-share-verification-records';
import type { BgvCollectiveSetupProfileDescription } from '#packages/wasm/src/index';
import { setupCommitmentComputer } from '#tests/support/setup-commitment-computer';

export function acceptedVssCoefficientCommitments(
    setupContext: CollectiveBgvSetupContext,
    profile: BgvCollectiveSetupProfileDescription,
    publicMatrixSeedHash: string,
): VssCoefficientCommitmentBundle {
    return createVssCoefficientCommitmentBundle({
        setupContext,
        publicMatrixSeedHash,
        setupCommitmentComputer,
        qSharePrimes: profile.qShare.primes,
        ringDegree: minimumSuccinctProofFixtureRingDegree,
        participantCount: firstProfileParticipantCount,
        thresholdDegree: firstProfileDecryptionThreshold,
        sourceTrusteeOpeningStates: Array.from(
            { length: firstProfileParticipantCount },
            (_unusedSourceTrustee, sourceTrusteeRosterPosition) =>
                createVssSourceTrusteeCoefficientOpeningState({
                    sourceTrusteeIdentity: `trustee-${String(sourceTrusteeRosterPosition)}`,
                    sourceTrusteeRosterPosition,
                    participantCount: firstProfileParticipantCount,
                    qSharePrimes: profile.qShare.primes,
                    ringDegree: minimumSuccinctProofFixtureRingDegree,
                    thresholdDegree: firstProfileDecryptionThreshold,
                    randomBytes: deterministicRandomBytes(
                        `trustee-${String(sourceTrusteeRosterPosition)}`,
                    ),
                }),
        ),
    });
}
