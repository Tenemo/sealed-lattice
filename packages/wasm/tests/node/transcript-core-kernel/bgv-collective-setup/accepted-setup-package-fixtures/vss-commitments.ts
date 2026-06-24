import {
    deterministicRandomBytes,
    firstRosterDecryptionThreshold,
    firstRosterParticipantCount,
    minimumSuccinctProofFixtureRingDegree,
} from '../setup-fixture-primitives.js';

import {
    createVssCoefficientCommitmentBundle,
    createVssSourceTrusteeCoefficientOpeningState,
    type VssCoefficientCommitmentBundle,
} from '#packages/protocol/src/setup/vss-coefficient-commitments';
import { type CollectiveBgvSetupContext } from '#packages/protocol/src/setup/vss-share-verification-records';
import type { BgvCollectiveSetupParametersDescription } from '#packages/wasm/src/index';
import { setupCommitmentComputer } from '#tests/support/setup-commitment-computer';

export function acceptedVssCoefficientCommitments(
    setupContext: CollectiveBgvSetupContext,
    parameters: BgvCollectiveSetupParametersDescription,
    publicMatrixSeedHash: string,
): VssCoefficientCommitmentBundle {
    return createVssCoefficientCommitmentBundle({
        setupContext,
        publicMatrixSeedHash,
        setupCommitmentComputer,
        qSharePrimes: parameters.qShare.primes,
        ringDegree: minimumSuccinctProofFixtureRingDegree,
        participantCount: firstRosterParticipantCount,
        thresholdDegree: firstRosterDecryptionThreshold,
        sourceTrusteeOpeningStates: Array.from(
            { length: firstRosterParticipantCount },
            (_unusedSourceTrustee, sourceTrusteeRosterPosition) =>
                createVssSourceTrusteeCoefficientOpeningState({
                    sourceTrusteeIdentity: `trustee-${String(sourceTrusteeRosterPosition)}`,
                    sourceTrusteeRosterPosition,
                    participantCount: firstRosterParticipantCount,
                    qSharePrimes: parameters.qShare.primes,
                    ringDegree: minimumSuccinctProofFixtureRingDegree,
                    thresholdDegree: firstRosterDecryptionThreshold,
                    randomBytes: deterministicRandomBytes(
                        `trustee-${String(sourceTrusteeRosterPosition)}`,
                    ),
                }),
        ),
    });
}
