import {
    firstProfileParticipantCount,
    type JsonRecord,
} from '../setup-fixture-primitives.js';

import {
    createEvaluatorKeySchedule,
    type EvaluatorKeySchedule,
} from '#packages/protocol/src/setup/evaluator-key-schedule';
import {
    type PublicKeyShareProofSet,
    type PublicKeyShareSet,
} from '#packages/protocol/src/setup/public-key-share-records';
import { type SameSecretConsistencyStatementSet } from '#packages/protocol/src/setup/same-secret-consistency-records';
import { type CollectiveBgvSetupContext } from '#packages/protocol/src/setup/vss-share-verification-records';
import type { BgvCollectiveSetupProfileDescription } from '#packages/wasm/src/index';

export function acceptedEvaluatorKeySchedule(
    setupContext: CollectiveBgvSetupContext,
    profile: BgvCollectiveSetupProfileDescription,
    commonRandomness: JsonRecord,
    sameSecretConsistency: SameSecretConsistencyStatementSet,
    publicKeyShares: PublicKeyShareSet,
    publicKeyShareProofs: PublicKeyShareProofSet,
): EvaluatorKeySchedule {
    const publicMatrixSeedHash = String(commonRandomness.publicMatrixSeedHash);
    const publicDerivations = commonRandomness.publicDerivations as JsonRecord;
    const crpRoots = publicDerivations.crpRoots as JsonRecord;

    return createEvaluatorKeySchedule({
        setupContext,
        qSharePrimes: profile.qShare.primes,
        participantCount: firstProfileParticipantCount,
        publicMatrixSeedHash,
        relinearizationCrpRoot: String(crpRoots.relinearizationCrpRoot),
        galoisKeyCrpRoot: String(crpRoots.galoisKeyCrpRoot),
        sameSecretConsistency,
        publicKeyShares,
        publicKeyShareProofs,
        requiredGaloisKeySchedule:
            profile.evaluatorKeyScheduleProfile.requiredGaloisKeySchedule,
    });
}
