import { fixedModulusBfvInputs } from '#tests/fixed-modulus-bfv-model.js';
import {
    compileBallotWordProofLayout,
    compileLinkedReleaseWordProofLayout,
} from '#tests/full-word-proof-layout-model.js';
import type { SupportedProfile } from '#tests/supported-profile-model.js';

// Fresh private randomness of a contribution generation or continuation, a
// ballot or a release is SHAKE256 output over its stream's domain and one
// 512-bit seed that the participant's root retains before the operation
// draws any byte. Its original FHE secret and first encryption error instead
// come from a separately retained registration source seed.
export const operationSeedBytes = 64n;

// The seeds the participants of one roster draw: each setup contributor's
// generation and continuation seeds, and each participant's ballot and
// release seeds. A repeated operation reads its retained seed again. Original
// registration source seeds are counted separately by their poll-family owner.
export const operationSeedCount = (profile: SupportedProfile) =>
    2n * BigInt(profile.setupContributorCount) +
    2n * BigInt(profile.participantCount);

// The proof stream's bytes when no candidate word is rejected: a ballot's
// proof requests, and a release's noise, drawn in whole reads, then its proof
// requests.
export const compileOperationProofDraws = (profile: SupportedProfile) => {
    const readBytes = 65_536n;
    if (profile.releaseNoiseBits % 8 !== 0)
        throw new Error('Release noise requires an exact byte width.');
    const noiseBytes =
        fixedModulusBfvInputs.polynomialDegree *
        BigInt(profile.releaseNoiseBits / 8);
    return {
        ballot: compileBallotWordProofLayout(profile)
            .minimumRequestedRandomBytes,
        release:
            ((noiseBytes + readBytes - 1n) / readBytes) * readBytes +
            compileLinkedReleaseWordProofLayout(profile)
                .minimumRequestedRandomBytes,
    };
};
