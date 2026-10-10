import { fixedModulusBfvInputs } from '#tests/fixed-modulus-bfv-model.js';
import {
    compileBallotWordProofLayout,
    compileLinkedReleaseWordProofLayout,
    merkleSaltSeedBytes,
} from '#tests/full-word-proof-layout-model.js';
import { compileProofVerifierQueryCensus } from '#tests/proof-verifier-query-model.js';
import { compileSetupSelectionCensus } from '#tests/setup-selection-model.js';
import type { SupportedProfile } from '#tests/supported-profile-model.js';

// Fresh private randomness of a contribution generation or continuation, a
// ballot or a release is SHAKE256 output over its stream's domain and one
// 512-bit seed that the participant's root retains before the operation
// draws any byte. Its original FHE secret and first encryption error instead
// come from a separately retained registration source seed.
export const operationSeedBytes = 64n;

// The maximum seeds of one roster: each eligible contributor's
// generation and continuation seeds, and each participant's ballot and
// release seeds. A repeated operation reads its retained seed again. Original
// registration source seeds are counted separately by their poll-family owner.
export const operationSeedCount = (profile: SupportedProfile) =>
    2n *
        BigInt(
            compileSetupSelectionCensus(profile.participantCount).eligibleCount,
        ) +
    2n * BigInt(profile.participantCount);

// Bounds seeded private-randomness scopes, not all private hash calls,
// repeated reads or completed rosters. A contribution intent may later have
// one continuation intent.
// A tree scope fixes its seed while allowing every encoded leaf index; it
// is not one XOF query. The whole-poll caller supplies its original source
// entry and intent populations, including unfinished work.
export const compilePrivateRandomnessScopes = (
    registrationSourceEntries: bigint,
    contributionIntents: bigint,
    ballotIntents: bigint,
    releaseIntents: bigint,
) => {
    if (
        [
            registrationSourceEntries,
            contributionIntents,
            ballotIntents,
            releaseIntents,
        ].some((count) => count < 0n)
    )
        throw new RangeError('Negative private-randomness population.');
    const treesPerProof = BigInt(
        compileProofVerifierQueryCensus().groups.length,
    );
    const proofScopes = contributionIntents + ballotIntents + releaseIntents;
    const treeSeedScopes = treesPerProof * proofScopes;
    const operationSeeds =
        2n * contributionIntents + ballotIntents + releaseIntents;
    const domains = [
        {
            domain: 'sealed-lattice/fhe-source-randomness/v2',
            initialized: registrationSourceEntries,
            read: registrationSourceEntries,
        },
        {
            domain: 'sealed-lattice/contribution-witness-randomness/v1',
            initialized: 2n * contributionIntents,
            read: contributionIntents,
        },
        {
            domain: 'sealed-lattice/contribution-proof-randomness/v1',
            initialized: 2n * contributionIntents,
            read: 2n * contributionIntents,
        },
        {
            domain: 'sealed-lattice/ballot-encryption-randomness/v1',
            initialized: ballotIntents,
            read: ballotIntents,
        },
        {
            domain: 'sealed-lattice/ballot-proof-randomness/v1',
            initialized: ballotIntents,
            read: ballotIntents,
        },
        {
            domain: 'sealed-lattice/release-proof-randomness/v1',
            initialized: releaseIntents,
            read: releaseIntents,
        },
        {
            domain: 'bounded-proof/salt',
            initialized: treeSeedScopes,
            read: treeSeedScopes,
        },
    ];
    const seedDraws =
        registrationSourceEntries + operationSeeds + treeSeedScopes;
    const minimumSeedBits =
        8n *
        (operationSeedBytes < merkleSaltSeedBytes
            ? operationSeedBytes
            : merkleSaltSeedBytes);
    return {
        domains,
        treesPerProof,
        proofScopes,
        operationSeeds,
        treeSeedScopes,
        maximumSeedDraws: seedDraws,
        maximumInitializedScopes: domains.reduce(
            (sum, row) => sum + row.initialized,
            0n,
        ),
        maximumReadScopes: domains.reduce((sum, row) => sum + row.read, 0n),
        // Conditional union bound after the separately justified ideal-tape
        // comparison. Equal seeds in different raw domains need not collide;
        // counting all pairs is conservative. This is not the query-hit term.
        seedCollisionPairs:
            (seedDraws * (seedDraws === 0n ? 0n : seedDraws - 1n)) / 2n,
        seedCollisionDenominator: 1n << minimumSeedBits,
    };
};

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
