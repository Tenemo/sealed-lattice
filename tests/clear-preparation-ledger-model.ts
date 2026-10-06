import assert from 'node:assert/strict';

import { compileCommonMatrixSamplingCensus } from '#tests/common-matrix-sampling-model.js';
import { sourceCacheWork } from '#tests/compressed-oracle-model.js';
import { fixedModulusBfvInputs } from '#tests/fixed-modulus-bfv-model.js';
import { compileRegistrationSetupBindingScreen } from '#tests/registration-setup-binding-model.js';
import { compileSetupSelectionCensus } from '#tests/setup-selection-model.js';
import {
    listSupportedProfiles,
    type SupportedProfile,
} from '#tests/supported-profile-model.js';
import { compileThresholdCompletionProfile } from '#tests/threshold-completion-model.js';

// Structural comparison counts start at an original retained contribution
// intent's first private generation, including work that never publishes an
// offer. H includes abandoned and unselected original honest registrations.
// Profile rows assume that roster size throughout; the separate poll census
// covers mixed-size forks. Neither supplies primitive advantages, complete
// reduction times, semantic-use errors or a numerical security limit on H.
let sourceCatalogue:
    | {
          families: bigint;
          ciphertextModuli: bigint;
          maximumModulusBytes: bigint;
      }
    | undefined;
const fixedSourceCatalogue = () => {
    if (sourceCatalogue !== undefined) return sourceCatalogue;
    const families = new Set<string>();
    const moduli = new Set<bigint>();
    for (const profile of listSupportedProfiles()) {
        const bits =
            compileCommonMatrixSamplingCensus(profile).fheBitsPerCoefficient;
        families.add(`${profile.ciphertext.modulus}:${bits}`);
        moduli.add(profile.ciphertext.modulus);
    }
    sourceCatalogue = {
        families: BigInt(families.size),
        ciphertextModuli: BigInt(moduli.size),
        maximumModulusBytes: [...moduli].reduce((maximum, modulus) => {
            const bytes = BigInt(Math.ceil(modulus.toString(2).length / 8));
            return bytes > maximum ? bytes : maximum;
        }, 0n),
    };
    return sourceCatalogue;
};

const choose = (population: bigint, selected: bigint) => {
    let result = 1n;
    for (let index = 0n; index < selected; index++)
        result = (result * (population - index)) / (index + 1n);
    return result;
};

const compileSourceCache = (requests: bigint) => {
    const catalogue = fixedSourceCatalogue();
    const familyIndexBits = BigInt(
        (catalogue.families - 1n).toString(2).length,
    );
    return sourceCacheWork(
        requests,
        // The authenticated registration digest binds its original owner,
        // context, recipient key and ordered source commitments. The fixed
        // family ordinal selects the particular commitment within that body.
        512n + familyIndexBits,
        // Canonical salt/coordinate plus the decoder's separate valid bit;
        // shorter families are zero-padded to the fixed catalogue maximum.
        1n +
            8n *
                (64n +
                    fixedModulusBfvInputs.polynomialDegree *
                        (1n + catalogue.maximumModulusBytes)),
    );
};

export const compileClearPreparationPollPopulations = (
    pollMaximumParticipants: number,
    optionCount: number,
    originalHonestRegistrations: bigint,
) => {
    assert.ok(originalHonestRegistrations >= 0n);
    const source = compileRegistrationSetupBindingScreen(
        pollMaximumParticipants,
        optionCount,
    );
    const thresholds = Array.from(
        { length: pollMaximumParticipants - 2 },
        (_, index) => compileThresholdCompletionProfile(index + 3),
    );
    const minimumHonestEndorsersPerCertificate = BigInt(
        Math.min(
            ...thresholds.map(
                (row, index) =>
                    index + 3 - 2 * row.maximumCorruptParticipantCount,
            ),
        ),
    );
    const maximumCorruptParticipants = BigInt(
        Math.max(
            ...thresholds.map((row) => row.maximumCorruptParticipantCount),
        ),
    );
    const maximumSourceCacheLookups =
        originalHonestRegistrations * maximumCorruptParticipants;
    return {
        pollMaximumParticipants,
        originalHonestRegistrations,
        minimumHonestEndorsersPerCertificate,
        maximumStartedPreparationRosters: originalHonestRegistrations,
        maximumCertifiedRosters:
            originalHonestRegistrations / minimumHonestEndorsersPerCertificate,
        maximumHonestRecipientRows:
            BigInt(pollMaximumParticipants) * originalHonestRegistrations,
        maximumSourceCacheLookups,
        maximumCorruptSourceExtractions: maximumSourceCacheLookups,
        generatedSourceEntries:
            originalHonestRegistrations * source.coordinateCount,
        sourceMaskScopes:
            originalHonestRegistrations * fixedSourceCatalogue().families,
        sourceCache: compileSourceCache(maximumSourceCacheLookups),
    };
};

export const compileClearPreparationLedger = (
    profile: SupportedProfile,
    originalHonestRegistrations: bigint,
    pollMaximumParticipants = profile.participantCount,
) => {
    assert.ok(originalHonestRegistrations >= 0n);
    assert.ok(pollMaximumParticipants >= profile.participantCount);
    const participants = BigInt(profile.participantCount);
    const thresholds = compileThresholdCompletionProfile(
        profile.participantCount,
    );
    const corrupt = BigInt(thresholds.maximumCorruptParticipantCount);
    const selection = compileSetupSelectionCensus(profile.participantCount);
    const source = compileRegistrationSetupBindingScreen(
        pollMaximumParticipants,
        profile.optionCount,
    );
    const catalogue = fixedSourceCatalogue();
    const honestEndorsersPerCertificate = participants - 2n * corrupt;
    const maximumStartedPreparationRosters = originalHonestRegistrations;
    const maximumCertifiedRosters =
        originalHonestRegistrations / honestEndorsersPerCertificate;
    const maximumHonestContributionScopes = originalHonestRegistrations;
    const certifiedBallotSlots = maximumCertifiedRosters * participants;
    const maximumHonestBallots =
        certifiedBallotSlots < originalHonestRegistrations
            ? certifiedBallotSlots
            : originalHonestRegistrations;
    const maximumHonestReleases = maximumHonestBallots;
    const maximumHonestRecipientRows =
        participants * maximumHonestContributionScopes;
    const selectedPositionSets = choose(
        BigInt(selection.eligibleCount),
        BigInt(selection.selectedCount),
    );
    // The embedding precedes private generation and guesses the ordinal of a
    // roster's first honest generation, the selected positions and (where
    // necessary) shared-stream modulus. Publication or certification counts
    // cannot supply an earlier online guess space.
    const selectedKeyEventComparisons =
        maximumStartedPreparationRosters *
        selectedPositionSets *
        catalogue.ciphertextModuli;
    // One lookup per corrupt eligible record at each first honest generation.
    // Replaying the retained generation intent reuses its already resolved
    // cache references. Cache misses, including unsuccessful extraction, are
    // immutable entries. No hit is counted as another oracle extraction.
    const maximumSourceCacheLookups =
        maximumStartedPreparationRosters * corrupt;
    return {
        originalHonestRegistrations,
        honestEndorsersPerCertificate,
        maximumStartedPreparationRosters,
        maximumCertifiedRosters,
        maximumHonestContributionScopes,
        maximumHonestBallots,
        maximumHonestReleases,
        maximumHonestProofScopes:
            maximumHonestContributionScopes +
            maximumHonestBallots +
            maximumHonestReleases,
        generatedSourceEntries:
            originalHonestRegistrations * source.coordinateCount,
        sourceMaskScopes: originalHonestRegistrations * catalogue.families,
        maximumCorruptSourceExtractions:
            maximumStartedPreparationRosters * corrupt,
        maximumSourceCacheLookups,
        sourceCache: compileSourceCache(maximumSourceCacheLookups),
        maximumHonestRecipientRows,
        recipientKeyComparisons: 2n * originalHonestRegistrations,
        recipientCiphertextComparisons: 2n * maximumHonestRecipientRows,
        fheTupleComparisons:
            2n * maximumHonestContributionScopes * catalogue.ciphertextModuli,
        selectedPositionSets,
        sharedFheModulusGuesses: catalogue.ciphertextModuli,
        fheSelectedKeyComparisons: 2n * selectedKeyEventComparisons,
        fheBallotComparisons: selectedKeyEventComparisons,
        // Each multi-message comparison must cover every potential ballot in
        // its guessed roster, even when fewer are ultimately published.
        messagesPerFheBallotComparison: participants,
        auxiliaryKeyComparisons: 1n,
        auxiliaryBallotComparisons: maximumHonestBallots === 0n ? 0n : 1n,
        messagesPerAuxiliaryBallotComparison: maximumHonestBallots,
    };
};
