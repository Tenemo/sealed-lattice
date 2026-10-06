import assert from 'node:assert/strict';

import { compileCommonMatrixSamplingCensus } from '#tests/common-matrix-sampling-model.js';
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
// These counts supply no primitive advantages, reduction times, semantic-use
// errors or numerical security limit on H.
let sourceCatalogue: { families: bigint; ciphertextModuli: bigint } | undefined;
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
    };
    return sourceCatalogue;
};

const choose = (population: bigint, selected: bigint) => {
    let result = 1n;
    for (let index = 0n; index < selected; index++)
        result = (result * (population - index)) / (index + 1n);
    return result;
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
