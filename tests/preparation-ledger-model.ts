import assert from 'node:assert/strict';

import { compileCommonMatrixSamplingCensus } from '#tests/common-matrix-sampling-model.js';
import { binomial } from '#tests/exact-integer.js';
import { fixedModulusBfvInputs } from '#tests/fixed-modulus-bfv-model.js';
import { compileSetupSelectionCensus } from '#tests/setup-selection-model.js';
import {
    listSupportedProfiles,
    type SupportedProfile,
} from '#tests/supported-profile-model.js';
import { thresholdProfileFor } from '#tests/threshold-completion-model.js';

const powerOfTwoCeiling = (value: bigint) =>
    value <= 1n ? 1n : 1n << BigInt((value - 1n).toString(2).length);

export const compilePreparationFamilyInventory = () => {
    const families = new Map<
        string,
        {
            degree: bigint;
            modulus: bigint;
            sampleBits: bigint;
            maximumPositions: bigint;
            selectedSetRange: bigint;
        }
    >();
    for (const profile of listSupportedProfiles()) {
        const sampleBits = BigInt(
            compileCommonMatrixSamplingCensus(profile).fheBitsPerCoefficient,
        );
        const key = `${profile.ciphertext.modulus}:${sampleBits}`;
        const selection = compileSetupSelectionCensus(profile.participantCount);
        const selectedSets = binomial(
            selection.eligibleContributorCount,
            selection.setupContributorCount,
        );
        const previous = families.get(key) ?? {
            degree: fixedModulusBfvInputs.polynomialDegree,
            modulus: profile.ciphertext.modulus,
            sampleBits,
            maximumPositions: 0n,
            selectedSetRange: 1n,
        };
        if (BigInt(profile.participantCount) > previous.maximumPositions)
            previous.maximumPositions = BigInt(profile.participantCount);
        if (powerOfTwoCeiling(selectedSets) > previous.selectedSetRange)
            previous.selectedSetRange = powerOfTwoCeiling(selectedSets);
        families.set(key, previous);
    }
    return [...families.values()];
};

let catalogue: ReturnType<typeof compilePreparationFamilyInventory> | undefined;
const sourceCatalogue = () =>
    (catalogue ??= compilePreparationFamilyInventory());
const pollFamilies = new Map<string, bigint>();
const registrationSourceFamilyCount = (
    maximumParticipants: number,
    optionCount: number,
) => {
    const key = `${maximumParticipants}:${optionCount}`;
    let count = pollFamilies.get(key);
    if (count === undefined) {
        const identities = new Set(
            listSupportedProfiles()
                .filter(
                    (profile) =>
                        profile.optionCount === optionCount &&
                        profile.participantCount <= maximumParticipants,
                )
                .map(
                    (profile) =>
                        `${profile.ciphertext.modulus}:${compileCommonMatrixSamplingCensus(profile).fheBitsPerCoefficient}`,
                ),
        );
        assert.ok(identities.size > 0);
        count = BigInt(identities.size);
        pollFamilies.set(key, count);
    }
    return count;
};

// The early primitive guess covers the complete catalogue, even when the
// public poll parameters are chosen after shared-oracle preprocessing.
// An actual original credential still creates only its poll's source list.
export const compilePreparationLedger = (
    profile: SupportedProfile,
    originalHonestRegistrations: bigint,
    pollMaximumParticipants = profile.participantCount,
) => {
    assert.ok(originalHonestRegistrations >= 0n);
    assert.ok(pollMaximumParticipants >= profile.participantCount);
    const participants = BigInt(pollMaximumParticipants);
    const threshold = thresholdProfileFor(profile.participantCount);
    const corrupt = BigInt(threshold.maximumCorruptParticipantCount);
    const honestEndorsersPerCertificate =
        BigInt(profile.participantCount) - 2n * corrupt;
    const sourceFamilies = registrationSourceFamilyCount(
        pollMaximumParticipants,
        profile.optionCount,
    );
    const allFamilies = sourceCatalogue();
    const selectedPositionEvents = allFamilies.reduce(
        (sum, family) =>
            sum + family.maximumPositions * family.selectedSetRange,
        0n,
    );
    const selection = compileSetupSelectionCensus(profile.participantCount);
    return {
        originalHonestRegistrations,
        honestEndorsersPerCertificate,
        maximumStartedPreparationRosters: originalHonestRegistrations,
        maximumCertifiedRosters:
            originalHonestRegistrations / honestEndorsersPerCertificate,
        maximumHonestContributionScopes: originalHonestRegistrations,
        maximumHonestBallots: originalHonestRegistrations,
        maximumHonestReleases: originalHonestRegistrations,
        maximumHonestProofScopes: 3n * originalHonestRegistrations,
        sourceFamilies,
        generatedSourceEntries: sourceFamilies * originalHonestRegistrations,
        maximumSourceDecodes: participants * originalHonestRegistrations,
        maximumHonestRecipientRows: participants * originalHonestRegistrations,
        recipientKeyComparisons: 2n * originalHonestRegistrations,
        recipientCiphertextComparisons:
            2n * participants * originalHonestRegistrations,
        sourceCiphertextComparisons:
            2n * sourceFamilies * originalHonestRegistrations,
        fheTupleComparisons:
            2n * BigInt(allFamilies.length) * originalHonestRegistrations,
        selectedPositionSets: binomial(
            selection.eligibleContributorCount,
            selection.setupContributorCount,
        ),
        guessedFheFamilies: BigInt(allFamilies.length),
        selectedPositionEvents,
        fheBallotComparisons:
            2n * originalHonestRegistrations * selectedPositionEvents,
        auxiliaryKeyComparisons: 3n,
        auxiliaryBallotComparisons: 2n * originalHonestRegistrations,
    };
};

export const compilePreparationPollPopulations = (
    pollMaximumParticipants: number,
    optionCount: number,
    originalHonestRegistrations: bigint,
) => {
    assert.ok(originalHonestRegistrations >= 0n);
    const families = registrationSourceFamilyCount(
        pollMaximumParticipants,
        optionCount,
    );
    let minimumHonestEndorsersPerCertificate = pollMaximumParticipants;
    for (
        let participants = 3;
        participants <= pollMaximumParticipants;
        participants++
    ) {
        const corrupt =
            thresholdProfileFor(participants).maximumCorruptParticipantCount;
        minimumHonestEndorsersPerCertificate = Math.min(
            minimumHonestEndorsersPerCertificate,
            participants - 2 * corrupt,
        );
    }
    return {
        pollMaximumParticipants,
        originalHonestRegistrations,
        minimumHonestEndorsersPerCertificate: BigInt(
            minimumHonestEndorsersPerCertificate,
        ),
        maximumStartedPreparationRosters: originalHonestRegistrations,
        maximumCertifiedRosters:
            originalHonestRegistrations /
            BigInt(minimumHonestEndorsersPerCertificate),
        maximumHonestRecipientRows:
            BigInt(pollMaximumParticipants) * originalHonestRegistrations,
        maximumSourceDecodes:
            BigInt(pollMaximumParticipants) * originalHonestRegistrations,
        generatedSourceEntries: originalHonestRegistrations * families,
    };
};
