import assert from 'node:assert/strict';

import { compilePreparationLedger } from '#tests/preparation-ledger-model.js';
import {
    fheKnownAttackFloor,
    type LatticeAssumptionGroup,
} from '#tests/security-margin/attack-screens.js';
import {
    reductionVariants,
    firstOracleResumeFactor,
    reductionOperands,
    reductionGates,
    decisiveExperimentGates,
    requiredFheAssumptionBits,
    supportedLevelBits,
    unpricedWorkAllowance,
} from '#tests/security-margin/reduction-work.js';
import {
    listSupportedProfiles,
    type SupportedProfile,
} from '#tests/supported-profile-model.js';

// The single-key Ring-LWE comparisons of the FHE instance in the
// preparation ledger. A good-key multi-message comparison over n messages
// expands into n single-message comparisons, as the ledger requires for a
// single-message assumption.
const fheRingLweComparisons = (
    ledger: ReturnType<typeof compilePreparationLedger>,
) =>
    ledger.fheSelectedKeyComparisons +
    ledger.fheBallotComparisons * ledger.messagesPerFheBallotComparison;

export const latticeGroupComparisons = (
    group: LatticeAssumptionGroup,
    ledger: ReturnType<typeof compilePreparationLedger>,
) => {
    switch (group) {
        case 'FHE Ring-LWE':
            return fheRingLweComparisons(ledger);
        case 'Evaluation-key circular security':
            return ledger.fheTupleComparisons;
        case 'Share-encryption Ring-LWE':
            // Every recipient key's good/uniform/good sweep and both
            // replacements of every honest sharing row to an honest
            // recipient, one ciphertext each.
            return (
                ledger.recipientKeyComparisons +
                ledger.recipientCiphertextComparisons
            );
        case 'Auxiliary Ring-LWE':
            return (
                ledger.auxiliaryKeyComparisons +
                ledger.auxiliaryBallotComparisons *
                    ledger.messagesPerAuxiliaryBallotComparison
            );
    }
};

// Every supported profile of each participant count, the largest modulus
// first and, among equal moduli, the most options first.
export const profilesByParticipantCount = () => {
    const groups = new Map<number, SupportedProfile[]>();
    for (const profile of listSupportedProfiles()) {
        const group = groups.get(profile.participantCount) ?? [];
        group.push(profile);
        groups.set(profile.participantCount, group);
    }
    return [...groups.entries()]
        .sort(([left], [right]) => left - right)
        .map(([participantCount, profiles]) => ({
            participantCount,
            profiles: profiles.sort(
                (left, right) =>
                    right.ciphertext.bits - left.ciphertext.bits ||
                    right.optionCount - left.optionCount,
            ),
        }));
};

// The ledger, comparisons and reduction operands of a group at a profile and
// original honest registration population of one poll.
const groupComparisonInputs = (
    group: LatticeAssumptionGroup,
    profile: SupportedProfile,
    honestRegistrations: bigint,
) => {
    const ledger = compilePreparationLedger(profile, honestRegistrations);
    return {
        ledger,
        comparisons: latticeGroupComparisons(group, ledger),
        operands: reductionOperands(
            profile,
            ledger,
            firstOracleResumeFactor(profile),
        ),
    };
};

const fheComparisonInputs = (
    profile: SupportedProfile,
    honestRegistrations: bigint,
) => groupComparisonInputs('FHE Ring-LWE', profile, honestRegistrations);

// One profile's screen at one original honest registration per participant:
// the smallest population with every member honest. A larger population H
// adds about log2(H/n) bits for the comparisons and as many again for the
// source-domain reduction, whose shadows grow with H.
const screenProfile = (profile: SupportedProfile) => {
    const experimentGates = decisiveExperimentGates;
    const honestRegistrations = BigInt(profile.participantCount);
    const modulusBits = BigInt(profile.ciphertext.bits);
    const { criterion, stressTest } = fheKnownAttackFloor(modulusBits);
    const { ledger, comparisons, operands } = fheComparisonInputs(
        profile,
        honestRegistrations,
    );
    const requirements = reductionVariants.map((variant) => {
        const gates = reductionGates(variant, experimentGates, operands);
        const requiredBits = requiredFheAssumptionBits(
            comparisons,
            gates,
            experimentGates,
        );
        return {
            variant,
            reductionGates: gates,
            requiredBits,
            marginToCriterion: criterion.log2Cost - Number(requiredBits),
            marginToStressTest: stressTest.log2Cost - Number(requiredBits),
        };
    });
    const sourceDomain = requirements.find(
        (value) => value.variant === 'source-domain reduction',
    );
    assert.ok(sourceDomain !== undefined);
    return {
        participantCount: profile.participantCount,
        optionCount: profile.optionCount,
        modulusBits,
        honestRegistrations,
        selectedPositionSets: ledger.selectedPositionSets,
        sharedFheModulusGuesses: ledger.sharedFheModulusGuesses,
        operands,
        comparisons,
        criterion,
        stressTest,
        requirements,
        // The record creation of the simulated proofs is the reduction
        // work this variant leaves unpriced.
        criterionAllowance: unpricedWorkAllowance(
            comparisons,
            sourceDomain.reductionGates,
            supportedLevelBits(criterion),
            experimentGates,
        ),
    };
};

// Each participant count's binding profile: the option count whose
// source-domain requirement leaves the least further work within its own
// criterion level, the largest modulus among equals.
export const compileSecurityMarginScreen = () =>
    profilesByParticipantCount().map(({ profiles }) =>
        profiles
            .map(screenProfile)
            .reduce((binding, row) =>
                row.criterionAllowance < binding.criterionAllowance
                    ? row
                    : binding,
            ),
    );

// The source-domain requirement of a group's comparisons at a profile and an
// original honest registration population of one poll, charged at an
// experiment of the given cost; the decisive experiment decides it. Every
// lattice comparison of the preparation hybrids runs inside the
// extracting simulator that the registration-source step installs, so each
// group's reduction pays the same source-domain work.
export const latticeRequirementAt = (
    group: LatticeAssumptionGroup,
    profile: SupportedProfile,
    honestRegistrations: bigint,
    experimentGates = decisiveExperimentGates,
) => {
    const { comparisons, operands } = groupComparisonInputs(
        group,
        profile,
        honestRegistrations,
    );
    const gates = reductionGates(
        'source-domain reduction',
        experimentGates,
        operands,
    );
    return {
        comparisons,
        operands,
        reductionGates: gates,
        requiredBits: requiredFheAssumptionBits(
            comparisons,
            gates,
            experimentGates,
        ),
    };
};

export const sourceDomainRequirementAt = (
    profile: SupportedProfile,
    honestRegistrations: bigint,
    experimentGates = decisiveExperimentGates,
) =>
    latticeRequirementAt(
        'FHE Ring-LWE',
        profile,
        honestRegistrations,
        experimentGates,
    );
