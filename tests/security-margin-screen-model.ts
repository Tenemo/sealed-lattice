import { compilePreparationLedger } from '#tests/preparation-ledger-model.js';
import { type LatticeAssumptionGroup } from '#tests/security-margin/attack-screens.js';
import {
    compileReductionWork,
    requiredAssumptionBits,
} from '#tests/security-margin/reduction-work.js';
import {
    listSupportedProfiles,
    type SupportedProfile,
} from '#tests/supported-profile-model.js';

export const latticeGroupComparisons = (
    group: LatticeAssumptionGroup,
    ledger: ReturnType<typeof compilePreparationLedger>,
) => {
    switch (group) {
        case 'FHE Ring-LWE':
            return ledger.fheBallotComparisons;
        case 'Evaluation-key circular security':
            return ledger.fheTupleComparisons;
        case 'Share-encryption Ring-LWE':
            return (
                ledger.recipientKeyComparisons +
                ledger.recipientCiphertextComparisons
            );
        case 'Auxiliary Ring-LWE':
            return (
                ledger.auxiliaryKeyComparisons +
                ledger.auxiliaryBallotComparisons +
                ledger.sourceCiphertextComparisons
            );
    }
};

export const profilesByParticipantCount = () => {
    const groups = new Map<number, SupportedProfile[]>();
    for (const profile of listSupportedProfiles()) {
        const group = groups.get(profile.participantCount) ?? [];
        group.push(profile);
        groups.set(profile.participantCount, group);
    }
    return [...groups].map(([participantCount, profiles]) => ({
        participantCount,
        profiles,
    }));
};

export const latticeRequirementAt = (
    group: LatticeAssumptionGroup,
    profile: SupportedProfile,
    honestRegistrations: bigint,
) => {
    const ledger = compilePreparationLedger(profile, honestRegistrations);
    const comparisons = latticeGroupComparisons(group, ledger);
    return {
        comparisons,
        work: compileReductionWork(honestRegistrations),
        requiredBits: requiredAssumptionBits(comparisons, honestRegistrations),
    };
};
