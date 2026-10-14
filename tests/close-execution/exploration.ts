import {
    bit,
    maskOf,
    masksAtMost,
    memberCount,
    members,
    organizer,
} from '#tests/close-contract-model.js';
import { runCloseExecution } from '#tests/close-execution-model.js';
import { thresholdProfileFor } from '#tests/threshold-completion-model.js';

type CompletionProfileExecutionCensus = Readonly<{
    participantCount: number;
    corruptionSets: number;
    executions: number;
    certifiedExecutions: number;
    maximumHonestOmission: number;
    forcedNoResultExecutions: number;
    maximumListedEntries: number;
    targetedExecutions: number;
    targetedCertifiedExecutions: number;
    organizerOnlyExecutions: number;
    organizerOnlyCertifiedExecutions: number;
    hiddenExecutions: number;
    hiddenCertifiedExecutions: number;
    maximumHeldPerSlot: number;
    maximumReceivedPerHonestSlot: number;
    maximumReceivedPerCorruptSlot: number;
    maximumOrganizerRequestsPerSlot: number;
    maximumForwardedPerResponder: number;
    maximumForwardedToHonestOrganizer: number;
    findings: readonly string[];
}>;

// Every corruption set, with an honest or corrupt organizer, full or partial
// honest turnout, departures inside the budget before the close and after
// certification, isolation of f honest voters, and corrupt equivocation,
// backdating, withheld bodies listed by corrupt responders, abstention,
// withheld responses with late bodies filling the organizer's slots and a
// different envelope for every other honest participant, corrupt ballots and
// responses the relay shows only to the organizer, corrupt ballots hidden from
// the organizer alone, and refused signatures.
export const exploreCompletionProfileExecutions = (
    participantCount = 10,
): CompletionProfileExecutionCensus => {
    const profile = thresholdProfileFor(participantCount);
    const everyone = (1 << participantCount) - 1;
    const findings = new Set<string>();
    let corruptionSets = 0;
    let executions = 0;
    let certifiedExecutions = 0;
    let maximumHonestOmission = 0;
    let forcedNoResultExecutions = 0;
    let maximumListedEntries = 0;
    let targetedExecutions = 0;
    let targetedCertifiedExecutions = 0;
    let organizerOnlyExecutions = 0;
    let organizerOnlyCertifiedExecutions = 0;
    let hiddenExecutions = 0;
    let hiddenCertifiedExecutions = 0;
    let maximumHeldPerSlot = 0;
    let maximumReceivedPerHonestSlot = 0;
    let maximumReceivedPerCorruptSlot = 0;
    let maximumOrganizerRequestsPerSlot = 0;
    let maximumForwardedPerResponder = 0;
    let maximumForwardedToHonestOrganizer = 0;
    for (const corrupt of masksAtMost(
        participantCount,
        profile.maximumCorruptParticipantCount,
    )) {
        corruptionSets += 1;
        const honest = everyone & ~corrupt;
        const others = members(honest & ~bit(organizer), participantCount);
        const budget =
            profile.maximumCorruptParticipantCount - memberCount(corrupt);
        const firstF = maskOf(
            others.slice(0, profile.maximumCorruptParticipantCount),
        );
        const lastF = maskOf(
            others.slice(
                others.length - profile.maximumCorruptParticipantCount,
            ),
        );
        const cases = [
            { isolated: 0, before: 0, after: 0, voters: honest },
            { isolated: firstF, before: 0, after: 0, voters: honest },
            {
                isolated: lastF,
                before: maskOf(others.slice(0, budget)),
                after: 0,
                voters: honest & 0b01010101010101010101,
            },
            { isolated: firstF, before: 0, after: lastF, voters: honest },
            {
                isolated: 0,
                before: 0,
                after: 0,
                voters: honest,
                targeted: true,
            },
            {
                isolated: 0,
                before: 0,
                after: 0,
                voters: honest,
                organizerOnly: true,
            },
            {
                isolated: 0,
                before: 0,
                after: 0,
                voters: honest,
                hidden: true,
            },
        ];
        for (const [index, value] of cases.entries()) {
            const seed = corrupt * 97 + index * 13 + 5;
            const result = runCloseExecution({
                participantCount,
                corrupt,
                voters: value.voters,
                departedBeforeClose: value.before,
                departedAfterCertification: value.after,
                isolated: value.isolated,
                seed,
                corruptVotes:
                    index % 2 === 0 ||
                    value.organizerOnly === true ||
                    value.hidden === true,
                corruptEquivocation: (corrupt + index) % 3,
                corruptBackdating: index === 2,
                corruptWithholdsBody: index === 3,
                corruptListsBodiless: index === 3,
                corruptSignTargets: (corrupt + index) % 2 === 0,
                corruptOmitsIsolated: index % 2 === 1,
                refuseAfterOwnOmission: false,
                corruptTargetsOrganizer: value.targeted === true,
                corruptWithholdsResponses:
                    value.targeted === true || value.hidden === true,
                corruptShowsOnlyOrganizer: value.organizerOnly === true,
                corruptHidesFromOrganizer: value.hidden === true,
            });
            executions += 1;
            if (result.certifiedTargets > 0) certifiedExecutions += 1;
            if (value.targeted === true && (corrupt & bit(organizer)) === 0) {
                targetedExecutions += 1;
                if (result.certifiedTargets > 0)
                    targetedCertifiedExecutions += 1;
            }
            if (
                value.organizerOnly === true &&
                (corrupt & bit(organizer)) === 0
            ) {
                organizerOnlyExecutions += 1;
                if (result.certifiedTargets > 0)
                    organizerOnlyCertifiedExecutions += 1;
            }
            if (value.hidden === true && (corrupt & bit(organizer)) === 0) {
                hiddenExecutions += 1;
                if (result.certifiedTargets > 0) hiddenCertifiedExecutions += 1;
            }
            maximumForwardedPerResponder = Math.max(
                maximumForwardedPerResponder,
                result.maximumForwardedPerResponder,
            );
            if ((corrupt & bit(organizer)) === 0)
                maximumForwardedToHonestOrganizer = Math.max(
                    maximumForwardedToHonestOrganizer,
                    result.maximumForwardedPerResponder,
                );
            maximumHeldPerSlot = Math.max(
                maximumHeldPerSlot,
                result.maximumHeldPerSlot,
            );
            maximumReceivedPerHonestSlot = Math.max(
                maximumReceivedPerHonestSlot,
                result.maximumReceivedPerHonestSlot,
            );
            maximumReceivedPerCorruptSlot = Math.max(
                maximumReceivedPerCorruptSlot,
                result.maximumReceivedPerCorruptSlot,
            );
            maximumOrganizerRequestsPerSlot = Math.max(
                maximumOrganizerRequestsPerSlot,
                result.maximumOrganizerRequestsPerSlot,
            );
            maximumHonestOmission = Math.max(
                maximumHonestOmission,
                result.omittedHonest,
            );
            maximumListedEntries = Math.max(
                maximumListedEntries,
                result.maximumListedEntries,
            );
            if (
                result.inventory?.branch === 'no-result' &&
                value.voters === honest &&
                memberCount(honest) >= profile.minimumTurnout
            )
                forcedNoResultExecutions += 1;
            for (const finding of result.findings) findings.add(finding);
        }
    }
    return {
        participantCount,
        corruptionSets,
        executions,
        certifiedExecutions,
        maximumHonestOmission,
        forcedNoResultExecutions,
        maximumListedEntries,
        targetedExecutions,
        targetedCertifiedExecutions,
        organizerOnlyExecutions,
        organizerOnlyCertifiedExecutions,
        hiddenExecutions,
        hiddenCertifiedExecutions,
        maximumHeldPerSlot,
        maximumReceivedPerHonestSlot,
        maximumReceivedPerCorruptSlot,
        maximumOrganizerRequestsPerSlot,
        maximumForwardedPerResponder,
        maximumForwardedToHonestOrganizer,
        findings: [...findings].sort(),
    };
};
