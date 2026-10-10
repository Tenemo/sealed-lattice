import {
    bit,
    checkCloseContract,
    closeInventory,
    deriveCloseProfile,
    identityOf,
    listKnownEnvelopes,
    maskOf,
    masksAtMost,
    masksOfSize,
    maximumListedEnvelopesPerSlot,
    memberCount,
    members,
    organizer,
    product,
    usableEnvelopes,
    verifyCloseProposal,
    type CloseEnvelope,
    type CloseIntent,
    type CloseProfile,
    type CloseProposal,
    type CloseResponse,
    type SlotClassification,
} from '#tests/close-contract-model.js';
import {
    exploreCompletionProfileExecutions,
    runCloseExecution,
    type CloseExecutionOptions,
} from '#tests/close-execution-model.js';
import { preparationStagePath } from '#tests/setup-selection-model.js';

// Analyses of the close-response contract over the contract model and its
// message-level executions: exhaustive joint views, every honest lister set,
// the obligation counterexamples, the productive visits and the census.
// This model creates no protocol capability.

const mandatoryVisitCeiling = 10;

// Exhaustive joint views for the smallest rosters.
//
// Delivery order reaches an honest participant's close behavior only through
// the envelopes and bodies it holds when it responds, which intent it locked
// first, whether its own locked ballot precedes it, and which valid proposal
// it verifies first. A corrupt slot here has at most two variants, so knowing
// both lists the same pair as holding both: envelope knowledge without bodies,
// and the organizer's later response, add no listing, only fewer holders of
// an already conflicting slot. Every combination enumerated
// here arises from some delivery order: cast every ballot, deliver the chosen
// envelopes, then the chosen intents; the relay may delay everything else.
// This enumerates delivery orders up to observable behavior. Late and
// bodiless envelopes cannot be listed by anyone, and a late honest ballot is
// not an omission, so both are covered by the absent case here and exercised
// by the message-level executions below. Positions 1 to n - 1 play identical
// roles, so one nonorganizer corruption represents all of them.

type JointEnvelope = Readonly<{
    author: number;
    time: number;
    validProof: boolean;
}>;

export type JointCloseCensus = Readonly<{
    participantCount: number;
    corruptionCases: number;
    views: number;
    inventories: number;
    referenceCrossChecks: number;
    maximumHonestOmission: number;
    noResultInventories: number;
    conflictingSlots: number;
    findings: readonly string[];
}>;

const corruptVariantChoices: readonly (readonly boolean[])[] = [
    [],
    [true],
    [false],
    [true, true],
    [true, false],
];

export const exploreJointCloseViews = (
    participantCount: 3 | 4,
): JointCloseCensus => {
    const profile = deriveCloseProfile(participantCount);
    const everyone = (1 << participantCount) - 1;
    const corruptionCases =
        profile.faultBound === 0 ? [0] : [0, bit(organizer), bit(1)];
    const findings = new Set<string>();
    let views = 0;
    let inventories = 0;
    let referenceCrossChecks = 0;
    let maximumHonestOmission = 0;
    let noResultInventories = 0;
    let conflictingSlots = 0;
    for (const corrupt of corruptionCases) {
        const honest = members(everyone & ~corrupt, participantCount);
        const corruptMembers = members(corrupt, participantCount);
        const organizerCorrupt = (corrupt & bit(organizer)) !== 0;
        // A corrupt organizer signs two intents; time class 1 is on time for
        // both and class 2 only for the later intent.
        const closeTimes = organizerCorrupt ? [1, 2] : [2];
        const honestBallotChoices = organizerCorrupt ? [0, 1, 2] : [0, 2];
        // A corrupt organizer's own variants add nothing beyond another
        // corrupt slot, so it casts at most one.
        const corruptChoices = organizerCorrupt
            ? corruptVariantChoices.slice(0, 3)
            : corruptVariantChoices;
        for (const honestTimes of product(
            honest.map(() => honestBallotChoices),
        ))
            for (const corruptVariants of product(
                corruptMembers.map(() => corruptChoices),
            )) {
                const envelopes: JointEnvelope[] = [];
                honest.forEach((author, index) => {
                    const time = honestTimes[index];
                    if (time !== 0)
                        envelopes.push({ author, time, validProof: true });
                });
                corruptMembers.forEach((author, index) => {
                    for (const validProof of corruptVariants[index])
                        envelopes.push({ author, time: 1, validProof });
                });
                const result = checkJointEnvelopeSet(
                    profile,
                    corrupt,
                    honest,
                    closeTimes,
                    envelopes,
                );
                views += result.views;
                inventories += result.inventories;
                referenceCrossChecks += result.referenceCrossChecks;
                maximumHonestOmission = Math.max(
                    maximumHonestOmission,
                    result.maximumHonestOmission,
                );
                noResultInventories += result.noResultInventories;
                conflictingSlots += result.conflictingSlots;
                for (const finding of result.findings) findings.add(finding);
            }
    }
    return {
        participantCount,
        corruptionCases: corruptionCases.length,
        views,
        inventories,
        referenceCrossChecks,
        maximumHonestOmission,
        noResultInventories,
        conflictingSlots,
        findings: [...findings].sort(),
    };
};

const checkJointEnvelopeSet = (
    profile: CloseProfile,
    corrupt: number,
    honest: readonly number[],
    closeTimes: readonly number[],
    envelopes: readonly JointEnvelope[],
) => {
    const n = profile.participantCount;
    const count = envelopes.length;
    const allEnvelopes = (1 << count) - 1;
    const slotMasks = Array.from({ length: n }, (_unused, author) =>
        envelopes.reduce(
            (mask, envelope, index) =>
                envelope.author === author ? mask | bit(index) : mask,
            0,
        ),
    );
    const onTimeMasks = closeTimes.map((closeTime) =>
        envelopes.reduce(
            (mask, envelope, index) =>
                envelope.time <= closeTime ? mask | bit(index) : mask,
            0,
        ),
    );
    const honestMask = maskOf(honest);
    const signerSets = masksOfSize(n, profile.quorum).filter(
        (mask) => (mask & bit(organizer)) !== 0,
    );
    // Every held subset of other envelopes, for every intent.
    type HonestOption = Readonly<{
        intent: number;
        held: number;
        listed: number;
    }>;
    const honestOptions = honest.map((participant) => {
        const own = slotMasks[participant];
        const others = allEnvelopes & ~own;
        const options: HonestOption[] = [];
        for (const [intent, onTime] of onTimeMasks.entries())
            for (let received = others; ; received = (received - 1) & others) {
                const held = own | received;
                options.push({ intent, held, listed: held & onTime });
                if (received === 0) break;
            }
        return options;
    });
    const corruptListings = onTimeMasks.map((onTime) => {
        const listings: number[] = [];
        for (let listed = onTime; ; listed = (listed - 1) & onTime) {
            listings.push(listed);
            if (listed === 0) break;
        }
        return listings;
    });
    const findings = new Set<string>();
    let views = 0;
    let inventories = 0;
    let referenceCrossChecks = 0;
    let maximumHonestOmission = 0;
    let noResultInventories = 0;
    let conflictingSlots = 0;
    const indices = new Array<number>(honest.length).fill(0);
    for (;;) {
        views += 1;
        const chosen = honest.map(
            (_participant, index) => honestOptions[index][indices[index]],
        );
        const holders = new Array<number>(count).fill(0);
        chosen.forEach((option, index) => {
            for (let envelope = 0; envelope < count; envelope += 1)
                if ((option.held & bit(envelope)) !== 0)
                    holders[envelope] |= bit(honest[index]);
        });
        const answerOf = new Map(
            honest.map((participant, index) => [participant, chosen[index]]),
        );
        let crossCheckPending = views % 64 === 1;
        for (const [intent, onTime] of onTimeMasks.entries())
            for (const signers of signerSets) {
                const honestInside = members(signers & honestMask, n);
                if (
                    honestInside.some(
                        (participant) =>
                            answerOf.get(participant)!.intent !== intent,
                    )
                )
                    continue;
                const honestUnion = honestInside.reduce(
                    (union, participant) =>
                        union | answerOf.get(participant)!.listed,
                    0,
                );
                const corruptInside = members(signers & corrupt, n);
                for (const listings of product(
                    corruptInside.map(() => corruptListings[intent]),
                )) {
                    const union = listings.reduce(
                        (value, listing) => value | listing,
                        honestUnion,
                    );
                    inventories += 1;
                    const outcome = checkJointInventory(
                        profile,
                        corrupt,
                        envelopes,
                        slotMasks,
                        onTime,
                        holders,
                        signers,
                        union,
                        answerOf.get(organizer)?.intent === intent,
                    );
                    for (const finding of outcome.findings)
                        findings.add(finding);
                    maximumHonestOmission = Math.max(
                        maximumHonestOmission,
                        outcome.omittedHonest,
                    );
                    if (outcome.branch === 'no-result')
                        noResultInventories += 1;
                    conflictingSlots += outcome.conflictingSlots;
                    if (crossCheckPending) {
                        crossCheckPending = false;
                        referenceCrossChecks += 1;
                        crossCheckReference(
                            profile,
                            corrupt,
                            envelopes,
                            closeTimes,
                            intent,
                            chosen,
                            honest,
                            corruptInside,
                            listings,
                            signers,
                            outcome,
                        );
                    }
                }
            }
        let position = 0;
        while (position < honest.length) {
            indices[position] = indices[position] + 1;
            if (indices[position] < honestOptions[position].length) break;
            indices[position] = 0;
            position += 1;
        }
        if (position === honest.length) break;
    }
    return {
        views,
        inventories,
        referenceCrossChecks,
        maximumHonestOmission,
        noResultInventories,
        conflictingSlots,
        findings: [...findings],
    };
};

type JointOutcome = Readonly<{
    findings: readonly string[];
    omittedHonest: number;
    branch: 'evaluation' | 'no-result';
    conflictingSlots: number;
    slots: readonly SlotClassification[];
}>;

const checkJointInventory = (
    profile: CloseProfile,
    corrupt: number,
    envelopes: readonly JointEnvelope[],
    slotMasks: readonly number[],
    onTime: number,
    holders: readonly number[],
    signers: number,
    union: number,
    organizerAnsweredIntent: boolean,
): JointOutcome => {
    const findings: string[] = [];
    const slots = slotMasks.map((slot): SlotClassification => {
        const listed = union & slot;
        if (listed === 0) return 'absent';
        if (memberCount(listed) > 1) return 'conflicting';
        const index = Math.log2(listed);
        return envelopes[index].validProof ? 'accepted' : 'invalid';
    });
    if ((union & ~onTime) !== 0) findings.push('cutoff');
    let omittedHonest = 0;
    envelopes.forEach((envelope, index) => {
        if ((onTime & bit(index)) === 0 || (union & bit(index)) !== 0) return;
        const covered = slots[envelope.author] === 'conflicting';
        const honestHolders = holders[index] & ~corrupt;
        if (!covered && memberCount(honestHolders) > profile.faultBound)
            findings.push('inclusion');
        if (
            !covered &&
            (corrupt & bit(organizer)) === 0 &&
            organizerAnsweredIntent &&
            (honestHolders & bit(organizer)) !== 0
        )
            findings.push('organizer-inclusion');
        if ((corrupt & bit(envelope.author)) !== 0) return;
        omittedHonest += 1;
        if (envelope.author === organizer) findings.push('omitted-organizer');
        if ((honestHolders & signers) !== 0)
            findings.push('omission-inside-proposal');
    });
    if (omittedHonest > profile.faultBound) findings.push('omission-bound');
    let acceptedCount = 0;
    let acceptedHonest = 0;
    let conflictingSlots = 0;
    slots.forEach((slot, author) => {
        if (slot === 'accepted') {
            acceptedCount += 1;
            if ((corrupt & bit(author)) === 0) acceptedHonest += 1;
        }
        if (slot === 'conflicting') {
            conflictingSlots += 1;
            if ((corrupt & bit(author)) === 0) findings.push('honest-conflict');
        }
    });
    const branch =
        acceptedCount >= profile.minimumTurnout ? 'evaluation' : 'no-result';
    if (branch === 'evaluation' && acceptedHonest < 2)
        findings.push('turnout-branch');
    return { findings, omittedHonest, branch, conflictingSlots, slots };
};

// The bitmask exploration and the reference semantics must agree.
const crossCheckReference = (
    profile: CloseProfile,
    corrupt: number,
    jointEnvelopes: readonly JointEnvelope[],
    closeTimes: readonly number[],
    intent: number,
    chosen: readonly Readonly<{ intent: number; held: number }>[],
    honest: readonly number[],
    corruptInside: readonly number[],
    corruptListings: readonly number[],
    signers: number,
    outcome: JointOutcome,
): void => {
    const variants = new Map<number, number>();
    const envelopes = jointEnvelopes.map((envelope): CloseEnvelope => {
        const variant = variants.get(envelope.author) ?? 0;
        variants.set(envelope.author, variant + 1);
        return { ...envelope, variant, bodyAvailable: true };
    });
    const byIdentity = new Map(
        envelopes.map((envelope) => [identityOf(envelope), envelope]),
    );
    const intents = new Map(
        closeTimes.map((closeTime, variant) => [
            variant,
            { variant, closeTime },
        ]),
    );
    const heldBeforeResponding = new Map<string, number>();
    const honestResponses = new Map<number, CloseResponse>();
    honest.forEach((participant, index) => {
        const option = chosen[index];
        const held = envelopes.filter(
            (_envelope, envelopeIndex) =>
                (option.held & bit(envelopeIndex)) !== 0,
        );
        for (const envelope of held)
            heldBeforeResponding.set(
                identityOf(envelope),
                (heldBeforeResponding.get(identityOf(envelope)) ?? 0) |
                    bit(participant),
            );
        honestResponses.set(participant, {
            signer: participant,
            intent: option.intent,
            listed: listKnownEnvelopes(
                held,
                new Set(held.map(identityOf)),
                intents.get(option.intent)!,
            ),
        });
    });
    const responses = members(signers, profile.participantCount).map(
        (signer): CloseResponse => {
            const honestResponse = honestResponses.get(signer);
            if (honestResponse !== undefined) return honestResponse;
            const listing = corruptListings[corruptInside.indexOf(signer)];
            return {
                signer,
                intent,
                listed: envelopes
                    .filter((_envelope, index) => (listing & bit(index)) !== 0)
                    .map(identityOf)
                    .sort(),
            };
        },
    );
    const proposal: CloseProposal = { intent, responses };
    if (!verifyCloseProposal(proposal, intents, byIdentity, profile))
        throw new Error('A joint proposal fails the reference verifier.');
    const inventory = closeInventory(proposal, byIdentity, profile);
    const referenceFindings = checkCloseContract({
        profile,
        corrupt,
        envelopes: byIdentity,
        intents,
        organizerAnswer: honestResponses.get(organizer)?.intent,
        heldBeforeResponding,
        inventory,
    });
    if (
        inventory.slots.join() !== outcome.slots.join() ||
        inventory.branch !== outcome.branch ||
        referenceFindings.join() !==
            [...new Set(outcome.findings)].sort().join()
    )
        throw new Error('The joint and reference close semantics disagree.');
};

// Every honest lister set, proposal and corruption set for small rosters,
// including the completion profile: an envelope listed by f + 1 honest
// participants is in every union, an honest organizer's listing always is,
// and at most f participants are outside any proposal. A set of f honest
// listers outside the proposal witnesses that the bound is tight.

export type ListerBruteForceCensus = Readonly<{
    participantCount: number;
    corruptionSets: number;
    proposals: number;
    listerSetChecks: bigint;
    minimumInclusionMargin: number;
    maximumOmittedAuthors: number;
    tightOmissionWitness: boolean;
}>;

export const bruteForceListerSets = (
    participantCount: number,
): ListerBruteForceCensus => {
    const profile = deriveCloseProfile(participantCount);
    const everyone = (1 << participantCount) - 1;
    const proposals = masksOfSize(participantCount, profile.quorum).filter(
        (mask) => (mask & bit(organizer)) !== 0,
    );
    let listerSetChecks = 0n;
    let minimumInclusionMargin = participantCount;
    let maximumOmittedAuthors = 0;
    let tightOmissionWitness = profile.faultBound === 0;
    let corruptionSets = 0;
    for (const corrupt of masksAtMost(participantCount, profile.faultBound)) {
        corruptionSets += 1;
        const honest = everyone & ~corrupt;
        for (const proposal of proposals) {
            maximumOmittedAuthors = Math.max(
                maximumOmittedAuthors,
                memberCount(honest & ~proposal),
            );
            for (let listers = honest; ; listers = (listers - 1) & honest) {
                listerSetChecks += 1n;
                const inside = listers & proposal;
                const size = memberCount(listers);
                if (size > profile.faultBound) {
                    if (inside === 0)
                        throw new Error('An f + 1 lister set was omitted.');
                    minimumInclusionMargin = Math.min(
                        minimumInclusionMargin,
                        memberCount(inside),
                    );
                } else if (size === profile.faultBound && inside === 0)
                    tightOmissionWitness = true;
                if ((listers & bit(organizer)) !== 0 && inside === 0)
                    throw new Error('An honest organizer listing was omitted.');
                if (listers === 0) break;
            }
        }
    }
    if (maximumOmittedAuthors > profile.faultBound)
        throw new Error('A proposal leaves more than f honest authors out.');
    return {
        participantCount,
        corruptionSets,
        proposals: proposals.length,
        listerSetChecks,
        minimumInclusionMargin,
        maximumOmittedAuthors,
        tightOmissionWitness,
    };
};

// Counterexamples for the four obligations found in review, the rejected
// support rule and the rejected author-route reads of signers and of the
// organizer. Each shows the violation under the variant and confirms the
// maintained rule avoids it.
export const compileCloseObligationCounterexamples = () => {
    const four = deriveCloseProfile(4);
    const ballot: CloseEnvelope = {
        author: 3,
        variant: 0,
        time: 1,
        bodyAvailable: true,
        validProof: true,
    };
    const intent: CloseIntent = { variant: 0, closeTime: 2 };
    const intents = new Map([[0, intent]]);
    const envelopes = new Map([[identityOf(ballot), ballot]]);
    // Participants 1 and 2 receive participant 3's ballot before closing.
    const heldBeforeResponding = new Map([
        [identityOf(ballot), bit(1) | bit(2) | bit(3)],
    ]);
    const responsesListing = (listers: readonly number[]): CloseResponse[] =>
        [0, 1, 2].map((signer) => ({
            signer,
            intent: 0,
            listed: listers.includes(signer) ? [identityOf(ballot)] : [],
        }));
    const findingsFor = (responses: CloseResponse[]) =>
        checkCloseContract({
            profile: four,
            corrupt: 0,
            envelopes,
            intents,
            organizerAnswer: 0,
            heldBeforeResponding,
            inventory: closeInventory(
                { intent: 0, responses },
                envelopes,
                four,
            ),
        });
    // Volatile holdings lose the ballot at a restart before the response.
    const volatileRetentionFindings = findingsFor(responsesListing([]));
    const durableRetentionFindings = findingsFor(responsesListing([1, 2]));

    // Refusing after one's own omission: f honest voters are isolated and
    // refuse, and the f corrupt participants refuse too.
    const refusalOptions: CloseExecutionOptions = {
        participantCount: 10,
        corrupt: bit(7) | bit(8) | bit(9),
        voters: 0b0001111111,
        departedBeforeClose: 0,
        departedAfterCertification: 0,
        isolated: bit(4) | bit(5) | bit(6),
        seed: 17,
        corruptVotes: false,
        corruptEquivocation: 0,
        corruptBackdating: false,
        corruptWithholdsBody: false,
        corruptSignTargets: false,
        corruptOmitsIsolated: true,
        refuseAfterOwnOmission: true,
    };
    const refusal = runCloseExecution(refusalOptions);
    const omittedSigner = runCloseExecution({
        ...refusalOptions,
        refuseAfterOwnOmission: false,
    });

    // Unlimited per-slot listing grows every honest response with a corrupt
    // author's equivocation count; the maintained cap does not.
    const equivocations = 8;
    const corruptVariants = Array.from(
        { length: equivocations },
        (_unused, variant): CloseEnvelope => ({
            author: 9,
            variant,
            time: 1,
            bodyAvailable: true,
            validProof: true,
        }),
    );

    // An organizer that answers at its intent cannot resolve an equivocation
    // it learns afterwards, even though its lock discards late bodies. After
    // that answer, corrupt 9 fills the organizer's two body slots for 9 with
    // on-time envelopes that no other response lists, and gives each other
    // honest participant a different on-time envelope; corrupt 7 and 8 sign
    // no response. The early response lists nothing for 9 and the organizer
    // holds no third body for 9, so each other response alone makes 9 usable
    // with a body the organizer lacks, and the one-at-a-time selection stays
    // below q. Answering at the proposal lists the two smallest known
    // envelopes, which makes 9 conflicting.
    const ten = deriveCloseProfile(10);
    const stallIntent: CloseIntent = { variant: 0, closeTime: 5 };
    const fillingVariants = [0, 1].map((variant): CloseEnvelope => ({
        author: 9,
        variant,
        time: 1,
        bodyAvailable: true,
        validProof: true,
    }));
    const otherHonest = [1, 2, 3, 4, 5, 6];
    const spreadVariants = otherHonest.map((signer): CloseEnvelope => ({
        author: 9,
        variant: 1 + signer,
        time: 1,
        bodyAvailable: true,
        validProof: true,
    }));
    const stallEnvelopes = new Map(
        [...fillingVariants, ...spreadVariants].map((value) => [
            identityOf(value),
            value,
        ]),
    );
    const organizerHeld = new Set(fillingVariants.map(identityOf));
    const otherResponses = otherHonest.map((signer, index): CloseResponse => ({
        signer,
        intent: 0,
        listed: [identityOf(spreadVariants[index])],
    }));
    const organizerSelection = (ownListing: readonly string[]): number => {
        const selected: CloseResponse[] = [
            { signer: organizer, intent: 0, listed: ownListing },
        ];
        for (const response of otherResponses)
            if (
                selected.length < ten.quorum &&
                usableEnvelopes([...selected, response], stallEnvelopes).every(
                    (value) => organizerHeld.has(identityOf(value)),
                )
            )
                selected.push(response);
        return selected.length;
    };
    const earlyOwnListing = listKnownEnvelopes([], new Set(), stallIntent);
    const lateOwnListing = listKnownEnvelopes(
        [...fillingVariants, ...spreadVariants],
        organizerHeld,
        stallIntent,
    );

    // The rejected support rule admits an envelope only when q of the used
    // responses list it. Every honest participant of four holds participant
    // 3's ballot; the proposal uses honest 0 and 1 and a corrupt 2 that does
    // not list it.
    const supportResponses: CloseResponse[] = [
        { signer: 0, intent: 0, listed: [identityOf(ballot)] },
        { signer: 1, intent: 0, listed: [identityOf(ballot)] },
        { signer: 2, intent: 0, listed: [] },
    ];
    const supportCount = supportResponses.filter(({ listed }) =>
        listed.includes(identityOf(ballot)),
    ).length;

    // Reads from authors and responders alone: of four, corrupt 3 casts a
    // ballot and responds, and the relay shows both only to the honest
    // organizer, whose own response lists the ballot. Every other signer
    // lacks the ballot and whatever the proposal names of 3, until the
    // organizer's closure delivers them.
    const organizerOnlyOptions: CloseExecutionOptions = {
        participantCount: 4,
        corrupt: bit(3),
        voters: 0b0111,
        departedBeforeClose: 0,
        departedAfterCertification: 0,
        isolated: 0,
        seed: 29,
        corruptVotes: true,
        corruptEquivocation: 0,
        corruptBackdating: false,
        corruptWithholdsBody: false,
        corruptSignTargets: false,
        corruptOmitsIsolated: false,
        refuseAfterOwnOmission: false,
        corruptShowsOnlyOrganizer: true,
        // The organizer takes the ballot before anyone answers its intent.
        priorityRecipient: organizer,
    };
    const authorRoutes = runCloseExecution({
        ...organizerOnlyOptions,
        withoutClosure: true,
    });
    const organizerClosure = runCloseExecution(organizerOnlyOptions);

    // Organizer reads from authors alone: of four, corrupt 3 hands its ballot
    // to honest 1 and 2 but not to the organizer before the close and signs
    // no response. Both responses the organizer needs list the ballot alone,
    // so it needs the body, which only their forwarded copies supply.
    const hiddenOptions: CloseExecutionOptions = {
        participantCount: 4,
        corrupt: bit(3),
        voters: 0b0111,
        departedBeforeClose: 0,
        departedAfterCertification: 0,
        isolated: 0,
        seed: 31,
        corruptVotes: true,
        corruptEquivocation: 0,
        corruptBackdating: false,
        corruptWithholdsBody: false,
        corruptSignTargets: false,
        corruptOmitsIsolated: false,
        refuseAfterOwnOmission: false,
        corruptWithholdsResponses: true,
        corruptHidesFromOrganizer: true,
    };
    const authorBodies = runCloseExecution({
        ...hiddenOptions,
        withoutForwarding: true,
    });
    const forwardedBodies = runCloseExecution(hiddenOptions);

    return {
        volatileRetentionFindings,
        durableRetentionFindings,
        refusalCertifiedTargets: refusal.certifiedTargets,
        refusalHonestSigners: refusal.honestSigners,
        refusalQuorum: deriveCloseProfile(10).quorum,
        omittedSignerCertifiedTargets: omittedSigner.certifiedTargets,
        omittedSignerHonestOmission: omittedSigner.omittedHonest,
        omittedSignerFindings: omittedSigner.findings,
        equivocations,
        uncappedResponseEntries: listKnownEnvelopes(
            corruptVariants,
            new Set(corruptVariants.map(identityOf)),
            intent,
            Number.POSITIVE_INFINITY,
        ).length,
        cappedResponseEntries: listKnownEnvelopes(
            corruptVariants,
            new Set(),
            intent,
        ).length,
        organizerStallQuorum: ten.quorum,
        earlyOrganizerSelection: organizerSelection(earlyOwnListing),
        lateOrganizerSelection: organizerSelection(lateOwnListing),
        lateOwnListing,
        authorRouteFindings: authorRoutes.findings,
        authorRouteCertifiedTargets: authorRoutes.certifiedTargets,
        closureFindings: organizerClosure.findings,
        closureCertifiedTargets: organizerClosure.certifiedTargets,
        authorBodyFindings: authorBodies.findings,
        authorBodyCertifiedTargets: authorBodies.certifiedTargets,
        forwardingFindings: forwardedBodies.findings,
        forwardingCertifiedTargets: forwardedBodies.certifiedTargets,
        supportRuleIncludesEnvelope: supportCount >= four.quorum,
        unionRuleIncludesEnvelope: closeInventory(
            { intent: 0, responses: supportResponses },
            envelopes,
            four,
        ).listed.has(identityOf(ballot)),
    };
};

// Productive visits observed in the message-level executions, added to the
// preparation visits of the certified clear setup. Each honest participant
// performs all work its newest delivery enables. Deliveries and sessions do
// not define visits: one protocol stage includes its restarts and the
// organizer's collection across sessions. Each counted visit performs a
// one-shot stage: setup verification with the ballot, the close response,
// the target signature, the release share and verification, and for the
// organizer the close intent and the proposal with its own response and
// target signature instead of the response and signature. A nonvoter may
// verify setup before a later close intent, in a visit of its own.
const closeStages = {
    voter: [
        'setup-and-ballot',
        'response',
        'target-signature',
        'release',
        'verify',
    ],
    nonvoter: ['setup', 'response', 'target-signature', 'release', 'verify'],
    organizer: ['setup-and-ballot', 'close', 'proposal', 'release', 'verify'],
} as const;

export type CloseVisitCensus = Readonly<{
    participantCount: number;
    preparationVisits: number;
    executions: number;
    organizerVisits: number;
    voterVisits: number;
    nonvoterVisits: number;
    organizerStageBound: number;
    voterStageBound: number;
    nonvoterStageBound: number;
    maximumVisits: number;
}>;

// The certified clear setup's stages before setup verification, which the
// close stages above begin with.
const preparationStages = (() => {
    const names = preparationStagePath('clear-certified', false).map(
        ({ name }) => name,
    );
    const setup = names.indexOf('setup-and-optional-ballot');
    if (setup < 0) throw new Error('The stage path has no setup stage.');
    return names.slice(0, setup);
})();

// The participants of each productive visit of a permitted sequential
// preparation schedule, not a maximum over asynchronous deliveries. Each
// stage consumes every participant's preceding publication, the first
// participant returns before the others complete each stage, and every
// visit performs all work the shared transcript enables.
const tracePreparationVisits = (
    participantCount: number,
): readonly number[] => {
    const published = preparationStages.map(() => new Set<number>());
    const visits: number[] = [];
    const visit = (participant: number): void => {
        let productive = false;
        for (const [stage, completed] of published.entries()) {
            if (completed.has(participant)) continue;
            if (stage > 0 && published[stage - 1].size !== participantCount)
                break;
            completed.add(participant);
            productive = true;
        }
        if (productive) visits.push(participant);
    };
    for (const completed of published) {
        for (
            let participant = 0;
            participant < participantCount;
            participant += 1
        )
            if (!completed.has(participant)) visit(participant);
        if (completed.size !== participantCount)
            throw new Error('A preparation stage is incomplete.');
    }
    return visits;
};

export const compileCloseVisitCensus = (
    participantCount: number,
): CloseVisitCensus => {
    const profile = deriveCloseProfile(participantCount);
    const preparation = tracePreparationVisits(participantCount);
    const preparationVisits = Math.max(
        ...Array.from(
            { length: participantCount },
            (_unused, participant) =>
                preparation.filter((visitor) => visitor === participant).length,
        ),
    );
    const everyone = (1 << participantCount) - 1;
    const lastF = maskOf(
        Array.from(
            { length: profile.faultBound },
            (_unused, index) => participantCount - 1 - index,
        ),
    );
    let executions = 0;
    let organizerVisits = 0;
    let voterVisits = 0;
    let nonvoterVisits = 0;
    // The alternate-position voter set leaves position one a nonvoter.
    const schedules = [undefined, organizer, 1, 2].flatMap((priority) =>
        [1, 2, 3].flatMap((seed) =>
            [everyone, everyone & 0b10101010101010101101].map((voters) => ({
                priority,
                seed,
                voters,
            })),
        ),
    );
    for (const { priority, seed, voters } of schedules) {
        const result = runCloseExecution({
            participantCount,
            corrupt: 0,
            voters,
            departedBeforeClose: 0,
            departedAfterCertification: 0,
            isolated: seed % 2 === 0 ? lastF : 0,
            seed: seed * 1_009 + participantCount,
            corruptVotes: false,
            corruptEquivocation: 0,
            corruptBackdating: false,
            corruptWithholdsBody: false,
            corruptSignTargets: false,
            corruptOmitsIsolated: false,
            refuseAfterOwnOmission: false,
            priorityRecipient: priority,
        });
        if (result.findings.length !== 0)
            throw new Error('A visit execution violated the contract.');
        executions += 1;
        organizerVisits = Math.max(organizerVisits, result.organizerVisits);
        voterVisits = Math.max(voterVisits, result.voterVisits);
        nonvoterVisits = Math.max(nonvoterVisits, result.nonvoterVisits);
    }
    const census = {
        participantCount,
        preparationVisits,
        executions,
        organizerVisits: preparationVisits + organizerVisits,
        voterVisits: preparationVisits + voterVisits,
        // The executions start after setup, so a nonvoter's own setup
        // verification visit is added here.
        nonvoterVisits: preparationVisits + 1 + nonvoterVisits,
        organizerStageBound: preparationVisits + closeStages.organizer.length,
        voterStageBound: preparationVisits + closeStages.voter.length,
        nonvoterStageBound: preparationVisits + closeStages.nonvoter.length,
    };
    if (
        census.organizerVisits > census.organizerStageBound ||
        census.voterVisits > census.voterStageBound ||
        census.nonvoterVisits > census.nonvoterStageBound
    )
        throw new Error('An execution exceeded its stage bound.');
    const maximumVisits = Math.max(
        census.organizerStageBound,
        census.voterStageBound,
        census.nonvoterStageBound,
    );
    if (maximumVisits > mandatoryVisitCeiling)
        throw new Error('The close-response graph exceeds the visit ceiling.');
    return { ...census, maximumVisits };
};

export const compileCloseResponseCensus = () => {
    const rosters = Array.from({ length: 18 }, (_unused, index) => index + 3);
    return {
        profiles: rosters.map((participantCount) => {
            const profile = deriveCloseProfile(participantCount);
            return {
                ...profile,
                inclusionHolderThreshold: profile.faultBound + 1,
                maximumHonestOmission: profile.faultBound,
                acceptedAtFullHonestTurnoutAfterOmission:
                    participantCount - 2 * profile.faultBound,
                noResultForceableAtFullHonestTurnout:
                    participantCount - 2 * profile.faultBound <
                    profile.minimumTurnout,
                maximumListedEntriesPerResponse:
                    maximumListedEnvelopesPerSlot * participantCount,
                visits: compileCloseVisitCensus(participantCount),
            };
        }),
        bruteForce: rosters
            .filter((participantCount) => participantCount <= 10)
            .map(bruteForceListerSets),
        joint: [exploreJointCloseViews(3), exploreJointCloseViews(4)],
        execution: exploreCompletionProfileExecutions(),
        counterexamples: compileCloseObligationCounterexamples(),
    };
};
