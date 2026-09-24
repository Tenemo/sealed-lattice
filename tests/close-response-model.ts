import { traceCommonMatrixPreparationVisits } from '#tests/participant-visit-dependency-model.js';
import { compileThresholdCompletionProfile } from '#tests/threshold-completion-model.js';

// Close responses under the owner's bounded-omission contract. The organizer
// is roster position zero. Messages are ideal authenticated objects: a model
// signature cannot be forged, and envelope, intent, response, proposal, and
// target identities cannot collide. This model creates no protocol capability.

const organizer = 0;
const maximumListedEnvelopesPerSlot = 2;
const mandatoryVisitCeiling = 10;

export type CloseProfile = Readonly<{
    participantCount: number;
    faultBound: number;
    quorum: number;
    minimumTurnout: number;
    releaseThreshold: number;
}>;

export const deriveCloseProfile = (participantCount: number): CloseProfile => {
    const profile = compileThresholdCompletionProfile(participantCount);
    return {
        participantCount,
        faultBound: profile.maximumCorruptParticipantCount,
        quorum: profile.inventoryCertificateThreshold,
        minimumTurnout: profile.minimumTurnout,
        releaseThreshold: profile.resultReleaseThreshold,
    };
};

const bit = (position: number): number => 1 << position;

const memberCount = (mask: number): number => {
    let count = 0;
    for (let remaining = mask >>> 0; remaining !== 0; count += 1)
        remaining &= remaining - 1;
    return count;
};

const members = (mask: number, participantCount: number): number[] =>
    Array.from(
        { length: participantCount },
        (_unused, position) => position,
    ).filter((position) => (mask & bit(position)) !== 0);

const maskOf = (positions: readonly number[]): number =>
    positions.reduce((mask, position) => mask | bit(position), 0);

const masksOfSize = (participantCount: number, size: number): number[] => {
    const masks: number[] = [];
    for (let mask = 0; mask < 1 << participantCount; mask += 1)
        if (memberCount(mask) === size) masks.push(mask);
    return masks;
};

const masksAtMost = (participantCount: number, size: number): number[] => {
    const masks: number[] = [];
    for (let mask = 0; mask < 1 << participantCount; mask += 1)
        if (memberCount(mask) <= size) masks.push(mask);
    return masks;
};

const product = <Value>(choices: readonly (readonly Value[])[]): Value[][] =>
    choices.reduce<Value[][]>(
        (combinations, values) =>
            combinations.flatMap((prefix) =>
                values.map((value) => [...prefix, value]),
            ),
        [[]],
    );

// Reference semantics. The Rust close verifier must implement these rules.

export type CloseEnvelope = Readonly<{
    author: number;
    variant: number;
    time: number;
    // False when no participant can supply the complete signed body.
    bodyAvailable: boolean;
    validProof: boolean;
}>;

export type CloseIntent = Readonly<{ variant: number; closeTime: number }>;

export type CloseResponse = Readonly<{
    signer: number;
    intent: number;
    listed: readonly string[];
}>;

export type CloseProposal = Readonly<{
    intent: number;
    responses: readonly CloseResponse[];
}>;

type SlotClassification = 'absent' | 'accepted' | 'invalid' | 'conflicting';

export type ClosedInventory = Readonly<{
    intent: number;
    responders: number;
    slots: readonly SlotClassification[];
    listed: ReadonlySet<string>;
    acceptedCount: number;
    branch: 'evaluation' | 'no-result';
    target: string;
}>;

export const envelopeIdentity = (author: number, variant: number): string =>
    `${String(author).padStart(2, '0')}/${String(variant)}`;

const identityOf = (envelope: CloseEnvelope): string =>
    envelopeIdentity(envelope.author, envelope.variant);

// The first `maximumPerSlot` identities of each slot, in canonical order.
const capListing = (
    identities: Iterable<string>,
    maximumPerSlot: number,
): string[] => {
    const listed: string[] = [];
    const perSlot = new Map<string, number>();
    for (const identity of [...new Set(identities)].sort()) {
        const slot = identity.slice(0, 2);
        const count = perSlot.get(slot) ?? 0;
        if (count >= maximumPerSlot) continue;
        perSlot.set(slot, count + 1);
        listed.push(identity);
    }
    return listed;
};

// The distinct known identities of each slot timed no later than the close
// time.
const knownSlots = (
    known: Iterable<CloseEnvelope>,
    intent: CloseIntent,
): Map<number, Set<string>> => {
    const perSlot = new Map<number, Set<string>>();
    for (const envelope of known) {
        if (envelope.time > intent.closeTime) continue;
        const identities = perSlot.get(envelope.author) ?? new Set<string>();
        identities.add(identityOf(envelope));
        perSlot.set(envelope.author, identities);
    }
    return perSlot;
};

// The honest listing rule over the envelopes a participant knows and the
// bodies it holds. A slot with at least two known on-time envelopes lists the
// two smallest identities: two already make it conflicting, so a longer list
// gains nothing and no body is needed. A slot with one known on-time envelope
// lists it only when its complete body is held.
export const listKnownEnvelopes = (
    known: Iterable<CloseEnvelope>,
    held: ReadonlySet<string>,
    intent: CloseIntent,
    maximumPerSlot: number = maximumListedEnvelopesPerSlot,
): string[] => {
    const listed: string[] = [];
    for (const identities of knownSlots(known, intent).values()) {
        if (identities.size > 1)
            listed.push(...capListing(identities, maximumPerSlot));
        else if (held.has([...identities][0])) listed.push(...identities);
    }
    return listed.sort();
};

// An organizer can include a response when every slot it lists whose only
// known envelope is that entry has the body held. A slot with two known
// envelopes is conflicting through the organizer's own listing.
const organizerReady = (
    slots: ReadonlyMap<number, ReadonlySet<string>>,
    held: ReadonlySet<string>,
    response: CloseResponse,
): boolean =>
    response.listed.every((identity) => {
        const known = slots.get(Number(identity.slice(0, 2)));
        return (
            known !== undefined &&
            known.has(identity) &&
            (known.size > 1 || held.has(identity))
        );
    });

// A response needs only the authenticated envelope of each listed entry.
export const verifyCloseResponse = (
    response: CloseResponse,
    intents: ReadonlyMap<number, CloseIntent>,
    envelopes: ReadonlyMap<string, CloseEnvelope>,
    participantCount: number,
): boolean => {
    const intent = intents.get(response.intent);
    if (
        intent === undefined ||
        !Number.isInteger(response.signer) ||
        response.signer < 0 ||
        response.signer >= participantCount
    )
        return false;
    const perSlot = new Map<number, number>();
    for (const [index, identity] of response.listed.entries()) {
        const envelope = envelopes.get(identity);
        const previous = response.listed[index - 1];
        if (
            envelope === undefined ||
            (previous !== undefined && previous >= identity) ||
            envelope.time > intent.closeTime ||
            envelope.author >= participantCount
        )
            return false;
        const count = (perSlot.get(envelope.author) ?? 0) + 1;
        if (count > maximumListedEnvelopesPerSlot) return false;
        perSlot.set(envelope.author, count);
    }
    return true;
};

// The single listed envelope of every usable slot in the union of these
// responses: the only envelopes whose bodies a barrier requires.
export const usableEnvelopes = (
    responses: readonly CloseResponse[],
    envelopes: ReadonlyMap<string, CloseEnvelope>,
): CloseEnvelope[] => {
    const perSlot = new Map<number, Set<string>>();
    for (const identity of responses.flatMap(({ listed }) => listed)) {
        const envelope = envelopes.get(identity);
        if (envelope === undefined) continue;
        const slot = perSlot.get(envelope.author) ?? new Set<string>();
        slot.add(identity);
        perSlot.set(envelope.author, slot);
    }
    return [...perSlot.values()]
        .filter((identities) => identities.size === 1)
        .map((identities) => envelopes.get([...identities][0])!);
};

// A proposal also needs the complete body of every usable slot; a conflicting
// slot needs none.
export const verifyCloseProposal = (
    proposal: CloseProposal,
    intents: ReadonlyMap<number, CloseIntent>,
    envelopes: ReadonlyMap<string, CloseEnvelope>,
    profile: CloseProfile,
): boolean => {
    const signers = proposal.responses.map(({ signer }) => signer);
    return (
        intents.has(proposal.intent) &&
        proposal.responses.length === profile.quorum &&
        signers.every(
            (signer, index) => index === 0 || signers[index - 1] < signer,
        ) &&
        signers.includes(organizer) &&
        proposal.responses.every(
            (response) =>
                response.intent === proposal.intent &&
                verifyCloseResponse(
                    response,
                    intents,
                    envelopes,
                    profile.participantCount,
                ),
        ) &&
        usableEnvelopes(proposal.responses, envelopes).every(
            (envelope) => envelope.bodyAvailable,
        )
    );
};

// The inventory is the union of the proposal's responses. One listed envelope
// makes its slot usable; two or more different envelopes make it conflicting.
export const closeInventory = (
    proposal: CloseProposal,
    envelopes: ReadonlyMap<string, CloseEnvelope>,
    profile: CloseProfile,
): ClosedInventory => {
    const listed = new Set(
        proposal.responses.flatMap((response) => response.listed),
    );
    const perSlot = Array.from(
        { length: profile.participantCount },
        () => [] as CloseEnvelope[],
    );
    for (const identity of listed) {
        const envelope = envelopes.get(identity);
        if (envelope === undefined)
            throw new Error('A verified proposal lists an unknown envelope.');
        perSlot[envelope.author].push(envelope);
    }
    const slots = perSlot.map((values): SlotClassification => {
        if (values.length === 0) return 'absent';
        if (values.length > 1) return 'conflicting';
        return values[0].validProof ? 'accepted' : 'invalid';
    });
    const acceptedCount = slots.filter((slot) => slot === 'accepted').length;
    const branch =
        acceptedCount >= profile.minimumTurnout ? 'evaluation' : 'no-result';
    return {
        intent: proposal.intent,
        responders: maskOf(proposal.responses.map(({ signer }) => signer)),
        slots,
        listed,
        acceptedCount,
        branch,
        target: `${String(proposal.intent)}|${[...listed].sort().join(',')}|${branch}`,
    };
};

// Contract checks for one certified inventory. `heldBeforeResponding` maps an
// envelope to the participants that had received it, with its complete body,
// before they signed their responses (frozen I.7 "received before closing").

export type CloseContractFinding =
    | 'inclusion'
    | 'organizer-inclusion'
    | 'omission-bound'
    | 'omitted-organizer'
    | 'omission-inside-proposal'
    | 'honest-conflict'
    | 'cutoff'
    | 'turnout-branch';

type CloseContractView = Readonly<{
    profile: CloseProfile;
    corrupt: number;
    envelopes: ReadonlyMap<string, CloseEnvelope>;
    intents: ReadonlyMap<number, CloseIntent>;
    organizerAnswer: number | undefined;
    heldBeforeResponding: ReadonlyMap<string, number>;
    inventory: ClosedInventory;
}>;

const checkCloseContract = (
    view: CloseContractView,
): CloseContractFinding[] => {
    const { profile, corrupt, envelopes, inventory } = view;
    const intent = view.intents.get(inventory.intent);
    if (intent === undefined)
        throw new Error('The certified intent is absent.');
    const findings = new Set<CloseContractFinding>();
    const honestOrganizer = (corrupt & bit(organizer)) === 0;
    let omittedHonest = 0;
    for (const [identity, envelope] of envelopes) {
        const onTime =
            envelope.bodyAvailable && envelope.time <= intent.closeTime;
        const included = inventory.listed.has(identity);
        if (included && envelope.time > intent.closeTime)
            findings.add('cutoff');
        if (!onTime || included) continue;
        // A corrupt author's further variant may be left out when its slot
        // is already conflicting; the slot then contributes no ballot.
        const covered = inventory.slots[envelope.author] === 'conflicting';
        const honestHolders =
            (view.heldBeforeResponding.get(identity) ?? 0) & ~corrupt;
        if (!covered && memberCount(honestHolders) > profile.faultBound)
            findings.add('inclusion');
        if (
            !covered &&
            honestOrganizer &&
            view.organizerAnswer === inventory.intent &&
            (honestHolders & bit(organizer)) !== 0
        )
            findings.add('organizer-inclusion');
        if ((corrupt & bit(envelope.author)) !== 0) continue;
        omittedHonest += 1;
        if (envelope.author === organizer) findings.add('omitted-organizer');
        // An omitted honest ballot was kept from every honest responder whose
        // response is used; its author lists it whenever inside.
        if ((honestHolders & inventory.responders) !== 0)
            findings.add('omission-inside-proposal');
    }
    if (omittedHonest > profile.faultBound) findings.add('omission-bound');
    for (const [author, slot] of inventory.slots.entries())
        if (slot === 'conflicting' && (corrupt & bit(author)) === 0)
            findings.add('honest-conflict');
    const acceptedHonest = inventory.slots.filter(
        (slot, author) => slot === 'accepted' && (corrupt & bit(author)) === 0,
    ).length;
    if (
        (inventory.branch === 'evaluation') !==
            inventory.acceptedCount >= profile.minimumTurnout ||
        (inventory.branch === 'evaluation' && acceptedHonest < 2)
    )
        findings.add('turnout-branch');
    return [...findings].sort();
};

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

// Deterministic message-level executions with a malicious relay. Honest
// handlers other than the organizer never wait for another participant: a
// response follows the first authenticated intent, a target signature the
// first valid proposal, a release share the certificate, and verification d
// shares or a no-result certificate. The organizer locks its own intent and
// answers once q - 1 other responses are ready, then proposes. A participant
// holds at most two bodies for one slot, discards late bodies at its intent
// lock and refuses late ones afterwards; the organizer requests the one known
// envelope's body of a slot a response lists. The relay reorders, duplicates,
// replays another action's messages, withholds an isolated participant's
// messages until certification, and otherwise delivers every message among
// cooperating participants.

const createRandom = (seed: number) => {
    let state = seed >>> 0 || 1;
    return (limit: number): number => {
        state ^= state << 13;
        state >>>= 0;
        state ^= state >>> 17;
        state ^= state << 5;
        state >>>= 0;
        return state % limit;
    };
};

type Message =
    | Readonly<{ kind: 'envelope'; envelope: CloseEnvelope }>
    | Readonly<{ kind: 'body'; envelope: CloseEnvelope }>
    | Readonly<{ kind: 'intent'; intent: CloseIntent }>
    | Readonly<{ kind: 'response'; response: CloseResponse }>
    | Readonly<{ kind: 'proposal'; proposal: CloseProposal }>
    | Readonly<{
          kind: 'signature';
          signer: number;
          proposal: CloseProposal;
      }>
    | Readonly<{ kind: 'share'; signer: number; target: string }>;

type Delivery = Readonly<{
    recipient: number;
    message: Message;
    action: number;
}>;

type HonestParticipant = {
    readonly position: number;
    readonly clockSkew: number;
    departed: boolean;
    ownEnvelope: string | undefined;
    // The envelopes known with or without a body, and the bodies held.
    readonly known: Map<string, CloseEnvelope>;
    readonly held: Map<string, CloseEnvelope>;
    // Bodies ever received for each slot.
    readonly received: Map<number, number>;
    // Bodies the organizer requested.
    readonly requested: Set<string>;
    heldAtResponse: ReadonlySet<string>;
    lockedIntent: CloseIntent | undefined;
    answeredIntent: number | undefined;
    readonly responses: Map<number, CloseResponse>;
    proposed: boolean;
    targetLock: string | undefined;
    readonly signatures: Map<string, Set<number>>;
    certified: string | undefined;
    readonly shares: Map<string, Set<number>>;
    released: boolean;
    verified: boolean;
    readonly visitSteps: Set<number>;
};

export type CloseExecutionOptions = Readonly<{
    participantCount: number;
    corrupt: number;
    voters: number;
    // Honest participants that stop before the close intent.
    departedBeforeClose: number;
    // Honest participants that stop once any certificate exists.
    departedAfterCertification: number;
    // Honest participants whose envelopes and later messages the relay
    // withholds until a certificate exists.
    isolated: number;
    seed: number;
    corruptVotes: boolean;
    corruptEquivocation: number;
    corruptBackdating: boolean;
    corruptWithholdsBody: boolean;
    // Corrupt responders also list envelopes whose bodies no one supplies.
    corruptListsBodiless?: boolean;
    corruptSignTargets: boolean;
    // Corrupt responders never list an isolated participant's ballot.
    corruptOmitsIsolated: boolean;
    refuseAfterOwnOmission: boolean;
    // Before an honest organizer's intent, each corrupt nonorganizer fills
    // the organizer's two body slots for it with late envelopes and gives
    // every other honest participant a different on-time envelope.
    corruptTargetsOrganizer?: boolean;
    // Corrupt participants sign no close response.
    corruptWithholdsResponses?: boolean;
    // The relay delivers this participant's messages before any other, so
    // each of its stages is enabled in a separate delivery.
    priorityRecipient?: number;
}>;

export type CloseExecutionResult = Readonly<{
    certifiedTargets: number;
    inventory: ClosedInventory | undefined;
    findings: readonly string[];
    omittedHonest: number;
    honestSigners: number;
    maximumListedEntries: number;
    ignoredMessages: number;
    organizerVisits: number;
    voterVisits: number;
    nonvoterVisits: number;
    // Bodies any honest participant held at once, and ever received, for one
    // honest or corrupt slot, and bodies the organizer requested for one slot.
    maximumHeldPerSlot: number;
    maximumReceivedPerHonestSlot: number;
    maximumReceivedPerCorruptSlot: number;
    maximumOrganizerRequestsPerSlot: number;
}>;

export const runCloseExecution = (
    options: CloseExecutionOptions,
): CloseExecutionResult => {
    const profile = deriveCloseProfile(options.participantCount);
    const n = options.participantCount;
    const random = createRandom(options.seed);
    const { corrupt } = options;
    const action = 1;
    const organizerCorrupt = (corrupt & bit(organizer)) !== 0;
    const envelopes = new Map<string, CloseEnvelope>();
    const intents = new Map<number, CloseIntent>();
    const participants = new Map<number, HonestParticipant>();
    for (const position of members(((1 << n) - 1) & ~corrupt, n))
        participants.set(position, {
            position,
            clockSkew: random(3) - 1,
            departed: false,
            ownEnvelope: undefined,
            known: new Map(),
            held: new Map(),
            received: new Map(),
            requested: new Set(),
            heldAtResponse: new Set(),
            lockedIntent: undefined,
            answeredIntent: undefined,
            responses: new Map(),
            proposed: false,
            targetLock: undefined,
            signatures: new Map(),
            certified: undefined,
            shares: new Map(),
            released: false,
            verified: false,
            visitSteps: new Set(),
        });
    let pending: Delivery[] = [];
    let withheld: Delivery[] = [];
    let step = 0;
    let ignoredMessages = 0;
    let maximumListedEntries = 0;
    let maximumHeldPerSlot = 0;
    let maximumReceivedPerHonestSlot = 0;
    let maximumReceivedPerCorruptSlot = 0;
    let maximumOrganizerRequestsPerSlot = 0;
    let anyCertificate = false;
    const allResponses: CloseResponse[] = [];
    const proposalsByTarget = new Map<string, CloseProposal>();
    const signersByTarget = new Map<string, Set<number>>();
    const corruptSigned = new Set<string>();
    const verifiedProposals = new Map<CloseProposal, ClosedInventory | null>();
    const verifiedResponses = new Map<CloseResponse, boolean>();

    const responseValid = (response: CloseResponse): boolean => {
        let valid = verifiedResponses.get(response);
        if (valid === undefined) {
            valid = verifyCloseResponse(response, intents, envelopes, n);
            verifiedResponses.set(response, valid);
        }
        return valid;
    };
    // Verification is deterministic, so honest participants share its cache.
    const proposalInventory = (
        proposal: CloseProposal,
    ): ClosedInventory | null => {
        let inventory = verifiedProposals.get(proposal);
        if (inventory === undefined) {
            inventory = verifyCloseProposal(
                proposal,
                intents,
                envelopes,
                profile,
            )
                ? closeInventory(proposal, envelopes, profile)
                : null;
            verifiedProposals.set(proposal, inventory);
        }
        return inventory;
    };
    const send = (message: Message, from: number | undefined): void => {
        const withhold =
            from !== undefined &&
            (options.isolated & bit(from)) !== 0 &&
            !anyCertificate;
        for (const recipient of participants.keys()) {
            if (recipient === from) continue;
            const delivery = { recipient, message, action };
            if (withhold) withheld.push(delivery);
            else pending.push(delivery);
        }
    };
    const work = (participant: HonestParticipant): void => {
        participant.visitSteps.add(step);
    };
    // A body is taken below the per-slot cap and, after the intent lock, only
    // on time. Its envelope becomes known either way.
    const holdBody = (
        participant: HonestParticipant,
        envelope: CloseEnvelope,
    ): boolean => {
        const identity = identityOf(envelope);
        participant.known.set(identity, envelope);
        const inSlot = [...participant.held.values()].filter(
            ({ author }) => author === envelope.author,
        ).length;
        if (
            participant.held.has(identity) ||
            !envelope.bodyAvailable ||
            (participant.lockedIntent !== undefined &&
                envelope.time > participant.lockedIntent.closeTime) ||
            inSlot >= maximumListedEnvelopesPerSlot
        )
            return false;
        participant.held.set(identity, envelope);
        const received = (participant.received.get(envelope.author) ?? 0) + 1;
        participant.received.set(envelope.author, received);
        maximumHeldPerSlot = Math.max(maximumHeldPerSlot, inSlot + 1);
        if ((corrupt & bit(envelope.author)) === 0)
            maximumReceivedPerHonestSlot = Math.max(
                maximumReceivedPerHonestSlot,
                received,
            );
        else
            maximumReceivedPerCorruptSlot = Math.max(
                maximumReceivedPerCorruptSlot,
                received,
            );
        return true;
    };
    // Late bodies can never be listed or needed.
    const lock = (participant: HonestParticipant, intent: CloseIntent) => {
        participant.lockedIntent = intent;
        for (const [identity, envelope] of participant.held)
            if (envelope.time > intent.closeTime)
                participant.held.delete(identity);
    };
    const respond = (
        participant: HonestParticipant,
        intent: CloseIntent,
    ): void => {
        participant.answeredIntent = intent.variant;
        participant.heldAtResponse = new Set(participant.held.keys());
        const response: CloseResponse = {
            signer: participant.position,
            intent: intent.variant,
            listed: listKnownEnvelopes(
                participant.known.values(),
                participant.heldAtResponse,
                intent,
            ),
        };
        maximumListedEntries = Math.max(
            maximumListedEntries,
            response.listed.length,
        );
        allResponses.push(response);
        participant.responses.set(participant.position, response);
        work(participant);
        send({ kind: 'response', response }, participant.position);
    };
    const recordSignature = (
        participant: HonestParticipant,
        signer: number,
        proposal: CloseProposal,
    ): void => {
        const inventory = proposalInventory(proposal);
        if (inventory === null) return;
        const signers =
            participant.signatures.get(inventory.target) ?? new Set();
        signers.add(signer);
        participant.signatures.set(inventory.target, signers);
        const global = signersByTarget.get(inventory.target) ?? new Set();
        global.add(signer);
        signersByTarget.set(inventory.target, global);
        proposalsByTarget.set(inventory.target, proposal);
        if (
            participant.certified === undefined &&
            signers.size >= profile.quorum
        ) {
            participant.certified = inventory.target;
            if (!anyCertificate) {
                anyCertificate = true;
                pending.push(...withheld);
                withheld = [];
                for (const position of members(
                    options.departedAfterCertification,
                    n,
                ))
                    participants.get(position)!.departed = true;
            }
            if (participant.departed) return;
            work(participant);
            if (inventory.branch === 'no-result') participant.verified = true;
            else if (!participant.released) {
                participant.released = true;
                send(
                    {
                        kind: 'share',
                        signer: participant.position,
                        target: inventory.target,
                    },
                    participant.position,
                );
                recordShare(
                    participant,
                    participant.position,
                    inventory.target,
                );
            }
        }
    };
    const recordShare = (
        participant: HonestParticipant,
        signer: number,
        target: string,
    ): void => {
        const shares = participant.shares.get(target) ?? new Set();
        shares.add(signer);
        participant.shares.set(target, shares);
        if (
            participant.certified === target &&
            !participant.verified &&
            shares.size >= profile.releaseThreshold
        ) {
            participant.verified = true;
            work(participant);
        }
    };
    const signTarget = (
        participant: HonestParticipant,
        proposal: CloseProposal,
    ): void => {
        if (participant.targetLock !== undefined) return;
        const inventory = proposalInventory(proposal);
        if (inventory === null) return;
        if (participant.answeredIntent === undefined) {
            // The proposal carries the organizer's intent.
            const intent = intents.get(proposal.intent)!;
            lock(participant, intent);
            respond(participant, intent);
        }
        const own = participant.ownEnvelope;
        if (
            options.refuseAfterOwnOmission &&
            own !== undefined &&
            !inventory.listed.has(own) &&
            envelopes.get(own)!.time <= intents.get(proposal.intent)!.closeTime
        )
            return;
        participant.targetLock = inventory.target;
        work(participant);
        send(
            { kind: 'signature', signer: participant.position, proposal },
            participant.position,
        );
        if (
            options.corruptSignTargets &&
            !corruptSigned.has(inventory.target)
        ) {
            corruptSigned.add(inventory.target);
            for (const signer of members(corrupt, n))
                send({ kind: 'signature', signer, proposal }, undefined);
        }
        recordSignature(participant, participant.position, proposal);
    };
    // The organizer asks the listing responder and the author for a body. An
    // honest source supplies it; for two corrupt sources the relay decides
    // once, and never supplies a withheld body.
    const corruptSupplies = new Map<string, boolean>();
    const scheduledBodies = new Set<string>();
    const requestBody = (
        participant: HonestParticipant,
        identity: string,
        responder: number,
    ): void => {
        const envelope = envelopes.get(identity)!;
        const sources = [responder, envelope.author].filter(
            (source) => (corrupt & bit(source)) === 0,
        );
        if (!participant.requested.has(identity)) {
            participant.requested.add(identity);
            const requests = [...participant.requested].filter(
                (value) => value.slice(0, 2) === identity.slice(0, 2),
            ).length;
            maximumOrganizerRequestsPerSlot = Math.max(
                maximumOrganizerRequestsPerSlot,
                requests,
            );
        }
        if (scheduledBodies.has(identity) || !envelope.bodyAvailable) return;
        if (sources.length === 0) {
            if (!corruptSupplies.has(identity))
                corruptSupplies.set(
                    identity,
                    !options.corruptWithholdsBody && random(2) === 0,
                );
            if (!corruptSupplies.get(identity)) return;
        }
        scheduledBodies.add(identity);
        const delivery: Delivery = {
            recipient: participant.position,
            message: { kind: 'body', envelope },
            action,
        };
        if (
            sources.length > 0 &&
            sources.every((source) => (options.isolated & bit(source)) !== 0) &&
            !anyCertificate
        )
            withheld.push(delivery);
        else pending.push(delivery);
    };
    // The organizer requests the one known envelope's body of each slot a
    // response lists when it lacks that body, answers once q - 1 other
    // responses are ready, and proposes its own response and the first q - 1
    // other responses in arrival order that keep every usable slot's body
    // held.
    const tryPropose = (participant: HonestParticipant): void => {
        const intent = participant.lockedIntent;
        if (
            participant.position !== organizer ||
            participant.proposed ||
            intent === undefined
        )
            return;
        const others = [...participant.responses.values()].filter(
            ({ signer, intent: named }) =>
                named === intent.variant && signer !== organizer,
        );
        const slots = knownSlots(participant.known.values(), intent);
        const held = new Set(participant.held.keys());
        for (const response of others)
            for (const identity of response.listed)
                if (
                    slots.get(Number(identity.slice(0, 2)))?.size === 1 &&
                    !held.has(identity)
                )
                    requestBody(participant, identity, response.signer);
        if (
            others.filter((response) => organizerReady(slots, held, response))
                .length <
            profile.quorum - 1
        )
            return;
        respond(participant, intent);
        const selected = [participant.responses.get(organizer)!];
        for (const response of others) {
            if (selected.length === profile.quorum) break;
            if (
                usableEnvelopes([...selected, response], envelopes).every(
                    (envelope) => held.has(identityOf(envelope)),
                )
            )
                selected.push(response);
        }
        if (selected.length < profile.quorum)
            throw new Error('A ready organizer could not propose.');
        const proposal: CloseProposal = {
            intent: intent.variant,
            responses: selected.sort(
                (left, right) => left.signer - right.signer,
            ),
        };
        participant.proposed = true;
        send({ kind: 'proposal', proposal }, organizer);
        signTarget(participant, proposal);
    };
    const receive = (participant: HonestParticipant, delivery: Delivery) => {
        if (participant.departed) return;
        const { message } = delivery;
        if (delivery.action !== action) {
            ignoredMessages += 1;
            return;
        }
        switch (message.kind) {
            case 'envelope':
            case 'body': {
                const known = participant.known.has(
                    identityOf(message.envelope),
                );
                if (!holdBody(participant, message.envelope) && known)
                    ignoredMessages += 1;
                tryPropose(participant);
                return;
            }
            case 'intent': {
                if (participant.lockedIntent !== undefined) {
                    ignoredMessages += 1;
                    return;
                }
                lock(participant, message.intent);
                respond(participant, message.intent);
                return;
            }
            case 'response': {
                const { response } = message;
                if (
                    !responseValid(response) ||
                    participant.responses.has(response.signer)
                ) {
                    ignoredMessages += 1;
                    return;
                }
                participant.responses.set(response.signer, response);
                if (participant.position === organizer)
                    for (const identity of response.listed)
                        participant.known.set(
                            identity,
                            envelopes.get(identity)!,
                        );
                tryPropose(participant);
                return;
            }
            case 'proposal':
                signTarget(participant, message.proposal);
                return;
            case 'signature':
                if (participant.targetLock === undefined)
                    signTarget(participant, message.proposal);
                recordSignature(participant, message.signer, message.proposal);
                return;
            case 'share':
                recordShare(participant, message.signer, message.target);
                return;
        }
    };
    const deliverOne = (): void => {
        const prioritized = pending.flatMap((delivery, index) =>
            delivery.recipient === options.priorityRecipient ? [index] : [],
        );
        const index =
            prioritized.length > 0
                ? prioritized[random(prioritized.length)]
                : random(pending.length);
        const [delivery] = pending.splice(index, 1);
        step += 1;
        const participant = participants.get(delivery.recipient);
        if (participant !== undefined) receive(participant, delivery);
        // The relay duplicates some deliveries.
        if (random(10) === 0) pending.push(delivery);
    };

    // Honest ballots are cast before the close, each in its own visit, at the
    // author's clock; they are never later than the honest close time.
    let clock = 100;
    for (const participant of participants.values()) {
        if ((options.voters & bit(participant.position)) === 0) continue;
        step += 1;
        const envelope: CloseEnvelope = {
            author: participant.position,
            variant: 0,
            time: clock + participant.clockSkew,
            bodyAvailable: true,
            validProof: true,
        };
        clock += 1;
        envelopes.set(identityOf(envelope), envelope);
        participant.ownEnvelope = identityOf(envelope);
        holdBody(participant, envelope);
        work(participant);
        send({ kind: 'envelope', envelope }, participant.position);
    }
    if (options.corruptVotes)
        for (const author of members(corrupt, n))
            for (
                let variant = 0;
                variant <= options.corruptEquivocation;
                variant += 1
            ) {
                const envelope: CloseEnvelope = {
                    author,
                    variant,
                    time: options.corruptBackdating ? 0 : clock + random(3),
                    bodyAvailable: !(
                        options.corruptWithholdsBody && variant === 0
                    ),
                    validProof: variant % 2 === 0,
                };
                envelopes.set(identityOf(envelope), envelope);
                send({ kind: 'envelope', envelope }, author);
            }
    // Replays from another action are ignored.
    for (const recipient of participants.keys())
        pending.push({
            recipient,
            message: { kind: 'intent', intent: { variant: 9, closeTime: 1e9 } },
            action: action + 1,
        });
    for (const position of members(options.departedBeforeClose, n))
        participants.get(position)!.departed = true;
    const partial = random(pending.length + 1);
    for (let index = 0; index < partial && pending.length > 0; index += 1)
        deliverOne();
    if (options.corruptTargetsOrganizer && !organizerCorrupt) {
        const organizerState = participants.get(organizer)!;
        for (const author of members(corrupt, n)) {
            for (const variant of [50, 51]) {
                const envelope: CloseEnvelope = {
                    author,
                    variant,
                    time: 1e9,
                    bodyAvailable: true,
                    validProof: true,
                };
                envelopes.set(identityOf(envelope), envelope);
                holdBody(organizerState, envelope);
            }
            for (const participant of participants.values()) {
                if (participant.position === organizer) continue;
                const envelope: CloseEnvelope = {
                    author,
                    variant: 100 + participant.position,
                    time: 0,
                    bodyAvailable: true,
                    validProof: participant.position % 2 === 0,
                };
                envelopes.set(identityOf(envelope), envelope);
                holdBody(participant, envelope);
            }
        }
    }
    clock += 4;
    if (!organizerCorrupt) {
        const organizerState = participants.get(organizer)!;
        if (!organizerState.departed) {
            step += 1;
            const intent: CloseIntent = {
                variant: 0,
                closeTime: clock + organizerState.clockSkew,
            };
            intents.set(0, intent);
            lock(organizerState, intent);
            work(organizerState);
            send({ kind: 'intent', intent }, organizer);
        }
    } else {
        // Two intents, one backdated, split among the honest participants.
        const backdated: CloseIntent = { variant: 0, closeTime: clock - 6 };
        const current: CloseIntent = { variant: 1, closeTime: clock };
        intents.set(0, backdated);
        intents.set(1, current);
        for (const recipient of participants.keys())
            pending.push({
                recipient,
                message: {
                    kind: 'intent',
                    intent: random(2) === 0 ? backdated : current,
                },
                action,
            });
    }
    // An honest nonvoter that has not yet authenticated the intent may still
    // cast a ballot concurrently with the close; its time decides lateness.
    for (const participant of participants.values()) {
        if (
            participant.ownEnvelope !== undefined ||
            participant.departed ||
            participant.lockedIntent !== undefined ||
            random(5) !== 0
        )
            continue;
        step += 1;
        const envelope: CloseEnvelope = {
            author: participant.position,
            variant: 0,
            time: clock + participant.clockSkew,
            bodyAvailable: true,
            validProof: true,
        };
        envelopes.set(identityOf(envelope), envelope);
        participant.ownEnvelope = identityOf(envelope);
        holdBody(participant, envelope);
        work(participant);
        send({ kind: 'envelope', envelope }, participant.position);
    }
    // Corrupt responders answer every intent with a relay-chosen listing of
    // at most two on-time envelopes per slot.
    if (!options.corruptWithholdsResponses)
        for (const signer of members(corrupt, n))
            for (const intent of intents.values()) {
                const response: CloseResponse = {
                    signer,
                    intent: intent.variant,
                    listed: capListing(
                        [...envelopes.values()]
                            .filter(
                                ({ author, time, bodyAvailable }) =>
                                    random(2) === 0 &&
                                    !(
                                        options.corruptOmitsIsolated &&
                                        (options.isolated & bit(author)) !== 0
                                    ) &&
                                    time <= intent.closeTime &&
                                    (bodyAvailable ||
                                        options.corruptListsBodiless === true),
                            )
                            .map(identityOf),
                        maximumListedEnvelopesPerSlot,
                    ),
                };
                allResponses.push(response);
                send({ kind: 'response', response }, undefined);
            }
    const corruptProposals = new Set<number>();
    let rounds = 0;
    while (pending.length > 0 || withheld.length > 0) {
        rounds += 1;
        if (rounds > 1_000_000)
            throw new Error('The close execution diverged.');
        if (pending.length === 0) {
            // Eventual delivery: the relay must release withheld messages.
            pending = withheld;
            withheld = [];
            continue;
        }
        deliverOne();
        if (!organizerCorrupt) continue;
        for (const intent of intents.values()) {
            if (corruptProposals.has(intent.variant)) continue;
            const bySigner = new Map<number, CloseResponse>();
            for (const response of allResponses)
                if (
                    response.intent === intent.variant &&
                    !bySigner.has(response.signer) &&
                    responseValid(response)
                )
                    bySigner.set(response.signer, response);
            if (bySigner.size < profile.quorum || !bySigner.has(organizer))
                continue;
            corruptProposals.add(intent.variant);
            const own = bySigner.get(organizer)!;
            const others = [...bySigner.values()].filter(
                ({ signer }) => signer !== organizer,
            );
            const proposal: CloseProposal = {
                intent: intent.variant,
                responses: [own, ...others.slice(0, profile.quorum - 1)].sort(
                    (left, right) => left.signer - right.signer,
                ),
            };
            for (const recipient of participants.keys())
                if (random(2) === 0)
                    pending.push({
                        recipient,
                        message: { kind: 'proposal', proposal },
                        action,
                    });
        }
    }

    const certifiedTargets = [...signersByTarget.entries()]
        .filter(([, signers]) => signers.size >= profile.quorum)
        .map(([target]) => target);
    const findings = new Set<string>();
    if (certifiedTargets.length > 1) findings.add('agreement');
    // Two bodies for one slot at once; an honest author's body once; for a
    // corrupt slot two before the lock and two on-time bodies after it; and
    // one organizer request per slot.
    if (
        maximumHeldPerSlot > maximumListedEnvelopesPerSlot ||
        maximumReceivedPerHonestSlot > 1 ||
        maximumReceivedPerCorruptSlot > 2 * maximumListedEnvelopesPerSlot ||
        maximumOrganizerRequestsPerSlot > 1
    )
        findings.add('body-bound');
    const heldBeforeResponding = new Map<string, number>();
    for (const participant of participants.values())
        for (const identity of participant.heldAtResponse)
            heldBeforeResponding.set(
                identity,
                (heldBeforeResponding.get(identity) ?? 0) |
                    bit(participant.position),
            );
    let inventory: ClosedInventory | undefined;
    let omittedHonest = 0;
    const target = certifiedTargets[0];
    if (target !== undefined) {
        inventory = proposalInventory(proposalsByTarget.get(target)!)!;
        for (const finding of checkCloseContract({
            profile,
            corrupt,
            envelopes,
            intents,
            organizerAnswer: participants.get(organizer)?.answeredIntent,
            heldBeforeResponding,
            inventory,
        }))
            findings.add(finding);
        const closeTime = intents.get(inventory.intent)!.closeTime;
        omittedHonest = [...envelopes.values()].filter(
            (envelope) =>
                (corrupt & bit(envelope.author)) === 0 &&
                envelope.time <= closeTime &&
                !inventory!.listed.has(identityOf(envelope)),
        ).length;
        // After certification every continuing honest participant verifies
        // the terminal without any departed participant.
        for (const participant of participants.values())
            if (!participant.departed && !participant.verified)
                findings.add('terminal-liveness');
    }
    const closeLivenessExpected =
        !organizerCorrupt &&
        (options.departedBeforeClose & bit(organizer)) === 0 &&
        memberCount(corrupt | options.departedBeforeClose) <=
            profile.faultBound &&
        !options.refuseAfterOwnOmission;
    if (closeLivenessExpected && certifiedTargets.length === 0)
        findings.add('close-liveness');
    const visitCounts = (predicate: (position: number) => boolean) =>
        Math.max(
            0,
            ...[...participants.values()]
                .filter(({ position }) => predicate(position))
                .map(({ visitSteps }) => visitSteps.size),
        );
    return {
        certifiedTargets: certifiedTargets.length,
        inventory,
        findings: [...findings].sort(),
        omittedHonest,
        // The largest honest signer set of any target, certified or not.
        honestSigners: Math.max(
            0,
            ...[...signersByTarget.values()].map(
                (signers) =>
                    [...signers].filter(
                        (signer) => (corrupt & bit(signer)) === 0,
                    ).length,
            ),
        ),
        maximumListedEntries,
        ignoredMessages,
        organizerVisits: visitCounts((position) => position === organizer),
        voterVisits: visitCounts(
            (position) =>
                position !== organizer &&
                participants.get(position)!.ownEnvelope !== undefined,
        ),
        nonvoterVisits: visitCounts(
            (position) =>
                position !== organizer &&
                participants.get(position)!.ownEnvelope === undefined,
        ),
        maximumHeldPerSlot,
        maximumReceivedPerHonestSlot,
        maximumReceivedPerCorruptSlot,
        maximumOrganizerRequestsPerSlot,
    };
};

export type CompletionProfileExecutionCensus = Readonly<{
    participantCount: number;
    corruptionSets: number;
    executions: number;
    certifiedExecutions: number;
    maximumHonestOmission: number;
    forcedNoResultExecutions: number;
    maximumListedEntries: number;
    targetedExecutions: number;
    targetedCertifiedExecutions: number;
    maximumHeldPerSlot: number;
    maximumReceivedPerHonestSlot: number;
    maximumReceivedPerCorruptSlot: number;
    maximumOrganizerRequestsPerSlot: number;
    findings: readonly string[];
}>;

// Every corruption set, with an honest or corrupt organizer, full or partial
// honest turnout, departures inside the budget before the close and after
// certification, isolation of f honest voters, and corrupt equivocation,
// backdating, withheld bodies listed by corrupt responders, abstention,
// withheld responses with late bodies filling the organizer's slots and a
// different envelope for every other honest participant, and refused
// signatures.
export const exploreCompletionProfileExecutions = (
    participantCount = 10,
): CompletionProfileExecutionCensus => {
    const profile = deriveCloseProfile(participantCount);
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
    let maximumHeldPerSlot = 0;
    let maximumReceivedPerHonestSlot = 0;
    let maximumReceivedPerCorruptSlot = 0;
    let maximumOrganizerRequestsPerSlot = 0;
    for (const corrupt of masksAtMost(participantCount, profile.faultBound)) {
        corruptionSets += 1;
        const honest = everyone & ~corrupt;
        const others = members(honest & ~bit(organizer), participantCount);
        const budget = profile.faultBound - memberCount(corrupt);
        const firstF = maskOf(others.slice(0, profile.faultBound));
        const lastF = maskOf(others.slice(others.length - profile.faultBound));
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
                corruptVotes: index % 2 === 0,
                corruptEquivocation: (corrupt + index) % 3,
                corruptBackdating: index === 2,
                corruptWithholdsBody: index === 3,
                corruptListsBodiless: index === 3,
                corruptSignTargets: (corrupt + index) % 2 === 0,
                corruptOmitsIsolated: index % 2 === 1,
                refuseAfterOwnOmission: false,
                corruptTargetsOrganizer: value.targeted === true,
                corruptWithholdsResponses: value.targeted === true,
            });
            executions += 1;
            if (result.certifiedTargets > 0) certifiedExecutions += 1;
            if (value.targeted === true && (corrupt & bit(organizer)) === 0) {
                targetedExecutions += 1;
                if (result.certifiedTargets > 0)
                    targetedCertifiedExecutions += 1;
            }
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
        maximumHeldPerSlot,
        maximumReceivedPerHonestSlot,
        maximumReceivedPerCorruptSlot,
        maximumOrganizerRequestsPerSlot,
        findings: [...findings].sort(),
    };
};

// Counterexamples for the four obligations found in review and the rejected
// support rule. Each shows the violation under the variant and confirms the
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
        supportRuleIncludesEnvelope: supportCount >= four.quorum,
        unionRuleIncludesEnvelope: closeInventory(
            { intent: 0, responses: supportResponses },
            envelopes,
            four,
        ).listed.has(identityOf(ballot)),
    };
};

// Productive visits observed in the message-level executions, added to the
// fixed-suite preparation visits. Each honest participant performs all work
// its newest delivery enables; separate deliveries are separate visits. Every
// visit performs at least one one-shot stage, so the stage count bounds the
// visits: a ballot, the close response, the target signature, the release
// share and verification, and for the organizer the close intent and the
// proposal with its own response and target signature instead of the
// response and signature.
const closeStages = {
    voter: ['ballot', 'response', 'target-signature', 'release', 'verify'],
    nonvoter: ['response', 'target-signature', 'release', 'verify'],
    organizer: ['ballot', 'close', 'proposal', 'release', 'verify'],
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

export const compileCloseVisitCensus = (
    participantCount: number,
): CloseVisitCensus => {
    const profile = deriveCloseProfile(participantCount);
    const preparation = traceCommonMatrixPreparationVisits(
        participantCount,
        [],
    );
    const preparationVisits = Math.max(
        ...Array.from(
            { length: participantCount },
            (_unused, participant) =>
                preparation.filter((visit) => visit.participant === participant)
                    .length,
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
        nonvoterVisits: preparationVisits + nonvoterVisits,
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
