import { compileThresholdCompletionProfile } from '#tests/threshold-completion-model.js';

// Close responses under the bounded-omission contract. The organizer
// is roster position zero. Messages are ideal authenticated objects: a model
// signature cannot be forged, and envelope, intent, response, proposal, and
// target identities cannot collide. This model creates no protocol capability.

export const organizer = 0;
export const maximumListedEnvelopesPerSlot = 2;

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

export const bit = (position: number): number => 1 << position;

export const memberCount = (mask: number): number => {
    let count = 0;
    for (let remaining = mask >>> 0; remaining !== 0; count += 1)
        remaining &= remaining - 1;
    return count;
};

export const members = (mask: number, participantCount: number): number[] =>
    Array.from(
        { length: participantCount },
        (_unused, position) => position,
    ).filter((position) => (mask & bit(position)) !== 0);

export const maskOf = (positions: readonly number[]): number =>
    positions.reduce((mask, position) => mask | bit(position), 0);

export const masksOfSize = (
    participantCount: number,
    size: number,
): number[] => {
    const masks: number[] = [];
    for (let mask = 0; mask < 1 << participantCount; mask += 1)
        if (memberCount(mask) === size) masks.push(mask);
    return masks;
};

export const masksAtMost = (
    participantCount: number,
    size: number,
): number[] => {
    const masks: number[] = [];
    for (let mask = 0; mask < 1 << participantCount; mask += 1)
        if (memberCount(mask) <= size) masks.push(mask);
    return masks;
};

export const product = <Value>(
    choices: readonly (readonly Value[])[],
): Value[][] =>
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

export type SlotClassification =
    'absent' | 'accepted' | 'invalid' | 'conflicting';

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

export const identityOf = (envelope: CloseEnvelope): string =>
    envelopeIdentity(envelope.author, envelope.variant);

// The first `maximumPerSlot` identities of each slot, in canonical order.
export const capListing = (
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
export const knownSlots = (
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
export const organizerReady = (
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

export const checkCloseContract = (
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
