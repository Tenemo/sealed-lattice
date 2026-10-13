import {
    bit,
    capListing,
    checkCloseContract,
    closeInventory,
    deriveCloseProfile,
    identityOf,
    knownSlots,
    listKnownEnvelopes,
    maximumListedEnvelopesPerSlot,
    memberCount,
    members,
    organizer,
    organizerReady,
    usableEnvelopes,
    verifyCloseProposal,
    verifyCloseResponse,
    type CloseEnvelope,
    type CloseIntent,
    type CloseProposal,
    type CloseResponse,
    type ClosedInventory,
} from '#tests/close-contract-model.js';
import {
    type Message,
    type Delivery,
    CloseDeliveryQueue,
} from '#tests/close-execution/delivery.js';
import {
    type HonestParticipant,
    retainCloseBody,
    lockCloseIntent,
    canVerifyCloseBarrier,
    retainReleaseShare,
    createHonestParticipant,
} from '#tests/close-execution/participant.js';

// Message-level executions of the close-response contract. Messages are
// the contract model's ideal authenticated objects; these executions
// create no protocol capability.

// Deterministic message-level executions with a malicious relay. Honest
// handlers other than the organizer act on the first message that enables
// them: a response follows the first authenticated intent, a target signature
// the first valid proposal whose records reached the signer, a release share
// the certificate, and verification d shares or a no-result certificate. The
// organizer locks its own intent and answers once q - 1 other responses are
// ready, then publishes its closure and proposes. The closure copies every
// named response, every envelope they list and every usable slot's body, so
// a signer needs nothing a corrupt author or responder showed the organizer
// alone. A participant holds at most two bodies for one slot, discards late
// bodies at its intent lock and refuses late ones afterwards. With its
// response, each other responder forwards the body of every slot it lists one
// envelope for that the organizer did not hold at its intent lock, and the
// organizer reads the one known envelope's body of a slot a response lists
// from its author or from such a copy. The
// relay reorders, duplicates, replays another action's messages, withholds an
// isolated participant's messages until certification, may show corrupt
// participants' messages to the organizer alone or hide corrupt ballots from
// it, and otherwise delivers every message among cooperating participants.

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
    // The relay shows corrupt ballots and responses only to the organizer.
    corruptShowsOnlyOrganizer?: boolean;
    // The rejected author-route reads: an honest organizer publishes no
    // closure, so a signer verifies only what authors and responders showed
    // it.
    withoutClosure?: boolean;
    // Before the close, corrupt authors give their ballots to every honest
    // participant but the organizer, and the relay never shows the organizer
    // a copy from them.
    corruptHidesFromOrganizer?: boolean;
    // The rejected organizer reads from authors alone: responders forward no
    // body.
    withoutForwarding?: boolean;
}>;

type CloseExecutionResult = Readonly<{
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
    // Bodies one responder forwarded to the organizer.
    maximumForwardedPerResponder: number;
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
        participants.set(
            position,
            createHonestParticipant(position, random(3) - 1),
        );

    let ignoredMessages = 0;
    let maximumListedEntries = 0;
    let maximumHeldPerSlot = 0;
    let maximumReceivedPerHonestSlot = 0;
    let maximumReceivedPerCorruptSlot = 0;
    let maximumOrganizerRequestsPerSlot = 0;
    let maximumForwardedPerResponder = 0;
    // The bodies an honest organizer held when it locked its intent, which it
    // publishes with the intent.
    let organizerHeldAtLock: ReadonlySet<string> | undefined;
    const deliveries = new CloseDeliveryQueue(
        new Set(participants.keys()),
        random,
        options.isolated,
        options.priorityRecipient,
        action,
    );
    const deliverOne = () =>
        deliveries.deliverNext((delivery) => {
            const participant = participants.get(delivery.recipient);
            if (participant !== undefined) receive(participant, delivery);
        });
    const holdBody = (
        participant: HonestParticipant,
        envelope: CloseEnvelope,
    ) => {
        const retained = retainCloseBody(participant, envelope);
        if (retained === undefined) return false;
        maximumHeldPerSlot = Math.max(maximumHeldPerSlot, retained.held);
        if ((corrupt & bit(envelope.author)) === 0)
            maximumReceivedPerHonestSlot = Math.max(
                maximumReceivedPerHonestSlot,
                retained.received,
            );
        else
            maximumReceivedPerCorruptSlot = Math.max(
                maximumReceivedPerCorruptSlot,
                retained.received,
            );
        return true;
    };
    const recordShare = (
        participant: HonestParticipant,
        signer: number,
        target: string,
    ) => {
        if (
            retainReleaseShare(
                participant,
                signer,
                target,
                profile.releaseThreshold,
            )
        )
            work(participant);
    };
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
    // A corrupt participant's message, which the relay may show only to the
    // organizer.
    const sendCorrupt = (message: Message): void => {
        if (options.corruptShowsOnlyOrganizer !== true)
            deliveries.send(message, undefined);
        else if (participants.has(organizer))
            deliveries.enqueue({ recipient: organizer, message, action });
    };
    const work = (participant: HonestParticipant): void => {
        participant.visitSteps.add(deliveries.step);
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
        participant.seen.add(response);
        work(participant);
        deliveries.send({ kind: 'response', response }, participant.position);
        if (
            participant.position === organizer ||
            options.withoutForwarding === true
        )
            return;
        // The same visit forwards the body of each slot the response lists
        // one envelope for, other than its own, that the organizer did not
        // hold at its lock; an unknown held list forwards every such body.
        const listed = response.listed.map((value) => envelopes.get(value)!);
        let forwards = 0;
        for (const envelope of listed)
            if (
                envelope.author !== participant.position &&
                organizerHeldAtLock?.has(identityOf(envelope)) !== true &&
                listed.filter(({ author }) => author === envelope.author)
                    .length === 1
            ) {
                forwards += 1;
                deliveries.sendTo(
                    { kind: 'forward', envelope },
                    participant.position,
                    organizer,
                );
            }
        maximumForwardedPerResponder = Math.max(
            maximumForwardedPerResponder,
            forwards,
        );
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
            if (deliveries.certify()) {
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
                deliveries.send(
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
            lockCloseIntent(participant, intent);
            respond(participant, intent);
        }
        if (!canVerifyCloseBarrier(participant, proposal, envelopes)) {
            if (!participant.waiting.includes(proposal))
                participant.waiting.push(proposal);
            return;
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
        deliveries.send(
            { kind: 'signature', signer: participant.position, proposal },
            participant.position,
        );
        if (
            options.corruptSignTargets &&
            !corruptSigned.has(inventory.target)
        ) {
            corruptSigned.add(inventory.target);
            for (const signer of members(corrupt, n))
                deliveries.send(
                    { kind: 'signature', signer, proposal },
                    undefined,
                );
        }
        recordSignature(participant, participant.position, proposal);
    };
    // The organizer reads a body from its author's route or from a copy a
    // listing responder forwarded. An honest author or a forwarded copy
    // supplies it; for a corrupt author the relay decides once, never
    // supplies a withheld body, and supplies none when corrupt authors hide
    // from the organizer, which then waits for a forwarded copy.
    const corruptSupplies = new Map<string, boolean>();
    const scheduledBodies = new Set<string>();
    const requestBody = (
        participant: HonestParticipant,
        identity: string,
    ): void => {
        const envelope = envelopes.get(identity)!;
        const honestAuthor = (corrupt & bit(envelope.author)) === 0;
        const forwarded = participant.forwarded.has(identity);
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
        if (!honestAuthor && !forwarded) {
            if (options.corruptHidesFromOrganizer === true) return;
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
            honestAuthor &&
            !forwarded &&
            (options.isolated & bit(envelope.author)) !== 0 &&
            !deliveries.certified
        )
            deliveries.withhold(delivery);
        else deliveries.enqueue(delivery);
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
                    requestBody(participant, identity);
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
        // The organizer holds its own closure, which precedes its proposal.
        participant.closures.add(proposal);
        if (options.withoutClosure !== true)
            deliveries.send({ kind: 'closure', proposal }, organizer);
        deliveries.send({ kind: 'proposal', proposal }, organizer);
        signTarget(participant, proposal);
    };
    // Verifies the proposals whose barrier a new delivery may complete.
    const retry = (participant: HonestParticipant): void => {
        for (const proposal of participant.waiting.splice(0))
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
                retry(participant);
                return;
            }
            case 'intent': {
                if (participant.lockedIntent !== undefined) {
                    ignoredMessages += 1;
                    return;
                }
                lockCloseIntent(participant, message.intent);
                respond(participant, message.intent);
                return;
            }
            case 'response': {
                const { response } = message;
                participant.seen.add(response);
                retry(participant);
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
            case 'closure':
                participant.closures.add(message.proposal);
                retry(participant);
                return;
            case 'forward': {
                // The organizer reads a forwarded copy only for a body it
                // requested.
                const identity = identityOf(message.envelope);
                participant.forwarded.set(identity, message.envelope);
                if (!participant.requested.has(identity)) return;
                if (!holdBody(participant, message.envelope))
                    ignoredMessages += 1;
                tryPropose(participant);
                return;
            }
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

    // Honest ballots are cast before the close, each in its own visit, at the
    // author's clock; they are never later than the honest close time.
    let clock = 100;
    for (const participant of participants.values()) {
        if ((options.voters & bit(participant.position)) === 0) continue;
        deliveries.advance();
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
        deliveries.send({ kind: 'envelope', envelope }, participant.position);
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
                if (options.corruptHidesFromOrganizer !== true)
                    sendCorrupt({ kind: 'envelope', envelope });
                else
                    for (const participant of participants.values())
                        if (participant.position !== organizer)
                            holdBody(participant, envelope);
            }
    // Replays from another action are ignored.
    for (const recipient of participants.keys())
        deliveries.enqueue({
            recipient,
            message: { kind: 'intent', intent: { variant: 9, closeTime: 1e9 } },
            action: action + 1,
        });
    for (const position of members(options.departedBeforeClose, n))
        participants.get(position)!.departed = true;
    const partial = random(deliveries.pendingCount + 1);
    for (
        let index = 0;
        index < partial && deliveries.pendingCount > 0;
        index += 1
    )
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
            deliveries.advance();
            const intent: CloseIntent = {
                variant: 0,
                closeTime: clock + organizerState.clockSkew,
            };
            intents.set(0, intent);
            lockCloseIntent(organizerState, intent);
            organizerHeldAtLock = new Set(organizerState.held.keys());
            work(organizerState);
            deliveries.send({ kind: 'intent', intent }, organizer);
        }
    } else {
        // Two intents, one backdated, split among the honest participants.
        const backdated: CloseIntent = { variant: 0, closeTime: clock - 6 };
        const current: CloseIntent = { variant: 1, closeTime: clock };
        intents.set(0, backdated);
        intents.set(1, current);
        for (const recipient of participants.keys())
            deliveries.enqueue({
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
        deliveries.advance();
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
        deliveries.send({ kind: 'envelope', envelope }, participant.position);
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
                sendCorrupt({ kind: 'response', response });
            }
    const corruptProposals = new Set<number>();
    let rounds = 0;
    while (deliveries.pendingCount > 0 || deliveries.hasWithheld) {
        rounds += 1;
        if (rounds > 1_000_000)
            throw new Error('The close execution diverged.');
        if (deliveries.pendingCount === 0) {
            // Eventual delivery: the relay must release withheld messages.
            deliveries.releaseWithheld();
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
            // A corrupt organizer publishes its closure with each proposal,
            // which lets honest participants sign whatever it proposes.
            for (const recipient of participants.keys())
                if (random(2) === 0)
                    deliveries.enqueue(
                        {
                            recipient,
                            message: { kind: 'closure', proposal },
                            action,
                        },
                        {
                            recipient,
                            message: { kind: 'proposal', proposal },
                            action,
                        },
                    );
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
        maximumForwardedPerResponder,
    };
};
