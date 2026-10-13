import {
    identityOf,
    maximumListedEnvelopesPerSlot,
    usableEnvelopes,
    type CloseEnvelope,
    type CloseIntent,
    type CloseProposal,
    type CloseResponse,
} from '#tests/close-contract-model.js';

export type HonestParticipant = {
    readonly position: number;
    readonly clockSkew: number;
    departed: boolean;
    ownEnvelope: string | undefined;
    // The envelopes known with or without a body, and the bodies held.
    readonly known: Map<string, CloseEnvelope>;
    readonly held: Map<string, CloseEnvelope>;
    // What reached this participant for a close barrier: every body it could
    // read, every response and the proposals whose closure it received.
    readonly readable: Set<string>;
    readonly seen: Set<CloseResponse>;
    readonly closures: Set<CloseProposal>;
    // Proposals it has yet to verify.
    readonly waiting: CloseProposal[];
    // The organizer's bodies that responders forwarded.
    readonly forwarded: Map<string, CloseEnvelope>;
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

export const retainCloseBody = (
    participant: HonestParticipant,
    envelope: CloseEnvelope,
): Readonly<{ held: number; received: number }> | undefined => {
    const identity = identityOf(envelope);
    participant.known.set(identity, envelope);
    if (envelope.bodyAvailable) participant.readable.add(identity);
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
        return undefined;
    participant.held.set(identity, envelope);
    const received = (participant.received.get(envelope.author) ?? 0) + 1;
    participant.received.set(envelope.author, received);
    return { held: inSlot + 1, received };
};

export const lockCloseIntent = (
    participant: HonestParticipant,
    intent: CloseIntent,
) => {
    participant.lockedIntent = intent;
    for (const [identity, envelope] of participant.held)
        if (envelope.time > intent.closeTime) participant.held.delete(identity);
};

export const canVerifyCloseBarrier = (
    participant: HonestParticipant,
    proposal: CloseProposal,
    envelopes: ReadonlyMap<string, CloseEnvelope>,
): boolean =>
    participant.closures.has(proposal) ||
    (proposal.responses.every(
        (response) =>
            participant.seen.has(response) &&
            response.listed.every((identity) =>
                participant.known.has(identity),
            ),
    ) &&
        usableEnvelopes(proposal.responses, envelopes).every((envelope) =>
            participant.readable.has(identityOf(envelope)),
        ));

export const retainReleaseShare = (
    participant: HonestParticipant,
    signer: number,
    target: string,
    releaseThreshold: number,
): boolean => {
    const shares = participant.shares.get(target) ?? new Set();
    shares.add(signer);
    participant.shares.set(target, shares);
    if (
        participant.certified === target &&
        !participant.verified &&
        shares.size >= releaseThreshold
    ) {
        participant.verified = true;
        return true;
    }
    return false;
};

export const createHonestParticipant = (
    position: number,
    clockSkew: number,
): HonestParticipant => ({
    position,
    clockSkew,
    departed: false,
    ownEnvelope: undefined,
    known: new Map(),
    held: new Map(),
    readable: new Set(),
    seen: new Set(),
    closures: new Set(),
    waiting: [],
    forwarded: new Map(),
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
