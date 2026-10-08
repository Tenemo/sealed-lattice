// The participant root's generations. Before the ballot: the enrollment
// intent and the completed registration, the organizer's locked roster
// proposal, the retained signed roster, the confirmed roster's setup
// preparation and the retained setup that opens the ballot. The ballot,
// close, target and release phases follow, and each phase's state module
// describes what the phase retains.
export const rootGeneration = {
    enrollmentIntent: 0,
    registered: 1,
    rosterLocked: 2,
    rosterSigned: 3,
    preparation: 4,
    setupRetained: 12,
} as const;

export const ballotPhase = {
    locked: 13,
    ready: 14,
    body: 15,
    signed: 17,
} as const;

export const closePhase = {
    intent: 18,
    locked: 19,
    responding: 20,
    responded: 21,
    proposed: 22,
} as const;

export const targetPhase = { intent: 23, signed: 24 } as const;

export const releasePhase = {
    locked: 25,
    ready: 26,
    body: 27,
    signed: 29,
} as const;

export const lastRootGeneration = releasePhase.signed;

// Whether a completed root can hold the generation. None lies between
// preparation and the retained setup, and none between a retained ballot or
// release body and its signature.
export const isRootGeneration = (generation: number) =>
    Number.isSafeInteger(generation) &&
    generation >= rootGeneration.registered &&
    generation <= lastRootGeneration &&
    (generation <= rootGeneration.preparation ||
        generation >= rootGeneration.setupRetained) &&
    !(generation > ballotPhase.body && generation < ballotPhase.signed) &&
    !(generation > releasePhase.body && generation < releasePhase.signed);
