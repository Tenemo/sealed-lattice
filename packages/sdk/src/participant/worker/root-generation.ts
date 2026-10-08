// The participant root's generations before the ballot: the enrollment
// intent and the completed registration, the organizer's locked roster
// proposal, the retained signed roster, the confirmed roster's setup
// preparation and the retained setup that opens the ballot. The ballot,
// close, target and release phases follow up to the last generation.
export const rootGeneration = {
    enrollmentIntent: 0,
    registered: 1,
    rosterLocked: 2,
    rosterSigned: 3,
    preparation: 4,
    setupRetained: 12,
} as const;

export const lastRootGeneration = 29;

// Whether a completed root can hold the generation. None lies between
// preparation and the retained setup, and none between a retained ballot or
// release body and its signature.
export const isRootGeneration = (generation: number) =>
    Number.isSafeInteger(generation) &&
    generation >= rootGeneration.registered &&
    generation <= lastRootGeneration &&
    (generation <= rootGeneration.preparation ||
        generation >= rootGeneration.setupRetained) &&
    generation !== 16 &&
    generation !== 28;
