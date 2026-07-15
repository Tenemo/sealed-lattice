/** Internal command identifiers shared by every action-randomness WASM caller. */
export const actionRandomnessCommandIdentifiers = Object.freeze({
    open: 1,
    close: 2,
    setupMailboxEncapsulate: 3,
    persistentProofAttempt: 4,
    ordinaryProofAttempt: 5,
    targetReleaseAttempt: 6,
    freshBallotAttempt: 7,
    createAndSeal: 8,
    openSealed: 9,
    setupActionRandomnessAuthorization: 10,
    validateSetupMailboxSourceKeys: 11,
    setupMailboxSignatureHedge: 12,
    createStructuredCommitmentOpening: 13,
    releaseStructuredCommitmentOpening: 14,
    computeStructuredCommitment: 15,
    setupObjectSignatureHedge: 16,
} as const);
