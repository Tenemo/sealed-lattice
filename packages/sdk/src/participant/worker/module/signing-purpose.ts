// The participant module's one-shot signing purposes by their bit positions
// in a restored credential's unused-purpose mask, under the names and
// positions of the module's own purposes.
export const signingPurpose = {
    rosterProposal: 0,
    offer: 1,
    selectionProposal: 2,
    selectionEndorsement: 3,
    ballot: 4,
    closeIntent: 5,
    closeResponse: 6,
    closeProposal: 7,
    target: 8,
    release: 9,
} as const;

export type SigningPurpose =
    (typeof signingPurpose)[keyof typeof signingPurpose];

export const purposeBit = (purpose: SigningPurpose) => 1 << purpose;
