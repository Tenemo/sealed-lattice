import type { FieldElement } from './field.js';
import type { ProtocolHash } from './protocol-hash.js';

/** Plain sparse target expected from the later homomorphic top-k evaluator. */
export type SparseTopKTarget = {
    readonly forbiddenSemanticSlots: readonly FieldElement[];
    readonly layoutHash: ProtocolHash;
    readonly optionCount: number;
    readonly targetHash: ProtocolHash;
    readonly targetIdSlots: readonly FieldElement[];
    readonly targetOrderSlots: readonly FieldElement[];
    readonly topOptionCount: number;
};

/** One decoded sparse target selection ordered by final result position. */
export type DecodedSparseTopKSelection = {
    readonly optionIndex: number;
    readonly optionOrdinal: number;
    readonly orderPosition: number;
};
