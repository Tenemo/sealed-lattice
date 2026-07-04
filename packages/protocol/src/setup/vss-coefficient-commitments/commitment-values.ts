// BDLOP setup commitment value shaping: the kernel commitment computation
// bridge that produces a canonical commitment and its root from an opening.
import type { ProtocolHash } from '@sealed-lattice/types';

import {
    type SetupCommitmentOpeningComputation,
    type SetupCommitmentOpeningComputer,
} from './constants-and-types.js';

export const computeSetupCommitmentWithKernel = (input: {
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly sourceRnsLimbIndex: number;
    readonly sourceMessageModulus: number;
    readonly shamirCoefficientIndex: number;
    readonly messageCoefficients: readonly number[];
    readonly randomnessByColumn: readonly (readonly number[])[];
    readonly ringDegree: number;
    readonly setupCommitmentComputer: SetupCommitmentOpeningComputer;
}): SetupCommitmentOpeningComputation =>
    input.setupCommitmentComputer({
        publicMatrixSeedHash: input.publicMatrixSeedHash,
        sourceRnsLimbIndex: input.sourceRnsLimbIndex,
        sourceMessageModulus: input.sourceMessageModulus,
        shamirCoefficientIndex: input.shamirCoefficientIndex,
        messageCoefficients: input.messageCoefficients,
        randomnessByColumn: input.randomnessByColumn,
        ringDegree: input.ringDegree,
    });
