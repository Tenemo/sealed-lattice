import { shareCommitmentOpeningDimension } from '../protocol-parameters.js';

import type { AggregateDerivationWitnessInput } from './types.js';

export const sumAggregateDerivationWitnesses = (input: {
    readonly witnesses: readonly AggregateDerivationWitnessInput[];
}): AggregateDerivationWitnessInput => {
    if (input.witnesses.length === 0) {
        throw new RangeError('Aggregate derivation requires witness inputs.');
    }
    const shareVectorWidth =
        input.witnesses[0].aggregateIntegerShareVector.length;

    return {
        aggregateIntegerShareVector: Array.from(
            { length: shareVectorWidth },
            (_unusedValue, coordinateIndex) =>
                input.witnesses.reduce(
                    (sum, witness) =>
                        sum +
                        (witness.aggregateIntegerShareVector[coordinateIndex] ??
                            0),
                    0,
                ),
        ),
        aggregateOpeningRandomness: Array.from(
            { length: shareCommitmentOpeningDimension },
            (_unusedValue, openingCoordinateIndex) =>
                input.witnesses.reduce(
                    (sum, witness) =>
                        sum +
                        (witness.aggregateOpeningRandomness[
                            openingCoordinateIndex
                        ] ?? 0),
                    0,
                ),
        ),
    };
};

export const aggregateWitnessFromReceiverPlaintext = (input: {
    readonly openingRandomness: readonly number[];
    readonly receiverShareVector: readonly number[];
}): AggregateDerivationWitnessInput => ({
    aggregateIntegerShareVector: [...input.receiverShareVector],
    aggregateOpeningRandomness: [...input.openingRandomness],
});
