import { deriveCanonicalObjectHash } from '@sealed-lattice/crypto';
import type {
    DecodedSparseTopKSelection,
    FieldElement,
    PlaintextTopKRankingEntry,
    RefusalRecord,
    SparseTopKTarget,
    SparseTopKTargetDecoding,
} from '@sealed-lattice/types';

import {
    createRefusal,
} from '../common/verification-helpers.js';

import { assertCanonicalFieldElement } from './field.js';

const deriveSparseTopKTargetLayoutHash = (input: {
    readonly optionCount: number;
    readonly topOptionCount: number;
}): string =>
    deriveCanonicalObjectHash({
        objectType: 'SparseTopKTargetLayout',
        optionCount: input.optionCount,
        optionOrdinalEncoding: 'one-based',
        targetIdSlotRule: 'optionOrdinalWhenRankLessThanTopOptionCountElseZero',
        targetOrderSlotRule:
            'rankPlusOneWhenRankLessThanTopOptionCountElseZero',
        topOptionCount: input.topOptionCount,
        zeroReserved: true,
    });

export const deriveSparseTopKTargetHash = (
    target: Omit<SparseTopKTarget, 'targetHash'>,
): string =>
    deriveCanonicalObjectHash({
        objectType: 'SparseTopKTarget',
        layoutHash: target.layoutHash,
        optionCount: target.optionCount,
        targetIdSlots: target.targetIdSlots,
        targetOrderSlots: target.targetOrderSlots,
        topOptionCount: target.topOptionCount,
    });

export const deriveSparseTopKTarget = (input: {
    readonly optionCount: number;
    readonly ranking: readonly PlaintextTopKRankingEntry[];
    readonly topOptionCount: number;
}): SparseTopKTarget => {
    if (
        !Number.isInteger(input.optionCount) ||
        input.optionCount < 1 ||
        input.optionCount > 20
    ) {
        throw new RangeError('Sparse target option count must be in 1..20.');
    }
    if (
        !Number.isInteger(input.topOptionCount) ||
        input.topOptionCount < 1 ||
        input.topOptionCount > input.optionCount
    ) {
        throw new RangeError(
            'Sparse target top option count must be in 1..optionCount.',
        );
    }
    if (input.ranking.length !== input.optionCount) {
        throw new RangeError(
            'Sparse target ranking must contain every option exactly once.',
        );
    }

    const seenOptionIndexes = new Set<number>();
    const seenRanks = new Set<number>();
    for (const rankingEntry of input.ranking) {
        if (
            !Number.isInteger(rankingEntry.optionIndex) ||
            rankingEntry.optionIndex < 0 ||
            rankingEntry.optionIndex >= input.optionCount ||
            rankingEntry.optionOrdinal !== rankingEntry.optionIndex + 1
        ) {
            throw new RangeError(
                'Sparse target ranking must contain canonical option indexes and ordinals.',
            );
        }
        if (
            !Number.isInteger(rankingEntry.rank) ||
            rankingEntry.rank < 0 ||
            rankingEntry.rank >= input.optionCount
        ) {
            throw new RangeError(
                'Sparse target ranking must contain ranks in 0..optionCount-1.',
            );
        }
        if (seenOptionIndexes.has(rankingEntry.optionIndex)) {
            throw new RangeError(
                'Sparse target ranking must contain distinct option indexes.',
            );
        }
        if (seenRanks.has(rankingEntry.rank)) {
            throw new RangeError(
                'Sparse target ranking must contain distinct ranks.',
            );
        }

        seenOptionIndexes.add(rankingEntry.optionIndex);
        seenRanks.add(rankingEntry.rank);
    }

    // Re-derive the canonical ranking from scratch (higher totalScore first,
    // then lower optionIndex) and assert the supplied ranking matches it. This
    // enforces the frozen tie-break order; any other ordering is rejected.
    const canonicalRanking = [...input.ranking]
        .sort(
            (left, right) =>
                right.totalScore - left.totalScore ||
                left.optionIndex - right.optionIndex,
        )
        .map((entry, rank) => ({
            optionIndex: entry.optionIndex,
            rank,
        }));
    for (const expectedEntry of canonicalRanking) {
        const actualEntry = input.ranking.find(
            (entry) => entry.optionIndex === expectedEntry.optionIndex,
        );
        if (actualEntry?.rank !== expectedEntry.rank) {
            throw new RangeError(
                'Sparse target ranking must match the higher-score-then-lower-option-index order.',
            );
        }
    }

    // Dual-slot top-k encoding, one slot pair per option index:
    //   targetIdSlots[i]    = optionOrdinal (optionIndex+1) if option i is in
    //                         the top-k, else 0
    //   targetOrderSlots[i] = its 1-based rank position (rank+1) if in top-k,
    //                         else 0
    // 0 is reserved for "not selected"; ordinals/positions are 1-based.
    const rankByOptionIndex = new Map(
        input.ranking.map((entry) => [entry.optionIndex, entry.rank]),
    );
    const targetIdSlots = Array.from(
        { length: input.optionCount },
        (_unused, optionIndex) => {
            const rank = rankByOptionIndex.get(optionIndex);
            if (rank === undefined) {
                throw new RangeError(
                    'Sparse target ranking is missing an option index.',
                );
            }

            return rank < input.topOptionCount ? optionIndex + 1 : 0;
        },
    );
    const targetOrderSlots = Array.from(
        { length: input.optionCount },
        (_unused, optionIndex) => {
            const rank = rankByOptionIndex.get(optionIndex)!;

            return rank < input.topOptionCount ? rank + 1 : 0;
        },
    );
    const layoutHash = deriveSparseTopKTargetLayoutHash({
        optionCount: input.optionCount,
        topOptionCount: input.topOptionCount,
    });
    const targetWithoutHash = {
        layoutHash,
        optionCount: input.optionCount,
        targetIdSlots,
        targetOrderSlots,
        topOptionCount: input.topOptionCount,
    } satisfies Omit<SparseTopKTarget, 'targetHash'>;

    return {
        ...targetWithoutHash,
        targetHash: deriveSparseTopKTargetHash(targetWithoutHash),
    };
};

const addSparseTargetRefusal = (
    refusedObjects: RefusalRecord[],
    message: string,
    objectHash?: string,
): void => {
    refusedObjects.push(
        createRefusal('SparseTargetInvalid', message, objectHash),
    );
};

const validateSlotElement = (
    refusedObjects: RefusalRecord[],
    value: FieldElement,
    fieldName: string,
    targetHash: string,
): boolean => {
    try {
        assertCanonicalFieldElement(value, fieldName);
        return true;
    } catch {
        addSparseTargetRefusal(
            refusedObjects,
            `${fieldName} is not a canonical field element.`,
            targetHash,
        );
        return false;
    }
};

const createSparseTargetDecodingFailure = (
    targetHash?: string,
): SparseTopKTargetDecoding => ({
    decodedSelections: [],
    isValid: false,
    refusedObjects: [
        createRefusal(
            'SparseTargetInvalid',
            'Sparse target could not be canonicalized or validated.',
            targetHash,
        ),
    ],
    selectedOptionOrdinals: [],
});

const decodeSparseTopKTargetUnchecked = (input: {
    readonly expectedLayoutHash: string;
    readonly target: SparseTopKTarget;
}): SparseTopKTargetDecoding => {
    const { target } = input;
    const refusedObjects: RefusalRecord[] = [];
    const recomputedHash = deriveSparseTopKTargetHash({
        layoutHash: target.layoutHash,
        optionCount: target.optionCount,
        targetIdSlots: target.targetIdSlots,
        targetOrderSlots: target.targetOrderSlots,
        topOptionCount: target.topOptionCount,
    });

    if (target.targetHash !== recomputedHash) {
        addSparseTargetRefusal(
            refusedObjects,
            'Sparse target hash does not match its canonical payload.',
            target.targetHash,
        );
    }
    if (target.layoutHash !== input.expectedLayoutHash) {
        addSparseTargetRefusal(
            refusedObjects,
            'Sparse target layout hash does not match the expected layout.',
            target.targetHash,
        );
    }
    if (
        !Number.isInteger(target.optionCount) ||
        target.optionCount < 1 ||
        target.optionCount > 20 ||
        !Number.isInteger(target.topOptionCount) ||
        target.topOptionCount < 1 ||
        target.topOptionCount > target.optionCount
    ) {
        addSparseTargetRefusal(
            refusedObjects,
            'Sparse target option and top-k counts are invalid.',
            target.targetHash,
        );
    }
    if (
        target.targetIdSlots.length !== target.optionCount ||
        target.targetOrderSlots.length !== target.optionCount
    ) {
        addSparseTargetRefusal(
            refusedObjects,
            'Sparse target slot arrays must match optionCount.',
            target.targetHash,
        );
    }

    const decodedSelections: DecodedSparseTopKSelection[] = [];
    const seenOptionOrdinals = new Set<number>();
    const seenOrderPositions = new Set<number>();

    for (
        let optionIndex = 0;
        optionIndex < target.targetIdSlots.length;
        optionIndex += 1
    ) {
        const optionOrdinal = target.targetIdSlots[optionIndex];
        const orderPosition = target.targetOrderSlots[optionIndex];
        const idIsCanonical = validateSlotElement(
            refusedObjects,
            optionOrdinal,
            'target ID slot',
            target.targetHash,
        );
        const orderIsCanonical = validateSlotElement(
            refusedObjects,
            orderPosition,
            'target order slot',
            target.targetHash,
        );
        if (!idIsCanonical || !orderIsCanonical) {
            continue;
        }

        // A slot pair is either fully unselected (both zero -> skip) or fully
        // selected (both nonzero). Exactly one zero is a half-filled, malformed
        // slot and is refused.
        if (optionOrdinal === 0 && orderPosition === 0) {
            continue;
        }
        if (optionOrdinal === 0 || orderPosition === 0) {
            addSparseTargetRefusal(
                refusedObjects,
                'Sparse target selected ID and order slots must both be nonzero.',
                target.targetHash,
            );
            continue;
        }
        if (
            optionOrdinal < 1 ||
            optionOrdinal > target.optionCount ||
            optionOrdinal !== optionIndex + 1
        ) {
            addSparseTargetRefusal(
                refusedObjects,
                'Sparse target option ordinal is out of range or in the wrong slot.',
                target.targetHash,
            );
        }
        if (orderPosition < 1 || orderPosition > target.topOptionCount) {
            addSparseTargetRefusal(
                refusedObjects,
                'Sparse target order position is out of range.',
                target.targetHash,
            );
        }
        if (seenOptionOrdinals.has(optionOrdinal)) {
            addSparseTargetRefusal(
                refusedObjects,
                'Sparse target selected option IDs must be distinct.',
                target.targetHash,
            );
        }
        if (seenOrderPositions.has(orderPosition)) {
            addSparseTargetRefusal(
                refusedObjects,
                'Sparse target order positions must be distinct.',
                target.targetHash,
            );
        }

        seenOptionOrdinals.add(optionOrdinal);
        seenOrderPositions.add(orderPosition);
        decodedSelections.push({
            optionIndex,
            optionOrdinal,
            orderPosition,
        });
    }

    if (decodedSelections.length !== target.topOptionCount) {
        addSparseTargetRefusal(
            refusedObjects,
            'Sparse target must contain exactly topOptionCount selected option IDs.',
            target.targetHash,
        );
    }

    for (
        let expectedOrderPosition = 1;
        expectedOrderPosition <= target.topOptionCount;
        expectedOrderPosition += 1
    ) {
        if (!seenOrderPositions.has(expectedOrderPosition)) {
            addSparseTargetRefusal(
                refusedObjects,
                'Sparse target order positions must be exactly 1..topOptionCount.',
                target.targetHash,
            );
            break;
        }
    }

    const sortedSelections = [...decodedSelections].sort(
        (left, right) => left.orderPosition - right.orderPosition,
    );

    return {
        decodedSelections: refusedObjects.length === 0 ? sortedSelections : [],
        isValid: refusedObjects.length === 0,
        refusedObjects,
        selectedOptionOrdinals:
            refusedObjects.length === 0
                ? sortedSelections.map((selection) => selection.optionOrdinal)
                : [],
        targetHash: refusedObjects.length === 0 ? target.targetHash : undefined,
    };
};

export const decodeSparseTopKTarget = (input: {
    readonly expectedLayoutHash: string;
    readonly target: SparseTopKTarget;
}): SparseTopKTargetDecoding => {
    try {
        return decodeSparseTopKTargetUnchecked(input);
    } catch {
        const targetHash = (
            input as
                | Partial<{
                      readonly target: Partial<SparseTopKTarget>;
                  }>
                | undefined
        )?.target?.targetHash;

        return createSparseTargetDecodingFailure(targetHash);
    }
};
