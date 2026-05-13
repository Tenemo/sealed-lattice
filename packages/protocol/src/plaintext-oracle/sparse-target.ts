import type {
    DecodedSparseTopKSelection,
    FieldElement,
    PlaintextTopKRankingEntry,
    RefusalRecord,
    SparseTopKTarget,
    SparseTopKTargetDecoding,
} from '@sealed-lattice/types';

import { deriveProtocolDigest } from '../common/digests.js';
import {
    createRefusal,
    uniqueStrings,
} from '../common/verification-helpers.js';

import { assertCanonicalFieldElement } from './field.js';

export const sparseTopKTargetLayoutId = 'WinnerRankTopK-v1' as const;
const forbiddenSemanticSlotCount = 4;

export const deriveSparseTopKTargetLayoutDigest = (input: {
    readonly optionCount: number;
    readonly topOptionCount: number;
}): string =>
    deriveProtocolDigest('TargetLayoutDigest', {
        forbiddenSemanticSlotCount,
        layoutId: sparseTopKTargetLayoutId,
        optionCount: input.optionCount,
        optionOrdinalEncoding: 'one-based',
        targetIdSlotRule: 'optionOrdinalWhenRankLessThanTopOptionCountElseZero',
        targetOrderSlotRule:
            'rankPlusOneWhenRankLessThanTopOptionCountElseZero',
        topOptionCount: input.topOptionCount,
        zeroReserved: true,
    });

export const deriveSparseTopKTargetDigest = (
    target: Omit<SparseTopKTarget, 'targetDigest'>,
): string =>
    deriveProtocolDigest('PlaintextRoot', {
        forbiddenSemanticSlots: target.forbiddenSemanticSlots,
        layoutDigest: target.layoutDigest,
        layoutId: target.layoutId,
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
    const layoutDigest = deriveSparseTopKTargetLayoutDigest({
        optionCount: input.optionCount,
        topOptionCount: input.topOptionCount,
    });
    const targetWithoutDigest = {
        forbiddenSemanticSlots: Array.from(
            { length: forbiddenSemanticSlotCount },
            () => 0 as FieldElement,
        ),
        layoutDigest,
        layoutId: sparseTopKTargetLayoutId,
        optionCount: input.optionCount,
        targetIdSlots,
        targetOrderSlots,
        topOptionCount: input.topOptionCount,
    } satisfies Omit<SparseTopKTarget, 'targetDigest'>;

    return {
        ...targetWithoutDigest,
        targetDigest: deriveSparseTopKTargetDigest(targetWithoutDigest),
    };
};

const addSparseTargetRefusal = (
    refusedObjects: RefusalRecord[],
    message: string,
    objectDigest?: string,
): void => {
    refusedObjects.push(
        createRefusal('SparseTargetInvalid', message, objectDigest),
    );
};

const validateSlotElement = (
    refusedObjects: RefusalRecord[],
    value: FieldElement,
    fieldName: string,
    targetDigest: string,
): boolean => {
    try {
        assertCanonicalFieldElement(value, fieldName);
        return true;
    } catch {
        addSparseTargetRefusal(
            refusedObjects,
            `${fieldName} is not a canonical field element.`,
            targetDigest,
        );
        return false;
    }
};

const createSparseTargetDecodingFailure = (
    targetDigest?: string,
): SparseTopKTargetDecoding => ({
    acceptedDigests: [],
    decodedSelections: [],
    ok: false,
    refusedObjects: [
        createRefusal(
            'SparseTargetInvalid',
            'Sparse target could not be canonicalized or validated.',
            targetDigest,
        ),
    ],
    selectedOptionOrdinals: [],
    statusLabels: [],
});

const decodeSparseTopKTargetUnchecked = (input: {
    readonly expectedLayoutDigest: string;
    readonly target: SparseTopKTarget;
}): SparseTopKTargetDecoding => {
    const { target } = input;
    const refusedObjects: RefusalRecord[] = [];
    const recomputedDigest = deriveSparseTopKTargetDigest({
        forbiddenSemanticSlots: target.forbiddenSemanticSlots,
        layoutDigest: target.layoutDigest,
        layoutId: target.layoutId,
        optionCount: target.optionCount,
        targetIdSlots: target.targetIdSlots,
        targetOrderSlots: target.targetOrderSlots,
        topOptionCount: target.topOptionCount,
    });

    if (target.targetDigest !== recomputedDigest) {
        addSparseTargetRefusal(
            refusedObjects,
            'Sparse target digest does not match its canonical payload.',
            target.targetDigest,
        );
    }
    if (target.layoutId !== sparseTopKTargetLayoutId) {
        addSparseTargetRefusal(
            refusedObjects,
            'Sparse target layout ID is not supported.',
            target.targetDigest,
        );
    }
    if (target.layoutDigest !== input.expectedLayoutDigest) {
        addSparseTargetRefusal(
            refusedObjects,
            'Sparse target layout digest does not match the expected layout.',
            target.targetDigest,
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
            target.targetDigest,
        );
    }
    if (
        target.targetIdSlots.length !== target.optionCount ||
        target.targetOrderSlots.length !== target.optionCount
    ) {
        addSparseTargetRefusal(
            refusedObjects,
            'Sparse target slot arrays must match optionCount.',
            target.targetDigest,
        );
    }
    if (target.forbiddenSemanticSlots.length !== forbiddenSemanticSlotCount) {
        addSparseTargetRefusal(
            refusedObjects,
            'Sparse target forbidden semantic slot count must match the layout.',
            target.targetDigest,
        );
    }

    const decodedSelections: DecodedSparseTopKSelection[] = [];
    const seenOptionOrdinals = new Set<number>();
    const seenOrderPositions = new Set<number>();

    target.forbiddenSemanticSlots.forEach((value) => {
        if (
            validateSlotElement(
                refusedObjects,
                value,
                'forbidden semantic slot',
                target.targetDigest,
            ) &&
            value !== 0
        ) {
            addSparseTargetRefusal(
                refusedObjects,
                'Sparse target forbidden semantic slots must be zero.',
                target.targetDigest,
            );
        }
    });

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
            target.targetDigest,
        );
        const orderIsCanonical = validateSlotElement(
            refusedObjects,
            orderPosition,
            'target order slot',
            target.targetDigest,
        );
        if (!idIsCanonical || !orderIsCanonical) {
            continue;
        }

        if (optionOrdinal === 0 && orderPosition === 0) {
            continue;
        }
        if (optionOrdinal === 0 || orderPosition === 0) {
            addSparseTargetRefusal(
                refusedObjects,
                'Sparse target selected ID and order slots must both be nonzero.',
                target.targetDigest,
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
                target.targetDigest,
            );
        }
        if (orderPosition < 1 || orderPosition > target.topOptionCount) {
            addSparseTargetRefusal(
                refusedObjects,
                'Sparse target order position is out of range.',
                target.targetDigest,
            );
        }
        if (seenOptionOrdinals.has(optionOrdinal)) {
            addSparseTargetRefusal(
                refusedObjects,
                'Sparse target selected option IDs must be distinct.',
                target.targetDigest,
            );
        }
        if (seenOrderPositions.has(orderPosition)) {
            addSparseTargetRefusal(
                refusedObjects,
                'Sparse target order positions must be distinct.',
                target.targetDigest,
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
            target.targetDigest,
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
                target.targetDigest,
            );
            break;
        }
    }

    const sortedSelections = [...decodedSelections].sort(
        (left, right) => left.orderPosition - right.orderPosition,
    );

    return {
        acceptedDigests:
            refusedObjects.length === 0
                ? uniqueStrings([target.targetDigest, target.layoutDigest])
                : [],
        decodedSelections: refusedObjects.length === 0 ? sortedSelections : [],
        ok: refusedObjects.length === 0,
        refusedObjects,
        selectedOptionOrdinals:
            refusedObjects.length === 0
                ? sortedSelections.map((selection) => selection.optionOrdinal)
                : [],
        statusLabels: [],
        targetDigest:
            refusedObjects.length === 0 ? target.targetDigest : undefined,
    };
};

export const decodeSparseTopKTarget = (input: {
    readonly expectedLayoutDigest: string;
    readonly target: SparseTopKTarget;
}): SparseTopKTargetDecoding => {
    try {
        return decodeSparseTopKTargetUnchecked(input);
    } catch {
        const targetDigest = (
            input as
                | Partial<{
                      readonly target: Partial<SparseTopKTarget>;
                  }>
                | undefined
        )?.target?.targetDigest;

        return createSparseTargetDecodingFailure(targetDigest);
    }
};
