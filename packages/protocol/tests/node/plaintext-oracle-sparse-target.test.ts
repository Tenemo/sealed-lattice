import type {
    PlaintextTopKRankingEntry,
    SparseTopKTarget,
} from '@sealed-lattice/types';
import { describe, expect, it } from 'vitest';

import {
    mutateSparseTarget,
    sparseTargetVectors,
} from './plaintext-oracle-test-vectors';

import {
    decodeSparseTopKTarget,
    deriveSparseTopKTarget,
} from '#packages/protocol/src/plaintext-oracle/index';

describe('sparse target decoder oracle', () => {
    const validRanking = [
        {
            optionIndex: 0,
            optionOrdinal: 1,
            rank: 0,
            totalScore: 30,
        },
        {
            optionIndex: 1,
            optionOrdinal: 2,
            rank: 1,
            totalScore: 20,
        },
        {
            optionIndex: 2,
            optionOrdinal: 3,
            rank: 2,
            totalScore: 10,
        },
    ] as const satisfies readonly PlaintextTopKRankingEntry[];

    it('decodes the canonical sparse top-k target vector', () => {
        const decoding = decodeSparseTopKTarget({
            expectedLayoutHash: sparseTargetVectors.layoutHash,
            target: sparseTargetVectors.target,
        });

        expect(decoding.isValid).toBe(true);
        expect(decoding.targetHash).toBe(sparseTargetVectors.targetHash);
        expect(decoding.selectedOptionOrdinals).toEqual(
            sparseTargetVectors.expectedSelectedOptionOrdinals,
        );
        expect(decoding.refusedObjects).toEqual([]);
    });

    it.each([
        {
            caseName: 'duplicate option index',
            ranking: [
                validRanking[0],
                {
                    ...validRanking[1],
                    optionIndex: 0,
                    optionOrdinal: 1,
                },
                validRanking[2],
            ],
        },
        {
            caseName: 'duplicate rank',
            ranking: [
                validRanking[0],
                {
                    ...validRanking[1],
                    rank: 0,
                },
                validRanking[2],
            ],
        },
        {
            caseName: 'rank outside the option range',
            ranking: [
                validRanking[0],
                {
                    ...validRanking[1],
                    rank: 5,
                },
                validRanking[2],
            ],
        },
        {
            caseName: 'ordinal that does not match the option index',
            ranking: [
                validRanking[0],
                {
                    ...validRanking[1],
                    optionOrdinal: 3,
                },
                validRanking[2],
            ],
        },
    ])('rejects malformed sparse target ranking: $caseName', ({ ranking }) => {
        expect(() =>
            deriveSparseTopKTarget({
                optionCount: 3,
                ranking,
                topOptionCount: 2,
            }),
        ).toThrow('ranking');
    });

    it.each([
        {
            caseName: 'duplicate option IDs',
            overrides: {
                targetIdSlots: [1, 1, 0, 0],
                targetOrderSlots: [2, 1, 0, 0],
            },
        },
        {
            caseName: 'missing order position',
            overrides: {
                targetIdSlots: [1, 2, 0, 0],
                targetOrderSlots: [1, 0, 0, 0],
            },
        },
        {
            caseName: 'duplicate order positions',
            overrides: {
                targetIdSlots: [1, 2, 0, 0],
                targetOrderSlots: [1, 1, 0, 0],
            },
        },
        {
            caseName: 'out-of-range ordinal',
            overrides: {
                targetIdSlots: [1, 5, 0, 0],
                targetOrderSlots: [2, 1, 0, 0],
            },
        },
        {
            caseName: 'nonzero forbidden semantic slot',
            overrides: {
                forbiddenSemanticSlots: [0, 1, 0, 0],
            },
        },
        {
            caseName: 'missing forbidden semantic slots',
            overrides: {
                forbiddenSemanticSlots: [],
            },
        },
        {
            caseName: 'extra forbidden semantic slot',
            overrides: {
                forbiddenSemanticSlots: [0, 0, 0, 0, 0],
            },
        },
    ])('rejects malformed sparse target: $caseName', ({ overrides }) => {
        const mutatedTarget = mutateSparseTarget(
            sparseTargetVectors.target,
            overrides,
        );
        const decoding = decodeSparseTopKTarget({
            expectedLayoutHash: sparseTargetVectors.layoutHash,
            target: mutatedTarget,
        });

        expect(decoding.isValid).toBe(false);
        expect(decoding.refusedObjects).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'SparseTargetInvalid' }),
            ]),
        );
    });

    it('rejects a target under the wrong layout hash even when the payload is self-consistent', () => {
        const decoding = decodeSparseTopKTarget({
            expectedLayoutHash: 'wrong-layout-hash',
            target: sparseTargetVectors.target,
        });

        expect(decoding.isValid).toBe(false);
        expect(decoding.refusedObjects).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'SparseTargetInvalid' }),
            ]),
        );
    });

    it('returns a structured refusal for non-canonical target payloads', () => {
        const malformedTarget = {
            ...sparseTargetVectors.target,
            optionCount: Number.NaN,
        } satisfies SparseTopKTarget;
        const decoding = decodeSparseTopKTarget({
            expectedLayoutHash: sparseTargetVectors.layoutHash,
            target: malformedTarget,
        });

        expect(decoding.isValid).toBe(false);
        expect(decoding.refusedObjects).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'SparseTargetInvalid' }),
            ]),
        );
    });
});
