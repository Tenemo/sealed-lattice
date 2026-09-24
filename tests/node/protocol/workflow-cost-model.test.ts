import { describe, expect, it } from 'vitest';

import { assessWorkflowCost } from '#tests/workflow-cost-model.js';

describe('complete workflow cost accounting', () => {
    it('does not turn an unmeasured suffix into a passing total or zero savings', () => {
        const value = assessWorkflowCost(
            [
                {
                    operation: 'preparation',
                    stage: 'prepare',
                    milliseconds: 80,
                },
                { operation: 'ballot', stage: 'vote', milliseconds: 30 },
                { operation: 'release', stage: 'release', milliseconds: null },
            ],
            100,
            90,
        );
        expect(value.measuredMilliseconds).toBe(110);
        expect(value.totalMilliseconds).toBeNull();
        expect(value.requiredSavingMilliseconds).toBeNull();
        expect(value.minimumRequiredSavingMilliseconds).toBe(10);
        expect(value.unmeasuredOperations).toEqual(['release']);
    });

    it('combines work in one visit while checking cumulative work separately', () => {
        const value = assessWorkflowCost(
            [
                { operation: 'restore', stage: 'result', milliseconds: 15 },
                { operation: 'evaluate', stage: 'result', milliseconds: 70 },
                { operation: 'certify', stage: 'result', milliseconds: 16 },
                { operation: 'retrieve', stage: 'retrieve', milliseconds: 9 },
            ],
            120,
            100,
        );
        expect(value.totalMilliseconds).toBe(110);
        expect(value.requiredSavingMilliseconds).toBe(0);
        expect(value.stages[0].measuredMilliseconds).toBe(101);
        expect(value.stages[0].exceedsVisitLimit).toBe(true);
    });

    it('charges an explicit recovery scenario without averaging or hiding its work', () => {
        const normal = [
            { operation: 'prepare', stage: 'prepare', milliseconds: 60 },
            { operation: 'publish', stage: 'prepare', milliseconds: 10 },
            { operation: 'finish', stage: 'finish', milliseconds: 20 },
        ];
        const recovery = [
            ...normal,
            { operation: 'failed-upload', stage: 'prepare', milliseconds: 8 },
            { operation: 'cold-restore', stage: 'prepare', milliseconds: 14 },
        ];
        expect(
            assessWorkflowCost(normal, 100, 80).requiredSavingMilliseconds,
        ).toBe(0);
        const value = assessWorkflowCost(recovery, 100, 80);
        expect(value.requiredSavingMilliseconds).toBe(12);
        expect(value.stages[0].exceedsVisitLimit).toBe(true);
    });

    it('rejects missing, duplicate, negative and nonfinite measurements', () => {
        expect(() => assessWorkflowCost([], 100, 80)).toThrow();
        const cost = {
            operation: 'prepare',
            stage: 'prepare',
            milliseconds: 1,
        };
        expect(() => assessWorkflowCost([cost, cost], 100, 80)).toThrow();
        for (const milliseconds of [-1, Number.NaN, Infinity])
            expect(() =>
                assessWorkflowCost([{ ...cost, milliseconds }], 100, 80),
            ).toThrow();
        expect(() =>
            assessWorkflowCost(
                [
                    { ...cost, milliseconds: Number.MAX_VALUE },
                    {
                        ...cost,
                        operation: 'finish',
                        milliseconds: Number.MAX_VALUE,
                    },
                ],
                100,
                80,
            ),
        ).toThrow();
    });
});
