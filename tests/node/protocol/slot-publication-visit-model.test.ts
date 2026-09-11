import { describe, expect, it } from 'vitest';

import { traceSlotPublicationVisits } from '#tests/slot-publication-visit-model.js';

describe('conditional slot-publication visit schedule', () => {
    it('completes missing and present slots without a separate global report wave', () => {
        const participants = Array.from({ length: 10 }, (_, index) => index);
        for (const authors of [[], [0], [1, 4], participants])
            for (let offset = 0; offset < 10; offset++) {
                const order = [
                    ...participants.slice(offset),
                    ...participants.slice(0, offset),
                ];
                const trace = traceSlotPublicationVisits(authors, order);
                expect(trace.inventory).toHaveLength(10);
                expect(new Set(trace.retrieved)).toEqual(new Set(participants));
                expect(
                    trace
                        .inventory!.filter(
                            (value) => value.classification === 'accepted',
                        )
                        .map((value) => value.author),
                ).toEqual(authors);
                expect(
                    Math.max(
                        ...trace.participantVisits.map((value) => value.count),
                    ),
                ).toBeLessThanOrEqual(9);
                expect(trace.released.length === 0).toBe(authors.length === 0);
            }
    });

    it('does not accept malformed actor orders or duplicate ballot origins', () => {
        const order = Array.from({ length: 10 }, (_, index) => index);
        expect(() => traceSlotPublicationVisits([0, 0], order)).toThrow();
        expect(() => traceSlotPublicationVisits([10], order)).toThrow();
        expect(() =>
            traceSlotPublicationVisits([], [0, ...order.slice(1, 9), 0]),
        ).toThrow();
        expect(() => traceSlotPublicationVisits([0], order, [1])).toThrow();
        expect(() => traceSlotPublicationVisits([0], order, [0, 0])).toThrow();
    });

    it('takes the no-result path when every authenticated submission is invalid', () => {
        const participants = Array.from({ length: 10 }, (_, index) => index);
        const invalid = traceSlotPublicationVisits(
            participants,
            participants,
            participants,
        );
        expect(invalid.inventory?.map((value) => value.classification)).toEqual(
            Array(10).fill('invalid'),
        );
        expect(invalid.released).toEqual([]);
        expect(invalid.retrieved).toHaveLength(10);
        expect(
            invalid.visits
                .flatMap((value) => value.actions)
                .filter((action) => action === 'verify-no-result'),
        ).toHaveLength(10);
        const mixed = traceSlotPublicationVisits([1, 4], participants, [1]);
        expect(
            mixed.inventory
                ?.filter((value) => value.classification === 'accepted')
                .map((value) => value.author),
        ).toEqual([4]);
        expect(mixed.released).toHaveLength(10);
        expect(mixed.retrieved).toHaveLength(10);
    });
});
