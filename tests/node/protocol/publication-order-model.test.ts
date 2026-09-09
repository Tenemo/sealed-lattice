import { describe, expect, it } from 'vitest';

import {
    delayedArchiveDiscoveryViews,
    orderedPublicationReference,
    publicationOriginOrderViews,
    retainPublishedValue,
    unorderedPublicationClassifications,
} from '#tests/publication-order-model.js';

describe('observable publication and non-revocation', () => {
    it('cannot recover corrupt origin order from identical authenticated views', () => {
        const [left, right] = publicationOriginOrderViews();
        expect(left.view).toEqual(right.view);
        expect(left.origins[0]).not.toEqual(right.origins[0]);
        expect(new Set(left.origins)).toEqual(new Set(right.origins));
    });

    it('exhausts the at-most-one final choices without preserving both singleton predecessors', () => {
        const outcomes = unorderedPublicationClassifications();
        expect(outcomes).toHaveLength(3);
        for (const result of outcomes)
            expect(
                result.preservesFirstSingleton &&
                    result.preservesSecondSingleton,
            ).toBe(false);
        expect(outcomes.some((result) => result.preservesFirstSingleton)).toBe(
            true,
        );
        expect(outcomes.some((result) => result.preservesSecondSingleton)).toBe(
            true,
        );
    });

    it('preserves a supplied prior publication while leaving its distributed finality unproved', () => {
        const [left] = publicationOriginOrderViews();
        const [first, second] = left.origins;
        expect(retainPublishedValue(first, second)).toEqual(first);
        expect(retainPublishedValue(second, first)).toEqual(second);
        expect(() =>
            retainPublishedValue(first, { ...second, slot: 'another-slot' }),
        ).toThrow();
    });

    it('does not turn eventual archive discovery into a complete finite close view', () => {
        const [empty, delayed] = delayedArchiveDiscoveryViews();
        expect(empty.closingView).toEqual(delayed.closingView);
        expect(empty.durableRecordsBeforeClose).not.toEqual(
            delayed.durableRecordsBeforeClose,
        );
        expect(delayed.deliveredAfterClose).toEqual(
            delayed.durableRecordsBeforeClose,
        );
    });

    it('preserves the first ordered outer publication despite later conflict and invalid proof data', () => {
        const model = orderedPublicationReference(4, 0);
        const first = model.registerFixture(3, 'first-valid', true);
        const later = model.registerFixture(3, 'later-valid', true);
        const invalid = model.registerFixture(3, 'later-invalid', false);
        expect(model.linearize(first)).toBe(true);
        expect(model.linearize(later)).toBe(false);
        expect(model.linearize(invalid)).toBe(false);
        expect(model.close(0)).toEqual({
            publications: [first],
            inventory: [
                { author: 3, identity: first, classification: 'accepted' },
            ],
        });
    });

    it('does not repair an invalid first publication with a second ballot', () => {
        const model = orderedPublicationReference(4, 0);
        const invalid = model.registerFixture(0, 'invalid-first', false);
        const replacement = model.registerFixture(0, 'valid-replacement', true);
        const other = model.registerFixture(1, 'valid-other', true);
        expect(model.linearize(invalid)).toBe(true);
        expect(model.linearize(replacement)).toBe(false);
        expect(model.linearize(other)).toBe(true);
        expect(model.close(0)!.inventory).toEqual([
            { author: 0, identity: invalid, classification: 'invalid' },
            { author: 1, identity: other, classification: 'accepted' },
        ]);
    });

    it('ignores unauthenticated and post-close input without changing an empty or nonempty cut', () => {
        const model = orderedPublicationReference(3, 0);
        expect(model.close(1)).toBeUndefined();
        expect(model.linearize('not-authenticated')).toBe(false);
        const empty = model.close(0);
        const late = model.registerFixture(0, 'late-valid', true);
        expect(model.linearize(late)).toBe(false);
        expect(model.close(0)).toEqual(empty);
        expect(empty).toEqual({ publications: [], inventory: [] });
    });
});
