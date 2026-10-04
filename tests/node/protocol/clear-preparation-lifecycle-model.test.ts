import { describe, expect, it } from 'vitest';

import { ClearPreparationLifecycleModel } from '#tests/clear-preparation-lifecycle-model.js';
import { compileSetupSelectionCensus } from '#tests/setup-selection-model.js';

const roster = '31'.repeat(64);
const offer = (position: number) => ({
    position,
    bodyIdentity: (position + 1).toString(16).padStart(2, '0').repeat(64),
});
const completeOffer = (
    model: ClearPreparationLifecycleModel,
    position: number,
) => {
    expect(model.beginOwnOffer(position)).toBe(true);
    for (let phase = 5; phase <= 9; phase++)
        expect(model.advanceOwnOffer(position)).toBe(true);
    expect(model.acceptVerifiedOffer(offer(position))).toBe(true);
    expect(model.publishOffer(offer(position))).toBe(true);
};
const endorse = (
    model: ClearPreparationLifecycleModel,
    position: number,
    selected: number[],
) => {
    expect(model.lockEndorsement(position, selected.map(offer))).toBe(true);
    const intended = model.snapshot(position);
    expect(model.restart(position)).toBe(true);
    expect(model.lockEndorsement(position, selected.map(offer))).toBe(true);
    expect(model.snapshot(position)).toEqual(intended);
    expect(model.publishEndorsement(position)).toBe(true);
    const signed = model.snapshot(position);
    expect(model.lockEndorsement(position, selected.map(offer))).toBe(true);
    expect(model.snapshot(position)).toEqual(signed);
    expect(signed.required.some(([name]) => name === 'endorsement-coins')).toBe(
        false,
    );
};

describe('clear preparation lifecycle under original custody', () => {
    it.each(Array.from({ length: 18 }, (_, index) => index + 3))(
        'finishes after eligible honest departures before any setup message at n=%i',
        (participants) => {
            const profile = compileSetupSelectionCensus(participants);
            const corrupt = Array.from(
                { length: profile.faultBound },
                (_, index) => index,
            );
            const missing = Array.from(
                { length: profile.faultBound },
                (_, index) => profile.faultBound + index,
            );
            const model = new ClearPreparationLifecycleModel(
                participants,
                roster,
                corrupt,
            );
            missing.forEach((position) => model.disappear(position));
            const continuers = Array.from(
                { length: participants },
                (_, index) => index,
            ).filter((position) => !missing.includes(position));
            continuers.forEach((position) =>
                expect(model.confirm(position)).toBe(true),
            );
            const selected = continuers
                .filter((position) => position < profile.eligibleCount)
                .slice(0, profile.selectedCount);
            expect(selected).toHaveLength(profile.selectedCount);
            selected.forEach((position) => completeOffer(model, position));
            expect(model.propose(selected.map(offer))).toBe(true);
            continuers.forEach((position) =>
                endorse(model, position, selected),
            );
            const certificate = {
                selected: selected.map(offer),
                signers: continuers,
            };
            expect(model.publishCertificate(certificate)).toBe(true);
            for (const position of continuers) {
                expect(model.activate(position, certificate)).toBe(true);
                expect(model.snapshot(position).generation).toBe(12);
            }
            expect(
                new Set(
                    continuers.map(
                        (position) => model.snapshot(position).setup,
                    ),
                ).size,
            ).toBe(1);
            // C and U are disjoint here; cooperative corrupt participants
            // count among continuers while honest failures consume U.
            expect(
                missing.every((position) => !corrupt.includes(position)),
            ).toBe(true);
        },
    );

    it.each([4, 5, 6, 7, 8, 9])(
        'endorses beside original own phase %i and retires it only after published certification',
        (phase) => {
            const model = new ClearPreparationLifecycleModel(4, roster);
            for (let position = 0; position < 4; position++)
                expect(model.confirm(position)).toBe(true);
            completeOffer(model, 0);
            completeOffer(model, 1);
            expect(model.beginOwnOffer(2)).toBe(true);
            for (let next = 5; next <= phase; next++)
                expect(model.advanceOwnOffer(2)).toBe(true);
            const before = model.snapshot(2);
            for (let restart = 0; restart < 12; restart++)
                expect(model.restart(2)).toBe(true);
            expect(model.snapshot(2)).toEqual(before);
            expect(model.propose([offer(0), offer(1)])).toBe(true);
            for (const position of [0, 1, 2]) endorse(model, position, [0, 1]);
            const certificate = {
                selected: [offer(0), offer(1)],
                signers: [0, 1, 2],
            };
            expect(model.activate(2, certificate)).toBe(false);
            expect(model.snapshot(2).ownPhase).toBe(phase);
            expect(model.publishCertificate(certificate)).toBe(true);
            model.disappear(0);
            model.disappear(1);
            // Published bodies/certificate remain retrievable without authors.
            expect(model.activate(2, certificate)).toBe(true);
            const after = model.snapshot(2);
            expect(after.generation).toBe(12);
            expect(after.ownPhase).toBeUndefined();
            expect(
                after.required.some(
                    ([name]) =>
                        name.startsWith('own-') || name.startsWith('source-'),
                ),
            ).toBe(false);
            expect(model.beginOwnOffer(2)).toBe(false);
            expect(model.lockEndorsement(2, [offer(1), offer(2)])).toBe(false);
        },
    );

    it('accepts a winning certificate after a losing endorsement without granting another endorsement', () => {
        const model = new ClearPreparationLifecycleModel(4, roster, [0]);
        for (let position = 0; position < 4; position++)
            model.confirm(position);
        for (const position of [0, 1, 2]) completeOffer(model, position);
        expect(model.propose([offer(1), offer(2)])).toBe(true);
        endorse(model, 3, [1, 2]);
        const locked = model.snapshot(3).endorsement;
        expect(model.propose([offer(0), offer(1)])).toBe(true);
        expect(model.lockEndorsement(3, [offer(0), offer(1)])).toBe(false);
        for (const position of [0, 1, 2]) endorse(model, position, [0, 1]);
        const certificate = {
            selected: [offer(0), offer(1)],
            signers: [0, 1, 2],
        };
        expect(model.publishCertificate(certificate)).toBe(true);
        expect(model.activate(3, certificate)).toBe(true);
        expect(model.snapshot(3).endorsement).toBe(locked);
        expect(model.snapshot(3).setup).not.toBe(locked);
    });

    it.each(['missing', 'changed', 'extra'] as const)(
        'stops on %s required local state before retiring excluded work',
        (damage) => {
            const model = new ClearPreparationLifecycleModel(4, roster);
            for (let position = 0; position < 4; position++)
                model.confirm(position);
            completeOffer(model, 0);
            completeOffer(model, 1);
            model.beginOwnOffer(2);
            model.advanceOwnOffer(2);
            model.propose([offer(0), offer(1)]);
            for (const position of [0, 1, 3]) endorse(model, position, [0, 1]);
            const certificate = {
                selected: [offer(0), offer(1)],
                signers: [0, 1, 3],
            };
            expect(model.publishCertificate(certificate)).toBe(true);
            model.damage(
                2,
                damage === 'extra' ? 'unreferenced-record' : 'own-phase-5',
                damage,
            );
            expect(model.activate(2, certificate)).toBe(false);
            expect(model.snapshot(2).stopped).toBe(true);
            expect(model.snapshot(2).generation).toBe(4);
            expect(
                model
                    .snapshot(2)
                    .required.some(([name]) => name === 'source-capsule'),
            ).toBe(true);
            expect(model.restart(2)).toBe(false);
        },
    );

    it('requires complete selected inputs and exact distinct endorsement carriers', () => {
        const model = new ClearPreparationLifecycleModel(4, roster);
        for (let position = 0; position < 4; position++)
            model.confirm(position);
        completeOffer(model, 0);
        expect(model.propose([offer(0), offer(1)])).toBe(false);
        expect(model.lockEndorsement(2, [offer(0), offer(1)])).toBe(false);
        completeOffer(model, 1);
        model.propose([offer(0), offer(1)]);
        for (let position = 0; position < 4; position++)
            endorse(model, position, [0, 1]);
        for (const signers of [
            [0, 1],
            [0, 1, 1],
            [1, 0, 2],
            [0, 1, 4],
            [0, 1, 2, 3],
        ])
            expect(
                model.verifyCertificate({
                    selected: [offer(0), offer(1)],
                    signers,
                }),
            ).toBeUndefined();
        const first = model.verifyCertificate({
            selected: [offer(0), offer(1)],
            signers: [0, 1, 2],
        });
        const second = model.verifyCertificate({
            selected: [offer(0), offer(1)],
            signers: [1, 2, 3],
        });
        expect(first).toBeDefined();
        expect(second).toBe(first);
    });
    it('cannot activate from a collector-only body copy before complete dependency publication', () => {
        const model = new ClearPreparationLifecycleModel(4, roster);
        for (let position = 0; position < 4; position++)
            model.confirm(position);
        for (const position of [0, 1])
            model.acceptLocallyVerifiedOffer(offer(position));
        model.propose([offer(0), offer(1)]);
        for (const position of [0, 1, 2]) endorse(model, position, [0, 1]);
        const certificate = {
            selected: [offer(0), offer(1)],
            signers: [0, 1, 2],
        };
        expect(model.verifyCertificate(certificate)).toBeDefined();
        expect(model.publishCertificate(certificate)).toBe(false);
        expect(model.activate(3, certificate)).toBe(false);
        model.publishOffer(offer(0));
        expect(model.publishCertificate(certificate)).toBe(false);
        model.publishOffer(offer(1));
        expect(model.publishCertificate(certificate)).toBe(true);
        expect(model.activate(3, certificate)).toBe(true);
    });
});
