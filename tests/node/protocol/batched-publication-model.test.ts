import { describe, expect, it } from 'vitest';

import {
    compileBatchedPublicationVisitCensus,
    createBatchedPublicationModel,
} from '#tests/batched-publication-model.js';

const body = { slot: 0, identity: 'first envelope', validBallot: true };

const requireMessage = <Message>(message: Message | undefined): Message => {
    if (message === undefined)
        throw new Error('Expected the model to emit a message.');
    return message;
};

describe('close-triggered batched publication', () => {
    it('allows a corrupt reporter to sign valid predecessors without following honest local stages', () => {
        const model = createBatchedPublicationModel(4, [3]);
        model.submit(body);
        const batches = [0, 1, 2].map((sender) =>
            requireMessage(model.witnessBatch(sender, [body])),
        );
        const corruptReport = requireMessage(model.report(3, batches));
        expect(model.supportedBodies(corruptReport)).toEqual([body]);
    });

    it('prevents a newly originated envelope from gaining support after the first valid report', () => {
        for (let count = 3; count <= 20; count++) {
            const bound = Math.floor((count - 1) / 3);
            const model = createBatchedPublicationModel(
                count,
                Array.from({ length: bound }, (_, position) => position),
            );
            const firstBatches = Array.from(
                { length: model.quorum },
                (_, sender) => requireMessage(model.witnessBatch(sender, [])),
            );
            const firstReport = requireMessage(
                model.report(bound, firstBatches),
            );
            const late = {
                ...body,
                slot: 0,
                identity: 'originated after the first report',
            };
            expect(model.submit(late)).toBe(bound > 0);
            const latest = Array.from({ length: count }, (_, sender) =>
                requireMessage(
                    model.witnessBatch(sender, [late]) ?? firstBatches[sender],
                ),
            );
            const endorsements = latest.filter(
                (batch) => batch.bodies.length > 0,
            );
            expect(endorsements.length).toBeLessThan(model.quorum);
            const reports = Array.from({ length: count }, (_, sender) =>
                requireMessage(
                    model.report(sender, latest) ??
                        (sender === bound ? firstReport : undefined),
                ),
            );
            for (const report of reports)
                expect(model.supportedBodies(report)).toEqual([]);
            expect(model.inventory(reports.slice(0, model.quorum))).toEqual([]);
        }
    });

    it('finishes valid, invalid, and empty inventories while corrupt parties refuse', () => {
        for (let count = 3; count <= 20; count++) {
            for (const bodies of [
                [],
                [body],
                [
                    body,
                    {
                        slot: 1,
                        identity: 'bad inner proof',
                        validBallot: false,
                    },
                ],
            ]) {
                const bound = Math.floor((count - 1) / 3);
                const honest = Array.from(
                    { length: count - bound },
                    (_, position) => position,
                );
                const model = createBatchedPublicationModel(
                    count,
                    Array.from(
                        { length: bound },
                        (_, position) => count - bound + position,
                    ),
                );
                for (const envelope of bodies)
                    expect(model.submit(envelope)).toBe(true);
                const witnesses = honest.map((sender) =>
                    requireMessage(model.witnessBatch(sender, bodies)),
                );
                const reports = honest.map((sender) =>
                    requireMessage(model.report(sender, witnesses)),
                );
                expect(model.inventory(reports)).toEqual(bodies);
                for (const report of reports)
                    expect(model.supportedBodies(report)).toEqual(bodies);
            }
        }
    });

    it('never emits another honest batch for separately delivered envelopes', () => {
        const model = createBatchedPublicationModel(10, [7, 8, 9]);
        const bodies = Array.from({ length: 7 }, (_, slot) => ({
            ...body,
            slot,
            identity: `envelope ${String(slot)}`,
        }));
        for (const envelope of bodies) model.submit(envelope);
        const first = requireMessage(model.witnessBatch(0, [bodies[0]]));
        for (const envelope of bodies.slice(1))
            expect(model.witnessBatch(0, [envelope])).toBeUndefined();
        const rest = [1, 2, 3, 4, 5, 6].map((sender) =>
            requireMessage(model.witnessBatch(sender, bodies)),
        );
        const report = requireMessage(model.report(0, [first, ...rest]));
        expect(model.supportedBodies(report)).toEqual([bodies[0]]);
        expect(model.report(0, [first, ...rest])).toBeUndefined();
        // Late bytes do not create another stage or replace the signed snapshot.
        expect(model.submit({ ...body, identity: 'second attempt' })).toBe(
            false,
        );
    });

    it('preserves every completed publication in every quorum cut', () => {
        const model = createBatchedPublicationModel(10, [7, 8, 9]);
        model.submit(body);
        const batches = Array.from({ length: 10 }, (_, sender) =>
            requireMessage(
                model.witnessBatch(sender, sender < 7 ? [body] : []),
            ),
        );
        const reports = Array.from({ length: 10 }, (_, sender) =>
            requireMessage(
                model.report(
                    sender,
                    sender < 7 ? batches.slice(0, 7) : batches.slice(3),
                ),
            ),
        );
        expect(
            reports.filter(
                (report) => model.supportedBodies(report)?.length === 1,
            ),
        ).toHaveLength(7);
        const cuts = Array.from({ length: 1 << 10 }, (_, mask) =>
            reports.filter((_report, index) => (mask & (1 << index)) !== 0),
        ).filter((selected) => selected.length === 7);
        for (const selected of cuts)
            expect(model.inventory(selected)).toEqual([body]);
    });

    it('exposes pending-operation extension without claiming all report quorums agree', () => {
        const model = createBatchedPublicationModel(4, [3]);
        model.submit(body);
        const witnesses = [0, 1, 2, 3].map((sender) =>
            requireMessage(
                model.witnessBatch(sender, sender === 3 ? [] : [body]),
            ),
        );
        const reports = [0, 1, 2, 3].map((sender) =>
            requireMessage(
                model.report(
                    sender,
                    sender === 0 ? witnesses.slice(0, 3) : witnesses.slice(1),
                ),
            ),
        );
        expect(model.inventory(reports.slice(0, 3))).toEqual([body]);
        expect(model.inventory(reports.slice(1))).toEqual([]);
        expect(
            reports.filter(
                (report) => model.supportedBodies(report)?.length === 1,
            ),
        ).toHaveLength(1);
        expect(model.report(1, witnesses)).toBeUndefined();
    });

    it('exposes organizer selection of an individual honest ballot before any target lock', () => {
        for (let count = 4; count <= 20; count++) {
            const bound = Math.floor((count - 1) / 3);
            const model = createBatchedPublicationModel(
                count,
                Array.from(
                    { length: bound },
                    (_, index) => count - bound + index,
                ),
            );
            const retained = { ...body, slot: 1, identity: 'always included' };
            expect(model.submit(body)).toBe(true);
            expect(model.submit(retained)).toBe(true);
            const batches = Array.from({ length: count }, (_, sender) =>
                requireMessage(
                    model.witnessBatch(
                        sender,
                        sender < model.quorum ? [body, retained] : [retained],
                    ),
                ),
            );
            const reports = Array.from({ length: count }, (_, sender) =>
                requireMessage(
                    model.report(
                        sender,
                        sender === 0
                            ? batches.slice(0, model.quorum)
                            : batches.slice(-model.quorum),
                    ),
                ),
            );
            // The same authenticated prefix, ballot origins, close intent,
            // and delivery schedule permit either organizer proposal.
            const included = model.inventory(reports.slice(0, model.quorum));
            const omitted = model.inventory(reports.slice(1, model.quorum + 1));
            expect(included).toEqual([body, retained]);
            expect(omitted).toEqual([retained]);
            expect(
                reports.filter((report) =>
                    model
                        .supportedBodies(report)
                        ?.some(({ slot }) => slot === 0),
                ),
            ).toHaveLength(1);
            // No target signature exists in this model. A later one-target
            // lock cannot make either first proposal fail these cut checks.
        }
    });

    it('ignores forged ballots and refuses changed or duplicate predecessor batches', () => {
        const model = createBatchedPublicationModel(4, [3]);
        model.submit(body);
        const witnesses = [0, 1, 2].map((sender) =>
            requireMessage(
                model.witnessBatch(sender, [body, { ...body, slot: 1 }]),
            ),
        );
        expect(witnesses[0].bodies).toEqual([body]);
        expect(
            model.report(0, [witnesses[0], witnesses[0], witnesses[2]]),
        ).toBeUndefined();
        expect(
            model.report(0, [
                { ...witnesses[0], bodies: [] },
                witnesses[1],
                witnesses[2],
            ]),
        ).toBeUndefined();
        const reports = [0, 1, 2].map((sender) =>
            requireMessage(model.report(sender, witnesses)),
        );
        expect(
            model.inventory([
                { ...reports[0], witnessBatches: [] },
                reports[1],
                reports[2],
            ]),
        ).toBeUndefined();
        expect(
            model.inventory([reports[0], reports[0], reports[2]]),
        ).toBeUndefined();
        expect(model.inventory(reports)).toEqual([body]);
    });

    it('does not certify both values of an equivocating corrupt author', () => {
        const model = createBatchedPublicationModel(4, [3]);
        const first = { ...body, slot: 3 };
        const second = { ...first, identity: 'other envelope' };
        model.submit(first);
        model.submit(second);
        const left = requireMessage(model.witnessBatch(0, [first]));
        const middle = requireMessage(model.witnessBatch(1, [first]));
        const right = requireMessage(model.witnessBatch(2, [second]));
        const corruptLeft = requireMessage(model.witnessBatch(3, [first]));
        const corruptRight = requireMessage(model.witnessBatch(3, [second]));
        expect(
            model.supportedBodies(
                requireMessage(model.report(0, [left, middle, corruptLeft])),
            ),
        ).toEqual([first]);
        expect(
            model.supportedBodies(
                requireMessage(model.report(1, [left, right, corruptRight])),
            ),
        ).toEqual([]);
    });

    it('counts at most one batch per participant and purpose', () => {
        const census = compileBatchedPublicationVisitCensus();
        expect(new Set(census.stages).size).toBe(census.stages.length);
        expect(census.maximumParticipantStages).toBe(9);
        expect(census.maximumNoResultStages).toBe(8);
    });
});
