import { describe, expect, it } from 'vitest';

import {
    compilePublicationCutCensus,
    createPublicationCutModel,
    type PublicationBody,
    type PublicationCutMessage,
} from '#tests/publication-cut-model.js';

const body: PublicationBody = { slot: 0, identity: 'first', validBallot: true };

const messagesOf = (
    model: ReturnType<typeof createPublicationCutModel>,
    kind: PublicationCutMessage['kind'],
) => model.messages().filter((message) => message.kind === kind);

describe('freeze-and-union publication cut model', () => {
    it('finishes the selective delivery trace that blocked wait-before-close', () => {
        for (let count = 3; count <= 20; count++) {
            const corruptCount = Math.floor((count - 1) / 3);
            const honestCount = count - corruptCount;
            const model = createPublicationCutModel(
                count,
                Array.from({ length: corruptCount }, (_, i) => honestCount + i),
            );
            for (let sender = 0; sender < honestCount; sender++)
                model.echo(sender, body);
            for (const echo of messagesOf(model, 'echo'))
                model.receive(0, echo);
            expect(messagesOf(model, 'ready')).toHaveLength(1);
            const reports = Array.from({ length: honestCount }, (_, sender) =>
                model.freeze(sender),
            );
            expect(model.inventory(reports)).toEqual([body]);
            // Eventual delivery creates no additional signature or wait lock.
            for (let recipient = 0; recipient < honestCount; recipient++)
                for (const message of model.messages())
                    expect(model.receive(recipient, message)).toBe(true);
            expect(messagesOf(model, 'ready')).toHaveLength(1);
            expect(model.inventory(reports)).toEqual([body]);
        }
    });

    it('includes completed publication despite every corrupt omission', () => {
        const model = createPublicationCutModel(10, [0, 1, 2]);
        for (let sender = 0; sender < 10; sender++) model.echo(sender, body);
        for (let recipient = 3; recipient < 10; recipient++)
            for (const echo of messagesOf(model, 'echo'))
                model.receive(recipient, echo);
        expect(messagesOf(model, 'ready')).toHaveLength(7);
        const reports = Array.from({ length: 10 }, (_, sender) =>
            model.freeze(sender),
        );
        const cuts = Array.from({ length: 1 << 10 }, (_, mask) =>
            reports.filter((_report, i) => (mask & (1 << i)) !== 0),
        ).filter((selected) => selected.length === 7);
        expect(cuts).toHaveLength(120);
        for (const selected of cuts)
            expect(model.inventory(selected)).toEqual([body]);
    });

    it('retains published invalid submissions while classifying them separately', () => {
        const model = createPublicationCutModel(4, [3]);
        const invalid = {
            slot: 2,
            identity: 'invalid proof',
            validBallot: false,
        };
        for (const envelope of [invalid, body])
            for (let sender = 0; sender < 3; sender++)
                model.echo(sender, envelope);
        for (let recipient = 0; recipient < 3; recipient++)
            for (const echo of messagesOf(model, 'echo'))
                model.receive(recipient, echo);
        const inventory = model.inventory([0, 1, 2].map(model.freeze));
        expect(inventory).toEqual([body, invalid]);
        expect(inventory?.filter(({ validBallot }) => validBallot)).toEqual([
            body,
        ]);
    });

    it('makes the unfinished-publication distinction observable', () => {
        const model = createPublicationCutModel(4, [3]);
        for (let sender = 0; sender < 3; sender++) model.echo(sender, body);
        for (const echo of messagesOf(model, 'echo')) model.receive(0, echo);
        const reports = [0, 1, 2, 3].map(model.freeze);
        expect(model.inventory([reports[0], reports[1], reports[2]])).toEqual([
            body,
        ]);
        expect(model.inventory([reports[1], reports[2], reports[3]])).toEqual(
            [],
        );
        // Neither alternative can omit a completed READY quorum: only one
        // READY exists. A finality protocol must still select one exact cut.
        expect(messagesOf(model, 'ready')).toHaveLength(1);
    });

    it('prevents an omitted in-flight body from completing after the cut', () => {
        const model = createPublicationCutModel(4, [3]);
        for (let sender = 0; sender < 4; sender++) model.echo(sender, body);
        const reports = [0, 1, 3].map(model.freeze);
        expect(model.inventory(reports)).toEqual([]);
        for (let recipient = 0; recipient < 4; recipient++)
            for (const echo of messagesOf(model, 'echo'))
                model.receive(recipient, echo);
        // Even adding the corrupt party's READY cannot reach the threshold.
        expect(messagesOf(model, 'ready')).toHaveLength(1);
        expect(messagesOf(model, 'ready').length + 1).toBeLessThan(
            model.quorum,
        );
    });

    it('refuses forged reports, duplicate voters, changed evidence, and late echo', () => {
        const model = createPublicationCutModel(4, [3]);
        for (let sender = 0; sender < 3; sender++) model.echo(sender, body);
        for (const echo of messagesOf(model, 'echo')) model.receive(0, echo);
        const reports = [0, 1, 2].map(model.freeze);
        const stripped = { ...reports[0], certificates: [] };
        expect(
            model.inventory([stripped, reports[1], reports[2]]),
        ).toBeUndefined();
        expect(
            model.inventory([reports[0], reports[0], reports[2]]),
        ).toBeUndefined();
        const ready = messagesOf(model, 'ready')[0];
        expect(
            model.receive(1, {
                ...ready,
                certificates: [{ body, signers: [0, 0, 1] }],
            }),
        ).toBe(false);
        expect(model.echo(1, { ...body, slot: 1 })).toBeUndefined();
        expect(model.inventory(reports)).toEqual([body]);
    });

    it('cannot certify two equivocations using the corrupt echoes twice', () => {
        const model = createPublicationCutModel(4, [3]);
        const other = { ...body, identity: 'conflicting' };
        model.echo(0, body);
        model.echo(1, body);
        model.echo(2, other);
        model.echo(3, body);
        model.echo(3, other);
        expect(model.echo(0, other)).toBeUndefined();
        for (let recipient = 0; recipient < 3; recipient++)
            for (const echo of messagesOf(model, 'echo'))
                model.receive(recipient, echo);
        expect(
            messagesOf(model, 'ready').map(
                ({ certificates }) => certificates[0].body,
            ),
        ).toEqual([body, body, body]);
    });

    it('checks all named publication, freeze, and corruption intersections', () => {
        expect(compilePublicationCutCensus()).toEqual({
            participantCount: 10,
            corruptionBound: 3,
            quorum: 7,
            checkedIntersections: 120 ** 3,
            minimumHonestPublicationReporters: 1,
        });
    });
});
