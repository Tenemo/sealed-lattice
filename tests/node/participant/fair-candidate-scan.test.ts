import { describe, expect, it } from 'vitest';

import { scanCandidatesFairly } from '#packages/sdk/src/participant/worker/relay/candidates.js';

// Discovery lists of named candidates by author position, in position order.
const lists = (entries: Record<number, readonly string[]>) =>
    new Map(
        Object.entries(entries).map(
            ([position, candidates]) =>
                [
                    Number(position),
                    (async function* () {
                        await Promise.resolve();
                        yield* candidates;
                    })(),
                ] as const,
        ),
    );

describe('fair candidate scan', () => {
    it('visits one candidate of every list per round and drops exhausted lists', async () => {
        const visits: string[] = [];
        let rounds = 0;
        const result = await scanCandidatesFairly(
            lists({ 0: ['a0', 'a1', 'a2'], 1: ['b0'], 2: ['c0', 'c1'] }),
            (_position, candidate) => {
                visits.push(candidate);
                return Promise.resolve(false);
            },
            () => undefined,
            () => {
                rounds++;
                return Promise.resolve();
            },
        );
        expect(result).toBeUndefined();
        expect(visits).toEqual(['a0', 'b0', 'c0', 'a1', 'c1', 'a2']);
        // The fourth round only finds the last list exhausted.
        expect(rounds).toBe(4);
    });

    it('reaches a later author first in the opening round however long an earlier list is', async () => {
        const visits: string[] = [];
        const flooded = Array.from({ length: 1000 }, (_, index) =>
            String(index),
        );
        let accepted: string | undefined;
        const result = await scanCandidatesFairly(
            lists({ 0: flooded, 1: ['valid'] }),
            (_position, candidate) => {
                visits.push(candidate);
                if (candidate === 'valid') accepted = candidate;
                return Promise.resolve(candidate === 'valid');
            },
            () => accepted,
        );
        expect(result).toBe('valid');
        expect(visits).toEqual(['0', 'valid']);
    });

    it('retires a position whose visit succeeds and ends mid-round on a result', async () => {
        const visits: string[] = [];
        let rounds = 0;
        let retired = 0;
        const result = await scanCandidatesFairly(
            lists({ 0: ['a0', 'a1', 'a2'], 1: ['b0', 'b1'], 2: ['c0', 'c1'] }),
            (position, candidate) => {
                visits.push(candidate);
                const retires = position === 1 || candidate === 'a1';
                if (retires) retired++;
                return Promise.resolve(retires);
            },
            () => (retired === 2 ? retired : undefined),
            () => {
                rounds++;
                return Promise.resolve();
            },
        );
        expect(result).toBe(2);
        // The second author is retired after its first candidate, and the
        // scan ends before the third author's second candidate.
        expect(visits).toEqual(['a0', 'b0', 'c0', 'a1']);
        expect(rounds).toBe(1);
    });

    it('returns a result that holds before any visit and keeps scanning after a round without one', async () => {
        const visits: string[] = [];
        expect(
            await scanCandidatesFairly(
                lists({ 0: ['a0'] }),
                (_position, candidate) => {
                    visits.push(candidate);
                    return Promise.resolve(false);
                },
                () => 'ready',
            ),
        ).toBe('ready');
        expect(visits).toEqual([]);
        let prepared: string | undefined;
        expect(
            await scanCandidatesFairly(
                lists({ 0: ['a0', 'a1'], 1: ['b0', 'b1'] }),
                (_position, candidate) => {
                    visits.push(candidate);
                    return Promise.resolve(false);
                },
                () => prepared,
                () => {
                    prepared = 'after the first round';
                    return Promise.resolve();
                },
            ),
        ).toBe('after the first round');
        expect(visits).toEqual(['a0', 'b0']);
    });
});
