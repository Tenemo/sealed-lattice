import { describe, expect, it } from 'vitest';

import {
    compileFixedPublicationWitnessCensus,
    fixedPublicationWitnesses,
    traceFixedPublicationWitnessVisits,
} from '#tests/fixed-publication-witness-model.js';

describe('fixed publication witnesses', () => {
    it('balances the smallest fixed sets containing an honest signer', () => {
        for (let participants = 3; participants <= 20; participants++) {
            const value = fixedPublicationWitnesses(participants);
            const corruptLimit = Math.floor((participants - 1) / 3);
            expect(value.minimumWitnesses).toBe(corruptLimit + 1);
            expect(value.assignments).toEqual(
                Array(participants).fill(corruptLimit + 1),
            );
            for (const [author, committee] of value.committees.entries()) {
                expect(new Set(committee).size).toBe(committee.length);
                expect(committee).toContain(author);
                expect(committee.length).toBeGreaterThan(corruptLimit);
            }
        }
    });

    it('finishes every publication and terminal without idle or recovery visits', () => {
        const trace = traceFixedPublicationWitnessVisits();
        for (const [author, committee] of trace.committees.entries())
            expect(new Set(trace.witnessed[author])).toEqual(
                new Set(committee),
            );
        const everyone = new Set(
            Array.from({ length: 10 }, (_, index) => index),
        );
        for (const completed of [
            trace.closed,
            trace.certified,
            trace.released,
            trace.retrieved,
        ])
            expect(new Set(completed)).toEqual(everyone);
        for (const visit of trace.visits)
            expect(visit.actions.length).toBeGreaterThan(0);
    });

    it('exceeds the visit ceiling even with one witness wave and an ideal close', () => {
        const value = compileFixedPublicationWitnessCensus();
        expect(value.firstParticipantActions).toEqual([
            ['registration-and-recipient-key'],
            ['roster-confirmation-and-setup-commitment'],
            ['setup-opening'],
            ['ballot-origin', 'witness-ballot-0'],
            ['witness-ballot-7'],
            ['witness-ballot-8'],
            ['witness-ballot-9'],
            ['close-evidence'],
            ['evaluate-and-certify-target'],
            ['release-share'],
            ['verify-terminal'],
        ]);
        expect(value.participantVisits[0]).toBe(11);
    });

    it('preserves the target and release dependencies in the completing trace', () => {
        const trace = traceFixedPublicationWitnessVisits();
        const closed = new Set<number>();
        const certified = new Set<number>();
        const released = new Set<number>();
        const retrieved = new Set<number>();
        const violations: string[] = [];
        const require = (condition: boolean, reason: string): void => {
            if (!condition) violations.push(reason);
        };
        let firstParticipantReleasePrefix: number | undefined;
        for (const visit of trace.visits)
            for (const action of visit.actions) {
                if (action === 'close-evidence') {
                    require(!closed.has(visit.participant), 'repeated close');
                    closed.add(visit.participant);
                } else if (action === 'evaluate-and-certify-target') {
                    require(closed.size === 10, 'target before close evidence');
                    require(!certified.has(
                        visit.participant,
                    ), 'repeated target');
                    certified.add(visit.participant);
                } else if (action === 'release-share') {
                    require(certified.size >=
                        7, 'release before target quorum');
                    require(!released.has(
                        visit.participant,
                    ), 'repeated release');
                    released.add(visit.participant);
                    if (visit.participant === 0)
                        firstParticipantReleasePrefix = released.size;
                } else if (action === 'verify-terminal') {
                    require(released.size >=
                        4, 'terminal before release threshold');
                    require(!retrieved.has(
                        visit.participant,
                    ), 'repeated terminal');
                    retrieved.add(visit.participant);
                }
            }
        expect(firstParticipantReleasePrefix).toBe(2);
        expect(violations).toEqual([]);
        expect(retrieved.size).toBe(10);
    });
});
