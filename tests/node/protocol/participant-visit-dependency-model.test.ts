import { describe, expect, it } from 'vitest';

import {
    compileParticipantVisitDependencyCensus,
    tracePreparationVisits,
    tracePublicationCompletionVisits,
} from '#tests/participant-visit-dependency-model.js';

describe('participant visit dependency model', () => {
    it('exhibits the missing preparation dependencies before any close work', () => {
        const visits = tracePreparationVisits(10, [0]);
        expect(visits.filter(({ participant }) => participant === 0)).toEqual([
            { participant: 0, actions: ['registration'] },
            {
                participant: 0,
                actions: ['roster-confirmation-and-seed-commitment'],
            },
            { participant: 0, actions: ['seed-opening'] },
            { participant: 0, actions: ['share-encryption-key'] },
            { participant: 0, actions: ['setup-contribution'] },
            { participant: 0, actions: ['setup-receipt'] },
            { participant: 0, actions: ['ballot-publication-attempt'] },
        ]);
        expect(compileParticipantVisitDependencyCensus()).toEqual({
            participantCount: 10,
            preparationWitnessVisitCount: 6,
            ballotAuthorWitnessVisitCount: 7,
            maximumPermittedVisitCount: 10,
            preferredVisitCount: 5,
            remainingVisitBudget: 3,
            completionWitnessVisitCount: 13,
            completionWitnessExcess: 3,
        });
    });

    it('performs all available work but never casts before every setup receipt', () => {
        // Replay the trace against independent prerequisite rules, including
        // visits that really can coalesce a receipt and a ballot.
        const prerequisites = new Map([
            ['roster-confirmation-and-seed-commitment', 'registration'],
            ['seed-opening', 'roster-confirmation-and-seed-commitment'],
            ['share-encryption-key', 'seed-opening'],
            ['setup-contribution', 'share-encryption-key'],
            ['setup-receipt', 'setup-contribution'],
            ['ballot-publication-attempt', 'setup-receipt'],
        ]);
        for (
            let participantCount = 3;
            participantCount <= 20;
            participantCount++
        ) {
            const authors = Array.from(
                { length: participantCount },
                (_, i) => i,
            );
            const completed = new Map<string, Set<number>>();
            const visits = tracePreparationVisits(participantCount, authors);
            for (const { participant, actions } of visits) {
                for (const action of actions) {
                    for (const [, prerequisite] of [...prerequisites].filter(
                        ([next]) => next === action,
                    )) {
                        expect(completed.get(prerequisite)?.size).toBe(
                            participantCount,
                        );
                    }
                    const senders = completed.get(action) ?? new Set<number>();
                    expect(senders.has(participant)).toBe(false);
                    senders.add(participant);
                    completed.set(action, senders);
                }
                for (const [next] of [...prerequisites].filter(
                    ([, prerequisite]) =>
                        completed.get(prerequisite)?.size === participantCount,
                )) {
                    expect(completed.get(next)?.has(participant)).toBe(true);
                }
            }
            expect(completed.get('ballot-publication-attempt')?.size).toBe(
                participantCount,
            );
            expect(visits.some(({ actions }) => actions.length > 1)).toBe(true);
            expect(
                visits.filter(({ participant }) => participant === 0),
            ).toHaveLength(7);
        }
    });

    it('completes preparation without requiring anyone to cast a ballot', () => {
        const visits = tracePreparationVisits(10, []);
        expect(visits.flatMap(({ actions }) => actions)).not.toContain(
            'ballot-publication-attempt',
        );
        expect(
            visits.filter(({ participant }) => participant === 0),
        ).toHaveLength(6);
    });

    it('exhibits a completing trace above the ceiling even with immediate delivery', () => {
        const visits = tracePublicationCompletionVisits();
        const first = visits.filter(({ participant }) => participant === 0);
        expect(first).toHaveLength(13);
        expect(first.slice(-4).map(({ actions }) => actions)).toEqual([
            ['close-intent', 'close-report'],
            ['target-proposal', 'target-signature'],
            ['release-share'],
            ['terminal-retrieval'],
        ]);
        // Publication work really coalesces as dependencies become available;
        // the excess is not produced by forcing one action into each visit.
        expect(first[7].actions).toContain('echo/6');
        expect(first[7].actions).toContain('ready/0');
        for (let participant = 0; participant < 7; participant++) {
            const actions = visits
                .filter((entry) => entry.participant === participant)
                .flatMap((entry) => entry.actions);
            expect(
                actions.filter((action) => action === 'target-signature'),
            ).toHaveLength(1);
            expect(
                actions.filter((action) => action === 'release-share'),
            ).toHaveLength(1);
            expect(
                actions.filter((action) => action === 'terminal-retrieval'),
            ).toHaveLength(1);
        }
        expect(
            visits
                .filter(({ participant }) => participant >= 7)
                .flatMap(({ actions }) => actions),
        ).not.toContain('target-signature');
    });
});
