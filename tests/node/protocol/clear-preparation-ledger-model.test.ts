import { describe, expect, it } from 'vitest';

import {
    compileClearPreparationLedger,
    compileClearPreparationPollPopulations,
} from '#tests/clear-preparation-ledger-model.js';
import { deriveSupportedProfile } from '#tests/supported-profile-model.js';

function* subsets(
    population: number,
    count: number,
    start = 0,
): Generator<number[]> {
    if (count === 0) {
        yield [];
        return;
    }
    for (let first = start; first <= population - count; first++)
        for (const rest of subsets(population, count - 1, first + 1))
            yield [first, ...rest];
}

describe('clear-preparation comparison populations', () => {
    it('bounds smaller certified forks independently of the maximum roster denominator', () => {
        const honest = Array.from({ length: 10 }, (_, index) => index + 1);
        const confirmations = new Map<number, number>();
        const rosters = Array.from({ length: 5 }, (_, index) => {
            const endorsers = honest.slice(2 * index, 2 * index + 2);
            for (const owner of endorsers) confirmations.set(owner, index);
            return {
                members: [
                    0,
                    ...endorsers,
                    honest[(2 * index + 2) % honest.length],
                ],
                endorsers: [0, ...endorsers],
            };
        });
        for (const [index, roster] of rosters.entries()) {
            const faults = Math.floor((roster.members.length - 1) / 3);
            expect(new Set(roster.members).size).toBe(roster.members.length);
            expect(roster.members.filter((owner) => owner === 0)).toHaveLength(
                1,
            );
            expect(roster.endorsers).toHaveLength(
                roster.members.length - faults,
            );
            expect(
                roster.endorsers
                    .filter((owner) => owner !== 0)
                    .every((owner) => confirmations.get(owner) === index),
            ).toBe(true);
        }
        const fixed = compileClearPreparationLedger(
            deriveSupportedProfile(10, 2),
            BigInt(honest.length),
        );
        const poll = compileClearPreparationPollPopulations(10, 2, 10n);
        expect(BigInt(rosters.length)).toBeGreaterThan(
            fixed.maximumCertifiedRosters,
        );
        expect(poll.maximumCertifiedRosters).toBe(BigInt(rosters.length));
    });

    it('counts larger stalled rosters even when a smaller roster can finish', () => {
        const honest = Array.from({ length: 11 }, (_, index) => index + 1);
        const stalled = honest.slice(0, 9).map((owner, index) => ({
            author: owner,
            members: [
                0,
                12 + 2 * index,
                13 + 2 * index,
                owner,
                ...honest.filter((other) => other !== owner).slice(0, 6),
            ],
        }));
        const completing = { members: [0, 10, 11, 1], authors: [10, 11] };
        let recipientRows = 0;
        let cacheLookups = 0;
        const corruptOwners = new Set<number>();
        for (const roster of [...stalled, completing]) {
            const faults = Math.floor((roster.members.length - 1) / 3);
            const eligible = Math.max(faults + 1, 2) + faults;
            const corrupt = roster.members.filter(
                (owner) => !honest.includes(owner),
            );
            expect(new Set(roster.members).size).toBe(roster.members.length);
            expect(corrupt.length).toBeLessThanOrEqual(faults);
            const authors =
                'author' in roster ? [roster.author] : roster.authors;
            expect(
                authors.every(
                    (owner) => roster.members.indexOf(owner) < eligible,
                ),
            ).toBe(true);
            recipientRows +=
                authors.length * (roster.members.length - corrupt.length);
            cacheLookups += roster.members
                .slice(0, eligible)
                .filter((owner) => corrupt.includes(owner)).length;
            for (const owner of corrupt) corruptOwners.add(owner);
        }
        expect(
            new Set([
                ...stalled.map((roster) => roster.author),
                ...completing.authors,
            ]).size,
        ).toBe(honest.length);
        const fixed = compileClearPreparationLedger(
            deriveSupportedProfile(4, 2),
            BigInt(honest.length),
            10,
        );
        const poll = compileClearPreparationPollPopulations(
            10,
            2,
            BigInt(honest.length),
        );
        expect(BigInt(recipientRows)).toBeGreaterThan(
            fixed.maximumHonestRecipientRows,
        );
        expect(BigInt(cacheLookups)).toBeGreaterThan(
            fixed.maximumSourceCacheLookups,
        );
        expect(BigInt(corruptOwners.size)).toBeGreaterThan(
            fixed.maximumCorruptSourceExtractions,
        );
        expect(poll.maximumHonestRecipientRows).toBeGreaterThanOrEqual(
            BigInt(recipientRows),
        );
        expect(poll.maximumSourceCacheLookups).toBeGreaterThanOrEqual(
            BigInt(cacheLookups),
        );
        expect(poll.maximumCorruptSourceExtractions).toBeGreaterThanOrEqual(
            BigInt(corruptOwners.size),
        );
    });

    it('uses the minimum endorsement consumption over every permitted roster size', () => {
        for (let maximum = 3; maximum <= 20; maximum++) {
            const costs = Array.from({ length: maximum - 2 }, (_, index) => {
                const size = index + 3;
                return size - 2 * Math.floor((size - 1) / 3);
            });
            for (const population of [0n, 1n, 2n, 3n, 31n]) {
                let remaining = population;
                let packed = 0n;
                while (costs.some((cost) => BigInt(cost) <= remaining)) {
                    remaining -= BigInt(
                        [...costs].sort((left, right) => left - right)[0],
                    );
                    packed++;
                }
                const poll = compileClearPreparationPollPopulations(
                    maximum,
                    2,
                    population,
                );
                expect(poll.maximumCertifiedRosters).toBe(packed);
                expect(poll.maximumStartedPreparationRosters).toBe(population);
                expect(poll.sourceCache.requests).toBe(
                    poll.maximumSourceCacheLookups,
                );
            }
        }
        expect(() =>
            compileClearPreparationPollPopulations(2, 2, 1n),
        ).toThrow();
        expect(() =>
            compileClearPreparationPollPopulations(21, 2, 1n),
        ).toThrow();
        expect(() =>
            compileClearPreparationPollPopulations(10, 1, 1n),
        ).toThrow();
        expect(() =>
            compileClearPreparationPollPopulations(10, 2, -1n),
        ).toThrow();
    });

    it('charges every possible selected set before selection, across supported rosters', () => {
        for (let participants = 3; participants <= 20; participants++) {
            const corrupt = Math.floor((participants - 1) / 3);
            const selected = Math.max(corrupt + 1, 2);
            const eligible = selected + corrupt;
            const combinations = [...subsets(eligible, selected)];
            const row = compileClearPreparationLedger(
                deriveSupportedProfile(participants, 2),
                101n,
            );
            expect(row.selectedPositionSets).toBe(BigInt(combinations.length));
            const events =
                101n *
                BigInt(combinations.length) *
                row.sharedFheModulusGuesses;
            expect(row.fheSelectedKeyComparisons).toBe(2n * events);
            expect(row.fheBallotComparisons).toBe(events);
            expect(row.messagesPerFheBallotComparison).toBe(
                BigInt(participants),
            );
            expect(row.maximumSourceCacheLookups).toBe(101n * BigInt(corrupt));
            expect(row.sourceCache.requests).toBe(101n * BigInt(corrupt));
            expect(row.sourceCache.totalGates === 0n).toBe(corrupt === 0);
        }
    });

    it('derives honest endorsement consumption from every small quorum', () => {
        for (let participants = 3; participants <= 10; participants++) {
            const corrupt = Math.floor((participants - 1) / 3);
            let minimumHonest = participants;
            for (const quorum of subsets(participants, participants - corrupt))
                minimumHonest = Math.min(
                    minimumHonest,
                    quorum.filter((position) => position >= corrupt).length,
                );
            for (const population of [
                0,
                1,
                minimumHonest - 1,
                minimumHonest,
                29,
            ]) {
                const row = compileClearPreparationLedger(
                    deriveSupportedProfile(participants, 2),
                    BigInt(population),
                );
                // Pack disjoint endorsement sets without using an algebraic
                // division as the independent reference.
                let remaining = population;
                let certificates = 0;
                while (remaining >= minimumHonest) {
                    remaining -= minimumHonest;
                    certificates++;
                }
                expect(row.honestEndorsersPerCertificate).toBe(
                    BigInt(minimumHonest),
                );
                expect(row.maximumCertifiedRosters).toBe(BigInt(certificates));
            }
        }
    });

    it('keeps stalled and losing views outside the certified-roster denominator', () => {
        // One corrupt creator can show these six distinct four-member rosters.
        // Each honest owner confirms only its own row and publishes one offer;
        // the other named honest members need not confirm that row.
        const honest = Array.from({ length: 6 }, (_, position) => position + 1);
        const exposed = honest.map((owner, index) => ({
            owner,
            roster: [
                0,
                owner,
                honest[(index + 1) % honest.length],
                honest[(index + 2) % honest.length],
            ],
        }));
        expect(new Set(exposed.map(({ owner }) => owner)).size).toBe(6);
        expect(
            new Set(exposed.map(({ roster }) => roster.join(','))).size,
        ).toBe(6);
        expect(exposed.every(({ roster }) => new Set(roster).size === 4)).toBe(
            true,
        );
        const row = compileClearPreparationLedger(
            deriveSupportedProfile(4, 2),
            6n,
        );
        expect(row.maximumStartedPreparationRosters).toBe(
            BigInt(exposed.length),
        );
        expect(row.maximumCertifiedRosters).toBe(3n);
        expect(row.maximumStartedPreparationRosters).toBeGreaterThan(
            row.maximumCertifiedRosters,
        );
        // The all-confirmation divisor would count only two exposure scopes.
        expect(exposed.length).toBeGreaterThan(Math.floor(honest.length / 3));
        expect(row.maximumCorruptSourceExtractions).toBe(6n);
        expect(row.maximumSourceCacheLookups).toBe(6n);
    });

    it('counts abandoned registrations and every source family without adding proof roles', () => {
        const profile = deriveSupportedProfile(10, 10);
        const one = compileClearPreparationLedger(profile, 1n);
        const many = compileClearPreparationLedger(profile, 257n);
        expect(many.generatedSourceEntries).toBe(
            257n * one.generatedSourceEntries,
        );
        expect(many.sourceMaskScopes).toBe(257n * one.sourceMaskScopes);
        expect(many.sourceMaskScopes).toBeGreaterThanOrEqual(
            many.generatedSourceEntries,
        );
        expect(many.recipientKeyComparisons).toBe(514n);
        expect(many.recipientCiphertextComparisons).toBe(5140n);
        expect(many.maximumHonestProofScopes).toBe(3n * 257n);
        expect(many.auxiliaryKeyComparisons).toBe(1n);
        expect(many.auxiliaryBallotComparisons).toBe(1n);
        expect(many.messagesPerAuxiliaryBallotComparison).toBe(257n);
        expect(one.maximumHonestBallots).toBe(0n);
        expect(one.maximumHonestProofScopes).toBe(1n);
        expect(() => compileClearPreparationLedger(profile, -1n)).toThrow();
    });

    it('counts private starts before the first published offer and does not count replays twice', () => {
        // One corrupt creator shows three losing views to different honest
        // owners. Their generation fails before publication; other named
        // registrants never confirm those views. Only the last roster closes.
        const rosters = [
            [0, 1, 4, 5],
            [0, 2, 4, 5],
            [0, 3, 4, 5],
            [0, 4, 5, 6],
        ];
        const confirmations = new Map([
            [1, 0],
            [2, 1],
            [3, 2],
            [4, 3],
            [5, 3],
            [6, 3],
        ]);
        const attempts = [
            { owner: 1, roster: 0, published: false },
            { owner: 2, roster: 1, published: false },
            { owner: 3, roster: 2, published: false },
            { owner: 4, roster: 3, published: false },
            { owner: 4, roster: 3, published: true },
        ];
        for (const attempt of attempts) {
            expect(confirmations.get(attempt.owner)).toBe(attempt.roster);
            expect(
                rosters[attempt.roster].indexOf(attempt.owner),
            ).toBeGreaterThan(0);
            expect(rosters[attempt.roster].indexOf(attempt.owner)).toBeLessThan(
                3,
            );
        }
        const started = [...new Set(attempts.map((attempt) => attempt.roster))];
        const published = [
            ...new Set(
                attempts
                    .filter((attempt) => attempt.published)
                    .map((attempt) => attempt.roster),
            ),
        ];
        const winning = 3;
        expect(started.indexOf(winning) + 1).toBe(4);
        expect(published.indexOf(winning) + 1).toBe(1);
        // The losing views violate no confirmation lock; a winning quorum
        // can use two different honest owners who confirmed only its roster.
        expect(
            [4, 5].every((owner) => confirmations.get(owner) === winning),
        ).toBe(true);
        const row = compileClearPreparationLedger(
            deriveSupportedProfile(4, 2),
            BigInt(confirmations.size),
        );
        expect(BigInt(started.length)).toBeLessThanOrEqual(
            row.maximumStartedPreparationRosters,
        );
        expect(BigInt(started.length)).toBeGreaterThan(
            row.maximumCertifiedRosters,
        );
        expect(new Set(attempts.map((attempt) => attempt.owner)).size).toBe(4);
        expect(row.maximumHonestContributionScopes).toBe(6n);
        // The same corrupt original coordinate can be cached; zero early
        // public offers still does not imply zero required source extraction.
        expect(
            attempts.slice(0, 3).every((attempt) => !attempt.published),
        ).toBe(true);
        expect(row.maximumCorruptSourceExtractions).toBeGreaterThan(0n);
    });

    it('uses the original poll family inventory when the final roster is smaller', () => {
        const profile = deriveSupportedProfile(4, 10);
        const smallPoll = compileClearPreparationLedger(profile, 31n, 4);
        const largePoll = compileClearPreparationLedger(profile, 31n, 20);
        expect(largePoll.generatedSourceEntries).toBeGreaterThan(
            smallPoll.generatedSourceEntries,
        );
        expect(largePoll.sourceMaskScopes).toBe(smallPoll.sourceMaskScopes);
        expect(largePoll.maximumCertifiedRosters).toBe(
            smallPoll.maximumCertifiedRosters,
        );
        expect(largePoll.selectedPositionSets).toBe(
            smallPoll.selectedPositionSets,
        );
        expect(() => compileClearPreparationLedger(profile, 31n, 3)).toThrow();
        expect(() => compileClearPreparationLedger(profile, 31n, 21)).toThrow();
    });
});
