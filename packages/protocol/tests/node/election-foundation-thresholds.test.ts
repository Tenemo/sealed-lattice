import type { PollSpec } from '@sealed-lattice/types';
import { describe, expect, it } from 'vitest';

import {
    deriveFrozenRosterParameters,
    deriveThresholdParameters,
    deriveThresholdParametersHash,
} from '#packages/protocol/src/index';

const rosterHash = 'b'.repeat(128);
const pollSpec = {
    maxRosterSize: 20,
    minRosterSize: 10,
    options: ['Alpha', 'Beta'],
    pollId: 'threshold-parameters-test',
    question: 'Choose one',
    scoreDomain: {
        max: 10,
        min: 1,
        skippedOptionScore: 1,
    },
    smallRosterPolicy: 'ForbidMicroRoster',
    topOptionCount: 1,
} as const satisfies PollSpec;

describe('election foundation threshold parameters', () => {
    it.each([
        { rosterSize: 3, corruptionBound: 1, activeFaultBound: 0 },
        { rosterSize: 5, corruptionBound: 1, activeFaultBound: 1 },
        { rosterSize: 6, corruptionBound: 2, activeFaultBound: 1 },
        { rosterSize: 9, corruptionBound: 3, activeFaultBound: 1 },
        { rosterSize: 10, corruptionBound: 3, activeFaultBound: 2 },
        { rosterSize: 11, corruptionBound: 3, activeFaultBound: 2 },
        { rosterSize: 16, corruptionBound: 5, activeFaultBound: 3 },
        { rosterSize: 18, corruptionBound: 6, activeFaultBound: 3 },
        { rosterSize: 20, corruptionBound: 6, activeFaultBound: 4 },
    ])(
        'derives structural counts for roster size $rosterSize',
        ({ rosterSize, corruptionBound, activeFaultBound }) => {
            expect(deriveThresholdParameters({ rosterSize })).toEqual({
                rosterSize,
                structuralCorruptionBound: corruptionBound,
                privacyCorruptionBound: corruptionBound,
                decryptionCorruptionBound: corruptionBound,
                activeFaultBound,
                ballotReleaseFloor: corruptionBound + 1,
                decryptionThreshold: corruptionBound + 1,
                releaseQuorum: rosterSize,
                maximumRaceShares: rosterSize,
                setupCompletionQuorum: rosterSize,
            });
        },
    );

    it.each([3, 4, 5, 6, 7, 8, 9, 10, 11, 16, 20])(
        'keeps structural feasibility invariants for roster size %d',
        (rosterSize) => {
            const thresholdParameters = deriveThresholdParameters({
                rosterSize,
            });

            expect(
                rosterSize - thresholdParameters.activeFaultBound,
            ).toBeGreaterThanOrEqual(thresholdParameters.decryptionThreshold);
            expect(thresholdParameters.ballotReleaseFloor).toBe(
                thresholdParameters.privacyCorruptionBound + 1,
            );
            expect(thresholdParameters.releaseQuorum).toBe(rosterSize);
            expect(thresholdParameters.maximumRaceShares).toBe(rosterSize);
            expect(thresholdParameters.setupCompletionQuorum).toBe(rosterSize);
        },
    );

    it.each([
        { rosterSize: 2, message: 'Roster size must be at least 3.' },
        { rosterSize: 3.5, message: 'Roster size must be an integer.' },
        { rosterSize: 21, message: 'Roster size must be at most 20.' },
    ])('rejects invalid roster size $rosterSize', ({ rosterSize, message }) => {
        expect(() => deriveThresholdParameters({ rosterSize })).toThrow(
            message,
        );
    });

    it('binds structural counts to the poll and frozen roster', () => {
        const frozenRosterParameters = deriveFrozenRosterParameters({
            pollSpec,
            rosterHash,
            rosterSize: 20,
        });

        expect(frozenRosterParameters.thresholdParametersHash).toBe(
            deriveThresholdParametersHash({
                maxRosterSize: pollSpec.maxRosterSize,
                minRosterSize: pollSpec.minRosterSize,
                pollSpecHash: frozenRosterParameters.pollSpecHash,
                rosterHash,
                smallRosterPolicy: pollSpec.smallRosterPolicy,
                thresholdParameters: frozenRosterParameters.thresholdParameters,
            }),
        );
        expect(
            deriveFrozenRosterParameters({
                pollSpec,
                rosterHash: 'c'.repeat(128),
                rosterSize: 20,
            }).thresholdParametersHash,
        ).not.toBe(frozenRosterParameters.thresholdParametersHash);
    });

    it.each([9, 21])(
        'rejects frozen roster size %d outside poll bounds',
        (rosterSize) => {
            expect(() =>
                deriveFrozenRosterParameters({
                    pollSpec,
                    rosterHash,
                    rosterSize,
                }),
            ).toThrow(
                'Frozen roster size must be inside the poll roster bounds.',
            );
        },
    );

    it('enforces the poll micro-roster policy', () => {
        const microRosterPollSpec = {
            ...pollSpec,
            minRosterSize: 3,
        } satisfies PollSpec;

        expect(() =>
            deriveFrozenRosterParameters({
                pollSpec: microRosterPollSpec,
                rosterHash,
                rosterSize: 3,
            }),
        ).toThrow('Poll policy forbids freezing a micro-roster.');

        expect(
            deriveFrozenRosterParameters({
                pollSpec: {
                    ...microRosterPollSpec,
                    smallRosterPolicy: 'AllowMicroRoster',
                },
                rosterHash,
                rosterSize: 3,
            }).thresholdParameters.decryptionThreshold,
        ).toBe(2);
    });
});
