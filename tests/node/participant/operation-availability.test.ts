import { describe, expect, it } from 'vitest';

import type { ParticipantStage } from '#packages/sdk/src/participant/worker/operation-availability.js';
import { isOperationAvailable } from '#packages/sdk/src/participant/worker/operation-availability.js';

// Every generation a completed participant root can hold.
const generations = [
    1, 2, 3, 4, 12, 13, 14, 15, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 29,
];

// The generations at which the operation may start, for a joiner whose
// retained roster names its profile unless the stage says otherwise.
const availableAt = (
    operation: string,
    stage: Partial<Omit<ParticipantStage, 'generation'>> = {},
) =>
    generations.filter((generation) =>
        isOperationAvailable(operation, {
            generation,
            isOrganizer: false,
            hasProfile: generation >= 2,
            isEligibleContributor: false,
            spentTargetVote: false,
            ...stage,
        }),
    );

describe('participant operation availability', () => {
    it('opens roster confirmation and setup work at their generations and roles', () => {
        expect(availableAt('confirm')).toEqual([3, 4]);
        expect(availableAt('contribute')).toEqual([]);
        expect(
            availableAt('contribute', { isEligibleContributor: true }),
        ).toEqual([4]);
        expect(availableAt('select-setup')).toEqual([]);
        expect(availableAt('select-setup', { isOrganizer: true })).toEqual([4]);
        expect(availableAt('endorse-setup')).toEqual([4]);
        expect(availableAt('verify-setup')).toEqual([4]);
        expect(availableAt('verify-setup', { hasProfile: false })).toEqual([]);
    });

    it('opens the ballot and the close from the retained setup', () => {
        const fromSetup = [
            12, 13, 14, 15, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 29,
        ];
        for (const operation of ['cast-ballot', 'close']) {
            expect(availableAt(operation)).toEqual(fromSetup);
            expect(availableAt(operation, { isOrganizer: true })).toEqual(
                fromSetup,
            );
            expect(availableAt(operation, { hasProfile: false })).toEqual([]);
        }
    });

    it('orders target signing, release and the result after each role completes its close', () => {
        expect(availableAt('sign-target')).toEqual([
            21, 22, 23, 24, 25, 26, 27, 29,
        ]);
        expect(availableAt('sign-target', { isOrganizer: true })).toEqual([
            22, 23, 24, 25, 26, 27, 29,
        ]);
        expect(availableAt('sign-target', { spentTargetVote: true })).toEqual(
            [],
        );
        expect(availableAt('release')).toEqual([21, 24, 25, 26, 27, 29]);
        expect(availableAt('release', { isOrganizer: true })).toEqual([
            22, 24, 25, 26, 27, 29,
        ]);
        expect(availableAt('compute-result')).toEqual([
            21, 22, 23, 24, 25, 26, 27, 29,
        ]);
        expect(availableAt('compute-result', { isOrganizer: true })).toEqual([
            22, 23, 24, 25, 26, 27, 29,
        ]);
    });

    it('always allows the status, publication and roster operations and has no other operation', () => {
        for (const operation of [
            'status',
            'publish',
            'propose-roster',
            'accept-roster',
        ])
            expect(availableAt(operation)).toEqual(generations);
        for (const operation of [
            'create',
            'verify-outcome',
            'toString',
            '__proto__',
        ])
            expect(
                isOperationAvailable(operation, {
                    generation: 29,
                    isOrganizer: true,
                    hasProfile: true,
                    isEligibleContributor: true,
                    spentTargetVote: false,
                }),
            ).toBeUndefined();
    });
});
