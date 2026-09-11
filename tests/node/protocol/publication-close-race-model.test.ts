import { describe, expect, it } from 'vitest';

import { runPublicationCloseRaceModel } from '#tests/publication-close-race-model.js';

describe('publication close race with separate local views', () => {
    it('completes the slot and close when all READY evidence arrives first', () => {
        for (const participants of [3, 4, 10, 20]) {
            const result = runPublicationCloseRaceModel(participants, true);
            expect(result.readySigners).toBe(result.honestParticipants);
            expect(result.closeSigners).toBe(result.honestParticipants);
            expect(result.unresolvedReadyWaiters).toBe(0);
            expect(result.deliveredMessages).toBe(
                2 * result.honestParticipants ** 2,
            );
        }
    });

    it('strands a READY sender after every honest message is eventually delivered', () => {
        for (let participants = 3; participants <= 20; participants += 1) {
            const result = runPublicationCloseRaceModel(participants, false);
            expect(result.readySigners).toBe(1);
            expect(result.closeSigners).toBe(result.honestParticipants - 1);
            expect(result.unresolvedReadyWaiters).toBe(1);
            expect(result.deliveredMessages).toBe(
                result.honestParticipants ** 2 + result.honestParticipants,
            );
        }
        expect(runPublicationCloseRaceModel(10, false)).toEqual({
            closeSigners: 6,
            deliveredMessages: 56,
            honestParticipants: 7,
            readySigners: 1,
            unresolvedReadyWaiters: 1,
        });
    });
});
