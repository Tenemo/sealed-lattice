import type { LifecycleState } from '@sealed-lattice/types';
import { describe, expect, it } from 'vitest';

import { isValidLifecycleTransition } from '@sealed-lattice/protocol';

describe('lifecycle transition validation', () => {
    const directBallotHappyPath = [
        'draft',
        'registrationOpen',
        'trusteeSetupOpen',
        'registrationClosed',
        'rosterFrozen',
        'votingOpen',
        'votingClosed',
        'encryptedBallotsSelected',
        'isBallotProofsVerified',
        'isEncryptedBallotAggregateComputed',
        'evaluatorReplayed',
        'targetFinalityReached',
        'isTargetAccepted',
        'decryptionPending',
        'decryptionSharesReady',
        'resultDecoded',
        'fullyVerified',
    ] as const satisfies readonly LifecycleState[];

    it('accepts every edge of the direct encrypted ballot lifecycle path', () => {
        for (
            let index = 0;
            index + 1 < directBallotHappyPath.length;
            index += 1
        ) {
            expect(
                isValidLifecycleTransition({
                    from: directBallotHappyPath[index],
                    to: directBallotHappyPath[index + 1],
                }),
            ).toBe(true);
        }
    });

    it('accepts fork detection from every interruptible runtime state', () => {
        const interruptibleStates = [
            'rosterFrozen',
            'votingOpen',
            'votingClosed',
            'encryptedBallotsSelected',
            'isBallotProofsVerified',
            'isEncryptedBallotAggregateComputed',
            'evaluatorReplayed',
            'targetFinalityReached',
            'isTargetAccepted',
            'decryptionPending',
            'decryptionSharesReady',
            'resultDecoded',
        ] as const satisfies readonly LifecycleState[];

        for (const from of interruptibleStates) {
            expect(
                isValidLifecycleTransition({ from, to: 'forkDetected' }),
            ).toBe(true);
        }
    });

    it('rejects skipped, backward, and out-of-terminal transitions', () => {
        expect(
            isValidLifecycleTransition({ from: 'draft', to: 'rosterFrozen' }),
        ).toBe(false);
        expect(
            isValidLifecycleTransition({ from: 'votingOpen', to: 'draft' }),
        ).toBe(false);
        expect(
            isValidLifecycleTransition({
                from: 'resultDecoded',
                to: 'isTargetAccepted',
            }),
        ).toBe(false);

        for (const terminal of [
            'fullyVerified',
            'pending',
            'outsideSupportedParameters',
            'forkDetected',
        ] as const satisfies readonly LifecycleState[]) {
            expect(
                isValidLifecycleTransition({ from: terminal, to: 'draft' }),
            ).toBe(false);
        }
    });

    it('returns false for unknown runtime lifecycle states on either side', () => {
        expect(
            isValidLifecycleTransition({
                from: 'totallyUnknownState' as LifecycleState,
                to: 'draft',
            }),
        ).toBe(false);
        expect(
            isValidLifecycleTransition({
                from: 'rosterFrozen',
                to: 'totallyUnknownState' as LifecycleState,
            }),
        ).toBe(false);
    });
});
