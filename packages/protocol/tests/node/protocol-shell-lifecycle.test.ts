import { describe, expect, it } from 'vitest';

import {
    deriveLifecycleLabels,
    deriveThresholdProfile,
    isValidLifecycleTransition,
} from '../../src/protocol-shell/index';
import type { LifecycleState } from '../../src/protocol-shell/index';

const expectValidPath = (states: readonly LifecycleState[]): void => {
    for (let index = 0; index < states.length - 1; index += 1) {
        expect(
            isValidLifecycleTransition({
                from: states[index],
                to: states[index + 1],
            }),
        ).toBe(true);
    }
};

describe('protocol-shell lifecycle shell', () => {
    it('accepts the primary v43 lifecycle path', () => {
        expectValidPath([
            'DraftPoll',
            'RegistrationOpen',
            'TrusteeSetupOpen',
            'RegistrationClosed',
            'RosterFrozen',
            'VotingOpen',
            'VotingClosed',
            'AwaitingAggregateContributors',
            'AggregateInputsReady',
            'AwaitingMobileEvaluation',
            'TopKEvaluated',
            'EvaluationReplayOpen',
            'EvaluationReplayAttested',
            'TargetAccepted',
            'AwaitingFirstDecryptionShares',
            'ResultComputedAuditable',
        ]);
    });

    it('accepts the optional evaluation-proof branch', () => {
        expectValidPath([
            'EvaluationReplayOpen',
            'OptionalEvaluationProofVerified',
            'TargetAccepted',
            'AwaitingFirstDecryptionShares',
            'FullyVerifiedResult',
        ]);
    });

    it.each([
        ['VotingOpen', 'TargetAccepted'],
        ['AggregateInputsReady', 'ResultComputedAuditable'],
        ['TopKEvaluated', 'AwaitingFirstDecryptionShares'],
        ['EvaluationReplayOpen', 'ResultComputedAuditable'],
        ['TargetAccepted', 'FullyVerifiedResult'],
        ['DraftPoll', 'VotingOpen'],
    ] satisfies readonly (readonly [LifecycleState, LifecycleState])[])(
        'rejects invalid transition %s -> %s',
        (from, to) => {
            expect(isValidLifecycleTransition({ from, to })).toBe(false);
        },
    );

    it('derives claim-bearing result labels only for claim-bearing profiles', () => {
        const mandatoryProfile = deriveThresholdProfile({ n: 20 });
        const unsafeProfile = deriveThresholdProfile({
            n: 19,
            unsafeMicroRosterAcknowledged: true,
        });

        const mandatoryLabels = deriveLifecycleLabels({
            lifecycleState: 'ResultComputedAuditable',
            thresholdProfile: mandatoryProfile,
            mheSecurityStage: 'ActiveMalicious',
        });
        const unsafeLabels = deriveLifecycleLabels({
            lifecycleState: 'ResultComputedAuditable',
            thresholdProfile: unsafeProfile,
            mheSecurityStage: 'ActiveMalicious',
        });

        expect(mandatoryLabels.primary).toContain('ResultComputedAuditable');
        expect(mandatoryLabels.resultClaimLabel).toBe(
            'ResultComputedAuditable',
        );
        expect(unsafeLabels.primary).toEqual(['Unresolved']);
        expect(unsafeLabels.failures).toContain('UnsafeMicroRoster');
        expect(unsafeLabels.resultClaimLabel).toBeUndefined();
    });

    it('marks passive MHE prototype and optional proof status explicitly', () => {
        const profile = deriveThresholdProfile({ n: 20 });
        const labels = deriveLifecycleLabels({
            lifecycleState: 'FullyVerifiedResult',
            thresholdProfile: profile,
        });

        expect(labels.primary).toEqual(
            expect.arrayContaining([
                'OptionalEvaluationProofVerified',
                'FullyVerifiedResult',
            ]),
        );
        expect(labels.failures).toContain('PassiveMHEPrototype');
        expect(labels.evaluationProofMode).toBe(
            'OptionalEvaluationProofVerified',
        );
        expect(labels.resultClaimLabel).toBe('FullyVerifiedResult');
    });
});
