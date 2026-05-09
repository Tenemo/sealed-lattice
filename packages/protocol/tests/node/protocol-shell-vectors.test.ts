import { describe, expect, it } from 'vitest';

import capabilityRefusalsJson from '../../../../test-vectors/protocol-shell/capability-refusals.json';
import lifecycleTransitionsJson from '../../../../test-vectors/protocol-shell/lifecycle-transitions.json';
import pollSpecsJson from '../../../../test-vectors/protocol-shell/poll-specs.json';
import thresholdProfilesJson from '../../../../test-vectors/protocol-shell/threshold-profiles.json';
import {
    deriveThresholdProfile,
    evaluateActionCapability,
    isValidLifecycleTransition,
    validatePollSpec,
} from '../../src/protocol-shell/index';
import type {
    CapabilityContext,
    PollSpecInput,
    ProtocolAction,
    ThresholdProfile,
    ThresholdProfileInput,
} from '../../src/protocol-shell/index';

type ThresholdProfileVector = {
    readonly caseName: string;
    readonly input: ThresholdProfileInput;
    readonly expected: ThresholdProfile;
};

type ThresholdProfileVectors = {
    readonly schemaVersion: 1;
    readonly profiles: readonly ThresholdProfileVector[];
};

type PollSpecVector = {
    readonly caseName: string;
    readonly input: PollSpecInput;
    readonly expectedOk: boolean;
    readonly expectedErrorCodes?: readonly string[];
};

type PollSpecVectors = {
    readonly schemaVersion: 1;
    readonly cases: readonly PollSpecVector[];
};

type LifecycleTransitionVector = {
    readonly from: CapabilityContext['lifecycleState'];
    readonly to: CapabilityContext['lifecycleState'];
};

type LifecycleTransitionVectors = {
    readonly schemaVersion: 1;
    readonly validTransitions: readonly LifecycleTransitionVector[];
    readonly invalidTransitions: readonly LifecycleTransitionVector[];
};

type CapabilityVector = {
    readonly caseName: string;
    readonly action: ProtocolAction;
    readonly context: Omit<CapabilityContext, 'thresholdProfile'>;
    readonly expected: ReturnType<typeof evaluateActionCapability>;
};

type CapabilityVectors = {
    readonly schemaVersion: 1;
    readonly cases: readonly CapabilityVector[];
};

const thresholdProfiles = thresholdProfilesJson as ThresholdProfileVectors;
const pollSpecs = pollSpecsJson as PollSpecVectors;
const lifecycleTransitions =
    lifecycleTransitionsJson as LifecycleTransitionVectors;
const capabilityRefusals = capabilityRefusalsJson as CapabilityVectors;

describe('protocol-shell test vectors', () => {
    it('matches deterministic threshold-profile vectors', () => {
        for (const vector of thresholdProfiles.profiles) {
            expect(
                deriveThresholdProfile(vector.input),
                vector.caseName,
            ).toEqual(vector.expected);
        }
    });

    it('matches poll-spec validation vectors', () => {
        for (const vector of pollSpecs.cases) {
            const validation = validatePollSpec(vector.input);

            expect(validation.ok, vector.caseName).toBe(vector.expectedOk);
            if (!validation.ok) {
                expect(validation.errors.map((error) => error.code)).toEqual(
                    vector.expectedErrorCodes,
                );
            }
        }
    });

    it('matches lifecycle transition vectors', () => {
        for (const transition of lifecycleTransitions.validTransitions) {
            expect(isValidLifecycleTransition(transition)).toBe(true);
        }
        for (const transition of lifecycleTransitions.invalidTransitions) {
            expect(isValidLifecycleTransition(transition)).toBe(false);
        }
    });

    it('matches capability refusal vectors against the mandatory n=20 profile', () => {
        const thresholdProfile = deriveThresholdProfile({ n: 20 });

        for (const vector of capabilityRefusals.cases) {
            expect(
                evaluateActionCapability(vector.action, {
                    ...vector.context,
                    thresholdProfile,
                }),
                vector.caseName,
            ).toEqual(vector.expected);
        }
    });
});
