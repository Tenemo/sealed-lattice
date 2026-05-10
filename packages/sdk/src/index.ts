import {
    deriveLifecycleLabels as deriveLifecycleLabelsInternal,
    deriveThresholdProfile as deriveThresholdProfileInternal,
    evaluateActionCapability as evaluateActionCapabilityInternal,
    isValidLifecycleTransition as isValidLifecycleTransitionInternal,
    validatePollSpecFromUnknown as validatePollSpecFromUnknownInternal,
} from '@sealed-lattice/protocol';
import type {
    CapabilityContext,
    CapabilityDecision,
    LifecycleLabelInput,
    LifecycleLabels,
    LifecycleTransition,
    PollSpecInput,
    PollSpecValidation,
    ProtocolAction,
    ThresholdProfile,
    ThresholdProfileInput,
    TranscriptCoreFixture,
    TranscriptCoreVerificationResult,
} from '@sealed-lattice/types';

import { loadTranscriptCoreKernel } from './kernel.js';

export type * from '@sealed-lattice/types';

export const deriveThresholdProfile = (
    input: ThresholdProfileInput,
): ThresholdProfile => deriveThresholdProfileInternal(input);

export function validatePollSpec(input: PollSpecInput): PollSpecValidation;
export function validatePollSpec(input: unknown): PollSpecValidation {
    return validatePollSpecFromUnknownInternal(input);
}

export const isValidLifecycleTransition = (
    transition: LifecycleTransition,
): boolean => isValidLifecycleTransitionInternal(transition);

export const deriveLifecycleLabels = (
    input: LifecycleLabelInput,
): LifecycleLabels => deriveLifecycleLabelsInternal(input);

export const evaluateActionCapability = (
    action: ProtocolAction,
    context: CapabilityContext,
): CapabilityDecision => evaluateActionCapabilityInternal(action, context);

export const verifyTranscriptCoreFixture = async (
    fixture: TranscriptCoreFixture,
): Promise<TranscriptCoreVerificationResult> => {
    const kernel = await loadTranscriptCoreKernel();
    const verification = kernel.verifyFixture(fixture);

    if ('expectedErrorCode' in verification) {
        return {
            caseName: verification.caseName,
            label: 'TranscriptCoreRejected',
            statusLabels: [],
            rejection: {
                code: verification.expectedErrorCode,
            },
        };
    }

    return {
        caseName: verification.caseName,
        label: 'TranscriptCoreVerified',
        objectHash512: verification.objectHash512,
        chunkRoot: verification.chunkRoot,
        statusLabels: verification.statusLabels,
    };
};
