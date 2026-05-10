import type {
    CapabilityContext,
    CapabilityDecision,
    LifecycleLabelInput,
    LifecycleLabels,
    LifecycleTransition,
    PollSpecValidation,
    ProtocolAction,
    ThresholdProfile,
    ThresholdProfileInput,
} from '@sealed-lattice/types';

export declare const deriveThresholdProfile: (
    input: ThresholdProfileInput,
) => ThresholdProfile;

export declare const validatePollSpec: (input: unknown) => PollSpecValidation;

export declare const isValidLifecycleTransition: (
    transition: LifecycleTransition,
) => boolean;

export declare const deriveLifecycleLabels: (
    input: LifecycleLabelInput,
) => LifecycleLabels;

export declare const evaluateActionCapability: (
    action: ProtocolAction,
    context: CapabilityContext,
) => CapabilityDecision;
