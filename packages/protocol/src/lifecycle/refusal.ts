import type {
    CapabilityDecision,
    LifecycleRefusalReason,
    ProtocolAction,
} from '@sealed-lattice/types';

export const allowAction = (action: ProtocolAction): CapabilityDecision => ({
    allowed: true,
    action,
});

export const refuseAction = (
    action: ProtocolAction,
    reason: LifecycleRefusalReason,
): CapabilityDecision => ({
    allowed: false,
    action,
    reason,
});
