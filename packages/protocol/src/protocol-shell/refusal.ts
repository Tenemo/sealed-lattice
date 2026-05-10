import type {
    CapabilityDecision,
    ProtocolAction,
    RefusalReason,
} from '@sealed-lattice/types';

export const allowAction = (action: ProtocolAction): CapabilityDecision => ({
    allowed: true,
    action,
});

export const refuseAction = (
    action: ProtocolAction,
    reason: RefusalReason,
): CapabilityDecision => ({
    allowed: false,
    action,
    reason,
});
