import type {
    CapabilityDecision,
    ProtocolAction,
    RefusalReason,
} from './types.js';

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
