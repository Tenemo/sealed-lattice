import {
    canonicalErrorCodeValues,
    type CanonicalErrorCode,
    type RefusalReason,
    refusalReasonCodes,
} from '@sealed-lattice/types';

export const canonicalErrorCodes: ReadonlySet<CanonicalErrorCode> = new Set(
    canonicalErrorCodeValues,
);

export const refusalReasonByCode: ReadonlyMap<number, RefusalReason> = new Map(
    Object.entries(refusalReasonCodes).map(([reason, code]) => [
        code,
        reason as RefusalReason,
    ]),
);
