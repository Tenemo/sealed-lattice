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

type WasmInternalErrorConstructor = new (message: string) => Error;

export const decodeWasmRefusalStatus = (
    status: number,
    InternalErrorConstructor: WasmInternalErrorConstructor,
    unknownStatusMessage: string,
): RefusalReason | undefined => {
    if (status === 0) {
        return undefined;
    }
    const refusalReason = refusalReasonByCode.get(status);
    if (refusalReason === undefined) {
        throw new InternalErrorConstructor(unknownStatusMessage);
    }
    return refusalReason;
};
