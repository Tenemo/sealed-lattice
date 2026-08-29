import {
    canonicalErrorCodeValues,
    type CanonicalErrorCode,
} from '../foundation-contract.js';

export const canonicalErrorCodes: ReadonlySet<CanonicalErrorCode> = new Set(
    canonicalErrorCodeValues,
);
