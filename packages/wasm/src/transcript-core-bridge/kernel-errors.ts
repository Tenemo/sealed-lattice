import {
    canonicalErrorCodeValues,
    type CanonicalErrorCode,
} from '@sealed-lattice/types';

export const canonicalErrorCodes: ReadonlySet<CanonicalErrorCode> = new Set(
    canonicalErrorCodeValues,
);
