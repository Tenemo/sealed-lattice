import { deriveCanonicalObjectHash } from '@sealed-lattice/crypto';
import type {
    ProtocolHash,
    ProtocolObjectType,
    ProtocolRefusalCode,
    RefusalRecord,
    SignedBoardHead,
    SignedObjectType,
} from '@sealed-lattice/types';

export const createRefusal = (
    code: ProtocolRefusalCode,
    message: string,
    objectHash?: ProtocolHash,
    objectType?: ProtocolObjectType | SignedObjectType,
): RefusalRecord => ({
    code,
    message,
    objectHash,
    objectType,
});

const maximumVerificationDiagnosticLength = 240;

// Diagnostics surfaced to callers are sanitized (control chars -> spaces,
// runs collapsed) and length-capped at 240 to avoid log injection and
// unbounded error text leaking out of a verifier.
const sanitizeVerificationDiagnostic = (value: string): string =>
    Array.from(value, (character) => {
        const codePoint = character.codePointAt(0) ?? 0;

        return codePoint <= 0x1f || codePoint === 0x7f ? ' ' : character;
    })
        .join('')
        .replace(/\s+/gu, ' ')
        .trim()
        .slice(0, maximumVerificationDiagnosticLength);

// Verifier contract (repo-wide): a public `verifyX`/`deriveX` runs an inner
// `…Unchecked` and wraps it in try/catch, converting any thrown error into a
// structured refusal via this helper, so public verifiers never throw to the
// caller — failures always come back as a RefusalRecord, never an exception.
export const verificationExceptionMessage = (
    summary: string,
    error: unknown,
): string => {
    const rawDetail =
        error instanceof Error
            ? error.message
            : typeof error === 'string'
              ? error
              : '';
    const detail = sanitizeVerificationDiagnostic(rawDetail);

    return detail.length === 0 ? summary : `${summary} Diagnostic: ${detail}`;
};

export const compareCanonicalStrings = (left: string, right: string): number =>
    left < right ? -1 : left > right ? 1 : 0;

export const defaultSignedRootContextHash = deriveCanonicalObjectHash({
    objectType: 'ActionContext',
    context: 'default',
});

export const protocolHashPattern = /^[0-9a-f]{128}$/u;

export const isProtocolHashString = (value: unknown): value is string =>
    typeof value === 'string' && protocolHashPattern.test(value);

export const isRecord = (
    value: unknown,
): value is Readonly<Record<string, unknown>> =>
    typeof value === 'object' && value !== null;

export const isNonEmptyString = (value: unknown): value is string =>
    typeof value === 'string' && value.length > 0;

export const isNonNegativeInteger = (value: number): boolean =>
    Number.isSafeInteger(value) && value >= 0 && !Object.is(value, -0);

export const buildBoardHeadMap = (
    heads: readonly SignedBoardHead[],
): Map<ProtocolHash, SignedBoardHead> =>
    new Map(heads.map((head) => [head.headHash, head]));
