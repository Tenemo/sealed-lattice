import { deriveProtocolDigest } from '@sealed-lattice/crypto';
import type {
    ProtocolDigest,
    ProtocolObjectType,
    ProtocolRefusalCode,
    RefusalRecord,
    SignedBoardHead,
    SignedObjectType,
} from '@sealed-lattice/types';

export const createRefusal = (
    code: ProtocolRefusalCode,
    message: string,
    objectDigest?: ProtocolDigest,
    objectType?: ProtocolObjectType | SignedObjectType,
): RefusalRecord => ({
    code,
    message,
    objectDigest,
    objectType,
});

export const uniqueStrings = <StringValue extends string>(
    values: readonly StringValue[],
): StringValue[] => [...new Set(values)];

export const compareCanonicalStrings = (left: string, right: string): number =>
    left < right ? -1 : left > right ? 1 : 0;

export const defaultSignedRootContextDigest = deriveProtocolDigest(
    'ActionContextDigest',
    { context: 'default' },
);

export const signedObjectRootByteLength = 64;

export const isProtocolDigestString = (value: unknown): value is string =>
    typeof value === 'string' && /^[0-9a-f]{128}$/u.test(value);

export const isNonNegativeInteger = (value: number): boolean =>
    Number.isSafeInteger(value) && value >= 0 && !Object.is(value, -0);

export const buildBoardHeadMap = (
    heads: readonly SignedBoardHead[],
): Map<ProtocolDigest, SignedBoardHead> =>
    new Map(heads.map((head) => [head.headDigest, head]));
