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

export const isNonNegativeInteger = (value: number): boolean =>
    Number.isSafeInteger(value) && value >= 0 && !Object.is(value, -0);

export const buildBoardHeadMap = (
    heads: readonly SignedBoardHead[],
): Map<ProtocolDigest, SignedBoardHead> =>
    new Map(heads.map((head) => [head.headDigest, head]));
