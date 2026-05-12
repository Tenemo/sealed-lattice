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

export const uniqueStrings = (values: readonly string[]): string[] => [
    ...new Set(values),
];

export const isNonNegativeInteger = (value: number): boolean =>
    Number.isInteger(value) && value >= 0;

export const buildBoardHeadMap = (
    heads: readonly SignedBoardHead[],
): Map<ProtocolDigest, SignedBoardHead> =>
    new Map(heads.map((head) => [head.headDigest, head]));
