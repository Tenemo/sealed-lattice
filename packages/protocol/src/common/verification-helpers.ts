import type {
    ProtocolDigest,
    ProtocolObjectType,
    ProtocolRefusalCode,
    RefusalRecord,
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
