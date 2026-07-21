import { isProtocolHash, type ProtocolHash } from '@sealed-lattice/types';

export const assertProtocolHash = (
    value: unknown,
    fieldName: string,
): ProtocolHash => {
    if (!isProtocolHash(value)) {
        throw new TypeError(`${fieldName} must be a protocol hash.`);
    }

    return value;
};
