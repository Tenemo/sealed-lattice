export const canonicalTupleSchemaIdentifier = 0x0001;
export const canonicalTupleVersion = 1;

/** Numeric item tags from the canonical tuple format used by runtime records. */
export const canonicalItemTypes = Object.freeze({
    rawBytes: 0x01,
    ascii: 0x02,
    unsigned16: 0x03,
    unsigned32: 0x04,
    unsigned64: 0x05,
    hash512: 0x06,
    participantIdentity: 0x07,
    nestedTuple: 0x09,
    homogeneousList: 0x0e,
} as const);
