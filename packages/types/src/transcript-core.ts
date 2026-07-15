export const canonicalErrorCodeValues = [
    'ComponentMismatch',
    'DuplicateField',
    'FixtureMismatch',
    'InvalidChunkSize',
    'InvalidEnum',
    'InvalidFixture',
    'InvalidProtocolObject',
    'InvalidHex',
    'InvalidUtf8',
    'MalformedLength',
    'MalformedMagic',
    'MalformedVarUint',
    'NonCanonicalVarUint',
    'TrailingBytes',
    'UnsupportedObjectType',
    'UnsupportedObjectVersion',
] as const;

/** Stable canonical error code emitted by kernel commands. */
export type CanonicalErrorCode = (typeof canonicalErrorCodeValues)[number];

/** Structured kernel error with a stable code and diagnostic message. */
export type CanonicalError = {
    readonly code: CanonicalErrorCode;
    readonly message: string;
};
