import type { CanonicalErrorCode } from '@sealed-lattice/types';

const bridgeCanonicalErrorCodeValues = [
    'DuplicateField',
    'FieldOrder',
    'FixtureMismatch',
    'InvalidChunkSize',
    'InvalidEnum',
    'InvalidFixture',
    'InvalidHex',
    'InvalidUtf8',
    'MalformedLength',
    'MalformedMagic',
    'MalformedVarUint',
    'MissingField',
    'NonCanonicalVarUint',
    'ProfileComponentMismatch',
    'TrailingBytes',
    'UnknownBaseClaimProfile',
    'UnknownField',
    'UnknownMheSecurityClosure',
    'UnknownProofProfile',
    'UnsupportedCanonicalEnvelopeVersion',
    'UnsupportedObjectType',
    'UnsupportedObjectVersion',
] as const satisfies readonly CanonicalErrorCode[];

export const canonicalErrorCodes: ReadonlySet<CanonicalErrorCode> = new Set(
    bridgeCanonicalErrorCodeValues,
);
