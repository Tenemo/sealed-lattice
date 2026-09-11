export type ProtocolHash = string;

const protocolHashPattern = /^[0-9a-f]{128}$/u;

export const isProtocolHash = (value: unknown): value is ProtocolHash =>
    typeof value === 'string' && protocolHashPattern.test(value);

export const refusalReasonValues = [
    'malformedEncoding',
    'unsupportedVersionOrSuite',
    'outsideSupportedProfile',
    'wrongContext',
    'wrongTypeOrLength',
    'duplicateIdentity',
] as const;

export type RefusalReason = (typeof refusalReasonValues)[number];

export type VerificationResult<VerifiedValue> =
    | {
          readonly isValid: true;
          readonly value: VerifiedValue;
      }
    | {
          readonly isValid: false;
          readonly refusalReason: RefusalReason;
      };

export const configurableOptionCountRange = Object.freeze({
    minimum: 2,
    maximum: 20,
} as const);

export const maximumFoundationCopiedBufferByteLength = 8_388_608;
export const maximumFoundationWasmMemoryByteLength = 671_088_640;

export const canonicalErrorCodeValues = [
    'InvalidEnum',
    'InvalidProtocolObject',
    'InvalidUtf8',
    'MalformedLength',
    'TrailingBytes',
] as const;

export type CanonicalErrorCode = (typeof canonicalErrorCodeValues)[number];

export type CanonicalError = {
    readonly code: CanonicalErrorCode;
    readonly message: string;
};
