export const canonicalErrorCodeValues = [
    'ComponentMismatch',
    'DuplicateField',
    'FieldOrder',
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
    'MissingField',
    'NonCanonicalVarUint',
    'TrailingBytes',
    'UnknownField',
    'UnsupportedCanonicalEnvelopeVersion',
    'UnsupportedObjectType',
    'UnsupportedObjectVersion',
] as const;

/** Stable canonical codec error code emitted by fixture verification. */
export type CanonicalErrorCode = (typeof canonicalErrorCodeValues)[number];

/** Structured canonical codec error with a stable code and diagnostic message. */
export type CanonicalError = {
    readonly code: CanonicalErrorCode;
    readonly message: string;
};

/** Golden transcript-core fixture with expected canonical hashes and labels. */
export type GoldenTranscriptCoreFixture = {
    readonly kind: 'golden-transcript-core';
    readonly fixtureVersion: 1;
    readonly caseName: string;
    readonly canonicalBytesHex: string;
    readonly objectType: 'TranscriptCore';
    readonly objectVersion: 1;
    readonly expectedObjectHash512: string;
    readonly expectedChunkRoot: string;
    readonly chunkSize: number;
};

/** Negative transcript-core fixture expected to fail canonical decoding. */
export type MalformedObjectFixture = {
    readonly kind: 'malformed-object';
    readonly fixtureVersion: 1;
    readonly caseName: string;
    readonly canonicalBytesHex: string;
    readonly expectedErrorCode: CanonicalErrorCode;
};

/** Transcript-core fixture accepted by the public verifier. */
export type TranscriptCoreFixture =
    | GoldenTranscriptCoreFixture
    | MalformedObjectFixture;

/** Decoded transcript-core analysis output used by fixture tooling. */
export type TranscriptCoreAnalysis = {
    readonly canonicalBytesHex: string;
    readonly objectType: 'TranscriptCore';
    readonly objectVersion: 1;
    readonly objectHash512: string;
    readonly chunkRoot: string;
    readonly chunkSize: number;
    readonly title: string;
    readonly sequence: number;
    readonly payloadHex: string;
    readonly tags: readonly string[];
    readonly checkpoints: readonly number[];
};

/** Verification result for a golden transcript-core fixture. */
export type GoldenTranscriptCoreFixtureVerification = {
    readonly caseName: string;
    readonly objectHash512: string;
    readonly chunkRoot: string;
};

/** Verification result for a malformed transcript-core fixture. */
export type MalformedObjectFixtureVerification = {
    readonly caseName: string;
    readonly expectedErrorCode: CanonicalErrorCode;
};

/** Detailed fixture verification result for transcript-core test data. */
export type TranscriptCoreFixtureVerification =
    | GoldenTranscriptCoreFixtureVerification
    | MalformedObjectFixtureVerification;

/** Public transcript-core fixture verifier result. */
export type TranscriptCoreVerificationResult =
    | {
          readonly isValid: true;
          readonly caseName: string;
          readonly objectHash512: string;
          readonly chunkRoot: string;
      }
    | {
          readonly isValid: false;
          readonly caseName: string;
          readonly rejection: {
              readonly code: CanonicalErrorCode;
          };
      };
