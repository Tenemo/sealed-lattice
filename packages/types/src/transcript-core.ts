/** Claim profile labels attached to transcript-core fixtures and results. */
export type BaseClaimProfile =
    | 'ResultComputedAuditable'
    | 'FullyVerifiedResult';

/** High-level malicious security stage claimed by transcript-core fixtures. */
export type MheSecurityStage = 'PassiveMHEPrototype' | 'ActiveMalicious';

/**
 * Alias retained for backward compatibility with consumers that read
 * the transcript-core fixture shape. Prefer {@link MheSecurityStage}.
 */
export type TranscriptCoreMheSecurityStage = MheSecurityStage;

/** Successful transcript-core status label returned by fixture verification. */
export type TranscriptCoreStatusLabel = 'TranscriptCoreVerified';

/** Top-level transcript-core verification label for accepted and rejected fixtures. */
export type TranscriptCoreVerificationLabel =
    | 'TranscriptCoreVerified'
    | 'TranscriptCoreRejected';

export const canonicalErrorCodeValues = [
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
    'UnknownMheSecurityStage',
    'UnknownProofProfile',
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

/** Golden transcript-core fixture with expected canonical digests and labels. */
export type GoldenTranscriptCoreFixture = {
    readonly kind: 'golden-transcript-core';
    readonly fixtureVersion: 1;
    readonly caseName: string;
    readonly canonicalBytesHex: string;
    readonly objectType: 'TranscriptCore';
    readonly objectVersion: 1;
    readonly baseClaimProfile: BaseClaimProfile;
    readonly mheSecurityStage: MheSecurityStage;
    readonly baseClaimProfileId: string;
    readonly mheSecurityProfileId: string;
    readonly heSetupProofProfileId: string;
    readonly evaluationProofProfileId: string;
    readonly decryptionProofProfileId: string;
    readonly expectedObjectHash512: string;
    readonly expectedChunkRoot: string;
    readonly chunkSize: number;
    readonly expectedStatusLabels: readonly TranscriptCoreStatusLabel[];
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

/** Replay fixture that binds a golden transcript-core fixture to expected labels. */
export type TranscriptCoreReplayFixture = {
    readonly schemaVersion: 1;
    readonly caseName: string;
    readonly fixture: GoldenTranscriptCoreFixture;
    readonly expectedStatusLabels: readonly TranscriptCoreStatusLabel[];
};

/** Decoded transcript-core analysis output used by fixture tooling. */
export type TranscriptCoreAnalysis = {
    readonly canonicalBytesHex: string;
    readonly objectType: 'TranscriptCore';
    readonly objectVersion: 1;
    readonly baseClaimProfile: BaseClaimProfile;
    readonly mheSecurityStage: MheSecurityStage;
    readonly baseClaimProfileId: string;
    readonly mheSecurityProfileId: string;
    readonly heSetupProofProfileId: string;
    readonly evaluationProofProfileId: string;
    readonly decryptionProofProfileId: string;
    readonly objectHash512: string;
    readonly chunkRoot: string;
    readonly chunkSize: number;
    readonly statusLabels: readonly TranscriptCoreStatusLabel[];
    readonly title: string;
    readonly sequence: number;
    readonly payloadHex: string;
    readonly tags: readonly string[];
    readonly checkpoints: readonly number[];
};

/** Verification result for a golden transcript-core fixture. */
export type GoldenTranscriptCoreFixtureVerification = {
    readonly verified: true;
    readonly caseName: string;
    readonly objectHash512: string;
    readonly chunkRoot: string;
    readonly statusLabels: readonly TranscriptCoreStatusLabel[];
};

/** Verification result for a malformed transcript-core fixture. */
export type MalformedObjectFixtureVerification = {
    readonly verified: true;
    readonly caseName: string;
    readonly expectedErrorCode: CanonicalErrorCode;
};

/** Detailed fixture verification result for transcript-core test data. */
export type TranscriptCoreFixtureVerification =
    | GoldenTranscriptCoreFixtureVerification
    | MalformedObjectFixtureVerification;

/** Public transcript-core fixture verifier result. */
export type TranscriptCoreVerificationResult = {
    readonly caseName: string;
    readonly label: TranscriptCoreVerificationLabel;
    readonly statusLabels: readonly TranscriptCoreStatusLabel[];
    readonly objectHash512?: string;
    readonly chunkRoot?: string;
    readonly rejection?: {
        readonly code: CanonicalErrorCode;
    };
};
