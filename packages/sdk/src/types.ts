export type SecurityProfile = 'StageP' | 'StageX' | 'StageA';

export type TranscriptCoreStatusLabel = 'TranscriptCoreVerified';

export type TranscriptCoreVerificationLabel =
    | 'TranscriptCoreVerified'
    | 'TranscriptCoreRejected';

export type CanonicalErrorCode =
    | 'DuplicateField'
    | 'FieldOrder'
    | 'FixtureMismatch'
    | 'InvalidChunkSize'
    | 'InvalidEnum'
    | 'InvalidFixture'
    | 'InvalidHex'
    | 'InvalidUtf8'
    | 'MalformedLength'
    | 'MalformedMagic'
    | 'MalformedVarUint'
    | 'MissingField'
    | 'NonCanonicalVarUint'
    | 'ProofProfileMismatch'
    | 'TrailingBytes'
    | 'UnknownField'
    | 'UnknownProofProfile'
    | 'UnknownSecurityProfile'
    | 'UnsupportedEnvelopeVersion'
    | 'UnsupportedObjectType'
    | 'UnsupportedObjectVersion';

export type CanonicalError = {
    readonly code: CanonicalErrorCode;
    readonly message: string;
};

export type GoldenTranscriptCoreFixture = {
    readonly kind: 'golden-transcript-core';
    readonly fixtureVersion: 1;
    readonly caseName: string;
    readonly canonicalBytesHex: string;
    readonly objectType: 'TranscriptCore';
    readonly objectVersion: 1;
    readonly securityProfile: SecurityProfile;
    readonly proofProfileId: string;
    readonly heSetupProofProfileId: string;
    readonly evaluationProofProfileId: string;
    readonly decryptionProofProfileId: string;
    readonly expectedObjectHash512: string;
    readonly expectedChunkRoot: string;
    readonly chunkSize: number;
    readonly expectedStatusLabels: readonly TranscriptCoreStatusLabel[];
};

export type MalformedObjectFixture = {
    readonly kind: 'malformed-object';
    readonly fixtureVersion: 1;
    readonly caseName: string;
    readonly canonicalBytesHex: string;
    readonly expectedErrorCode: CanonicalErrorCode;
};

export type TranscriptCoreFixture =
    | GoldenTranscriptCoreFixture
    | MalformedObjectFixture;

export type TranscriptCoreReplayFixture = {
    readonly schemaVersion: 1;
    readonly caseName: string;
    readonly fixture: GoldenTranscriptCoreFixture;
    readonly expectedStatusLabels: readonly TranscriptCoreStatusLabel[];
};

export type TranscriptCoreFixtureVerification =
    | {
          readonly verified: true;
          readonly caseName: string;
          readonly objectHash512: string;
          readonly chunkRoot: string;
          readonly statusLabels: readonly TranscriptCoreStatusLabel[];
      }
    | {
          readonly verified: true;
          readonly caseName: string;
          readonly expectedErrorCode: CanonicalErrorCode;
      };

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
