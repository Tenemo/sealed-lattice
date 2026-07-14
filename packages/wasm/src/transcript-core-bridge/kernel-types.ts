import type { CanonicalError, ProtocolHash } from '@sealed-lattice/types';

import type {
    BgvCollectiveSetupParametersDescription,
    BgvCollectiveSetupVerification,
    BgvTrusteeEvaluationKeyProofGeneration,
    BgvTrusteeEvaluationKeyStatementDescription,
    BgvTrusteeEvaluationKeySameSecretBridge,
    BgvTrusteeEvaluationKeySameSecretLinkage,
    BgvTrusteeEvaluationKeyStatementContext,
    BgvTrusteeEvaluationKeyStatementKey,
    BgvLocalTrusteeSetupStateVerification,
    BgvPrivateVssShareEnvelopeVerification,
    BgvRnsParametersDescription,
    BgvSameSecretBridgeProofContext,
    BgvSameSecretBridgeProofGeneration,
    BgvVssCommittedMaterialCommitmentComputation,
    BgvVssShareLinkageProofContext,
    BgvVssShareLinkageProofGeneration,
    BgvSetupCommitmentOpeningComputation,
    BgvTargetDecryptionShare,
    BgvTargetDecryptionShareProofMaterial,
    BgvTargetDecryptionResultReleaseBegin,
    BgvTargetDecryptionResultReleaseCompletion,
} from './kernel-types/bgv.js';

export type {
    BgvCollectiveSetupParametersDescription,
    BgvCollectiveSetupVerification,
    BgvTrusteeEvaluationKeyProofGeneration,
    BgvTrusteeEvaluationKeyStatementDescription,
    BgvTrusteeEvaluationKeySameSecretBridge,
    BgvTrusteeEvaluationKeySameSecretLinkage,
    BgvLocalTrusteeSetupStateVerification,
    BgvPrivateVssShareEnvelopeVerification,
    BgvRnsParametersDescription,
    BgvSameSecretBridgeProofContext,
    BgvSameSecretBridgeProofGeneration,
    BgvVssCommittedMaterialCommitmentComputation,
    BgvVssShareLinkageProofContext,
    BgvVssShareLinkageProofGeneration,
    BgvSetupCommitmentOpeningComputation,
    BgvTargetDecryptionShare,
    BgvTargetDecryptionShareProofMaterial,
    BgvTargetDecryptionResultReleaseBegin,
    BgvTargetDecryptionResultReleaseShareEvidence,
    BgvTargetDecryptionResultReleaseCompletion,
} from './kernel-types/bgv.js';
type BgvTargetDecryptionLocalCommandContext = Readonly<{
    readonly setupPackage: unknown;
    readonly targetAcceptedRecord: unknown;
    readonly targetCiphertexts: unknown;
    readonly targetCiphertextBinding: unknown;
    readonly targetShareProfile: unknown;
}>;

export type BgvCollectiveSetupVerificationInput = Readonly<{
    readonly setupPackage: unknown;
    readonly expectedSetupPackageHash?: ProtocolHash;
    readonly expectedManifestHash?: ProtocolHash;
    readonly expectedRosterHash?: ProtocolHash;
}>;

export type MailboxPayloadType = 1 | 2;

export type CanonicalFoundationValueValidation = Readonly<{
    readonly schemaIdentifier: number;
    readonly canonicalBytesHex: string;
    readonly bindingHash?: ProtocolHash;
}>;

export type CanonicalFoundationValueValidationInput =
    | Readonly<{
          readonly schemaIdentifier: number;
          readonly canonicalBytesHex: string;
      }>
    | Readonly<{
          readonly schemaIdentifier: number;
          readonly canonicalByteLength: number;
          readonly canonicalByteChunksHex: readonly string[];
      }>;

export type CeremonyContextInput = Readonly<{
    readonly suiteId: ProtocolHash;
    readonly manifestHash: ProtocolHash;
    readonly rosterHash: ProtocolHash;
    readonly ceremonyIdentifier: string;
}>;

export type ActionContextInput = Readonly<{
    readonly ceremonyContextHash: ProtocolHash;
    readonly actionIdentifier: string;
    readonly actionDefinitionHash: ProtocolHash;
    readonly boardPolicyHash: ProtocolHash;
}>;

export type MailboxKeyScheduleInput = Readonly<{
    readonly suiteId: ProtocolHash;
    readonly ceremonyContextHash: ProtocolHash;
    readonly actionContextHash: ProtocolHash;
    readonly rosterHash: ProtocolHash;
    readonly sourceParticipantId: string;
    readonly recipientParticipantId: string;
    readonly producerSequence: string;
    readonly envelopeAttemptIdentifierHex: string;
    readonly payloadType: MailboxPayloadType;
    readonly statementHash: ProtocolHash;
    readonly orderedMaterialRoots: readonly ProtocolHash[];
    readonly kemCiphertextHash: ProtocolHash;
}>;

export type MailboxAssociatedData = Readonly<
    MailboxKeyScheduleInput & {
        readonly plaintextByteLength: string;
    }
>;

export type SetupMailboxSlot = Omit<
    MailboxKeyScheduleInput,
    'envelopeAttemptIdentifierHex' | 'kemCiphertextHash'
>;

export type MailboxCiphertextDescriptor = Readonly<{
    readonly totalByteLength: string;
    readonly orderedChunkDigests: readonly ProtocolHash[];
    readonly fullObjectDigest: ProtocolHash;
}>;

export type UnsignedMailboxEnvelope = Readonly<{
    readonly associatedData: MailboxAssociatedData;
    readonly kemCiphertextHex: string;
    readonly ciphertextDescriptor: MailboxCiphertextDescriptor;
    readonly gcmTagHex: string;
}>;

export type SignedMailboxEnvelope = Readonly<
    UnsignedMailboxEnvelope & {
        readonly sourceSignatureHex: string;
    }
>;

export type EncodedMailboxKeyScheduleInput = Readonly<{
    readonly canonicalBytesHex: string;
    readonly hkdfExtractSaltHex: string;
}>;

export type DecodedMailboxKeyScheduleInput = Readonly<{
    readonly value: MailboxKeyScheduleInput;
    readonly hkdfExtractSaltHex: string;
}>;

export type EncodedMailboxAssociatedData = Readonly<{
    readonly canonicalBytesHex: string;
    readonly hkdfExtractSaltHex: string;
}>;

export type DecodedMailboxAssociatedData = Readonly<{
    readonly value: MailboxAssociatedData;
    readonly hkdfExtractSaltHex: string;
}>;

export type EncodedStreamDescriptor = Readonly<{
    readonly canonicalBytesHex: string;
}>;

export type DecodedStreamDescriptor = Readonly<{
    readonly value: MailboxCiphertextDescriptor;
}>;

export type PrivateRandomCursor = Readonly<{
    readonly family: number;
    readonly purpose: number;
    readonly derivationContextHash: ProtocolHash;
    readonly streamAttemptIdentifierHex: string;
    readonly nextCounter: string;
    readonly nextUnreadBitOffsetInBufferedBlock?: number;
}>;

export type ActionRandomnessDerivationInput = Readonly<{
    readonly suiteId: ProtocolHash;
    readonly ceremonyContextHash: ProtocolHash;
    readonly actionContextHash: ProtocolHash;
    readonly participantId: string;
}>;

export type PrivateRandomBlockInput = Readonly<
    ActionRandomnessDerivationInput & {
        readonly family: number;
        readonly purpose: number;
        readonly derivationContextHash: ProtocolHash;
        readonly attemptIdentifierHex: string;
        readonly counter: string;
    }
>;

export type EncodedActionRandomnessDerivationInput = Readonly<{
    readonly canonicalBytesHex: string;
}>;

export type DecodedActionRandomnessDerivationInput = Readonly<{
    readonly value: ActionRandomnessDerivationInput;
}>;

export type EncodedPrivateRandomBlockInput = Readonly<{
    readonly canonicalBytesHex: string;
}>;

export type DecodedPrivateRandomBlockInput = Readonly<{
    readonly value: PrivateRandomBlockInput;
}>;

export type EncodedPrivateRandomCursor = Readonly<{
    readonly canonicalBytesHex: string;
}>;

export type DecodedPrivateRandomCursor = Readonly<{
    readonly value: PrivateRandomCursor;
}>;

export type GeneratedProofSuiteCandidate = Readonly<{
    readonly suiteId: ProtocolHash;
    readonly canonicalSuiteRecordHex: string;
    readonly artifacts: readonly Readonly<{
        readonly artifactKind: number;
        readonly canonicalArtifactHex: string;
        readonly byteLength: number;
        readonly artifactHash: ProtocolHash;
    }>[];
}>;

export type EncodedSignedMailboxEnvelope = Readonly<{
    readonly canonicalBytesHex: string;
    readonly envelopeHash: ProtocolHash;
}>;

export type DecodedSignedMailboxEnvelope = Readonly<{
    readonly value: SignedMailboxEnvelope;
    readonly envelopeHash: ProtocolHash;
}>;

export type AcceptedSetupSession = Readonly<{
    cancel(): void;
    verifyCollectiveBgvSetup(
        input: BgvCollectiveSetupVerificationInput,
    ): BgvCollectiveSetupVerification;
}>;

type BgvTrusteeEvaluationKeyContext = Extract<
    BgvTrusteeEvaluationKeyStatementContext,
    { readonly evaluatorKeyScheduleRoot: ProtocolHash }
>;

type BgvPublicKeyShareContext = Extract<
    BgvTrusteeEvaluationKeyStatementContext,
    { readonly sameSecretBridgeStatementRoot: ProtocolHash }
>;

type BgvEvaluationKeyStatementKey = Exclude<
    BgvTrusteeEvaluationKeyStatementKey,
    { readonly proofFamily: 'public-key-share' }
>;

type BgvPublicKeyShareStatementKey = Extract<
    BgvTrusteeEvaluationKeyStatementKey,
    { readonly proofFamily: 'public-key-share' }
>;

type BgvTrusteeEvaluationKeyStatementCommonInput<Context, Key> = Readonly<{
    readonly context: Context;
    readonly ringDegree: number;
    readonly keys: readonly Key[];
}>;

export type BgvTrusteeEvaluationKeyStatementInput =
    | Readonly<
          BgvTrusteeEvaluationKeyStatementCommonInput<
              BgvTrusteeEvaluationKeyContext,
              BgvEvaluationKeyStatementKey
          > & {
              readonly statementFamily: 'trustee-evaluation-key';
              readonly sameSecretLinkage: BgvTrusteeEvaluationKeySameSecretLinkage;
          }
      >
    | Readonly<
          Omit<
              BgvTrusteeEvaluationKeyStatementCommonInput<
                  BgvPublicKeyShareContext,
                  BgvPublicKeyShareStatementKey
              >,
              'keys'
          > & {
              readonly statementFamily: 'public-key-share';
              readonly keys: readonly [BgvPublicKeyShareStatementKey];
              readonly sameSecretBridge: BgvTrusteeEvaluationKeySameSecretBridge;
          }
      >;

type BgvTrusteeEvaluationKeyProofCommonInput = Readonly<{
    readonly secretCoefficients: readonly number[];
    readonly errorCoefficientsByKey: readonly (readonly (readonly number[])[])[];
    readonly negativeIndicatorCoefficients: readonly number[];
    readonly proofRandomnessSeedHex: string;
    readonly proofRandomnessNonceHex: string;
}>;

export type BgvTrusteeEvaluationKeyProofInput =
    | Readonly<
          Extract<
              BgvTrusteeEvaluationKeyStatementInput,
              { readonly statementFamily: 'trustee-evaluation-key' }
          > &
              BgvTrusteeEvaluationKeyProofCommonInput & {
                  readonly openingRandomnessByLimb: readonly (readonly (readonly number[])[])[];
              }
      >
    | Readonly<
          Extract<
              BgvTrusteeEvaluationKeyStatementInput,
              { readonly statementFamily: 'public-key-share' }
          > &
              BgvTrusteeEvaluationKeyProofCommonInput & {
                  readonly vssCommittedMaterialSeedsByBoundMessage: readonly string[];
                  readonly vssCommittedMaterialContextHashesByBoundMessage: readonly string[];
              }
      >;

export type TranscriptCoreKernel = {
    readonly exportedFunctionNames: readonly string[];
    beginAcceptedSetupSession(): AcceptedSetupSession;
    deriveCanonicalObjectHash(input: { readonly value: unknown }): ProtocolHash;
    validateCanonicalFoundationValue(
        input: CanonicalFoundationValueValidationInput,
    ): CanonicalFoundationValueValidation;
    deriveCeremonyContextHash(value: CeremonyContextInput): ProtocolHash;
    deriveActionContextHash(value: ActionContextInput): ProtocolHash;
    encodeMailboxKeyScheduleInput(
        value: MailboxKeyScheduleInput,
    ): EncodedMailboxKeyScheduleInput;
    decodeMailboxKeyScheduleInput(input: {
        readonly canonicalBytesHex: string;
    }): DecodedMailboxKeyScheduleInput;
    encodeMailboxAssociatedData(
        value: MailboxAssociatedData,
    ): EncodedMailboxAssociatedData;
    decodeMailboxAssociatedData(input: {
        readonly canonicalBytesHex: string;
    }): DecodedMailboxAssociatedData;
    encodeStreamDescriptor(
        value: MailboxCiphertextDescriptor,
    ): EncodedStreamDescriptor;
    decodeStreamDescriptor(input: {
        readonly canonicalBytesHex: string;
    }): DecodedStreamDescriptor;
    deriveSetupMailboxSlotHash(value: SetupMailboxSlot): ProtocolHash;
    encodeActionRandomnessDerivationInput(
        value: ActionRandomnessDerivationInput,
    ): EncodedActionRandomnessDerivationInput;
    decodeActionRandomnessDerivationInput(input: {
        readonly canonicalBytesHex: string;
    }): DecodedActionRandomnessDerivationInput;
    deriveActionRandomnessCommitment(input: {
        readonly actionRandomnessRootHex: string;
        readonly value: ActionRandomnessDerivationInput;
    }): ProtocolHash;
    encodePrivateRandomBlockInput(
        value: PrivateRandomBlockInput,
    ): EncodedPrivateRandomBlockInput;
    decodePrivateRandomBlockInput(input: {
        readonly canonicalBytesHex: string;
    }): DecodedPrivateRandomBlockInput;
    encodePrivateRandomCursor(
        value: PrivateRandomCursor,
    ): EncodedPrivateRandomCursor;
    decodePrivateRandomCursor(input: {
        readonly canonicalBytesHex: string;
    }): DecodedPrivateRandomCursor;
    generateProofSuiteCandidate(): GeneratedProofSuiteCandidate;
    encodeSignedMailboxEnvelope(
        value: SignedMailboxEnvelope,
    ): EncodedSignedMailboxEnvelope;
    decodeSignedMailboxEnvelope(input: {
        readonly canonicalBytesHex: string;
    }): DecodedSignedMailboxEnvelope;
    deriveMailboxKemCiphertextHash(input: {
        readonly kemCiphertextHex: string;
    }): ProtocolHash;
    deriveMailboxEnvelopeHash(value: UnsignedMailboxEnvelope): ProtocolHash;
    generateBgvTargetDecryptionShareFromLocalShare(
        input: BgvTargetDecryptionLocalCommandContext & {
            readonly trusteeIdentity: string;
            readonly localTargetShareWitness: unknown;
        },
    ): BgvTargetDecryptionShare;
    generateBgvTargetDecryptionShareProofMaterialFromLocalWitness(
        input: BgvTargetDecryptionLocalCommandContext & {
            readonly trusteeIdentity: string;
            readonly localTargetShareWitness: unknown;
            readonly targetDecryptionShare: unknown;
            readonly proofStatement: unknown;
            readonly proofRandomnessSeedHex: string;
            readonly proofRandomnessNonceHex: string;
        },
    ): BgvTargetDecryptionShareProofMaterial;
    describeBgvRnsParameters(): BgvRnsParametersDescription;
    describeCollectiveBgvSetupParameters(input?: {
        readonly participantCount?: number;
    }): BgvCollectiveSetupParametersDescription;
    verifyPrivateVssShareEnvelope(input: {
        readonly setupContext: unknown;
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly sourceTrusteeCoefficientCommitmentRecord: unknown;
        readonly sourceTrusteeCoefficientCommitmentMaterialRecords: readonly unknown[];
        readonly privateEnvelope: unknown;
        readonly expectedPrivateEnvelopeHash?: ProtocolHash;
        readonly expectedLocalVerificationRoot?: ProtocolHash;
    }): BgvPrivateVssShareEnvelopeVerification;
    generateTrusteeEvaluationKeyProof(
        input: BgvTrusteeEvaluationKeyProofInput,
    ): BgvTrusteeEvaluationKeyProofGeneration;
    describeTrusteeEvaluationKeyStatement(
        input: BgvTrusteeEvaluationKeyStatementInput,
    ): BgvTrusteeEvaluationKeyStatementDescription;
    computeSetupCommitmentFromOpening(input: {
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly sourceRnsLimbIndex: number;
        readonly sourceMessageModulus: number;
        readonly shamirCoefficientIndex: number;
        readonly messageCoefficients: readonly number[];
        readonly randomnessByColumn: readonly (readonly number[])[];
        readonly ringDegree: number;
    }): BgvSetupCommitmentOpeningComputation;
    computeVssCommittedMaterialCommitment(input: {
        readonly commitmentRole: string;
        readonly commitmentContext: Record<string, unknown>;
        readonly rnsLimbIndex: number;
        readonly rnsPrime: number;
        readonly ringDegree: number;
        readonly messageCoefficientBound?: number;
        readonly messageCoefficients: readonly number[];
        readonly materialSeedHex: string;
    }): BgvVssCommittedMaterialCommitmentComputation;
    generateVssShareLinkageProof(input: {
        readonly context: BgvVssShareLinkageProofContext;
        readonly ringDegree: number;
        readonly vssShareLinkage: Record<string, unknown>;
        readonly coefficientMessagesByShamirIndex: readonly (readonly number[])[];
        readonly recipientShareMessagesByItem: readonly (readonly number[])[];
        readonly carryWitnessesByItem: readonly (readonly number[])[];
        readonly vssCommittedMaterialSeedsByBoundMessage: readonly string[];
        readonly vssCommittedMaterialContextHashesByBoundMessage: readonly string[];
        readonly proofRandomnessSeedHex: string;
        readonly proofRandomnessNonceHex: string;
    }): BgvVssShareLinkageProofGeneration;
    generateSameSecretBridgeProof(input: {
        readonly context: BgvSameSecretBridgeProofContext;
        readonly ringDegree: number;
        readonly sameSecretLinkage: BgvTrusteeEvaluationKeySameSecretLinkage;
        readonly sameSecretBridge: BgvTrusteeEvaluationKeySameSecretBridge;
        readonly secretCoefficients: readonly number[];
        readonly negativeIndicatorCoefficients: readonly number[];
        readonly openingRandomnessByLimb: readonly (readonly (readonly number[])[])[];
        readonly vssCommittedMaterialSeedsByBoundMessage: readonly string[];
        readonly vssCommittedMaterialContextHashesByBoundMessage: readonly string[];
        readonly proofRandomnessSeedHex: string;
        readonly proofRandomnessNonceHex: string;
    }): BgvSameSecretBridgeProofGeneration;
    beginBgvTargetDecryptionResultRelease(input: {
        readonly releaseVerificationId: string;
        readonly acceptedSetupHandle: number;
        readonly targetAcceptedRecord: unknown;
        readonly targetCiphertexts: unknown;
        readonly targetCiphertextBinding: unknown;
        readonly targetShareProfile: unknown;
    }): BgvTargetDecryptionResultReleaseBegin;
    absorbBgvTargetDecryptionResultReleaseShare(input: {
        readonly releaseVerificationId: string;
        readonly targetShareProof: unknown;
    }): void;
    finishBgvTargetDecryptionResultRelease(input: {
        readonly releaseVerificationId: string;
    }): BgvTargetDecryptionResultReleaseCompletion;
    verifyLocalTrusteeSetupState(input: {
        readonly setupContext: unknown;
        readonly localStateCommitment: unknown;
    }): BgvLocalTrusteeSetupStateVerification;
};

export type TranscriptCoreKernelContextOwner = Pick<
    TranscriptCoreKernel,
    'exportedFunctionNames'
>;

export type PublishedSdkKernel = Pick<
    TranscriptCoreKernel,
    | 'beginAcceptedSetupSession'
    | 'exportedFunctionNames'
    | 'verifyPrivateVssShareEnvelope'
    | 'beginBgvTargetDecryptionResultRelease'
    | 'absorbBgvTargetDecryptionResultReleaseShare'
    | 'finishBgvTargetDecryptionResultRelease'
>;

type KernelMethodInput<MethodName extends keyof TranscriptCoreKernel> =
    TranscriptCoreKernel[MethodName] extends (input: infer Input) => unknown
        ? NonNullable<Input>
        : never;

type KernelWireInput<Input> = Input extends unknown
    ? Omit<Input, 'statementFamily'>
    : never;

type KernelCommandFromMethod<
    CommandName extends string,
    MethodName extends keyof TranscriptCoreKernel,
> = Readonly<
    {
        readonly command: CommandName;
    } & KernelWireInput<KernelMethodInput<MethodName>>
>;

type TranscriptCoreKernelCommand =
    | KernelCommandFromMethod<
          'DeriveCanonicalObjectHash',
          'deriveCanonicalObjectHash'
      >
    | KernelCommandFromMethod<
          'ValidateCanonicalFoundationValue',
          'validateCanonicalFoundationValue'
      >
    | Readonly<{
          readonly command: 'DeriveCeremonyContextHash';
          readonly value: CeremonyContextInput;
      }>
    | Readonly<{
          readonly command: 'DeriveActionContextHash';
          readonly value: ActionContextInput;
      }>
    | Readonly<{
          readonly command: 'EncodeMailboxKeyScheduleInput';
          readonly value: MailboxKeyScheduleInput;
      }>
    | KernelCommandFromMethod<
          'DecodeMailboxKeyScheduleInput',
          'decodeMailboxKeyScheduleInput'
      >
    | Readonly<{
          readonly command: 'EncodeMailboxAssociatedData';
          readonly value: MailboxAssociatedData;
      }>
    | KernelCommandFromMethod<
          'DecodeMailboxAssociatedData',
          'decodeMailboxAssociatedData'
      >
    | Readonly<{
          readonly command: 'EncodeStreamDescriptor';
          readonly value: MailboxCiphertextDescriptor;
      }>
    | KernelCommandFromMethod<
          'DecodeStreamDescriptor',
          'decodeStreamDescriptor'
      >
    | Readonly<{
          readonly command: 'DeriveSetupMailboxSlotHash';
          readonly value: SetupMailboxSlot;
      }>
    | Readonly<{
          readonly command: 'EncodeActionRandomnessDerivationInput';
          readonly value: ActionRandomnessDerivationInput;
      }>
    | KernelCommandFromMethod<
          'DecodeActionRandomnessDerivationInput',
          'decodeActionRandomnessDerivationInput'
      >
    | KernelCommandFromMethod<
          'DeriveActionRandomnessCommitment',
          'deriveActionRandomnessCommitment'
      >
    | Readonly<{
          readonly command: 'EncodePrivateRandomBlockInput';
          readonly value: PrivateRandomBlockInput;
      }>
    | KernelCommandFromMethod<
          'DecodePrivateRandomBlockInput',
          'decodePrivateRandomBlockInput'
      >
    | Readonly<{
          readonly command: 'EncodePrivateRandomCursor';
          readonly value: PrivateRandomCursor;
      }>
    | KernelCommandFromMethod<
          'DecodePrivateRandomCursor',
          'decodePrivateRandomCursor'
      >
    | Readonly<{
          readonly command: 'GenerateProofSuiteCandidate';
      }>
    | Readonly<{
          readonly command: 'EncodeSignedMailboxEnvelope';
          readonly value: SignedMailboxEnvelope;
      }>
    | KernelCommandFromMethod<
          'DecodeSignedMailboxEnvelope',
          'decodeSignedMailboxEnvelope'
      >
    | KernelCommandFromMethod<
          'DeriveMailboxKemCiphertextHash',
          'deriveMailboxKemCiphertextHash'
      >
    | Readonly<{
          readonly command: 'DeriveMailboxEnvelopeHash';
          readonly value: UnsignedMailboxEnvelope;
      }>
    | KernelCommandFromMethod<
          'GenerateBgvTargetDecryptionShareFromLocalShare',
          'generateBgvTargetDecryptionShareFromLocalShare'
      >
    | KernelCommandFromMethod<
          'GenerateBgvTargetDecryptionShareProofMaterialFromLocalWitness',
          'generateBgvTargetDecryptionShareProofMaterialFromLocalWitness'
      >
    | {
          readonly command: 'DescribeBgvRnsParameters';
      }
    | KernelCommandFromMethod<
          'DescribeCollectiveBgvSetupParameters',
          'describeCollectiveBgvSetupParameters'
      >
    | Readonly<
          {
              readonly command: 'VerifyCollectiveBgvSetup';
          } & BgvCollectiveSetupVerificationInput
      >
    | KernelCommandFromMethod<
          'VerifyPrivateVssShareEnvelope',
          'verifyPrivateVssShareEnvelope'
      >
    | KernelCommandFromMethod<
          'GenerateTrusteeEvaluationKeyProof',
          'generateTrusteeEvaluationKeyProof'
      >
    | KernelCommandFromMethod<
          'DescribeTrusteeEvaluationKeyStatement',
          'describeTrusteeEvaluationKeyStatement'
      >
    | KernelCommandFromMethod<
          'ComputeSetupCommitmentFromOpening',
          'computeSetupCommitmentFromOpening'
      >
    | KernelCommandFromMethod<
          'ComputeVssCommittedMaterialCommitment',
          'computeVssCommittedMaterialCommitment'
      >
    | KernelCommandFromMethod<
          'GenerateVssShareLinkageProof',
          'generateVssShareLinkageProof'
      >
    | KernelCommandFromMethod<
          'GenerateSameSecretBridgeProof',
          'generateSameSecretBridgeProof'
      >
    | KernelCommandFromMethod<
          'BeginBgvTargetDecryptionResultRelease',
          'beginBgvTargetDecryptionResultRelease'
      >
    | KernelCommandFromMethod<
          'AbsorbBgvTargetDecryptionResultReleaseShare',
          'absorbBgvTargetDecryptionResultReleaseShare'
      >
    | KernelCommandFromMethod<
          'FinishBgvTargetDecryptionResultRelease',
          'finishBgvTargetDecryptionResultRelease'
      >
    | KernelCommandFromMethod<
          'VerifyLocalTrusteeSetupState',
          'verifyLocalTrusteeSetupState'
      >;

type TranscriptCoreKernelExports = WebAssembly.Exports & {
    memory?: WebAssembly.Memory;
    sealed_lattice_allocate?: (length: number) => number;
    sealed_lattice_accepted_setup_canonical_stream_begin?: (
        setupSessionHandle: number,
        familyCode: number,
        materialRootPointer: number,
        materialRootLength: number,
        descriptorPointer: number,
        descriptorLength: number,
        statusPointer: number,
        totalByteLengthPointer: number,
        chunkCountPointer: number,
    ) => number;
    sealed_lattice_accepted_setup_command_with_length?: (
        pointer: number,
        length: number,
        sessionHandle: number,
        outputLengthPointer: number,
    ) => number;
    sealed_lattice_accepted_setup_session_begin?: (
        statusPointer: number,
    ) => number;
    sealed_lattice_accepted_setup_session_cancel?: (
        sessionHandle: number,
    ) => number;
    sealed_lattice_bgv_canonical_stream_absorb_chunk?: (
        handle: number,
        chunkIndex: number,
        chunkPointer: number,
        chunkLength: number,
    ) => number;
    sealed_lattice_bgv_canonical_stream_begin?: (
        familyCode: number,
        materialRootPointer: number,
        materialRootLength: number,
        descriptorPointer: number,
        descriptorLength: number,
        statusPointer: number,
        totalByteLengthPointer: number,
        chunkCountPointer: number,
    ) => number;
    sealed_lattice_bgv_canonical_stream_cancel?: (handle: number) => number;
    sealed_lattice_bgv_canonical_stream_finish?: (handle: number) => number;
    sealed_lattice_bgv_canonical_material_reader_begin?: (
        familyCode: number,
        materialRootPointer: number,
        materialRootLength: number,
        statusPointer: number,
        totalByteLengthPointer: number,
        chunkCountPointer: number,
    ) => number;
    sealed_lattice_bgv_canonical_material_reader_cancel?: (
        handle: number,
    ) => number;
    sealed_lattice_bgv_canonical_material_reader_finish?: (
        handle: number,
    ) => number;
    sealed_lattice_bgv_canonical_material_reader_read_chunk?: (
        handle: number,
        chunkIndex: number,
        outputPointer: number,
        outputLength: number,
    ) => number;
    sealed_lattice_canonical_stream_absorb_chunk?: (
        handle: number,
        chunkIndex: number,
        chunkPointer: number,
        chunkLength: number,
    ) => number;
    sealed_lattice_canonical_stream_begin_verifier?: (
        streamDomain: number,
        descriptorPointer: number,
        descriptorLength: number,
        statusPointer: number,
        totalByteLengthPointer: number,
        chunkCountPointer: number,
    ) => number;
    sealed_lattice_canonical_stream_begin_writer?: (
        streamDomain: number,
        totalByteLength: number,
        statusPointer: number,
        chunkCountPointer: number,
    ) => number;
    sealed_lattice_canonical_stream_cancel?: (handle: number) => number;
    sealed_lattice_canonical_stream_finish_verifier?: (
        handle: number,
    ) => number;
    sealed_lattice_canonical_stream_finish_writer?: (
        handle: number,
        statusPointer: number,
        outputLengthPointer: number,
    ) => number;
    sealed_lattice_mailbox_gcm_authenticate_chunk?: (
        handle: number,
        chunkPointer: number,
        chunkLength: number,
    ) => number;
    sealed_lattice_mailbox_gcm_begin_encryptor?: (
        keyPointer: number,
        keyLength: number,
        noncePointer: number,
        nonceLength: number,
        associatedDataPointer: number,
        associatedDataLength: number,
        totalByteLength: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_mailbox_gcm_begin_verifier?: (
        keyPointer: number,
        keyLength: number,
        noncePointer: number,
        nonceLength: number,
        associatedDataPointer: number,
        associatedDataLength: number,
        totalByteLength: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_mailbox_gcm_cancel?: (handle: number) => number;
    sealed_lattice_mailbox_gcm_decrypt_chunk?: (
        handle: number,
        chunkPointer: number,
        chunkLength: number,
    ) => number;
    sealed_lattice_mailbox_gcm_encrypt_chunk?: (
        handle: number,
        chunkPointer: number,
        chunkLength: number,
    ) => number;
    sealed_lattice_mailbox_gcm_finish_authentication?: (
        handle: number,
        tagPointer: number,
        tagLength: number,
    ) => number;
    sealed_lattice_mailbox_gcm_finish_decryptor?: (handle: number) => number;
    sealed_lattice_mailbox_gcm_finish_encryptor?: (
        handle: number,
        tagPointer: number,
        tagLength: number,
    ) => number;
    sealed_lattice_deallocate?: (pointer: number, length: number) => void;
    sealed_lattice_local_storage_root_command?: (
        command: number,
        inputPointer: number,
        inputLength: number,
        statusPointer: number,
        outputLengthPointer: number,
    ) => number;
    sealed_lattice_state_verifier_begin?: (
        configurationPointer: number,
        configurationLength: number,
        capabilityPointer: number,
        capabilityLength: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_state_verifier_cancel?: (
        sessionHandle: number,
        capabilityPointer: number,
        capabilityLength: number,
    ) => number;
    sealed_lattice_state_verifier_certify_intent?: (
        sessionHandle: number,
        capabilityPointer: number,
        capabilityLength: number,
        verifiedIntentHandle: number,
        canonicalStateCertificatePointer: number,
        canonicalStateCertificateLength: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_state_verifier_certify_unordered_votes?: (
        sessionHandle: number,
        capabilityPointer: number,
        capabilityLength: number,
        verifiedIntentHandle: number,
        framedCanonicalVoteCarriersPointer: number,
        framedCanonicalVoteCarriersLength: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_state_verifier_describe?: (
        sessionHandle: number,
        capabilityPointer: number,
        capabilityLength: number,
        verifiedObjectHandle: number,
        outputPointer: number,
        outputLength: number,
    ) => number;
    sealed_lattice_state_verifier_release?: (
        sessionHandle: number,
        capabilityPointer: number,
        capabilityLength: number,
        verifiedObjectHandle: number,
    ) => number;
    sealed_lattice_state_verifier_finish_output?: (
        sessionHandle: number,
        capabilityPointer: number,
        capabilityLength: number,
        streamHandle: number,
        verifiedReservationHandle: number,
        canonicalOutputIntentCarrierPointer: number,
        canonicalOutputIntentCarrierLength: number,
        canonicalStateCertificatePointer: number,
        canonicalStateCertificateLength: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_state_verifier_prepare_output?: (
        sessionHandle: number,
        capabilityPointer: number,
        capabilityLength: number,
        streamHandle: number,
        verifiedReservationHandle: number,
        canonicalOutputIntentCarrierPointer: number,
        canonicalOutputIntentCarrierLength: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_state_verifier_prepare_recovery?: (
        sessionHandle: number,
        capabilityPointer: number,
        capabilityLength: number,
        subjectParticipantIdentityPointer: number,
        subjectParticipantIdentityLength: number,
        capabilityKindCode: number,
        predecessorRecoveryHandle: number,
        preservedIntentHandle: number,
        canonicalRecoveryTransitionCarrierPointer: number,
        canonicalRecoveryTransitionCarrierLength: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_state_verifier_prepare_witness_vote?: (
        sessionHandle: number,
        capabilityPointer: number,
        capabilityLength: number,
        verifiedIntentHandle: number,
        witnessParticipantIdentityPointer: number,
        witnessParticipantIdentityLength: number,
        signatureMessageOutputPointer: number,
        signatureMessageOutputLength: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_state_verifier_prepare_reservation?: (
        sessionHandle: number,
        capabilityPointer: number,
        capabilityLength: number,
        subjectParticipantIdentityPointer: number,
        subjectParticipantIdentityLength: number,
        capabilityKindCode: number,
        predecessorRecoveryHandle: number,
        expectedAuthorizationHashPointer: number,
        expectedAuthorizationHashLength: number,
        canonicalReservationIntentCarrierPointer: number,
        canonicalReservationIntentCarrierLength: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_state_verifier_verify_recovery?: (
        sessionHandle: number,
        capabilityPointer: number,
        capabilityLength: number,
        subjectParticipantIdentityPointer: number,
        subjectParticipantIdentityLength: number,
        capabilityKindCode: number,
        predecessorRecoveryHandle: number,
        preservedIntentHandle: number,
        canonicalRecoveryTransitionCarrierPointer: number,
        canonicalRecoveryTransitionCarrierLength: number,
        canonicalStateCertificatePointer: number,
        canonicalStateCertificateLength: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_state_verifier_verify_reservation?: (
        sessionHandle: number,
        capabilityPointer: number,
        capabilityLength: number,
        subjectParticipantIdentityPointer: number,
        subjectParticipantIdentityLength: number,
        capabilityKindCode: number,
        predecessorRecoveryHandle: number,
        expectedAuthorizationHashPointer: number,
        expectedAuthorizationHashLength: number,
        canonicalReservationIntentCarrierPointer: number,
        canonicalReservationIntentCarrierLength: number,
        canonicalStateCertificatePointer: number,
        canonicalStateCertificateLength: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_state_verifier_finish_witness_vote?: (
        sessionHandle: number,
        capabilityPointer: number,
        capabilityLength: number,
        preparedHandle: number,
        signaturePointer: number,
        signatureLength: number,
        carrierOutputPointer: number,
        carrierOutputLength: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_transcript_core_command_with_length?: (
        pointer: number,
        length: number,
        outputLengthPointer: number,
    ) => number;
};

type KernelSuccessResponse<T> = {
    readonly success: true;
    readonly value: T;
};

type KernelFailureResponse = {
    readonly success: false;
    readonly error: CanonicalError;
};

export type {
    TranscriptCoreKernelCommand,
    TranscriptCoreKernelExports,
    KernelSuccessResponse,
    KernelFailureResponse,
};
