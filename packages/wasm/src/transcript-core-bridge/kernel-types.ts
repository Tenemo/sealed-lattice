import type {
    CanonicalError,
    MailboxAssociatedData,
    MailboxCiphertextDescriptor,
    MailboxKeyScheduleInput,
    ProtocolHash,
    SetupMailboxSlot,
    SignedMailboxEnvelope,
    UnsignedMailboxEnvelope,
    VerificationResult,
} from '@sealed-lattice/types';

export type {
    MailboxAssociatedData,
    MailboxCiphertextDescriptor,
    MailboxKeyScheduleInput,
    SetupMailboxSlot,
    SignedMailboxEnvelope,
    UnsignedMailboxEnvelope,
} from '@sealed-lattice/types';

import type {
    BgvCollectiveSetupParametersDescription,
    BgvCollectiveSetupVerification,
    BgvLatticeAnchorCommitmentComputation,
    BgvPublicKeyShareStatementContext,
    BgvTrusteeEvaluationKeyProofGeneration,
    BgvTrusteeEvaluationKeySameSecretBridge,
    BgvTrusteeEvaluationKeySameSecretLinkage,
    BgvTrusteeEvaluationKeyStatementContext,
    BgvTrusteeEvaluationKeyStatementKey,
    BgvPrivateVssShareEnvelopeVerification,
    BgvRnsParametersDescription,
    BgvVssCommittedMaterialCommitmentComputation,
    BgvSetupCommitmentOpeningComputation,
} from './kernel-types/bgv.js';

export type {
    BgvCollectiveSetupParametersDescription,
    BgvCollectiveSetupVerification,
    BgvLatticeAnchorCommitmentComputation,
    BgvTrusteeEvaluationKeyProofGeneration,
    BgvPrivateVssShareEnvelopeVerification,
    BgvRnsParametersDescription,
    BgvVssCommittedMaterialCommitmentComputation,
    BgvSetupCommitmentOpeningComputation,
} from './kernel-types/bgv.js';

export type BgvCollectiveSetupVerificationInput = Readonly<{
    readonly setupPackage: unknown;
    readonly expectedSetupPackageHash?: ProtocolHash;
    readonly expectedManifestHash?: ProtocolHash;
    readonly expectedRosterHash?: ProtocolHash;
}>;

export type DecodedProofApplicationBinding = Readonly<{
    readonly canonicalBytesHex: string;
    readonly applicationSlotCanonicalBytesHex: string;
    readonly applicationSlotHash: ProtocolHash;
    readonly suiteIdentifier: ProtocolHash;
    readonly ceremonyContextHash: ProtocolHash;
    readonly actionContextHash: ProtocolHash;
    readonly applicationStatementSchemaIdentifier: number;
    readonly rosterPosition: number | null;
    readonly schedulePosition: number | null;
    readonly producerSequence: string | null;
    readonly proofHeaderHash: ProtocolHash;
    readonly proofStreamDescriptorCanonicalBytesHex: string;
    readonly proofByteLength: string;
}>;

export type FoundationOptionDefinitionIngress = Readonly<{
    readonly displayLabelUtf8Hex: string;
    readonly optionIdentifier: string;
    readonly optionIndex: number;
}>;

export type EncodedFoundationManifest = Readonly<{
    readonly canonicalBytesHex: string;
    readonly manifestHash: ProtocolHash;
}>;

export type FoundationManifestVerification = VerificationResult<{
    readonly manifestHash: ProtocolHash;
}>;

export type EncodedFoundationActionDefinition = Readonly<{
    readonly actionDefinitionHash: ProtocolHash;
    readonly canonicalBytesHex: string;
}>;

export type FoundationActionDefinitionVerification = VerificationResult<{
    readonly actionDefinitionHash: ProtocolHash;
}>;

export type EncodedFoundationBoardPolicy = Readonly<{
    readonly boardPolicyHash: ProtocolHash;
    readonly canonicalBytesHex: string;
}>;

export type FoundationBoardPolicyVerification = VerificationResult<{
    readonly boardPolicyHash: ProtocolHash;
}>;

export type FoundationSuiteRecordVerification = VerificationResult<{
    readonly suiteId: ProtocolHash;
}>;

export type FoundationCeremonyContextVerification = VerificationResult<{
    readonly ceremonyContextHash: ProtocolHash;
    readonly manifestHash: ProtocolHash;
    readonly rosterHash: ProtocolHash;
    readonly suiteId: ProtocolHash;
}>;

export type FoundationActionContextVerification = VerificationResult<{
    readonly actionContextHash: ProtocolHash;
    readonly actionDefinitionHash: ProtocolHash;
    readonly boardPolicyHash: ProtocolHash;
    readonly ceremonyContextHash: ProtocolHash;
    readonly rosterHash: ProtocolHash;
    readonly submissionCutoffHash: ProtocolHash;
    readonly suiteId: ProtocolHash;
}>;

export type EncodedMailboxKeyScheduleInput = Readonly<{
    readonly canonicalBytesHex: string;
    readonly hkdfExtractSaltHex: string;
}>;

export type DecodedMailboxKeyScheduleInput = Readonly<{
    readonly value: MailboxKeyScheduleInput;
}>;

export type EncodedMailboxAssociatedData = Readonly<{
    readonly canonicalBytesHex: string;
}>;

export type DecodedMailboxAssociatedData = Readonly<{
    readonly value: MailboxAssociatedData;
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

export type EncodedPrivateRandomCursor = Readonly<{
    readonly canonicalBytesHex: string;
}>;

export type DecodedPrivateRandomCursor = Readonly<{
    readonly value: PrivateRandomCursor;
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

type BgvTrusteeEvaluationKeyContext = BgvTrusteeEvaluationKeyStatementContext;

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
    readonly keys: readonly Key[];
}>;

type BgvTrusteeEvaluationKeyStatementInput =
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
                  BgvPublicKeyShareStatementContext,
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
    readonly proofRandomnessSeedHex: string;
}>;

type BgvTrusteeEvaluationKeyProofInput =
    | Readonly<
          Extract<
              BgvTrusteeEvaluationKeyStatementInput,
              { readonly statementFamily: 'trustee-evaluation-key' }
          > &
              BgvTrusteeEvaluationKeyProofCommonInput & {
                  readonly openingRandomnessBySourceLimbAndCommitmentLimb: readonly (readonly (readonly (readonly number[])[])[])[];
              }
      >
    | Readonly<
          Extract<
              BgvTrusteeEvaluationKeyStatementInput,
              { readonly statementFamily: 'public-key-share' }
          > &
              BgvTrusteeEvaluationKeyProofCommonInput & {
                  readonly vssCommittedMaterialSeedsByBoundMessage: readonly string[];
              }
      >;

export type TranscriptCoreKernel = {
    beginAcceptedSetupSession(): AcceptedSetupSession;
    deriveCanonicalObjectHash(input: { readonly value: unknown }): ProtocolHash;
    encodeFoundationManifest(input: {
        readonly displayTitleUtf8Hex: string;
        readonly optionDefinitions: readonly FoundationOptionDefinitionIngress[];
    }): EncodedFoundationManifest;
    verifyFoundationManifest(input: {
        readonly canonicalBytesHex: string;
    }): FoundationManifestVerification;
    encodeFoundationActionDefinition(input: {
        readonly submissionCutoffUnixMilliseconds: string;
        readonly topCount: number;
    }): EncodedFoundationActionDefinition;
    verifyFoundationActionDefinition(input: {
        readonly canonicalBytesHex: string;
    }): FoundationActionDefinitionVerification;
    encodeFoundationBoardPolicy(input: {
        readonly boardOriginIdentifier: string;
    }): EncodedFoundationBoardPolicy;
    verifyFoundationBoardPolicy(input: {
        readonly canonicalBytesHex: string;
    }): FoundationBoardPolicyVerification;
    verifyFoundationSuiteRecord(input: {
        readonly canonicalBytesHex: string;
    }): FoundationSuiteRecordVerification;
    verifyFoundationCeremonyContext(input: {
        readonly canonicalManifestBytesHex: string;
        readonly canonicalRosterBytesHex: string;
        readonly canonicalSuiteRecordBytesHex: string;
        readonly ceremonyIdentifier: string;
        readonly expectedSuiteId: ProtocolHash;
    }): FoundationCeremonyContextVerification;
    verifyFoundationActionContext(input: {
        readonly actionIdentifier: string;
        readonly canonicalActionDefinitionBytesHex: string;
        readonly canonicalBoardPolicyBytesHex: string;
        readonly canonicalManifestBytesHex: string;
        readonly canonicalRosterBytesHex: string;
        readonly canonicalSuiteRecordBytesHex: string;
        readonly ceremonyIdentifier: string;
        readonly expectedCeremonyContextHash: ProtocolHash;
        readonly expectedSuiteId: ProtocolHash;
    }): FoundationActionContextVerification;
    decodeProofApplicationBinding(input: {
        readonly canonicalBytesHex: string;
    }): DecodedProofApplicationBinding;
    encodeMailboxKeyScheduleInput(input: {
        readonly kemCiphertextHex: string;
        readonly value: MailboxKeyScheduleInput;
    }): EncodedMailboxKeyScheduleInput;
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
    encodePrivateRandomCursor(
        value: PrivateRandomCursor,
    ): EncodedPrivateRandomCursor;
    decodePrivateRandomCursor(input: {
        readonly canonicalBytesHex: string;
    }): DecodedPrivateRandomCursor;
    encodeSignedMailboxEnvelope(
        value: SignedMailboxEnvelope,
    ): EncodedSignedMailboxEnvelope;
    decodeSignedMailboxEnvelope(input: {
        readonly canonicalBytesHex: string;
    }): DecodedSignedMailboxEnvelope;
    deriveMailboxEnvelopeHash(value: UnsignedMailboxEnvelope): ProtocolHash;
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
    }): BgvPrivateVssShareEnvelopeVerification;
    generateTrusteeEvaluationKeyProof(
        input: BgvTrusteeEvaluationKeyProofInput,
    ): BgvTrusteeEvaluationKeyProofGeneration;
    computeLatticeAnchorCommitmentFromOpening(input: {
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly commitmentDataPrimeIndex: number;
        readonly secretContributionCoefficients: readonly number[];
        readonly openingPolynomials: readonly (readonly number[])[];
    }): BgvLatticeAnchorCommitmentComputation;
    computeSetupCommitmentFromOpening(input: {
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly sourceRnsLimbIndex: number;
        readonly shamirCoefficientIndex: number;
        readonly messageCoefficients: readonly number[];
        readonly randomnessByCommitmentLimb: readonly (readonly (readonly number[])[])[];
        readonly ringDegree: number;
    }): BgvSetupCommitmentOpeningComputation;
    computeVssCommittedMaterialCommitment(input: {
        readonly commitmentRole: string;
        readonly commitmentContext: Record<string, unknown>;
        readonly rnsLimbIndex: number;
        readonly messageCoefficients: readonly number[];
        readonly materialSeedHex: string;
    }): BgvVssCommittedMaterialCommitmentComputation;
};

export type TranscriptCoreKernelContextOwner = object;

export type PublishedSdkKernel = Pick<
    TranscriptCoreKernel,
    | 'beginAcceptedSetupSession'
    | 'encodeFoundationActionDefinition'
    | 'encodeFoundationBoardPolicy'
    | 'encodeFoundationManifest'
    | 'verifyFoundationActionContext'
    | 'verifyFoundationActionDefinition'
    | 'verifyFoundationBoardPolicy'
    | 'verifyFoundationCeremonyContext'
    | 'verifyFoundationManifest'
    | 'verifyFoundationSuiteRecord'
    | 'verifyPrivateVssShareEnvelope'
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
          'EncodeFoundationManifest',
          'encodeFoundationManifest'
      >
    | KernelCommandFromMethod<
          'VerifyFoundationManifest',
          'verifyFoundationManifest'
      >
    | KernelCommandFromMethod<
          'EncodeFoundationActionDefinition',
          'encodeFoundationActionDefinition'
      >
    | KernelCommandFromMethod<
          'VerifyFoundationActionDefinition',
          'verifyFoundationActionDefinition'
      >
    | KernelCommandFromMethod<
          'EncodeFoundationBoardPolicy',
          'encodeFoundationBoardPolicy'
      >
    | KernelCommandFromMethod<
          'VerifyFoundationBoardPolicy',
          'verifyFoundationBoardPolicy'
      >
    | KernelCommandFromMethod<
          'VerifyFoundationSuiteRecord',
          'verifyFoundationSuiteRecord'
      >
    | KernelCommandFromMethod<
          'VerifyFoundationCeremonyContext',
          'verifyFoundationCeremonyContext'
      >
    | KernelCommandFromMethod<
          'VerifyFoundationActionContext',
          'verifyFoundationActionContext'
      >
    | KernelCommandFromMethod<
          'DecodeProofApplicationBinding',
          'decodeProofApplicationBinding'
      >
    | Readonly<{
          readonly command: 'EncodeMailboxKeyScheduleInput';
          readonly kemCiphertextHex: string;
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
          readonly command: 'EncodePrivateRandomCursor';
          readonly value: PrivateRandomCursor;
      }>
    | KernelCommandFromMethod<
          'DecodePrivateRandomCursor',
          'decodePrivateRandomCursor'
      >
    | Readonly<{
          readonly command: 'EncodeSignedMailboxEnvelope';
          readonly value: SignedMailboxEnvelope;
      }>
    | KernelCommandFromMethod<
          'DecodeSignedMailboxEnvelope',
          'decodeSignedMailboxEnvelope'
      >
    | Readonly<{
          readonly command: 'DeriveMailboxEnvelopeHash';
          readonly value: UnsignedMailboxEnvelope;
      }>
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
          'ComputeLatticeAnchorCommitmentFromOpening',
          'computeLatticeAnchorCommitmentFromOpening'
      >
    | KernelCommandFromMethod<
          'ComputeSetupCommitmentFromOpening',
          'computeSetupCommitmentFromOpening'
      >
    | KernelCommandFromMethod<
          'ComputeVssCommittedMaterialCommitment',
          'computeVssCommittedMaterialCommitment'
      >;

type TranscriptCoreKernelExports = WebAssembly.Exports & {
    memory?: WebAssembly.Memory;
    sealed_lattice_allocate?: (length: number) => number;
    sealed_lattice_action_randomness_command?: (
        command: number,
        inputPointer: number,
        inputLength: number,
        statusPointer: number,
        outputLengthPointer: number,
    ) => number;
    sealed_lattice_accepted_setup_canonical_stream_begin?: (
        setupSessionHandle: number,
        familyCode: number,
        materialRootPointer: number,
        materialRootLength: number,
        descriptorPointer: number,
        descriptorLength: number,
        statusPointer: number,
        totalByteLengthPointer: number,
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
    ) => number;
    sealed_lattice_bgv_canonical_stream_cancel?: (handle: number) => number;
    sealed_lattice_bgv_canonical_stream_finish?: (handle: number) => number;
    sealed_lattice_bgv_canonical_material_reader_begin?: (
        familyCode: number,
        materialRootPointer: number,
        materialRootLength: number,
        statusPointer: number,
        totalByteLengthPointer: number,
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
    ) => number;
    sealed_lattice_canonical_stream_begin_writer?: (
        streamDomain: number,
        totalByteLength: number,
        statusPointer: number,
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
    sealed_lattice_board_verifier_begin?: (
        configurationPointer: number,
        configurationLength: number,
        capabilityPointer: number,
        capabilityLength: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_board_verifier_cached_carrier_length?: (
        sessionHandle: number,
        capabilityPointer: number,
        capabilityLength: number,
        verifiedObjectHandle: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_board_verifier_cancel?: (
        sessionHandle: number,
        capabilityPointer: number,
        capabilityLength: number,
    ) => number;
    sealed_lattice_board_verifier_copy_cached_carrier?: (
        sessionHandle: number,
        capabilityPointer: number,
        capabilityLength: number,
        verifiedObjectHandle: number,
        outputPointer: number,
        outputLength: number,
    ) => number;
    sealed_lattice_board_verifier_describe?: (
        sessionHandle: number,
        capabilityPointer: number,
        capabilityLength: number,
        verifiedObjectHandle: number,
        outputPointer: number,
        outputLength: number,
    ) => number;
    sealed_lattice_board_verifier_release?: (
        sessionHandle: number,
        capabilityPointer: number,
        capabilityLength: number,
        verifiedObjectHandle: number,
    ) => number;
    sealed_lattice_board_verifier_verify_unordered?: (
        sessionHandle: number,
        capabilityPointer: number,
        capabilityLength: number,
        framedCarrierPointer: number,
        framedCarrierLength: number,
        outputPointer: number,
        outputCapacity: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_finality_verifier_begin?: (
        configurationPointer: number,
        configurationLength: number,
        capabilityPointer: number,
        capabilityLength: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_finality_verifier_cancel?: (
        sessionHandle: number,
        capabilityPointer: number,
        capabilityLength: number,
    ) => number;
    sealed_lattice_finality_verifier_describe?: (
        sessionHandle: number,
        capabilityPointer: number,
        capabilityLength: number,
        verifiedFinalityHandle: number,
        outputPointer: number,
        outputLength: number,
    ) => number;
    sealed_lattice_finality_verifier_release?: (
        sessionHandle: number,
        capabilityPointer: number,
        capabilityLength: number,
        verifiedFinalityHandle: number,
    ) => number;
    sealed_lattice_finality_verifier_verify?: (
        sessionHandle: number,
        capabilityPointer: number,
        capabilityLength: number,
        verifiedEvaluatorReplayHandle: number,
        boardSessionHandle: number,
        boardCapabilityPointer: number,
        boardCapabilityLength: number,
        verifiedFinalityObjectHandlesPointer: number,
        verifiedFinalityObjectHandlesLength: number,
        canonicalStatementPointer: number,
        canonicalStatementLength: number,
        canonicalCertificatePointer: number,
        canonicalCertificateLength: number,
        statusPointer: number,
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
    sealed_lattice_state_verifier_prepare_reservation?: (
        sessionHandle: number,
        capabilityPointer: number,
        capabilityLength: number,
        subjectParticipantIdentityPointer: number,
        subjectParticipantIdentityLength: number,
        capabilityKindCode: number,
        expectedAuthorizationHashPointer: number,
        expectedAuthorizationHashLength: number,
        canonicalReservationIntentCarrierPointer: number,
        canonicalReservationIntentCarrierLength: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_state_verifier_verify_reservation?: (
        sessionHandle: number,
        capabilityPointer: number,
        capabilityLength: number,
        subjectParticipantIdentityPointer: number,
        subjectParticipantIdentityLength: number,
        capabilityKindCode: number,
        expectedAuthorizationHashPointer: number,
        expectedAuthorizationHashLength: number,
        canonicalReservationIntentCarrierPointer: number,
        canonicalReservationIntentCarrierLength: number,
        canonicalStateCertificatePointer: number,
        canonicalStateCertificateLength: number,
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
