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
    BgvPrivateVssShareEnvelopeVerification,
    BgvRnsParametersDescription,
} from './kernel-types/bgv.js';

export type {
    BgvCollectiveSetupParametersDescription,
    BgvCollectiveSetupVerification,
    BgvPrivateVssShareEnvelopeVerification,
    BgvRnsParametersDescription,
} from './kernel-types/bgv.js';

export type BgvCollectiveSetupVerificationInput = Readonly<{
    readonly setupPackage: unknown;
    readonly expectedSetupPackageHash?: ProtocolHash;
    readonly expectedManifestHash?: ProtocolHash;
    readonly expectedRosterHash?: ProtocolHash;
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
    sealed_lattice_common_proof_begin_generation?: (
        preparedGenerationHandle: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_common_proof_discard_prepared_generation?: (
        handle: number,
    ) => number;
    sealed_lattice_common_proof_discard_prepared_verification?: (
        handle: number,
    ) => number;
    sealed_lattice_common_proof_resume_generation?: (
        preparedGenerationHandle: number,
        authenticatedCheckpointStatePointer: number,
        authenticatedCheckpointStateByteLength: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_common_proof_generation_checkpoint_state_byte_length?: () => number;
    sealed_lattice_common_proof_generation_describe_checkpoint?: (
        operationHandle: number,
        safeBoundaryOrdinalPointer: number,
        stateByteLengthPointer: number,
        cursorCountPointer: number,
    ) => number;
    sealed_lattice_common_proof_generation_copy_checkpoint_state?: (
        operationHandle: number,
        outputPointer: number,
        outputByteLength: number,
    ) => number;
    sealed_lattice_common_proof_generation_checkpoint_cursor_byte_length?: (
        operationHandle: number,
        cursorIndex: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_common_proof_generation_copy_checkpoint_cursor?: (
        operationHandle: number,
        cursorIndex: number,
        outputPointer: number,
        outputByteLength: number,
    ) => number;
    sealed_lattice_common_proof_generation_copy_checkpoint_stable_attempt_binding_hash?: (
        operationHandle: number,
        outputPointer: number,
        outputByteLength: number,
    ) => number;
    sealed_lattice_common_proof_generation_acknowledge_checkpoint?: (
        operationHandle: number,
    ) => number;
    sealed_lattice_common_proof_generation_discard_checkpoint?: (
        operationHandle: number,
    ) => number;
    sealed_lattice_common_proof_generation_acknowledge_output_chunk?: (
        operationHandle: number,
        expectedChunkIndex: number,
    ) => number;
    sealed_lattice_common_proof_generation_confirm_output_readback?: (
        operationHandle: number,
        chunkIndex: number,
        readbackPointer: number,
        readbackLength: number,
    ) => number;
    sealed_lattice_common_proof_generation_copy_output_chunk?: (
        operationHandle: number,
        expectedChunkIndex: number,
        outputPointer: number,
        outputLength: number,
    ) => number;
    sealed_lattice_common_proof_generation_copy_storage_request?: (
        operationHandle: number,
        outputPointer: number,
        outputLength: number,
    ) => number;
    sealed_lattice_common_proof_generation_finish?: (
        operationHandle: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_common_proof_generation_poll?: (
        operationHandle: number,
        pollKindPointer: number,
        primaryValuePointer: number,
        secondaryValuePointer: number,
    ) => number;
    sealed_lattice_common_proof_generation_release_cancelled?: (
        operationHandle: number,
    ) => number;
    sealed_lattice_common_proof_generation_retire_failed?: (
        operationHandle: number,
    ) => number;
    sealed_lattice_common_proof_generation_request_cancellation?: (
        operationHandle: number,
    ) => number;
    sealed_lattice_common_proof_generation_supply_storage_response?: (
        operationHandle: number,
        responsePointer: number,
        responseLength: number,
    ) => number;
    sealed_lattice_common_proof_release_generated_proof?: (
        handle: number,
    ) => number;
    sealed_lattice_common_proof_application_frame_byte_length?: () => number;
    sealed_lattice_common_proof_prepare_application?: (
        terminalCapabilityHandle: number,
        storageRootHandle: number,
        storageRootCapabilityPointer: number,
        predecessorNamespaceSequence: bigint,
        predecessorAuthenticatedHeadDigestPointer: number,
        storageInstanceIdentityPointer: number,
        durableFrameOutputPointer: number,
        durableFrameOutputByteLength: number,
        proofApplicationSlotHashOutputPointer: number,
        proofApplicationSlotHashOutputByteLength: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_common_proof_confirm_application?: (
        pendingHandle: number,
        storageRootHandle: number,
        storageRootCapabilityPointer: number,
        predecessorNamespaceSequence: bigint,
        predecessorAuthenticatedHeadDigestPointer: number,
        successorNamespaceSequence: bigint,
        successorAuthenticatedHeadDigestPointer: number,
        storageInstanceIdentityPointer: number,
        authenticatedDurableFramePointer: number,
        authenticatedDurableFrameByteLength: number,
    ) => number;
    sealed_lattice_common_proof_abort_application?: (
        pendingHandle: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_common_proof_release_suite?: (handle: number) => number;
    sealed_lattice_common_proof_select_suite?: (
        canonicalSuiteRecordPointer: number,
        canonicalSuiteRecordLength: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_common_proof_begin_verification?: (
        preparedVerificationHandle: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_common_proof_discard_verified_proof?: (
        handle: number,
    ) => number;
    sealed_lattice_common_proof_verification_absorb_input_chunk?: (
        operationHandle: number,
        chunkIndex: number,
        chunkPointer: number,
        chunkLength: number,
    ) => number;
    sealed_lattice_common_proof_verification_cancel?: (
        operationHandle: number,
    ) => number;
    sealed_lattice_common_proof_verification_finish?: (
        operationHandle: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_common_proof_verification_finish_input?: (
        operationHandle: number,
    ) => number;
    sealed_lattice_common_proof_verification_poll?: (
        operationHandle: number,
        pollKindPointer: number,
        primaryValuePointer: number,
        secondaryValuePointer: number,
    ) => number;
    sealed_lattice_common_proof_verification_supply_readback_chunk?: (
        operationHandle: number,
        chunkIndex: number,
        chunkPointer: number,
        chunkLength: number,
    ) => number;
    sealed_lattice_local_storage_root_command?: (
        command: number,
        inputPointer: number,
        inputLength: number,
        statusPointer: number,
        outputLengthPointer: number,
    ) => number;
    sealed_lattice_board_verifier_begin?: (
        canonicalSuiteRecordPointer: number,
        canonicalSuiteRecordLength: number,
        canonicalManifestPointer: number,
        canonicalManifestLength: number,
        canonicalRosterPointer: number,
        canonicalRosterLength: number,
        canonicalActionDefinitionPointer: number,
        canonicalActionDefinitionLength: number,
        canonicalBoardPolicyPointer: number,
        canonicalBoardPolicyLength: number,
        ceremonyIdentifierPointer: number,
        ceremonyIdentifierLength: number,
        actionIdentifierPointer: number,
        actionIdentifierLength: number,
        expectedSuiteIdentifierPointer: number,
        expectedSuiteIdentifierLength: number,
        expectedCeremonyContextHashPointer: number,
        expectedCeremonyContextHashLength: number,
        expectedActionContextHashPointer: number,
        expectedActionContextHashLength: number,
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
    sealed_lattice_state_producer_command?: (
        command: number,
        inputPointer: number,
        inputLength: number,
        statusPointer: number,
        outputLengthPointer: number,
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
