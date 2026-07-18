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
    BgvRnsParametersDescription,
} from './kernel-types/bgv.js';

export type {
    BgvCollectiveSetupParametersDescription,
    BgvCollectiveSetupVerification,
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
      >;

type TranscriptCoreKernelExports = WebAssembly.Exports & {
    memory?: WebAssembly.Memory;
    sealed_lattice_aggregate_threshold_share_begin_recipient_authority?: (
        actionRandomnessHandle: number,
        localRecipientRosterPosition: number,
        boardVerifierSessionHandle: number,
        boardVerifierSessionCapabilityPointer: number,
        boardVerifierSessionCapabilityByteLength: number,
        orderedPublicRandomnessHandleBytesPointer: number,
        orderedPublicRandomnessHandleBytesByteLength: number,
        orderedDealerTerminalHandleBytesPointer: number,
        orderedDealerTerminalHandleBytesByteLength: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_aggregate_threshold_share_absorb_authenticated_recipient_payload?: (
        recipientAuthorityHandle: number,
        authenticatedPlaintextCapabilityHandle: number,
        canonicalSignedEnvelopePointer: number,
        canonicalSignedEnvelopeLength: number,
        canonicalPlaintextPointer: number,
        canonicalPlaintextLength: number,
    ) => number;
    sealed_lattice_aggregate_threshold_share_discard_recipient_authority?: (
        recipientAuthorityHandle: number,
    ) => number;
    sealed_lattice_setup_generation_authority_begin?: (
        selectedSuiteHandle: number,
        boardVerifierSessionHandle: number,
        boardVerifierSessionCapabilityPointer: number,
        boardVerifierSessionCapabilityByteLength: number,
        orderedPublicRandomnessObjectHandlesPointer: number,
        orderedPublicRandomnessObjectHandlesByteLength: number,
        actionRandomnessHandle: number,
        stateVerifierSessionHandle: number,
        stateVerifierSessionCapabilityPointer: number,
        stateVerifierSessionCapabilityByteLength: number,
        verifiedReservationHandle: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_setup_generation_authority_release?: (
        authorityHandle: number,
    ) => number;
    sealed_lattice_setup_generation_recipient_vss_payload_byte_length?: (
        authorityHandle: number,
        recipientRosterPosition: number,
        statusPointer: number,
    ) => bigint;
    sealed_lattice_setup_generation_recipient_vss_payload_open?: (
        authorityHandle: number,
        recipientRosterPosition: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_setup_generation_recipient_vss_payload_source_byte_length?: (
        sourceHandle: number,
        statusPointer: number,
    ) => bigint;
    sealed_lattice_setup_generation_recipient_vss_payload_source_recipient_roster_position?: (
        sourceHandle: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_setup_generation_recipient_vss_payload_read?: (
        sourceHandle: number,
        expectedOffset: bigint,
        outputPointer: number,
        outputByteLength: number,
    ) => number;
    sealed_lattice_setup_generation_recipient_vss_payload_cancel?: (
        sourceHandle: number,
    ) => number;
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
    sealed_lattice_accepted_setup_authority_release?: (
        authorityHandle: number,
    ) => number;
    sealed_lattice_accepted_setup_verification_begin?: (
        vssRecipientAuthorityHandle: number,
        canonicalPackagePointer: number,
        canonicalPackageByteLength: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_accepted_setup_verification_cancel?: (
        assemblyHandle: number,
    ) => number;
    sealed_lattice_prepackage_evaluator_source_catalog_begin?: (
        vssRecipientAuthorityHandle: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_prepackage_evaluator_source_catalog_complete?: (
        catalogHandle: number,
    ) => number;
    sealed_lattice_prepackage_evaluator_source_catalog_cancel?: (
        catalogHandle: number,
    ) => number;
    sealed_lattice_prepackage_evaluator_generated_proofs_bind_package?: (
        acceptedSetupAssemblyHandle: number,
        prepackageCatalogHandle: number,
    ) => number;
    sealed_lattice_evaluator_aggregate_store_source_request_byte_length?: () => number;
    sealed_lattice_evaluator_aggregate_begin_store_construction?: (
        prepackageCatalogHandle: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_evaluator_aggregate_store_construction_poll?: (
        sessionHandle: number,
        firstValuePointer: number,
        secondValuePointer: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_evaluator_aggregate_copy_store_source_request?: (
        sessionHandle: number,
        outputPointer: number,
        outputByteLength: number,
    ) => number;
    sealed_lattice_evaluator_aggregate_supply_store_source_range?: (
        sessionHandle: number,
        requestPointer: number,
        requestByteLength: number,
        sourcePointer: number,
        sourceByteLength: number,
    ) => number;
    sealed_lattice_evaluator_aggregate_copy_store_output_chunk?: (
        sessionHandle: number,
        chunkIndex: number,
        outputPointer: number,
        outputByteLength: number,
    ) => number;
    sealed_lattice_evaluator_aggregate_acknowledge_store_output_chunk?: (
        sessionHandle: number,
        chunkIndex: number,
    ) => number;
    sealed_lattice_evaluator_aggregate_finish_store_construction?: (
        sessionHandle: number,
    ) => number;
    sealed_lattice_evaluator_aggregate_describe_store?: (
        sessionHandle: number,
        outputPointer: number,
        outputByteLength: number,
    ) => number;
    sealed_lattice_evaluator_aggregate_begin_runtime_component_tree?: (
        sessionHandle: number,
        selectedSuiteHandle: number,
        logicalComponentOrdinal: number,
    ) => number;
    sealed_lattice_evaluator_aggregate_absorb_runtime_component_chunk?: (
        sessionHandle: number,
        logicalComponentOrdinal: number,
        chunkIndex: number,
        chunkPointer: number,
        chunkByteLength: number,
    ) => number;
    sealed_lattice_evaluator_aggregate_finish_runtime_component_tree?: (
        sessionHandle: number,
        logicalComponentOrdinal: number,
    ) => number;
    sealed_lattice_evaluator_aggregate_finalize_statement?: (
        sessionHandle: number,
        selectedSuiteHandle: number,
    ) => number;
    sealed_lattice_evaluator_aggregate_application_statement_byte_length?: (
        sessionHandle: number,
        statusPointer: number,
    ) => bigint;
    sealed_lattice_evaluator_aggregate_copy_application_statement?: (
        sessionHandle: number,
        outputPointer: number,
        outputByteLength: number,
    ) => number;
    sealed_lattice_evaluator_aggregate_absorb_store_material_chunk?: (
        sessionHandle: number,
        chunkIndex: number,
        chunkPointer: number,
        chunkByteLength: number,
    ) => number;
    sealed_lattice_evaluator_aggregate_finish_store_material?: (
        sessionHandle: number,
    ) => number;
    sealed_lattice_evaluator_aggregate_prepare_generation?: (
        sessionHandle: number,
        actionRandomnessHandle: number,
        stateVerifierSessionHandle: number,
        stateVerifierSessionCapabilityPointer: number,
        stateVerifierSessionCapabilityByteLength: number,
        verifiedReservationHandle: number,
        checkpointLineageIdentifierPointer: number,
        checkpointLineageIdentifierByteLength: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_evaluator_aggregate_prepare_resumed_generation?: (
        sessionHandle: number,
        actionRandomnessHandle: number,
        stateVerifierSessionHandle: number,
        stateVerifierSessionCapabilityPointer: number,
        stateVerifierSessionCapabilityByteLength: number,
        verifiedReservationHandle: number,
        checkpointLineageIdentifierPointer: number,
        checkpointLineageIdentifierByteLength: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_evaluator_aggregate_commit_generated_proof?: (
        sessionHandle: number,
        generatedCommonProofHandle: number,
    ) => number;
    sealed_lattice_evaluator_aggregate_take_package_statement_source?: (
        sessionHandle: number,
    ) => number;
    sealed_lattice_evaluator_aggregate_prepare_verification?: (
        selectedSuiteHandle: number,
        sessionHandle: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_evaluator_aggregate_finish_verification?: (
        sessionHandle: number,
        verifiedCommonProofHandle: number,
    ) => number;
    sealed_lattice_evaluator_aggregate_commit_verified_store?: (
        sessionHandle: number,
        acceptedSetupAssemblyHandle: number,
    ) => number;
    sealed_lattice_evaluator_aggregate_discard_session?: (
        sessionHandle: number,
    ) => number;
    sealed_lattice_galois_key_share_prepare_generation?: (
        selectedSuiteHandle: number,
        setupGenerationAuthorityHandle: number,
        actionRandomnessHandle: number,
        stateVerifierSessionHandle: number,
        stateVerifierSessionCapabilityPointer: number,
        stateVerifierSessionCapabilityByteLength: number,
        verifiedReservationHandle: number,
        boardVerifierSessionHandle: number,
        boardVerifierSessionCapabilityPointer: number,
        boardVerifierSessionCapabilityByteLength: number,
        setupIntentObjectHandle: number,
        checkpointLineageIdentifierPointer: number,
        checkpointLineageIdentifierByteLength: number,
        generationSourceHandleOutputPointer: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_galois_key_share_prepare_resumed_generation?: (
        selectedSuiteHandle: number,
        setupGenerationAuthorityHandle: number,
        actionRandomnessHandle: number,
        stateVerifierSessionHandle: number,
        stateVerifierSessionCapabilityPointer: number,
        stateVerifierSessionCapabilityByteLength: number,
        verifiedReservationHandle: number,
        boardVerifierSessionHandle: number,
        boardVerifierSessionCapabilityPointer: number,
        boardVerifierSessionCapabilityByteLength: number,
        setupIntentObjectHandle: number,
        checkpointLineageIdentifierPointer: number,
        checkpointLineageIdentifierByteLength: number,
        generationSourceHandleOutputPointer: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_galois_key_share_commit_generated_source?: (
        prepackageCatalogHandle: number,
        generatedCommonProofHandle: number,
        generationSourceHandle: number,
    ) => number;
    sealed_lattice_galois_key_share_discard_generation_source?: (
        generationSourceHandle: number,
    ) => number;
    sealed_lattice_galois_key_share_component_readback_open?: (
        generationSourceHandle: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_galois_key_share_component_readback_component_count?: (
        readbackHandle: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_galois_key_share_component_readback_descriptor_byte_length?: (
        readbackHandle: number,
        componentOrdinal: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_galois_key_share_component_readback_copy_descriptor?: (
        readbackHandle: number,
        componentOrdinal: number,
        outputPointer: number,
        outputByteLength: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_galois_key_share_component_readback_copy_material_root?: (
        readbackHandle: number,
        componentOrdinal: number,
        outputPointer: number,
        outputByteLength: number,
    ) => number;
    sealed_lattice_galois_key_share_component_readback_total_byte_length?: (
        readbackHandle: number,
        componentOrdinal: number,
        statusPointer: number,
    ) => bigint;
    sealed_lattice_galois_key_share_component_readback_read_chunk?: (
        readbackHandle: number,
        componentOrdinal: number,
        chunkIndex: number,
        outputPointer: number,
        outputByteLength: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_galois_key_share_component_readback_finish?: (
        generationSourceHandle: number,
        readbackHandle: number,
    ) => number;
    sealed_lattice_galois_key_share_component_readback_cancel?: (
        generationSourceHandle: number,
        readbackHandle: number,
    ) => number;
    sealed_lattice_galois_key_share_verification_ingress_begin?: (
        selectedSuiteHandle: number,
        prepackageCatalogHandle: number,
        rosterPosition: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_galois_key_share_component_begin?: (
        ingressHandle: number,
        componentOrdinal: number,
        streamDescriptorPointer: number,
        streamDescriptorByteLength: number,
    ) => number;
    sealed_lattice_galois_key_share_component_absorb_chunk?: (
        ingressHandle: number,
        componentOrdinal: number,
        chunkIndex: number,
        chunkPointer: number,
        chunkByteLength: number,
    ) => number;
    sealed_lattice_galois_key_share_component_finish?: (
        ingressHandle: number,
        componentOrdinal: number,
    ) => number;
    sealed_lattice_galois_key_share_prepare_verification?: (
        selectedSuiteHandle: number,
        ingressHandle: number,
        terminalSourceHandleOutputPointer: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_galois_key_share_finish_verification?: (
        verifiedCommonProofHandle: number,
        terminalSourceHandle: number,
    ) => number;
    sealed_lattice_galois_key_share_discard_verification_ingress?: (
        ingressHandle: number,
    ) => number;
    sealed_lattice_galois_key_share_discard_verification_terminal_source?: (
        terminalSourceHandle: number,
    ) => number;
    sealed_lattice_accepted_setup_verification_transfer_prepackage_evaluator_sources?: (
        assemblyHandle: number,
        catalogHandle: number,
    ) => number;
    sealed_lattice_accepted_setup_verification_complete_evaluator_sources?: (
        assemblyHandle: number,
    ) => number;
    sealed_lattice_accepted_setup_verification_complete_public_proofs?: (
        assemblyHandle: number,
    ) => number;
    sealed_lattice_accepted_setup_verification_finalize?: (
        assemblyHandle: number,
        stateSessionHandle: number,
        stateSessionCapabilityPointer: number,
        stateSessionCapabilityByteLength: number,
        orderedCommitmentReservationHandlesPointer: number,
        orderedCommitmentReservationHandlesByteLength: number,
        terminalPackageReservationHandlesPointer: number,
        terminalPackageReservationHandlesByteLength: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_accepted_setup_same_secret_prepare_verification?: (
        selectedSuiteHandle: number,
        assemblyHandle: number,
        canonicalApplicationStatementPointer: number,
        canonicalApplicationStatementByteLength: number,
        terminalSourceHandleOutputPointer: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_accepted_setup_same_secret_finish_verification?: (
        verifiedCommonProofHandle: number,
        terminalSourceHandle: number,
    ) => number;
    sealed_lattice_accepted_setup_same_secret_finish_generated_verification?: (
        verifiedCommonProofHandle: number,
        terminalSourceHandle: number,
        generatedCommonProofHandle: number,
    ) => number;
    sealed_lattice_accepted_setup_same_secret_discard_terminal_source?: (
        terminalSourceHandle: number,
    ) => number;
    sealed_lattice_accepted_setup_public_key_share_prepare_verification?: (
        selectedSuiteHandle: number,
        assemblyHandle: number,
        canonicalApplicationStatementPointer: number,
        canonicalApplicationStatementByteLength: number,
        terminalSourceHandleOutputPointer: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_accepted_setup_public_key_share_finish_verification?: (
        verifiedCommonProofHandle: number,
        terminalSourceHandle: number,
    ) => number;
    sealed_lattice_accepted_setup_public_key_share_finish_generated_verification?: (
        verifiedCommonProofHandle: number,
        terminalSourceHandle: number,
        generatedCommonProofHandle: number,
    ) => number;
    sealed_lattice_accepted_setup_public_key_share_discard_terminal_source?: (
        terminalSourceHandle: number,
    ) => number;
    sealed_lattice_same_secret_prepare_generation?: (
        selectedSuiteHandle: number,
        setupGenerationAuthorityHandle: number,
        actionRandomnessHandle: number,
        stateVerifierSessionHandle: number,
        stateVerifierSessionCapabilityPointer: number,
        stateVerifierSessionCapabilityByteLength: number,
        verifiedReservationHandle: number,
        boardVerifierSessionHandle: number,
        boardVerifierSessionCapabilityPointer: number,
        boardVerifierSessionCapabilityByteLength: number,
        setupIntentObjectHandle: number,
        checkpointLineageIdentifierPointer: number,
        checkpointLineageIdentifierByteLength: number,
        statementSourceHandleOutputPointer: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_same_secret_prepare_resumed_generation?: (
        selectedSuiteHandle: number,
        setupGenerationAuthorityHandle: number,
        actionRandomnessHandle: number,
        stateVerifierSessionHandle: number,
        stateVerifierSessionCapabilityPointer: number,
        stateVerifierSessionCapabilityByteLength: number,
        verifiedReservationHandle: number,
        boardVerifierSessionHandle: number,
        boardVerifierSessionCapabilityPointer: number,
        boardVerifierSessionCapabilityByteLength: number,
        setupIntentObjectHandle: number,
        checkpointLineageIdentifierPointer: number,
        checkpointLineageIdentifierByteLength: number,
        statementSourceHandleOutputPointer: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_public_key_share_prepare_generation?: (
        selectedSuiteHandle: number,
        setupGenerationAuthorityHandle: number,
        actionRandomnessHandle: number,
        stateVerifierSessionHandle: number,
        stateVerifierSessionCapabilityPointer: number,
        stateVerifierSessionCapabilityByteLength: number,
        verifiedReservationHandle: number,
        boardVerifierSessionHandle: number,
        boardVerifierSessionCapabilityPointer: number,
        boardVerifierSessionCapabilityByteLength: number,
        setupIntentObjectHandle: number,
        checkpointLineageIdentifierPointer: number,
        checkpointLineageIdentifierByteLength: number,
        statementSourceHandleOutputPointer: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_public_key_share_prepare_resumed_generation?: (
        selectedSuiteHandle: number,
        setupGenerationAuthorityHandle: number,
        actionRandomnessHandle: number,
        stateVerifierSessionHandle: number,
        stateVerifierSessionCapabilityPointer: number,
        stateVerifierSessionCapabilityByteLength: number,
        verifiedReservationHandle: number,
        boardVerifierSessionHandle: number,
        boardVerifierSessionCapabilityPointer: number,
        boardVerifierSessionCapabilityByteLength: number,
        setupIntentObjectHandle: number,
        checkpointLineageIdentifierPointer: number,
        checkpointLineageIdentifierByteLength: number,
        statementSourceHandleOutputPointer: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_setup_key_relation_generation_statement_byte_length?: (
        statementSourceHandle: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_setup_key_relation_generation_statement_copy_and_release?: (
        statementSourceHandle: number,
        outputPointer: number,
        outputByteLength: number,
    ) => number;
    sealed_lattice_setup_key_relation_generation_statement_discard?: (
        statementSourceHandle: number,
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
    sealed_lattice_common_proof_describe_generation_family_adapter?: (
        adapterHandle: number,
        runtimeBindingHashOutputPointer: number,
        verificationBindingHashOutputPointer: number,
        proofAttemptLineageIdentifierOutputPointer: number,
        checkpointLineageIdentifierOutputPointer: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_common_proof_describe_verification_family_adapter?: (
        adapterHandle: number,
        verificationBindingHashOutputPointer: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_common_proof_prepare_generation_family_adapter?: (
        adapterHandle: number,
        authenticatedCheckpointStatePointer: number,
        authenticatedCheckpointStateByteLength: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_common_proof_prepare_verification_family_adapter?: (
        adapterHandle: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_common_proof_discard_generation_family_adapter?: (
        adapterHandle: number,
    ) => number;
    sealed_lattice_common_proof_discard_verification_family_adapter?: (
        adapterHandle: number,
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
    sealed_lattice_ballot_validity_prepare_generation?: (
        selectedSuiteHandle: number,
        actionRandomnessHandle: number,
        acceptedSetupAuthorityHandle: number,
        producerSequence: bigint,
        scoresPointer: number,
        scoresByteLength: number,
        encryptionAttemptIdentifierPointer: number,
        proofAttemptNoncePointer: number,
        checkpointLineageIdentifierPointer: number,
        ciphertextReadbackHandleOutputPointer: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_ballot_validity_prepare_resumed_generation?: (
        selectedSuiteHandle: number,
        actionRandomnessHandle: number,
        acceptedSetupAuthorityHandle: number,
        producerSequence: bigint,
        scoresPointer: number,
        scoresByteLength: number,
        encryptionAttemptIdentifierPointer: number,
        proofAttemptNoncePointer: number,
        checkpointLineageIdentifierPointer: number,
        ciphertextReadbackHandleOutputPointer: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_ballot_validity_ciphertext_descriptor_byte_length?: (
        ciphertextReadbackHandle: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_ballot_validity_copy_ciphertext_descriptor?: (
        ciphertextReadbackHandle: number,
        outputPointer: number,
        outputByteLength: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_ballot_validity_read_ciphertext_chunk?: (
        ciphertextReadbackHandle: number,
        chunkIndex: number,
        outputPointer: number,
        outputByteLength: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_ballot_validity_finish_ciphertext_readback?: (
        ciphertextReadbackHandle: number,
    ) => number;
    sealed_lattice_ballot_validity_bind_generated_proof_to_board?: (
        generatedCommonProofHandle: number,
        ciphertextReadbackHandle: number,
        boardVerifierSessionHandle: number,
        boardVerifierSessionCapabilityPointer: number,
        boardVerifierSessionCapabilityByteLength: number,
        ballotPackageObjectHandle: number,
    ) => number;
    sealed_lattice_ballot_validity_discard_ciphertext_readback?: (
        ciphertextReadbackHandle: number,
    ) => number;
    sealed_lattice_ballot_validity_begin_verification?: (
        selectedSuiteHandle: number,
        acceptedSetupAuthorityHandle: number,
        boardVerifierSessionHandle: number,
        boardVerifierSessionCapabilityPointer: number,
        boardVerifierSessionCapabilityByteLength: number,
        ballotPackageObjectHandle: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_ballot_validity_absorb_ciphertext_chunk?: (
        preparationHandle: number,
        chunkIndex: number,
        chunkPointer: number,
        chunkByteLength: number,
    ) => number;
    sealed_lattice_ballot_validity_finish_verification_preparation?: (
        preparationHandle: number,
        terminalSourceHandleOutputPointer: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_ballot_validity_discard_verification_preparation?: (
        preparationHandle: number,
    ) => number;
    sealed_lattice_ballot_validity_finish_verification?: (
        verifiedCommonProofHandle: number,
        terminalSourceHandle: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_ballot_validity_discard_verification_terminal_source?: (
        terminalSourceHandle: number,
    ) => number;
    sealed_lattice_ballot_validity_discard_verified_output?: (
        outputHandle: number,
    ) => number;
    sealed_lattice_ballot_aggregation_begin?: (statusPointer: number) => number;
    sealed_lattice_ballot_aggregation_absorb?: (
        aggregationHandle: number,
        verifiedBallotOutputHandle: number,
    ) => number;
    sealed_lattice_ballot_aggregation_finish?: (
        aggregationHandle: number,
        boardVerifierSessionHandle: number,
        boardVerifierSessionCapabilityPointer: number,
        boardVerifierSessionCapabilityByteLength: number,
        verifiedAggregateObjectHandle: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_ballot_aggregation_cancel?: (
        aggregationHandle: number,
    ) => number;
    sealed_lattice_ballot_aggregation_discard_verified_aggregate?: (
        verifiedAggregateAuthorityHandle: number,
    ) => number;
    sealed_lattice_evaluator_execution_begin?: (
        acceptedSetupAuthorityHandle: number,
        verifiedAggregateAuthorityHandle: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_evaluator_execution_poll?: (
        executionHandle: number,
        outputPointer: number,
        outputByteLength: number,
    ) => number;
    sealed_lattice_evaluator_execution_absorb_store_chunk?: (
        executionHandle: number,
        storeByteOffset: bigint,
        chunkPointer: number,
        chunkByteLength: number,
    ) => number;
    sealed_lattice_evaluator_execution_finish?: (
        executionHandle: number,
    ) => number;
    sealed_lattice_evaluator_execution_replay_carrier_byte_length?: (
        executionHandle: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_evaluator_execution_copy_replay_carrier?: (
        executionHandle: number,
        outputPointer: number,
        outputByteLength: number,
    ) => number;
    sealed_lattice_evaluator_execution_bind_replay_object?: (
        executionHandle: number,
        boardVerifierSessionHandle: number,
        boardVerifierSessionCapabilityPointer: number,
        boardVerifierSessionCapabilityByteLength: number,
        verifiedReplayObjectHandle: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_evaluator_execution_cancel?: (
        executionHandle: number,
    ) => number;
    sealed_lattice_evaluator_replay_release?: (
        verifiedReplayHandle: number,
    ) => number;
    sealed_lattice_common_proof_generation_checkpoint_state_byte_length?: () => number;
    sealed_lattice_common_proof_generation_authenticated_source_request_byte_length?: () => number;
    sealed_lattice_common_proof_generation_describe_checkpoint?: (
        operationHandle: number,
        safeBoundaryOrdinalPointer: number,
        stateByteLengthPointer: number,
        cursorManifestByteLengthPointer: number,
    ) => number;
    sealed_lattice_common_proof_generation_copy_checkpoint_state?: (
        operationHandle: number,
        outputPointer: number,
        outputByteLength: number,
    ) => number;
    sealed_lattice_common_proof_generation_copy_checkpoint_cursor_manifest?: (
        operationHandle: number,
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
    sealed_lattice_common_proof_generation_copy_authenticated_source_request?: (
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
    sealed_lattice_common_proof_generation_supply_authenticated_source_range?: (
        operationHandle: number,
        sourcePointer: number,
        sourceLength: number,
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
    sealed_lattice_common_proof_copy_selected_suite_record?: (
        handle: number,
        outputPointer: number,
        outputByteLength: number,
    ) => number;
    sealed_lattice_common_proof_selected_suite_record_byte_length?: (
        handle: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_common_proof_select_suite?: (
        canonicalSuiteRecordPointer: number,
        canonicalSuiteRecordLength: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_foundation_roster_encode?: (
        inputPointer: number,
        inputByteLength: number,
        outputPointer: number,
        outputByteLength: number,
    ) => number;
    sealed_lattice_foundation_roster_encoded_byte_length?: (
        inputPointer: number,
        inputByteLength: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_vss_share_linkage_board_object_handle_catalog_byte_length?: () => number;
    sealed_lattice_vss_share_linkage_prepare_generation?: (
        selectedSuiteHandle: number,
        setupGenerationAuthorityHandle: number,
        actionRandomnessHandle: number,
        stateVerifierSessionHandle: number,
        stateVerifierSessionCapabilityPointer: number,
        stateVerifierSessionCapabilityByteLength: number,
        verifiedReservationHandle: number,
        boardVerifierSessionHandle: number,
        boardVerifierSessionCapabilityPointer: number,
        boardVerifierSessionCapabilityByteLength: number,
        setupIntentObjectHandle: number,
        checkpointLineageIdentifierPointer: number,
        checkpointLineageIdentifierByteLength: number,
        boardBindingSourceHandleOutputPointer: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_vss_share_linkage_prepare_resumed_generation?: (
        selectedSuiteHandle: number,
        setupGenerationAuthorityHandle: number,
        actionRandomnessHandle: number,
        stateVerifierSessionHandle: number,
        stateVerifierSessionCapabilityPointer: number,
        stateVerifierSessionCapabilityByteLength: number,
        verifiedReservationHandle: number,
        boardVerifierSessionHandle: number,
        boardVerifierSessionCapabilityPointer: number,
        boardVerifierSessionCapabilityByteLength: number,
        setupIntentObjectHandle: number,
        checkpointLineageIdentifierPointer: number,
        checkpointLineageIdentifierByteLength: number,
        boardBindingSourceHandleOutputPointer: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_vss_share_linkage_bind_generated_proof_to_board?: (
        generatedCommonProofHandle: number,
        boardBindingSourceHandle: number,
        boardVerifierSessionHandle: number,
        boardVerifierSessionCapabilityPointer: number,
        boardVerifierSessionCapabilityByteLength: number,
        orderedObjectHandleBytesPointer: number,
        orderedObjectHandleBytesByteLength: number,
    ) => number;
    sealed_lattice_vss_share_linkage_discard_generation_board_binding_source?: (
        boardBindingSourceHandle: number,
    ) => number;
    sealed_lattice_vss_share_linkage_prepare_verification?: (
        selectedSuiteHandle: number,
        boardVerifierSessionHandle: number,
        boardVerifierSessionCapabilityPointer: number,
        boardVerifierSessionCapabilityByteLength: number,
        orderedObjectHandleBytesPointer: number,
        orderedObjectHandleBytesByteLength: number,
        terminalSourceHandleOutputPointer: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_vss_share_linkage_finish_verification?: (
        verifiedCommonProofHandle: number,
        terminalSourceHandle: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_vss_share_linkage_discard_verification_terminal_source?: (
        terminalSourceHandle: number,
    ) => number;
    sealed_lattice_vss_share_linkage_discard_verified_terminal?: (
        terminalHandle: number,
    ) => number;
    sealed_lattice_target_release_prepare_generation?: (
        selectedSuiteHandle: number,
        acceptedSetupAuthorityHandle: number,
        actionRandomnessHandle: number,
        stateVerifierSessionHandle: number,
        stateVerifierSessionCapabilityPointer: number,
        stateVerifierSessionCapabilityByteLength: number,
        verifiedReservationHandle: number,
        finalityVerifierSessionHandle: number,
        finalityVerifierSessionCapabilityPointer: number,
        finalityVerifierSessionCapabilityByteLength: number,
        verifiedFinalityHandle: number,
        boardVerifierSessionHandle: number,
        boardVerifierSessionCapabilityPointer: number,
        boardVerifierSessionCapabilityByteLength: number,
        reservationIntentObjectHandle: number,
        targetIdentifierPointer: number,
        targetIdentifierByteLength: number,
        targetOrderPointer: number,
        targetOrderByteLength: number,
        checkpointLineageIdentifierPointer: number,
        checkpointLineageIdentifierByteLength: number,
        generationSourceHandleOutputPointer: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_target_release_prepare_resumed_generation?: (
        selectedSuiteHandle: number,
        acceptedSetupAuthorityHandle: number,
        actionRandomnessHandle: number,
        stateVerifierSessionHandle: number,
        stateVerifierSessionCapabilityPointer: number,
        stateVerifierSessionCapabilityByteLength: number,
        verifiedReservationHandle: number,
        finalityVerifierSessionHandle: number,
        finalityVerifierSessionCapabilityPointer: number,
        finalityVerifierSessionCapabilityByteLength: number,
        verifiedFinalityHandle: number,
        boardVerifierSessionHandle: number,
        boardVerifierSessionCapabilityPointer: number,
        boardVerifierSessionCapabilityByteLength: number,
        reservationIntentObjectHandle: number,
        targetIdentifierPointer: number,
        targetIdentifierByteLength: number,
        targetOrderPointer: number,
        targetOrderByteLength: number,
        checkpointLineageIdentifierPointer: number,
        checkpointLineageIdentifierByteLength: number,
        generationSourceHandleOutputPointer: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_target_release_partial_descriptor_byte_length?: (
        generationSourceHandle: number,
        roleOrdinal: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_target_release_copy_partial_descriptor?: (
        generationSourceHandle: number,
        roleOrdinal: number,
        outputPointer: number,
        outputByteLength: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_target_release_partial_total_byte_length?: (
        generationSourceHandle: number,
        roleOrdinal: number,
        statusPointer: number,
    ) => bigint;
    sealed_lattice_target_release_read_partial_chunk?: (
        generationSourceHandle: number,
        roleOrdinal: number,
        chunkIndex: number,
        outputPointer: number,
        outputByteLength: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_target_release_bind_generated_proof?: (
        generatedCommonProofHandle: number,
        generationSourceHandle: number,
        verifiedOutputHandle: number,
        targetShareObjectHandle: number,
    ) => number;
    sealed_lattice_target_release_discard_generation_source?: (
        generationSourceHandle: number,
    ) => number;
    sealed_lattice_target_release_prepare_verification?: (
        selectedSuiteHandle: number,
        acceptedSetupAuthorityHandle: number,
        stateVerifierSessionHandle: number,
        stateVerifierSessionCapabilityPointer: number,
        stateVerifierSessionCapabilityByteLength: number,
        verifiedReservationHandle: number,
        verifiedOutputHandle: number,
        finalityVerifierSessionHandle: number,
        finalityVerifierSessionCapabilityPointer: number,
        finalityVerifierSessionCapabilityByteLength: number,
        verifiedFinalityHandle: number,
        boardVerifierSessionHandle: number,
        boardVerifierSessionCapabilityPointer: number,
        boardVerifierSessionCapabilityByteLength: number,
        targetShareObjectHandle: number,
        targetIdentifierPointer: number,
        targetIdentifierByteLength: number,
        targetOrderPointer: number,
        targetOrderByteLength: number,
        targetIdentifierPartialPointer: number,
        targetIdentifierPartialByteLength: number,
        targetOrderPartialPointer: number,
        targetOrderPartialByteLength: number,
        terminalSourceHandleOutputPointer: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_target_release_finish_verification?: (
        verifiedCommonProofHandle: number,
        terminalSourceHandle: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_target_release_discard_verification_terminal_source?: (
        terminalSourceHandle: number,
    ) => number;
    sealed_lattice_target_release_discard_verified_share?: (
        verifiedShareHandle: number,
    ) => number;
    sealed_lattice_target_release_reconstruct_verified_shares?: (
        finalityVerifierSessionHandle: number,
        finalityVerifierSessionCapabilityPointer: number,
        finalityVerifierSessionCapabilityByteLength: number,
        verifiedFinalityHandle: number,
        targetIdentifierPointer: number,
        targetIdentifierByteLength: number,
        targetOrderPointer: number,
        targetOrderByteLength: number,
        verifiedShareHandlesPointer: number,
        verifiedShareHandlesByteLength: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_target_release_reconstructed_slot_count?: (
        reconstructedTargetPairHandle: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_target_release_copy_reconstructed_role?: (
        reconstructedTargetPairHandle: number,
        roleOrdinal: number,
        outputPointer: number,
        outputByteLength: number,
        statusPointer: number,
    ) => number;
    sealed_lattice_target_release_finish_reconstruction?: (
        reconstructedTargetPairHandle: number,
    ) => number;
    sealed_lattice_target_release_discard_reconstruction?: (
        reconstructedTargetPairHandle: number,
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
