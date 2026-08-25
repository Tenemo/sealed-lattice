import type {
    CanonicalError,
    ProtocolHash,
    VerificationResult,
} from '@sealed-lattice/types';

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

export type TranscriptCoreKernel = {
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
    verifyFoundationCeremonyContext(input: {
        readonly canonicalManifestBytesHex: string;
        readonly canonicalRosterBytesHex: string;
        readonly ceremonyIdentifier: string;
        readonly expectedSuiteId: ProtocolHash;
    }): FoundationCeremonyContextVerification;
    verifyFoundationActionContext(input: {
        readonly actionIdentifier: string;
        readonly canonicalActionDefinitionBytesHex: string;
        readonly canonicalBoardPolicyBytesHex: string;
        readonly canonicalManifestBytesHex: string;
        readonly canonicalRosterBytesHex: string;
        readonly ceremonyIdentifier: string;
        readonly expectedCeremonyContextHash: ProtocolHash;
        readonly expectedSuiteId: ProtocolHash;
    }): FoundationActionContextVerification;
};

export type PublishedSdkKernel = Omit<
    TranscriptCoreKernel,
    'deriveCanonicalObjectHash'
>;

type KernelMethodInput<MethodName extends keyof TranscriptCoreKernel> =
    TranscriptCoreKernel[MethodName] extends (input: infer Input) => unknown
        ? NonNullable<Input>
        : never;

type KernelCommandFromMethod<
    CommandName extends string,
    MethodName extends keyof TranscriptCoreKernel,
> = Readonly<
    {
        readonly command: CommandName;
    } & KernelMethodInput<MethodName>
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
          'VerifyFoundationCeremonyContext',
          'verifyFoundationCeremonyContext'
      >
    | KernelCommandFromMethod<
          'VerifyFoundationActionContext',
          'verifyFoundationActionContext'
      >;

type TranscriptCoreKernelExports = WebAssembly.Exports & {
    memory?: WebAssembly.Memory;
    sealed_lattice_allocate?: (length: number) => number;
    sealed_lattice_deallocate?: (pointer: number, length: number) => void;
    sealed_lattice_transcript_core_command_with_length?: (
        pointer: number,
        length: number,
        outputLengthPointer: number,
    ) => number;
};

type KernelSuccessResponse<Result> = {
    readonly success: true;
    readonly value: Result;
};

type KernelFailureResponse = {
    readonly success: false;
    readonly error: CanonicalError;
};

export type {
    KernelFailureResponse,
    KernelSuccessResponse,
    TranscriptCoreKernelCommand,
    TranscriptCoreKernelExports,
};
