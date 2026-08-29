import type {
    ProtocolHash,
    VerificationResult,
} from '../foundation-contract.js';

export type FoundationManifestVerification = VerificationResult<{
    readonly manifestHash: ProtocolHash;
}>;

export type FoundationActionDefinitionVerification = VerificationResult<{
    readonly actionDefinitionHash: ProtocolHash;
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

export type FoundationKernelExports = WebAssembly.Exports & {
    memory?: WebAssembly.Memory;
    sealed_lattice_allocate?: (length: number) => number;
    sealed_lattice_deallocate?: (pointer: number, length: number) => void;
    sealed_lattice_foundation_command_with_length?: (
        pointer: number,
        length: number,
        outputLengthPointer: number,
    ) => number;
};
