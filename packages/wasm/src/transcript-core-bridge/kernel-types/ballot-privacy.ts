/** Runtime status reported by the ballot privacy proof backend. */
export type BallotPrivacyProofBackendStatus = {
    readonly backendName: string;
    readonly backendAvailable: boolean;
    readonly portableRustWasmPortRequired: boolean;
    readonly requiredComponents: readonly string[];
    readonly blockedReason: string | null;
};

/** Structured result returned by WASM ballot privacy proof verification commands. */
export type BallotPrivacyKernelVerification = {
    readonly ok: boolean;
    readonly backendAvailable: boolean;
    readonly backendStatus: BallotPrivacyProofBackendStatus;
    readonly operation: string;
    readonly statusLabels: readonly string[];
    readonly acceptedDigests: readonly string[];
    readonly refusedObjects: readonly {
        readonly code: string;
        readonly message: string;
        readonly objectDigest?: string;
    }[];
    readonly unresolvedReason: string | null;
};

export type BallotPrivacyLinearProofVectorVerification = {
    readonly ok: boolean;
    readonly backendAvailable: boolean;
    readonly backendStatus: BallotPrivacyProofBackendStatus;
    readonly statusLabels: readonly string[];
    readonly acceptedDigests: readonly string[];
    readonly refusedObjects: readonly {
        readonly code: string;
        readonly message: string;
    }[];
    readonly unresolvedReason: string | null;
    readonly caseName?: string;
    readonly vectorAvailable?: boolean;
    readonly expectedOutcome?: string;
};

export type BallotPrivacyEncodedRelationVectorVerification = {
    readonly ok: boolean;
    readonly backendAvailable: boolean;
    readonly backendStatus: BallotPrivacyProofBackendStatus;
    readonly statusLabels: readonly string[];
    readonly acceptedDigests: readonly string[];
    readonly refusedObjects: readonly {
        readonly code: string;
        readonly message: string;
    }[];
    readonly unresolvedReason: string | null;
    readonly caseName?: string;
    readonly vectorAvailable?: boolean;
    readonly expectedOutcome?: string;
};

export type BallotPrivacyReceiverKeyVectorVerification = {
    readonly ok: boolean;
    readonly backendAvailable: boolean;
    readonly backendStatus: BallotPrivacyProofBackendStatus;
    readonly statusLabels: readonly string[];
    readonly acceptedDigests: readonly string[];
    readonly refusedObjects: readonly {
        readonly code: string;
        readonly message: string;
    }[];
    readonly unresolvedReason: string | null;
    readonly caseName?: string;
    readonly vectorAvailable?: boolean;
    readonly expectedOutcome?: string;
};

export type BallotPrivacyReceiverKeyProofGenerationPreparation =
    BallotPrivacyKernelVerification & {
        readonly generatedProofBytes?: false;
        readonly summary?: {
            readonly relationWitnessPolynomialCount: number;
            readonly shortWitnessPolynomialCount: number;
            readonly preparedShortWitnessPolynomialCount: number;
            readonly witnessL2Squared: string;
            readonly witnessL2BoundSquared: string;
            readonly normSlack: string;
            readonly abdlopCommitment?: {
                readonly compressedCommitmentPolynomialCount: number;
                readonly openingRandomnessPolynomialCount: number;
                readonly openingRemainderPolynomialCount: number;
                readonly proverRandomnessSeedBytes: number;
                readonly subprotocolSeedBytes: number;
                readonly abdlopCommitmentHash: string;
            } | null;
        };
    };

export type BallotPrivacyReceiverKeyProofGeneration =
    BallotPrivacyKernelVerification & {
        readonly generatedProofBytes?: true;
        readonly proofBytesHex?: string;
        readonly proofSizeBytes?: number;
        readonly summary?: {
            readonly abdlopCommitmentHash: string;
            readonly z34ChallengeHash: string;
            readonly generatorChallengeHash: string;
            readonly quadraticChallengeHash: string;
        };
    };

export type BallotPrivacyProofGeneration =
    BallotPrivacyReceiverKeyProofGeneration & {
        readonly ballotProof?: unknown;
        readonly componentProofBundle?: unknown;
        readonly componentProofInputs?: readonly unknown[];
        readonly parameterSet?: unknown;
        readonly proofEncoding?: unknown;
        readonly verification?: BallotPrivacyKernelVerification;
    };
