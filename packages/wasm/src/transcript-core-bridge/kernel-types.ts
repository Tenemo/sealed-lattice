import type {
    CanonicalError,
    FieldElement,
    ProtocolHash,
    TranscriptCoreAnalysis,
    TranscriptCoreFixture,
    TranscriptCoreFixtureVerification,
} from '@sealed-lattice/types';

import type {
    BgvBaseConversionFixture,
    BgvBatchPlaintextEncoding,
    BgvCanonicalObjectAnalysis,
    BgvCiphertextConventionFixture,
    BgvCollectiveSetupTransportCompanions,
    BgvCollectiveSetupProfileDescription,
    BgvCollectiveSetupPublicDerivations,
    BgvCollectiveSetupVerification,
    BgvCompactVssAggregateThresholdCommitmentSetVerification,
    BgvCompactVssCommitmentBodyDecoding,
    BgvCompactVssCommitmentBodyEncoding,
    BgvCompactVssCommitmentBodyMetadata,
    BgvCompactVssCommitmentOpeningComputation,
    BgvCompactVssCoefficientCommitmentSetVerification,
    BgvCompactVssCommitmentOpeningInput,
    BgvCompactVssCommitmentOpeningVerification,
    BgvCompactVssRecipientShareCommitmentSetVerification,
    BgvCompactSameSecretBridgeProofGeneration,
    BgvCompactSameSecretBridgeProofStatement,
    BgvCompactSameSecretBridgeProofVerification,
    BgvCompactVssSameSecretBridgeProofMaterialSetVerification,
    BgvCompactVssSameSecretBridgeStatementSetVerification,
    BgvCompactVssShareLinkageProofGeneration,
    BgvCompactVssShareLinkageProofMaterialSetVerification,
    BgvCompactVssShareLinkageProofStatement,
    BgvCompactVssShareLinkageProofVerification,
    BgvCompactVssShareLinkageStatementVerification,
    BgvTransportedVssCoefficientCommitmentMaterial,
    BgvTrusteeEvaluationKeyProofGeneration,
    BgvTrusteeEvaluationKeyProofVerification,
    BgvTrusteeEvaluationKeySameSecretLinkage,
    BgvTrusteeEvaluationKeyStatementContext,
    BgvTrusteeEvaluationKeyStatementKey,
    BgvEvaluatorOperationValidation,
    BgvLocalTrusteeSetupStateVerification,
    BgvObjectValidation,
    BgvPassiveSetupPackage,
    BgvPassiveSetupParticipantInput,
    BgvPassiveSetupVerification,
    BgvPrivateVssShareEnvelopeVerification,
    BgvPrivateVssShareProofGeneration,
    BgvProfileRejection,
    BgvRnsProfileDescription,
    BgvSetupCommitmentOpeningComputation,
    BgvSetupProofMaterialTransportStreamBegin,
    BgvSetupProofMaterialTransportStreamChunkAbsorption,
    BgvSetupProofMaterialTransportStreamVerification,
    BgvTargetCiphertextPairInput,
    BgvTargetDecryptionDevelopmentFixture,
    BgvTargetDecryptionReleaseSetupContext,
    BgvTargetDecryptionResultReleaseBegin,
    BgvTargetDecryptionResultReleaseShareAbsorption,
    BgvTargetDecryptionResultRelease,
    BgvTargetDecryptionShare,
    BgvTargetDecryptionShareBinaryProofMaterialTransport,
    BgvTargetDecryptionShareBinaryProofMaterialVerification,
    BgvTargetDecryptionShareProofLayoutDescription,
    BgvTargetDecryptionShareProofMaterial,
    BgvTargetDecryptionShareProofMaterialVerification,
    BgvTargetDecryptionShareProofStatement,
    BgvTargetDecryptionShareProofStatementBindingVerification,
    BgvThresholdShareCommitmentDerivation,
    BgvThresholdShareCommitmentTransportDerivation,
    BgvThresholdShareCommitmentTransportStreamAbort,
    BgvThresholdShareCommitmentTransportStreamBegin,
    BgvThresholdShareCommitmentTransportStreamChunkAbsorption,
    BgvThresholdShareCommitmentTransportStreamDerivation,
    BgvTransportedVssCoefficientCommitmentMaterialReference,
    BgvTransportedVssCoefficientCommitmentMaterialTemplate,
    BgvVerifiedTransportedVssMaterialRelease,
} from './kernel-types/bgv.js';

export type {
    BgvAcceptedSetupHandoff,
    BgvBaseConversionFixture,
    BgvBatchPlaintextEncoding,
    BgvCanonicalObjectAnalysis,
    BgvCiphertextConventionFixture,
    BgvCollectiveSetupProfileDescription,
    BgvCollectiveSetupPublicDerivations,
    BgvCollectiveSetupVerification,
    BgvCompactVssAggregateThresholdCommitmentSetVerification,
    BgvCompactVssCommitmentBodyDecoding,
    BgvCompactVssCommitmentBodyEncoding,
    BgvCompactVssCommitmentBodyMetadata,
    BgvCompactVssCommitmentOpeningComputation,
    BgvCompactVssCoefficientCommitmentSetVerification,
    BgvCompactVssCommitmentOpeningInput,
    BgvCompactVssCommitmentOpeningVerification,
    BgvCompactVssRecipientShareCommitmentSetVerification,
    BgvCompactSameSecretBridgeProofGeneration,
    BgvCompactSameSecretBridgeProofStatement,
    BgvCompactSameSecretBridgeProofVerification,
    BgvCompactVssSameSecretBridgeProofMaterialSetVerification,
    BgvCompactVssSameSecretBridgeStatementSetVerification,
    BgvCompactVssShareLinkageProofGeneration,
    BgvCompactVssShareLinkageProofMaterialSetVerification,
    BgvCompactVssShareLinkageProofStatement,
    BgvCompactVssShareLinkageProofVerification,
    BgvCompactVssShareLinkageStatementVerification,
    BgvTrusteeEvaluationKeyProofGeneration,
    BgvTrusteeEvaluationKeyProofVerification,
    BgvTrusteeEvaluationKeySameSecretLinkage,
    BgvTrusteeEvaluationKeyStatementContext,
    BgvTrusteeEvaluationKeyStatementKey,
    BgvEvaluatorOperationValidation,
    BgvLocalTrusteeSetupStateVerification,
    BgvObjectValidation,
    BgvPassiveSetupPackage,
    BgvPassiveSetupParticipantInput,
    BgvPassiveSetupVerification,
    BgvPrivateVssShareEnvelopeVerification,
    BgvPrivateVssShareProofGeneration,
    BgvProfileRejection,
    BgvRnsProfileDescription,
    BgvSetupCommitmentOpeningComputation,
    BgvSetupProofMaterialTransportStreamBegin,
    BgvSetupProofMaterialTransportStreamChunkAbsorption,
    BgvSetupProofMaterialTransportStreamVerification,
    BgvTargetCiphertextPairInput,
    BgvTargetDecryptionDevelopmentFixture,
    BgvTargetDecryptionReleaseSetupContext,
    BgvTargetDecryptionResultReleaseBegin,
    BgvTargetDecryptionResultReleaseShareAbsorption,
    BgvTargetDecryptionResultRelease,
    BgvTargetDecryptionShare,
    BgvTargetDecryptionShareBinaryProofMaterialTransport,
    BgvTargetDecryptionShareBinaryProofMaterialVerification,
    BgvTargetDecryptionShareProofLayoutDescription,
    BgvTargetDecryptionShareProofMaterial,
    BgvTargetDecryptionShareProofMaterialVerification,
    BgvTargetDecryptionShareProofStatement,
    BgvTargetDecryptionShareProofStatementBindingVerification,
    BgvThresholdShareCommitmentDerivation,
    BgvThresholdShareCommitmentTransportDerivation,
    BgvThresholdShareCommitmentTransportStreamAbort,
    BgvThresholdShareCommitmentTransportStreamBegin,
    BgvThresholdShareCommitmentTransportStreamChunkAbsorption,
    BgvThresholdShareCommitmentTransportStreamDerivation,
    BgvTransportedVssCoefficientCommitmentMaterialReference,
    BgvTransportedVssCoefficientCommitmentMaterialTemplate,
    BgvVerifiedTransportedVssMaterialRelease,
} from './kernel-types/bgv.js';
export type TranscriptCoreKernelSharePoint = {
    readonly rosterPosition: number;
    readonly value: FieldElement;
};

export type TranscriptCorePlaintextComparison = {
    readonly greaterThan: FieldElement;
    readonly equal: FieldElement;
    readonly scoreDifference: number;
};

export type TranscriptCoreKernel = {
    readonly exportedFunctionNames: readonly string[];
    wasmMemoryByteLength(): number;
    analyzeCanonicalObject(input: {
        readonly canonicalBytesHex: string;
        readonly chunkSize: number;
    }): TranscriptCoreAnalysis;
    computeChunkRoot(input: {
        readonly inputHex: string;
        readonly chunkSize: number;
    }): string;
    deriveProtocolHash(input: {
        readonly namespace: string;
        readonly value: unknown;
    }): ProtocolHash;
    evaluatePlaintextComparison(input: {
        readonly leftTotalScore: number;
        readonly rightTotalScore: number;
        readonly rosterSize: number;
    }): TranscriptCorePlaintextComparison;
    hashRaw(inputHex: string): string;
    interpolateShamirConstantTerm(input: {
        readonly sharePoints: readonly TranscriptCoreKernelSharePoint[];
    }): FieldElement;
    listCanonicalErrorCodes(): readonly string[];
    listReservedRootNamespaces(): readonly string[];
    roundTripBytes(input: Uint8Array): Uint8Array;
    verifyFixture(
        fixture: TranscriptCoreFixture,
    ): TranscriptCoreFixtureVerification;
    describeBgvRnsProfile(): BgvRnsProfileDescription;
    describeBgvOperationRegistry(): unknown;
    describeBgvPassiveSetupObjectModel(): unknown;
    describeCollectiveBgvSetupProfile(): BgvCollectiveSetupProfileDescription;
    deriveCollectiveBgvSetupPublicDerivations(input: {
        readonly publicMatrixSeedHash: ProtocolHash;
    }): BgvCollectiveSetupPublicDerivations;
    generateBgvPassiveSetup(input: {
        readonly ceremonyId: string;
        readonly manifestHash: ProtocolHash;
        readonly rosterHash: ProtocolHash;
        readonly thresholdProfileHash: ProtocolHash;
        readonly participants: readonly BgvPassiveSetupParticipantInput[];
        readonly setupSeed?: string;
    }): BgvPassiveSetupPackage;
    generateBgvEvaluationKeyMaterial(input: {
        readonly setupPackage: BgvPassiveSetupPackage;
        readonly setupPrivateWitness: {
            readonly setupSeed: string;
        };
        readonly workingLevel?: number;
        readonly rotationKeys?: readonly {
            readonly rotation: number;
            readonly level: number;
        }[];
    }): Record<string, unknown>;
    generateBgvTargetDecryptionDevelopmentFixture(): BgvTargetDecryptionDevelopmentFixture;
    generateBgvTargetDecryptionShareFromLocalShare(input: {
        readonly setupPackage: BgvPassiveSetupPackage;
        readonly localTargetShareWitness: unknown;
        readonly targetAcceptedRecord: unknown;
        readonly targetCiphertextBinding: unknown;
        readonly targetCiphertexts: BgvTargetCiphertextPairInput;
        readonly targetShareProfile: unknown;
        readonly trusteeIdentity: string;
    }): BgvTargetDecryptionShare;
    deriveBgvTargetDecryptionShareProofStatement(input: {
        readonly setupPackage: BgvPassiveSetupPackage;
        readonly localTargetShareWitness: unknown;
        readonly targetAcceptedRecord: unknown;
        readonly targetCiphertextBinding: unknown;
        readonly targetCiphertexts: BgvTargetCiphertextPairInput;
        readonly targetShareProfile: unknown;
        readonly trusteeIdentity: string;
        readonly targetDecryptionShare: BgvTargetDecryptionShare;
    }): BgvTargetDecryptionShareProofStatement;
    describeBgvTargetDecryptionShareProofLayout(input: {
        readonly setupPackage: BgvPassiveSetupPackage;
        readonly targetAcceptedRecord: unknown;
        readonly targetCiphertextBinding: unknown;
        readonly targetCiphertexts: BgvTargetCiphertextPairInput;
        readonly targetShareProfile: unknown;
        readonly targetDecryptionShare: BgvTargetDecryptionShare;
        readonly proofStatement: BgvTargetDecryptionShareProofStatement;
    }): BgvTargetDecryptionShareProofLayoutDescription;
    generateBgvTargetDecryptionShareProofMaterialFromLocalWitness(input: {
        readonly setupPackage: BgvPassiveSetupPackage;
        readonly localTargetShareWitness: unknown;
        readonly targetAcceptedRecord: unknown;
        readonly targetCiphertextBinding: unknown;
        readonly targetCiphertexts: BgvTargetCiphertextPairInput;
        readonly targetShareProfile: unknown;
        readonly trusteeIdentity: string;
        readonly targetDecryptionShare: BgvTargetDecryptionShare;
        readonly proofStatement: BgvTargetDecryptionShareProofStatement;
        readonly proofRandomnessSeedHex: string;
        readonly proofRandomnessNonceHex: string;
    }): BgvTargetDecryptionShareProofMaterial;
    verifyBgvTargetDecryptionShareProofMaterial(input: {
        readonly setupPackage: BgvPassiveSetupPackage;
        readonly targetAcceptedRecord: unknown;
        readonly targetCiphertextBinding: unknown;
        readonly targetCiphertexts: BgvTargetCiphertextPairInput;
        readonly targetShareProfile: unknown;
        readonly targetDecryptionShare: BgvTargetDecryptionShare;
        readonly proofStatement: BgvTargetDecryptionShareProofStatement;
        readonly proofMaterial: BgvTargetDecryptionShareProofMaterial;
    }): BgvTargetDecryptionShareProofMaterialVerification;
    verifyBgvTargetDecryptionShareBinaryProofMaterial(input: {
        readonly setupPackage: BgvPassiveSetupPackage;
        readonly targetAcceptedRecord: unknown;
        readonly targetCiphertextBinding: unknown;
        readonly targetCiphertexts: BgvTargetCiphertextPairInput;
        readonly targetShareProfile: unknown;
        readonly targetDecryptionShare: BgvTargetDecryptionShare;
        readonly proofStatement: BgvTargetDecryptionShareProofStatement;
        readonly transportedProofMaterial: BgvTargetDecryptionShareBinaryProofMaterialTransport;
    }): BgvTargetDecryptionShareBinaryProofMaterialVerification;
    verifyBgvTargetDecryptionShareProofStatementBinding(input: {
        readonly setupPackage: BgvPassiveSetupPackage;
        readonly targetAcceptedRecord: unknown;
        readonly targetCiphertextBinding: unknown;
        readonly targetCiphertexts: BgvTargetCiphertextPairInput;
        readonly targetShareProfile: unknown;
        readonly targetDecryptionShare: BgvTargetDecryptionShare;
        readonly proofStatement: BgvTargetDecryptionShareProofStatement;
    }): BgvTargetDecryptionShareProofStatementBindingVerification;
    deriveBgvTargetDecryptionResultReleaseSetupContext(input: {
        readonly setupPackage: BgvPassiveSetupPackage;
    }): BgvTargetDecryptionReleaseSetupContext;
    beginBgvTargetDecryptionResultRelease(input: {
        readonly releaseVerificationId: string;
        readonly releaseSetupContext: BgvTargetDecryptionReleaseSetupContext;
        readonly targetAcceptedRecord: unknown;
        readonly targetCiphertextBinding: unknown;
        readonly targetCiphertexts: BgvTargetCiphertextPairInput;
        readonly targetShareProfile: unknown;
    }): BgvTargetDecryptionResultReleaseBegin;
    absorbBgvTargetDecryptionResultReleaseShare(input: {
        readonly releaseVerificationId: string;
        readonly targetShareProof: {
            readonly targetDecryptionShare: BgvTargetDecryptionShare;
            readonly proofStatement: BgvTargetDecryptionShareProofStatement;
            readonly proofMaterial: BgvTargetDecryptionShareProofMaterial;
        };
    }): BgvTargetDecryptionResultReleaseShareAbsorption;
    finishBgvTargetDecryptionResultRelease(input: {
        readonly releaseVerificationId: string;
    }): BgvTargetDecryptionResultRelease;
    verifyBgvPassiveSetup(input: {
        readonly setupPackage: BgvPassiveSetupPackage;
        readonly expectedSetupPackageHash?: ProtocolHash;
        readonly expectedManifestHash?: ProtocolHash;
        readonly expectedRosterHash?: ProtocolHash;
        readonly expectedCollectivePublicKeyRoot?: ProtocolHash;
        readonly expectedRotSetHash?: ProtocolHash;
        readonly expectedEvaluationKeyRoot?: ProtocolHash;
    }): BgvPassiveSetupVerification;
    verifyCollectiveBgvSetup(
        input: Readonly<
            {
                readonly setupPackage: unknown;
                readonly expectedSetupPackageHash?: ProtocolHash;
                readonly expectedManifestHash?: ProtocolHash;
                readonly expectedRosterHash?: ProtocolHash;
            } & BgvCollectiveSetupTransportCompanions
        >,
    ): BgvCollectiveSetupVerification;
    verifyPrivateVssShareEnvelope(input: {
        readonly setupContext: unknown;
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly sourceTrusteeCoefficientCommitmentRecord: unknown;
        readonly sourceTrusteeCoefficientCommitmentMaterialRecords: readonly unknown[];
        readonly privateEnvelope: unknown;
        readonly transportedPrivateVssShareProofMaterial?: unknown;
        readonly expectedPrivateEnvelopeHash?: ProtocolHash;
        readonly expectedLocalVerificationRoot?: ProtocolHash;
    }): BgvPrivateVssShareEnvelopeVerification;
    generatePrivateVssShareProof(input: {
        readonly setupContext: unknown;
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly privateEnvelopeAadHash: ProtocolHash;
        readonly sourceTrusteeCoefficientCommitmentRecord: unknown;
        readonly sourceTrusteeCoefficientCommitmentMaterialRecords: readonly unknown[];
        readonly recipientIdentity: string;
        readonly recipientRosterPosition: number;
        readonly rnsLimbIndex: number;
        readonly rnsPrime: number;
        readonly ringDegree: number;
        readonly shareValues: readonly number[];
        readonly coefficientCommitmentRoots: readonly ProtocolHash[];
        readonly coefficientMessagesByShamirIndex: readonly (readonly number[])[];
        readonly openingRandomnessByShamirIndex: readonly (readonly (readonly number[])[])[];
        readonly proofRandomnessSeedHex: string;
        readonly proofRandomnessNonceHex: string;
    }): BgvPrivateVssShareProofGeneration;
    generateTrusteeEvaluationKeyProof(input: {
        readonly context: BgvTrusteeEvaluationKeyStatementContext;
        readonly ringDegree: number;
        readonly keys: readonly BgvTrusteeEvaluationKeyStatementKey[];
        readonly sameSecretLinkage?: BgvTrusteeEvaluationKeySameSecretLinkage;
        readonly secretCoefficients: readonly number[];
        readonly errorCoefficientsByKey: readonly (readonly (readonly number[])[])[];
        readonly negativeIndicatorCoefficients?: readonly number[];
        readonly openingRandomnessByLimb?: readonly (readonly (readonly number[])[])[];
        readonly proofRandomnessSeedHex: string;
        readonly proofRandomnessNonceHex: string;
    }): BgvTrusteeEvaluationKeyProofGeneration;
    verifyTrusteeEvaluationKeyProof(input: {
        readonly context: BgvTrusteeEvaluationKeyStatementContext;
        readonly ringDegree: number;
        readonly keys: readonly BgvTrusteeEvaluationKeyStatementKey[];
        readonly sameSecretLinkage?: BgvTrusteeEvaluationKeySameSecretLinkage;
        readonly proofBytesHex: string;
    }): BgvTrusteeEvaluationKeyProofVerification;
    generateCompactVssShareLinkageProof(input: {
        readonly context: BgvTrusteeEvaluationKeyStatementContext;
        readonly ringDegree: number;
        readonly compactVssShareLinkage: BgvCompactVssShareLinkageProofStatement;
        readonly coefficientMessagesByShamirIndex: readonly (readonly number[])[];
        readonly recipientShareMessages: readonly number[];
        readonly coefficientOpeningRandomnessByShamirIndex: readonly (readonly (readonly number[])[])[];
        readonly recipientShareOpeningRandomness: readonly (readonly number[])[];
        readonly carryWitnesses: readonly number[];
        readonly recipientShareMessagesByItem?: readonly (readonly number[])[];
        readonly recipientShareOpeningRandomnessByItem?: readonly (readonly (readonly number[])[])[];
        readonly carryWitnessesByItem?: readonly (readonly number[])[];
        readonly proofRandomnessSeedHex: string;
        readonly proofRandomnessNonceHex: string;
    }): BgvCompactVssShareLinkageProofGeneration;
    verifyCompactVssShareLinkageProof(input: {
        readonly context: BgvTrusteeEvaluationKeyStatementContext;
        readonly ringDegree: number;
        readonly compactVssShareLinkage: BgvCompactVssShareLinkageProofStatement;
        readonly proofBytesHex: string;
    }): BgvCompactVssShareLinkageProofVerification;
    verifyCompactVssShareLinkageProofMaterialSet(input: {
        readonly statement: Readonly<Record<string, unknown>>;
        readonly coefficientCommitmentSet: Readonly<Record<string, unknown>>;
        readonly recipientShareCommitmentSet: Readonly<Record<string, unknown>>;
        readonly aggregateThresholdCommitmentSet: Readonly<
            Record<string, unknown>
        >;
        readonly proofMaterialSet: Readonly<Record<string, unknown>>;
    }): BgvCompactVssShareLinkageProofMaterialSetVerification;
    generateCompactSameSecretBridgeProof(input: {
        readonly context: BgvTrusteeEvaluationKeyStatementContext;
        readonly ringDegree: number;
        readonly compactSameSecretBridge: BgvCompactSameSecretBridgeProofStatement;
        readonly secretCoefficients: readonly number[];
        readonly negativeIndicatorCoefficients: readonly number[];
        readonly openingRandomnessByLimb: readonly (readonly (readonly number[])[])[];
        readonly proofRandomnessSeedHex: string;
        readonly proofRandomnessNonceHex: string;
    }): BgvCompactSameSecretBridgeProofGeneration;
    verifyCompactSameSecretBridgeProof(input: {
        readonly context: BgvTrusteeEvaluationKeyStatementContext;
        readonly ringDegree: number;
        readonly compactSameSecretBridge: BgvCompactSameSecretBridgeProofStatement;
        readonly proofBytesHex: string;
    }): BgvCompactSameSecretBridgeProofVerification;
    computeSetupCommitmentFromOpening(input: {
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly sourceRnsLimbIndex: number;
        readonly sourceMessageModulus: number;
        readonly shamirCoefficientIndex: number;
        readonly messageCoefficients: readonly number[];
        readonly randomnessByColumn: readonly (readonly number[])[];
        readonly ringDegree: number;
    }): BgvSetupCommitmentOpeningComputation;
    computeCompactVssCommitmentFromOpening(
        input: BgvCompactVssCommitmentOpeningInput,
    ): BgvCompactVssCommitmentOpeningComputation;
    encodeCompactVssCommitmentBody(input: {
        readonly commitment: Readonly<Record<string, unknown>>;
    }): BgvCompactVssCommitmentBodyEncoding;
    decodeCompactVssCommitmentBody(input: {
        readonly metadata: BgvCompactVssCommitmentBodyMetadata;
        readonly commitmentBodyBytes: Uint8Array;
    }): BgvCompactVssCommitmentBodyDecoding;
    verifyCompactVssCommitmentOpening(input: {
        readonly opening: BgvCompactVssCommitmentOpeningInput;
        readonly expectedCommitmentRoot: ProtocolHash;
        readonly expectedOpeningRoot: ProtocolHash;
    }): BgvCompactVssCommitmentOpeningVerification;
    verifyCompactVssCoefficientCommitmentSet(input: {
        readonly coefficientCommitmentSet: Readonly<Record<string, unknown>>;
    }): BgvCompactVssCoefficientCommitmentSetVerification;
    verifyCompactVssRecipientShareCommitmentSet(input: {
        readonly recipientShareCommitmentSet: Readonly<Record<string, unknown>>;
    }): BgvCompactVssRecipientShareCommitmentSetVerification;
    verifyCompactVssAggregateThresholdCommitmentSet(input: {
        readonly aggregateThresholdCommitmentSet: Readonly<
            Record<string, unknown>
        >;
    }): BgvCompactVssAggregateThresholdCommitmentSetVerification;
    verifyCompactVssShareLinkageStatement(input: {
        readonly statement: Readonly<Record<string, unknown>>;
        readonly coefficientCommitmentSet: Readonly<Record<string, unknown>>;
        readonly recipientShareCommitmentSet: Readonly<Record<string, unknown>>;
        readonly aggregateThresholdCommitmentSet: Readonly<
            Record<string, unknown>
        >;
    }): BgvCompactVssShareLinkageStatementVerification;
    verifyCompactVssSameSecretBridgeStatementSet(input: {
        readonly statementSet: Readonly<Record<string, unknown>>;
        readonly sameSecretConsistency: Readonly<Record<string, unknown>>;
        readonly sameSecretProofs: Readonly<Record<string, unknown>>;
        readonly transportedSameSecretProofMaterial?: Readonly<
            Record<string, unknown>
        >;
    }): BgvCompactVssSameSecretBridgeStatementSetVerification;
    verifyCompactVssSameSecretBridgeProofMaterialSet(input: {
        readonly statementSet: Readonly<Record<string, unknown>>;
        readonly proofMaterialSet: Readonly<Record<string, unknown>>;
        readonly sameSecretConsistency: Readonly<Record<string, unknown>>;
        readonly sameSecretProofs: Readonly<Record<string, unknown>>;
        readonly transportedSameSecretProofMaterial?: Readonly<
            Record<string, unknown>
        >;
    }): BgvCompactVssSameSecretBridgeProofMaterialSetVerification;
    deriveThresholdShareCommitments(input: {
        readonly setupContext: unknown;
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly sourceTrusteeCoefficientCommitmentRecords: readonly unknown[];
        readonly coefficientCommitments: readonly unknown[];
    }): BgvThresholdShareCommitmentDerivation;
    deriveThresholdShareCommitmentsFromTransport(input: {
        readonly setupContext: unknown;
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly vssCoefficientCommitmentRoot: ProtocolHash;
        readonly sourceTrusteeCoefficientCommitmentRecords: readonly unknown[];
        readonly transportedVssCoefficientCommitmentMaterial: BgvTransportedVssCoefficientCommitmentMaterial;
    }): BgvThresholdShareCommitmentTransportDerivation;
    beginThresholdShareCommitmentsFromTransportStream(input: {
        readonly derivationId: string;
        readonly setupContext: unknown;
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly transportedVssCoefficientCommitmentMaterial:
            | BgvTransportedVssCoefficientCommitmentMaterialReference
            | BgvTransportedVssCoefficientCommitmentMaterialTemplate;
    }): BgvThresholdShareCommitmentTransportStreamBegin;
    abortThresholdShareCommitmentsFromTransportStream(input: {
        readonly derivationId: string;
    }): BgvThresholdShareCommitmentTransportStreamAbort;
    absorbThresholdShareCommitmentsFromTransportStreamChunk(input: {
        readonly derivationId: string;
        readonly chunkIndex: number;
        readonly bytesHex: string;
    }): BgvThresholdShareCommitmentTransportStreamChunkAbsorption;
    finishThresholdShareCommitmentsFromTransportStream(input: {
        readonly derivationId: string;
        readonly vssCoefficientCommitmentRoot: ProtocolHash;
        readonly sourceTrusteeCoefficientCommitmentRecords: readonly unknown[];
    }): BgvThresholdShareCommitmentTransportStreamDerivation;
    releaseVerifiedTransportedVssMaterial(input: {
        readonly verificationId: string;
    }): BgvVerifiedTransportedVssMaterialRelease;
    beginSetupProofMaterialTransportStream(input: {
        readonly verificationId: string;
        readonly transportedSetupProofMaterial: unknown;
    }): BgvSetupProofMaterialTransportStreamBegin;
    absorbSetupProofMaterialTransportStreamChunk(input: {
        readonly verificationId: string;
        readonly chunkIndex: number;
        readonly bytesHex: string;
    }): BgvSetupProofMaterialTransportStreamChunkAbsorption;
    finishSetupProofMaterialTransportStream(input: {
        readonly verificationId: string;
    }): BgvSetupProofMaterialTransportStreamVerification;
    verifyLocalTrusteeSetupState(input: {
        readonly setupContext: unknown;
        readonly localStateCommitment: unknown;
    }): BgvLocalTrusteeSetupStateVerification;
    encodeBgvBatchPlaintext(input: {
        readonly slots: readonly number[];
        readonly level?: number;
        readonly layoutBinding: unknown;
        readonly includeCanonicalBytesHex?: boolean;
    }): BgvBatchPlaintextEncoding | BgvProfileRejection;
    validateBgvPlaintextObject(input: {
        readonly canonicalBytesHex: string;
        readonly expectedPlaintextRoot?: string;
    }): BgvObjectValidation | BgvProfileRejection;
    validateBgvCiphertextObject(input: {
        readonly canonicalBytesHex: string;
        readonly expectedCiphertextRoot?: string;
    }): BgvObjectValidation | BgvProfileRejection;
    generateBgvCiphertextConventionFixture(input: {
        readonly leftSlots: readonly number[];
        readonly rightSlots: readonly number[];
        readonly includeCanonicalBytesHex?: boolean;
    }): BgvCiphertextConventionFixture | BgvProfileRejection;
    generateBgvBaseConversionFixture(input: {
        readonly slots: readonly number[];
    }): BgvBaseConversionFixture | BgvProfileRejection;
    analyzeBgvCanonicalObject(input: {
        readonly canonicalBytesHex: string;
    }): BgvCanonicalObjectAnalysis | BgvProfileRejection;
    validateBgvEvaluatorOperation(input: {
        readonly operation: string;
    }): BgvEvaluatorOperationValidation;
};

type TranscriptCoreKernelCommand =
    | {
          readonly command: 'AnalyzeCanonicalObject';
          readonly canonicalBytesHex: string;
          readonly chunkSize: number;
      }
    | {
          readonly command: 'ComputeChunkRoot';
          readonly inputHex: string;
          readonly chunkSize: number;
      }
    | {
          readonly command: 'DeriveProtocolHash';
          readonly namespace: string;
          readonly value: unknown;
      }
    | {
          readonly command: 'EvaluatePlaintextComparison';
          readonly leftTotalScore: number;
          readonly rightTotalScore: number;
          readonly rosterSize: number;
      }
    | {
          readonly command: 'HashRaw';
          readonly inputHex: string;
      }
    | {
          readonly command: 'InterpolateShamirConstantTerm';
          readonly sharePoints: readonly TranscriptCoreKernelSharePoint[];
      }
    | {
          readonly command: 'ListCanonicalErrorCodes';
      }
    | {
          readonly command: 'ListReservedRootNamespaces';
      }
    | {
          readonly command: 'VerifyFixture';
          readonly fixture: TranscriptCoreFixture;
      }
    | {
          readonly command: 'DescribeBgvRnsProfile';
      }
    | {
          readonly command: 'DescribeBgvOperationRegistry';
      }
    | {
          readonly command: 'ValidateBgvEvaluatorOperation';
          readonly operation: string;
      }
    | {
          readonly command: 'DescribeBgvPassiveSetupObjectModel';
      }
    | {
          readonly command: 'DescribeCollectiveBgvSetupProfile';
      }
    | {
          readonly command: 'DeriveCollectiveBgvSetupPublicDerivations';
          readonly publicMatrixSeedHash: ProtocolHash;
      }
    | {
          readonly command: 'GenerateBgvPassiveSetup';
          readonly ceremonyId: string;
          readonly manifestHash: ProtocolHash;
          readonly rosterHash: ProtocolHash;
          readonly thresholdProfileHash: ProtocolHash;
          readonly participants: readonly BgvPassiveSetupParticipantInput[];
          readonly setupSeed?: string;
      }
    | {
          readonly command: 'GenerateBgvEvaluationKeyMaterial';
          readonly setupPackage: BgvPassiveSetupPackage;
          readonly setupPrivateWitness: {
              readonly setupSeed: string;
          };
          readonly workingLevel?: number;
          readonly rotationKeys?: readonly {
              readonly rotation: number;
              readonly level: number;
          }[];
      }
    | {
          readonly command: 'GenerateBgvTargetDecryptionDevelopmentFixture';
      }
    | {
          readonly command: 'GenerateBgvTargetDecryptionShareFromLocalShare';
          readonly setupPackage: BgvPassiveSetupPackage;
          readonly localTargetShareWitness: unknown;
          readonly targetAcceptedRecord: unknown;
          readonly targetCiphertextBinding: unknown;
          readonly targetCiphertexts: BgvTargetCiphertextPairInput;
          readonly targetShareProfile: unknown;
          readonly trusteeIdentity: string;
      }
    | {
          readonly command: 'DeriveBgvTargetDecryptionShareProofStatement';
          readonly setupPackage: BgvPassiveSetupPackage;
          readonly localTargetShareWitness: unknown;
          readonly targetAcceptedRecord: unknown;
          readonly targetCiphertextBinding: unknown;
          readonly targetCiphertexts: BgvTargetCiphertextPairInput;
          readonly targetShareProfile: unknown;
          readonly trusteeIdentity: string;
          readonly targetDecryptionShare: BgvTargetDecryptionShare;
      }
    | {
          readonly command: 'DescribeBgvTargetDecryptionShareProofLayout';
          readonly setupPackage: BgvPassiveSetupPackage;
          readonly targetAcceptedRecord: unknown;
          readonly targetCiphertextBinding: unknown;
          readonly targetCiphertexts: BgvTargetCiphertextPairInput;
          readonly targetShareProfile: unknown;
          readonly targetDecryptionShare: BgvTargetDecryptionShare;
          readonly proofStatement: BgvTargetDecryptionShareProofStatement;
      }
    | {
          readonly command: 'GenerateBgvTargetDecryptionShareProofMaterialFromLocalWitness';
          readonly setupPackage: BgvPassiveSetupPackage;
          readonly localTargetShareWitness: unknown;
          readonly targetAcceptedRecord: unknown;
          readonly targetCiphertextBinding: unknown;
          readonly targetCiphertexts: BgvTargetCiphertextPairInput;
          readonly targetShareProfile: unknown;
          readonly trusteeIdentity: string;
          readonly targetDecryptionShare: BgvTargetDecryptionShare;
          readonly proofStatement: BgvTargetDecryptionShareProofStatement;
          readonly proofRandomnessSeedHex: string;
          readonly proofRandomnessNonceHex: string;
      }
    | {
          readonly command: 'VerifyBgvTargetDecryptionShareProofMaterial';
          readonly setupPackage: BgvPassiveSetupPackage;
          readonly targetAcceptedRecord: unknown;
          readonly targetCiphertextBinding: unknown;
          readonly targetCiphertexts: BgvTargetCiphertextPairInput;
          readonly targetShareProfile: unknown;
          readonly targetDecryptionShare: BgvTargetDecryptionShare;
          readonly proofStatement: BgvTargetDecryptionShareProofStatement;
          readonly proofMaterial: BgvTargetDecryptionShareProofMaterial;
      }
    | {
          readonly command: 'VerifyBgvTargetDecryptionShareBinaryProofMaterial';
          readonly setupPackage: BgvPassiveSetupPackage;
          readonly targetAcceptedRecord: unknown;
          readonly targetCiphertextBinding: unknown;
          readonly targetCiphertexts: BgvTargetCiphertextPairInput;
          readonly targetShareProfile: unknown;
          readonly targetDecryptionShare: BgvTargetDecryptionShare;
          readonly proofStatement: BgvTargetDecryptionShareProofStatement;
          readonly transportedProofMaterial: Readonly<Record<string, unknown>>;
      }
    | {
          readonly command: 'VerifyBgvTargetDecryptionShareProofStatementBinding';
          readonly setupPackage: BgvPassiveSetupPackage;
          readonly targetAcceptedRecord: unknown;
          readonly targetCiphertextBinding: unknown;
          readonly targetCiphertexts: BgvTargetCiphertextPairInput;
          readonly targetShareProfile: unknown;
          readonly targetDecryptionShare: BgvTargetDecryptionShare;
          readonly proofStatement: BgvTargetDecryptionShareProofStatement;
      }
    | {
          readonly command: 'DeriveBgvTargetDecryptionResultReleaseSetupContext';
          readonly setupPackage: BgvPassiveSetupPackage;
      }
    | {
          readonly command: 'BeginBgvTargetDecryptionResultRelease';
          readonly releaseVerificationId: string;
          readonly releaseSetupContext: BgvTargetDecryptionReleaseSetupContext;
          readonly targetAcceptedRecord: unknown;
          readonly targetCiphertextBinding: unknown;
          readonly targetCiphertexts: BgvTargetCiphertextPairInput;
          readonly targetShareProfile: unknown;
      }
    | {
          readonly command: 'AbsorbBgvTargetDecryptionResultReleaseShare';
          readonly releaseVerificationId: string;
          readonly targetShareProof: {
              readonly targetDecryptionShare: BgvTargetDecryptionShare;
              readonly proofStatement: BgvTargetDecryptionShareProofStatement;
              readonly proofMaterial: BgvTargetDecryptionShareProofMaterial;
          };
      }
    | {
          readonly command: 'FinishBgvTargetDecryptionResultRelease';
          readonly releaseVerificationId: string;
      }
    | {
          readonly command: 'VerifyBgvPassiveSetup';
          readonly setupPackage: BgvPassiveSetupPackage;
          readonly expectedSetupPackageHash?: ProtocolHash;
          readonly expectedManifestHash?: ProtocolHash;
          readonly expectedRosterHash?: ProtocolHash;
          readonly expectedCollectivePublicKeyRoot?: ProtocolHash;
          readonly expectedRotSetHash?: ProtocolHash;
          readonly expectedEvaluationKeyRoot?: ProtocolHash;
      }
    | Readonly<
          {
              readonly command: 'VerifyCollectiveBgvSetup';
              readonly setupPackage: unknown;
              readonly expectedSetupPackageHash?: ProtocolHash;
              readonly expectedManifestHash?: ProtocolHash;
              readonly expectedRosterHash?: ProtocolHash;
          } & BgvCollectiveSetupTransportCompanions
      >
    | {
          readonly command: 'VerifyPrivateVssShareEnvelope';
          readonly setupContext: unknown;
          readonly publicMatrixSeedHash: ProtocolHash;
          readonly sourceTrusteeCoefficientCommitmentRecord: unknown;
          readonly sourceTrusteeCoefficientCommitmentMaterialRecords: readonly unknown[];
          readonly privateEnvelope: unknown;
          readonly transportedPrivateVssShareProofMaterial?: unknown;
          readonly expectedPrivateEnvelopeHash?: ProtocolHash;
          readonly expectedLocalVerificationRoot?: ProtocolHash;
      }
    | {
          readonly command: 'GeneratePrivateVssShareProof';
          readonly setupContext: unknown;
          readonly publicMatrixSeedHash: ProtocolHash;
          readonly privateEnvelopeAadHash: ProtocolHash;
          readonly sourceTrusteeCoefficientCommitmentRecord: unknown;
          readonly sourceTrusteeCoefficientCommitmentMaterialRecords: readonly unknown[];
          readonly recipientIdentity: string;
          readonly recipientRosterPosition: number;
          readonly rnsLimbIndex: number;
          readonly rnsPrime: number;
          readonly ringDegree: number;
          readonly shareValues: readonly number[];
          readonly coefficientCommitmentRoots: readonly ProtocolHash[];
          readonly coefficientMessagesByShamirIndex: readonly (readonly number[])[];
          readonly openingRandomnessByShamirIndex: readonly (readonly (readonly number[])[])[];
          readonly proofRandomnessSeedHex: string;
          readonly proofRandomnessNonceHex: string;
      }
    | {
          readonly command: 'GenerateTrusteeEvaluationKeyProof';
          readonly context: BgvTrusteeEvaluationKeyStatementContext;
          readonly ringDegree: number;
          readonly keys: readonly BgvTrusteeEvaluationKeyStatementKey[];
          readonly sameSecretLinkage?: BgvTrusteeEvaluationKeySameSecretLinkage;
          readonly secretCoefficients: readonly number[];
          readonly errorCoefficientsByKey: readonly (readonly (readonly number[])[])[];
          readonly negativeIndicatorCoefficients?: readonly number[];
          readonly openingRandomnessByLimb?: readonly (readonly (readonly number[])[])[];
          readonly proofRandomnessSeedHex: string;
          readonly proofRandomnessNonceHex: string;
      }
    | {
          readonly command: 'VerifyTrusteeEvaluationKeyProof';
          readonly context: BgvTrusteeEvaluationKeyStatementContext;
          readonly ringDegree: number;
          readonly keys: readonly BgvTrusteeEvaluationKeyStatementKey[];
          readonly sameSecretLinkage?: BgvTrusteeEvaluationKeySameSecretLinkage;
          readonly proofBytesHex: string;
      }
    | {
          readonly command: 'GenerateCompactVssShareLinkageProof';
          readonly context: BgvTrusteeEvaluationKeyStatementContext;
          readonly ringDegree: number;
          readonly compactVssShareLinkage: BgvCompactVssShareLinkageProofStatement;
          readonly coefficientMessagesByShamirIndex: readonly (readonly number[])[];
          readonly recipientShareMessages: readonly number[];
          readonly coefficientOpeningRandomnessByShamirIndex: readonly (readonly (readonly number[])[])[];
          readonly recipientShareOpeningRandomness: readonly (readonly number[])[];
          readonly carryWitnesses: readonly number[];
          readonly recipientShareMessagesByItem?: readonly (readonly number[])[];
          readonly recipientShareOpeningRandomnessByItem?: readonly (readonly (readonly number[])[])[];
          readonly carryWitnessesByItem?: readonly (readonly number[])[];
          readonly proofRandomnessSeedHex: string;
          readonly proofRandomnessNonceHex: string;
      }
    | {
          readonly command: 'VerifyCompactVssShareLinkageProof';
          readonly context: BgvTrusteeEvaluationKeyStatementContext;
          readonly ringDegree: number;
          readonly compactVssShareLinkage: BgvCompactVssShareLinkageProofStatement;
          readonly proofBytesHex: string;
      }
    | {
          readonly command: 'GenerateCompactSameSecretBridgeProof';
          readonly context: BgvTrusteeEvaluationKeyStatementContext;
          readonly ringDegree: number;
          readonly compactSameSecretBridge: BgvCompactSameSecretBridgeProofStatement;
          readonly secretCoefficients: readonly number[];
          readonly negativeIndicatorCoefficients: readonly number[];
          readonly openingRandomnessByLimb: readonly (readonly (readonly number[])[])[];
          readonly proofRandomnessSeedHex: string;
          readonly proofRandomnessNonceHex: string;
      }
    | {
          readonly command: 'VerifyCompactSameSecretBridgeProof';
          readonly context: BgvTrusteeEvaluationKeyStatementContext;
          readonly ringDegree: number;
          readonly compactSameSecretBridge: BgvCompactSameSecretBridgeProofStatement;
          readonly proofBytesHex: string;
      }
    | {
          readonly command: 'ComputeSetupCommitmentFromOpening';
          readonly publicMatrixSeedHash: ProtocolHash;
          readonly sourceRnsLimbIndex: number;
          readonly sourceMessageModulus: number;
          readonly shamirCoefficientIndex: number;
          readonly messageCoefficients: readonly number[];
          readonly randomnessByColumn: readonly (readonly number[])[];
          readonly ringDegree: number;
      }
    | (BgvCompactVssCommitmentOpeningInput & {
          readonly command: 'ComputeCompactVssCommitmentFromOpening';
      })
    | {
          readonly command: 'EncodeCompactVssCommitmentBody';
          readonly commitment: Readonly<Record<string, unknown>>;
      }
    | {
          readonly command: 'DecodeCompactVssCommitmentBody';
          readonly metadata: BgvCompactVssCommitmentBodyMetadata;
          readonly commitmentBodyBytesHex: string;
      }
    | {
          readonly command: 'VerifyCompactVssCommitmentOpening';
          readonly opening: BgvCompactVssCommitmentOpeningInput;
          readonly expectedCommitmentRoot: ProtocolHash;
          readonly expectedOpeningRoot: ProtocolHash;
      }
    | {
          readonly command: 'VerifyCompactVssCoefficientCommitmentSet';
          readonly coefficientCommitmentSet: Readonly<Record<string, unknown>>;
      }
    | {
          readonly command: 'VerifyCompactVssRecipientShareCommitmentSet';
          readonly recipientShareCommitmentSet: Readonly<
              Record<string, unknown>
          >;
      }
    | {
          readonly command: 'VerifyCompactVssAggregateThresholdCommitmentSet';
          readonly aggregateThresholdCommitmentSet: Readonly<
              Record<string, unknown>
          >;
      }
    | {
          readonly command: 'VerifyCompactVssShareLinkageStatement';
          readonly statement: Readonly<Record<string, unknown>>;
          readonly coefficientCommitmentSet: Readonly<Record<string, unknown>>;
          readonly recipientShareCommitmentSet: Readonly<
              Record<string, unknown>
          >;
          readonly aggregateThresholdCommitmentSet: Readonly<
              Record<string, unknown>
          >;
      }
    | {
          readonly command: 'VerifyCompactVssShareLinkageProofMaterialSet';
          readonly statement: Readonly<Record<string, unknown>>;
          readonly coefficientCommitmentSet: Readonly<Record<string, unknown>>;
          readonly recipientShareCommitmentSet: Readonly<
              Record<string, unknown>
          >;
          readonly aggregateThresholdCommitmentSet: Readonly<
              Record<string, unknown>
          >;
          readonly proofMaterialSet: Readonly<Record<string, unknown>>;
      }
    | {
          readonly command: 'VerifyCompactVssSameSecretBridgeStatementSet';
          readonly statementSet: Readonly<Record<string, unknown>>;
          readonly sameSecretConsistency: Readonly<Record<string, unknown>>;
          readonly sameSecretProofs: Readonly<Record<string, unknown>>;
          readonly transportedSameSecretProofMaterial?: Readonly<
              Record<string, unknown>
          >;
      }
    | {
          readonly command: 'VerifyCompactVssSameSecretBridgeProofMaterialSet';
          readonly statementSet: Readonly<Record<string, unknown>>;
          readonly proofMaterialSet: Readonly<Record<string, unknown>>;
          readonly sameSecretConsistency: Readonly<Record<string, unknown>>;
          readonly sameSecretProofs: Readonly<Record<string, unknown>>;
          readonly transportedSameSecretProofMaterial?: Readonly<
              Record<string, unknown>
          >;
      }
    | {
          readonly command: 'DeriveThresholdShareCommitments';
          readonly setupContext: unknown;
          readonly publicMatrixSeedHash: ProtocolHash;
          readonly sourceTrusteeCoefficientCommitmentRecords: readonly unknown[];
          readonly coefficientCommitments: readonly unknown[];
      }
    | {
          readonly command: 'DeriveThresholdShareCommitmentsFromTransport';
          readonly setupContext: unknown;
          readonly publicMatrixSeedHash: ProtocolHash;
          readonly vssCoefficientCommitmentRoot: ProtocolHash;
          readonly sourceTrusteeCoefficientCommitmentRecords: readonly unknown[];
          readonly transportedVssCoefficientCommitmentMaterial: BgvTransportedVssCoefficientCommitmentMaterial;
      }
    | {
          readonly command: 'BeginThresholdShareCommitmentsFromTransportStream';
          readonly derivationId: string;
          readonly setupContext: unknown;
          readonly publicMatrixSeedHash: ProtocolHash;
          readonly transportedVssCoefficientCommitmentMaterial:
              | BgvTransportedVssCoefficientCommitmentMaterialReference
              | BgvTransportedVssCoefficientCommitmentMaterialTemplate;
      }
    | {
          readonly command: 'AbortThresholdShareCommitmentsFromTransportStream';
          readonly derivationId: string;
      }
    | {
          readonly command: 'AbsorbThresholdShareCommitmentsFromTransportStreamChunk';
          readonly derivationId: string;
          readonly chunkIndex: number;
          readonly bytesHex: string;
      }
    | {
          readonly command: 'FinishThresholdShareCommitmentsFromTransportStream';
          readonly derivationId: string;
          readonly vssCoefficientCommitmentRoot: ProtocolHash;
          readonly sourceTrusteeCoefficientCommitmentRecords: readonly unknown[];
      }
    | {
          readonly command: 'ReleaseVerifiedTransportedVssMaterial';
          readonly verificationId: string;
      }
    | {
          readonly command: 'BeginSetupProofMaterialTransportStream';
          readonly verificationId: string;
          readonly transportedSetupProofMaterial: unknown;
      }
    | {
          readonly command: 'AbsorbSetupProofMaterialTransportStreamChunk';
          readonly verificationId: string;
          readonly chunkIndex: number;
          readonly bytesHex: string;
      }
    | {
          readonly command: 'FinishSetupProofMaterialTransportStream';
          readonly verificationId: string;
      }
    | {
          readonly command: 'VerifyLocalTrusteeSetupState';
          readonly setupContext: unknown;
          readonly localStateCommitment: unknown;
      }
    | {
          readonly command: 'EncodeBgvBatchPlaintext';
          readonly slots: readonly number[];
          readonly level?: number;
          readonly layoutBinding: unknown;
          readonly includeCanonicalBytesHex?: boolean;
      }
    | {
          readonly command: 'ValidateBgvPlaintextObject';
          readonly canonicalBytesHex: string;
          readonly expectedPlaintextRoot?: string;
      }
    | {
          readonly command: 'ValidateBgvCiphertextObject';
          readonly canonicalBytesHex: string;
          readonly expectedCiphertextRoot?: string;
      }
    | {
          readonly command: 'GenerateBgvCiphertextConventionFixture';
          readonly leftSlots: readonly number[];
          readonly rightSlots: readonly number[];
          readonly includeCanonicalBytesHex?: boolean;
      }
    | {
          readonly command: 'GenerateBgvBaseConversionFixture';
          readonly slots: readonly number[];
      }
    | {
          readonly command: 'AnalyzeBgvCanonicalObject';
          readonly canonicalBytesHex: string;
      }
    | {
          readonly command: 'RunDirectEncryptedBallot';
          readonly setupPackage: BgvPassiveSetupPackage;
          readonly setupPrivateWitness: {
              readonly setupSeed: string;
          };
          readonly ballotEncryptionRandomness: {
              readonly source:
                  | 'fresh-csprng'
                  | 'development-deterministic-fixture';
              readonly encryptionSeedHexes: readonly string[];
          };
          readonly proofMaskRandomness: {
              readonly source:
                  | 'fresh-csprng'
                  | 'development-deterministic-fixture';
              readonly ballotProofRandomnessHexes: readonly string[];
          };
          readonly ballots: readonly {
              readonly voterIdentity: string;
              readonly actionContextHash: string;
              readonly scores: readonly number[];
              readonly oneHotWitnesses?: readonly (readonly number[])[];
          }[];
          readonly topCount?: number;
          readonly topCounts?: readonly number[];
          readonly publicEvaluationKeyMaterial?: unknown;
          readonly targetFinalityPolicyHash?: string;
      };

type TranscriptCoreKernelExports = WebAssembly.Exports & {
    memory?: WebAssembly.Memory;
    sealed_lattice_allocate?: (length: number) => number;
    sealed_lattice_deallocate?: (pointer: number, length: number) => void;
    sealed_lattice_transcript_core_command_with_length?: (
        pointer: number,
        length: number,
        outputLengthPointer: number,
    ) => number;
    sealed_lattice_roundtrip?: (pointer: number, length: number) => number;
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
