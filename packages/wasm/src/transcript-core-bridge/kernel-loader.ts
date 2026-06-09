import type {
    FieldElement,
    ProtocolHash,
    TranscriptCoreAnalysis,
    TranscriptCoreFixtureVerification,
} from '@sealed-lattice/types';

import type {
    BgvCanonicalObjectAnalysis,
    BgvBaseConversionFixture,
    BgvBatchPlaintextEncoding,
    BgvCiphertextConventionFixture,
    BgvCollectiveSetupProfileDescription,
    BgvCollectiveSetupPublicDerivations,
    BgvCollectiveSetupVerification,
    BgvEvaluationKeyShareLnpProofGeneration,
    BgvEvaluatorOperationValidation,
    BgvLocalTrusteeSetupStateVerification,
    BgvObjectValidation,
    BgvPassiveSetupPackage,
    BgvPassiveSetupVerification,
    BgvPrivateVssShareEnvelopeVerification,
    BgvPrivateVssShareProofGeneration,
    BgvPublicKeyShareLnpProofGeneration,
    BgvProfileRejection,
    BgvReferenceOracleRejection,
    BgvRnsProfileDescription,
    BgvSameSecretLnpProofGeneration,
    BgvSetupCommitmentOpeningComputation,
    BgvTargetDecryptionResult,
    BgvTargetDecryptionShare,
    BgvThresholdShareCommitmentDerivation,
    BgvThresholdShareCommitmentTransportDerivation,
    BgvThresholdShareCommitmentTransportStreamBegin,
    BgvThresholdShareCommitmentTransportStreamChunkAbsorption,
    BgvThresholdShareCommitmentTransportStreamDerivation,
    TranscriptCoreKernel,
    TranscriptCoreKernelCommand,
    TranscriptCoreKernelExports,
    TranscriptCorePlaintextComparison,
} from './kernel-contracts.js';
import type { TranscriptCoreKernelLoaderOptions } from './kernel-runtime.js';
import {
    TranscriptCoreKernelCommandError,
    copyFromKernelMemory,
    copyIntoKernelMemory,
    requireKernelIntegrityExpectation,
    resolveKernelBytes,
    resolveMemory,
    resolveNumberExport,
    runKernelCommand,
    verifyKernelIntegrity,
} from './kernel-runtime.js';

export const createTranscriptCoreKernelLoader = (
    transcriptCoreKernelUrl: URL,
    options: TranscriptCoreKernelLoaderOptions = {},
): (() => Promise<TranscriptCoreKernel>) => {
    let kernelPromise: Promise<TranscriptCoreKernel> | undefined;

    return async (): Promise<TranscriptCoreKernel> => {
        kernelPromise ??= (async (): Promise<TranscriptCoreKernel> => {
            const expectedKernelSha256Hex =
                requireKernelIntegrityExpectation(options);
            const bytes = await resolveKernelBytes(transcriptCoreKernelUrl);
            if (expectedKernelSha256Hex !== undefined) {
                await verifyKernelIntegrity(bytes, expectedKernelSha256Hex);
            }
            const instantiatedSource = await WebAssembly.instantiate(bytes, {});
            const exports = instantiatedSource.instance
                .exports as TranscriptCoreKernelExports;
            const memory = resolveMemory(exports);
            const allocate = resolveNumberExport(
                exports,
                'sealed_lattice_allocate',
            ) as (length: number) => number;
            const deallocate = resolveNumberExport(
                exports,
                'sealed_lattice_deallocate',
            );
            const transcriptCoreCommandWithLength = resolveNumberExport(
                exports,
                'sealed_lattice_transcript_core_command_with_length',
            ) as (
                pointer: number,
                length: number,
                outputLengthPointer: number,
            ) => number;
            const roundtrip = resolveNumberExport(
                exports,
                'sealed_lattice_roundtrip',
            ) as (pointer: number, length: number) => number;
            const exportedFunctionNames = WebAssembly.Module.exports(
                instantiatedSource.module,
            )
                .map((entry) => entry.name)
                .sort();
            let kernelOperationInProgress = false;
            // One WASM instance has a single shared linear memory and allocator, so
            // overlapping commands would corrupt each other's buffers; the kernel is
            // single-threaded by contract, so reject any re-entrant operation.
            const runExclusiveKernelOperation = <Result>(
                operationName: string,
                operation: () => Result,
            ): Result => {
                if (kernelOperationInProgress) {
                    throw new Error(
                        `The transcript-core kernel cannot run overlapping ${operationName} operations on one instance.`,
                    );
                }
                kernelOperationInProgress = true;
                try {
                    return operation();
                } finally {
                    kernelOperationInProgress = false;
                }
            };
            const executeCommand = <T>(
                request: TranscriptCoreKernelCommand,
            ): T =>
                runExclusiveKernelOperation('command', () =>
                    runKernelCommand<T>(
                        memory,
                        allocate,
                        deallocate,
                        transcriptCoreCommandWithLength,
                        request,
                    ),
                );
            const executeAcceptedSetupCommand = <
                Result extends BgvCollectiveSetupVerification,
            >(
                request: TranscriptCoreKernelCommand,
            ): Result => {
                try {
                    return executeCommand<Result>(request);
                } catch (error) {
                    if (
                        error instanceof TranscriptCoreKernelCommandError &&
                        error.code === 'InvalidFixture'
                    ) {
                        const message = error.message.replace(
                            /^InvalidFixture: /u,
                            '',
                        );
                        throw new TranscriptCoreKernelCommandError({
                            code: 'InvalidProtocolObject',
                            message,
                        });
                    }

                    throw error;
                }
            };

            return {
                exportedFunctionNames,
                analyzeCanonicalObject: (input): TranscriptCoreAnalysis =>
                    executeCommand<TranscriptCoreAnalysis>({
                        command: 'AnalyzeCanonicalObject',
                        canonicalBytesHex: input.canonicalBytesHex,
                        chunkSize: input.chunkSize,
                    }),
                computeChunkRoot: (input): string =>
                    executeCommand<{ readonly chunkRoot: string }>({
                        command: 'ComputeChunkRoot',
                        inputHex: input.inputHex,
                        chunkSize: input.chunkSize,
                    }).chunkRoot,
                deriveProtocolHash: (input): ProtocolHash =>
                    executeCommand<{ readonly protocolHash: ProtocolHash }>({
                        command: 'DeriveProtocolHash',
                        namespace: input.namespace,
                        value: input.value,
                    }).protocolHash,
                evaluatePlaintextComparison: (
                    input,
                ): TranscriptCorePlaintextComparison =>
                    executeCommand<TranscriptCorePlaintextComparison>({
                        command: 'EvaluatePlaintextComparison',
                        leftTotalScore: input.leftTotalScore,
                        rightTotalScore: input.rightTotalScore,
                        rosterSize: input.rosterSize,
                    }),
                hashRaw: (inputHex): string =>
                    executeCommand<{ readonly hash512: string }>({
                        command: 'HashRaw',
                        inputHex,
                    }).hash512,
                interpolateShamirConstantTerm: (input): FieldElement =>
                    executeCommand<{ readonly fieldElement: FieldElement }>({
                        command: 'InterpolateShamirConstantTerm',
                        sharePoints: input.sharePoints,
                    }).fieldElement,
                listCanonicalErrorCodes: (): readonly string[] =>
                    executeCommand<readonly string[]>({
                        command: 'ListCanonicalErrorCodes',
                    }),
                listReservedRootNamespaces: (): readonly string[] =>
                    executeCommand<readonly string[]>({
                        command: 'ListReservedRootNamespaces',
                    }),
                roundTripBytes: (input: Uint8Array): Uint8Array =>
                    runExclusiveKernelOperation('round-trip', () => {
                        const normalizedInput = Uint8Array.from(input);
                        let inputPointer = 0;
                        let outputPointer = 0;

                        try {
                            inputPointer = copyIntoKernelMemory(
                                memory,
                                allocate,
                                normalizedInput,
                            );
                            outputPointer = roundtrip(
                                inputPointer,
                                normalizedInput.length,
                            );

                            return copyFromKernelMemory(
                                memory,
                                outputPointer,
                                normalizedInput.length,
                                'round-trip',
                            );
                        } finally {
                            if (outputPointer !== 0) {
                                deallocate(
                                    outputPointer,
                                    normalizedInput.length,
                                );
                            }
                            if (
                                inputPointer !== 0 &&
                                inputPointer !== outputPointer
                            ) {
                                deallocate(
                                    inputPointer,
                                    normalizedInput.length,
                                );
                            }
                        }
                    }),
                verifyFixture: (fixture): TranscriptCoreFixtureVerification =>
                    executeCommand<TranscriptCoreFixtureVerification>({
                        command: 'VerifyFixture',
                        fixture,
                    }),
                describeBgvRnsProfile: (): BgvRnsProfileDescription =>
                    executeCommand<BgvRnsProfileDescription>({
                        command: 'DescribeBgvRnsProfile',
                    }),
                describeBgvOperationRegistry: (): unknown =>
                    executeCommand<unknown>({
                        command: 'DescribeBgvOperationRegistry',
                    }),
                validateBgvEvaluatorOperation: (
                    input,
                ): BgvEvaluatorOperationValidation =>
                    executeCommand<BgvEvaluatorOperationValidation>({
                        command: 'ValidateBgvEvaluatorOperation',
                        operation: input.operation,
                    }),
                describeBgvPassiveSetupObjectModel: (): unknown =>
                    executeCommand<unknown>({
                        command: 'DescribeBgvPassiveSetupObjectModel',
                    }),
                describeCollectiveBgvSetupProfile:
                    (): BgvCollectiveSetupProfileDescription =>
                        executeCommand<BgvCollectiveSetupProfileDescription>({
                            command: 'DescribeCollectiveBgvSetupProfile',
                        }),
                deriveCollectiveBgvSetupPublicDerivations: (
                    input,
                ): BgvCollectiveSetupPublicDerivations =>
                    executeCommand<BgvCollectiveSetupPublicDerivations>({
                        command: 'DeriveCollectiveBgvSetupPublicDerivations',
                        publicMatrixSeedHash: input.publicMatrixSeedHash,
                    }),
                generateBgvPassiveSetup: (input): BgvPassiveSetupPackage =>
                    executeCommand<BgvPassiveSetupPackage>({
                        command: 'GenerateBgvPassiveSetup',
                        ceremonyId: input.ceremonyId,
                        manifestHash: input.manifestHash,
                        rosterHash: input.rosterHash,
                        thresholdProfileHash: input.thresholdProfileHash,
                        participants: input.participants,
                        setupSeed: input.setupSeed,
                    }),
                generateBgvEvaluationKeyMaterial: (
                    input,
                ): Record<string, unknown> =>
                    executeCommand<Record<string, unknown>>({
                        command: 'GenerateBgvEvaluationKeyMaterial',
                        setupPackage: input.setupPackage,
                        setupPrivateWitness: input.setupPrivateWitness,
                        workingLevel: input.workingLevel,
                        rotationKeys: input.rotationKeys,
                    }),
                generateBgvTargetDecryptionShare: (
                    input,
                ): BgvTargetDecryptionShare =>
                    executeCommand<BgvTargetDecryptionShare>({
                        command: 'GenerateBgvTargetDecryptionShare',
                        setupPackage: input.setupPackage,
                        setupPrivateWitness: input.setupPrivateWitness,
                        targetAcceptedRecord: input.targetAcceptedRecord,
                        targetCiphertextBinding: input.targetCiphertextBinding,
                        targetCiphertexts: input.targetCiphertexts,
                        targetShareProfile: input.targetShareProfile,
                        trusteeIdentity: input.trusteeIdentity,
                    }),
                recombineBgvTargetDecryptionShares: (
                    input,
                ): BgvTargetDecryptionResult =>
                    executeCommand<BgvTargetDecryptionResult>({
                        command: 'RecombineBgvTargetDecryptionShares',
                        setupPackage: input.setupPackage,
                        targetAcceptedRecord: input.targetAcceptedRecord,
                        targetCiphertextBinding: input.targetCiphertextBinding,
                        targetCiphertexts: input.targetCiphertexts,
                        targetShareProfile: input.targetShareProfile,
                        decryptionShares: input.decryptionShares,
                    }),
                verifyBgvPassiveSetup: (input): BgvPassiveSetupVerification =>
                    executeCommand<BgvPassiveSetupVerification>({
                        command: 'VerifyBgvPassiveSetup',
                        setupPackage: input.setupPackage,
                        expectedSetupPackageHash:
                            input.expectedSetupPackageHash,
                        expectedManifestHash: input.expectedManifestHash,
                        expectedRosterHash: input.expectedRosterHash,
                        expectedCollectivePublicKeyRoot:
                            input.expectedCollectivePublicKeyRoot,
                        expectedRotSetHash: input.expectedRotSetHash,
                        expectedEvaluationKeyRoot:
                            input.expectedEvaluationKeyRoot,
                    }),
                verifyCollectiveBgvSetup: (
                    input,
                ): BgvCollectiveSetupVerification =>
                    executeAcceptedSetupCommand<BgvCollectiveSetupVerification>(
                        {
                            command: 'VerifyCollectiveBgvSetup',
                            setupPackage: input.setupPackage,
                            expectedSetupPackageHash:
                                input.expectedSetupPackageHash,
                            expectedManifestHash: input.expectedManifestHash,
                            expectedRosterHash: input.expectedRosterHash,
                            transportedVssCoefficientCommitmentMaterial:
                                input.transportedVssCoefficientCommitmentMaterial,
                            verifiedVssCoefficientCommitmentMaterial:
                                input.verifiedVssCoefficientCommitmentMaterial,
                            transportedSameSecretProofMaterial:
                                input.transportedSameSecretProofMaterial,
                            transportedPublicKeyShareMaterial:
                                input.transportedPublicKeyShareMaterial,
                            transportedPublicKeyShareProofMaterial:
                                input.transportedPublicKeyShareProofMaterial,
                            transportedEvaluationKeyShareProofMaterial:
                                input.transportedEvaluationKeyShareProofMaterial,
                            transportedEvaluationKeyShareComponentMaterial:
                                input.transportedEvaluationKeyShareComponentMaterial,
                            transportedPublicEvaluationKeyMaterial:
                                input.transportedPublicEvaluationKeyMaterial,
                        },
                    ),
                verifyPrivateVssShareEnvelope: (
                    input,
                ): BgvPrivateVssShareEnvelopeVerification =>
                    executeCommand<BgvPrivateVssShareEnvelopeVerification>({
                        command: 'VerifyPrivateVssShareEnvelope',
                        setupContext: input.setupContext,
                        publicMatrixSeedHash: input.publicMatrixSeedHash,
                        sourceTrusteeCoefficientCommitmentRecord:
                            input.sourceTrusteeCoefficientCommitmentRecord,
                        sourceTrusteeCoefficientCommitmentMaterialRecords:
                            input.sourceTrusteeCoefficientCommitmentMaterialRecords,
                        privateEnvelope: input.privateEnvelope,
                        transportedPrivateVssShareProofMaterial:
                            input.transportedPrivateVssShareProofMaterial,
                        expectedPrivateEnvelopeHash:
                            input.expectedPrivateEnvelopeHash,
                        expectedLocalVerificationRoot:
                            input.expectedLocalVerificationRoot,
                    }),
                generatePrivateVssShareProof: (
                    input,
                ): BgvPrivateVssShareProofGeneration =>
                    executeCommand<BgvPrivateVssShareProofGeneration>({
                        command: 'GeneratePrivateVssShareProof',
                        setupContext: input.setupContext,
                        publicMatrixSeedHash: input.publicMatrixSeedHash,
                        privateEnvelopeAadHash: input.privateEnvelopeAadHash,
                        sourceTrusteeCoefficientCommitmentRecord:
                            input.sourceTrusteeCoefficientCommitmentRecord,
                        sourceTrusteeCoefficientCommitmentMaterialRecords:
                            input.sourceTrusteeCoefficientCommitmentMaterialRecords,
                        recipientIdentity: input.recipientIdentity,
                        recipientRosterPosition: input.recipientRosterPosition,
                        rnsLimbIndex: input.rnsLimbIndex,
                        rnsPrime: input.rnsPrime,
                        ringDegree: input.ringDegree,
                        shareValues: input.shareValues,
                        coefficientCommitmentRoots:
                            input.coefficientCommitmentRoots,
                        coefficientMessagesByShamirIndex:
                            input.coefficientMessagesByShamirIndex,
                        openingRandomnessByShamirIndex:
                            input.openingRandomnessByShamirIndex,
                        proofRandomnessSource: input.proofRandomnessSource,
                        proofRandomnessSeedHex: input.proofRandomnessSeedHex,
                    }),
                generateSameSecretLnpProof: (
                    input,
                ): BgvSameSecretLnpProofGeneration =>
                    executeCommand<BgvSameSecretLnpProofGeneration>({
                        command: 'GenerateSameSecretLnpProof',
                        publicMatrixSeedHash: input.publicMatrixSeedHash,
                        statementRecord: input.statementRecord,
                        constantCommitments: input.constantCommitments,
                        setupProofBinding: input.setupProofBinding,
                        secretCoefficients: input.secretCoefficients,
                        openingRandomnessByLimb: input.openingRandomnessByLimb,
                        proofRandomnessSource: input.proofRandomnessSource,
                        proofRandomnessSeedHex: input.proofRandomnessSeedHex,
                    }),
                generatePublicKeyShareLnpProof: (
                    input,
                ): BgvPublicKeyShareLnpProofGeneration =>
                    executeCommand<BgvPublicKeyShareLnpProofGeneration>({
                        command: 'GeneratePublicKeyShareLnpProof',
                        publicMatrixSeedHash: input.publicMatrixSeedHash,
                        publicKeyShareRecord: input.publicKeyShareRecord,
                        publicKeyShareProofRecord:
                            input.publicKeyShareProofRecord,
                        sameSecretStatementRecord:
                            input.sameSecretStatementRecord,
                        constantCommitments: input.constantCommitments,
                        publicShareCoefficientsByLimb:
                            input.publicShareCoefficientsByLimb,
                        setupProofBinding: input.setupProofBinding,
                        secretCoefficients: input.secretCoefficients,
                        openingRandomnessByLimb: input.openingRandomnessByLimb,
                        errorCoefficientsByLimb: input.errorCoefficientsByLimb,
                        proofRandomnessSource: input.proofRandomnessSource,
                        proofRandomnessSeedHex: input.proofRandomnessSeedHex,
                    }),
                generateEvaluationKeyShareLnpProof: (
                    input,
                ): BgvEvaluationKeyShareLnpProofGeneration =>
                    executeCommand<BgvEvaluationKeyShareLnpProofGeneration>({
                        command: 'GenerateEvaluationKeyShareLnpProof',
                        proofFamily: input.proofFamily,
                        publicMatrixSeedHash: input.publicMatrixSeedHash,
                        proofRecord: input.proofRecord,
                        sameSecretStatementRecord:
                            input.sameSecretStatementRecord,
                        constantCommitments: input.constantCommitments,
                        setupProofBinding: input.setupProofBinding,
                        transportedKeySwitchComponentMaterial:
                            input.transportedKeySwitchComponentMaterial,
                        secretCoefficients: input.secretCoefficients,
                        openingRandomnessByLimb: input.openingRandomnessByLimb,
                        errorCoefficientsByDigit:
                            input.errorCoefficientsByDigit,
                        relinearizationSourceCoefficientsByDigit:
                            input.relinearizationSourceCoefficientsByDigit,
                        roundOneAggregateSourceCoefficientsByDigit:
                            input.roundOneAggregateSourceCoefficientsByDigit,
                        proofRandomnessSource: input.proofRandomnessSource,
                        proofRandomnessSeedHex: input.proofRandomnessSeedHex,
                    }),
                computeSetupCommitmentFromOpening: (
                    input,
                ): BgvSetupCommitmentOpeningComputation =>
                    executeCommand<BgvSetupCommitmentOpeningComputation>({
                        command: 'ComputeSetupCommitmentFromOpening',
                        publicMatrixSeedHash: input.publicMatrixSeedHash,
                        sourceRnsLimbIndex: input.sourceRnsLimbIndex,
                        sourceMessageModulus: input.sourceMessageModulus,
                        shamirCoefficientIndex: input.shamirCoefficientIndex,
                        messageCoefficients: input.messageCoefficients,
                        randomnessByColumn: input.randomnessByColumn,
                        ringDegree: input.ringDegree,
                    }),
                deriveThresholdShareCommitments: (
                    input,
                ): BgvThresholdShareCommitmentDerivation =>
                    executeCommand<BgvThresholdShareCommitmentDerivation>({
                        command: 'DeriveThresholdShareCommitments',
                        setupContext: input.setupContext,
                        publicMatrixSeedHash: input.publicMatrixSeedHash,
                        sourceTrusteeCoefficientCommitmentRecords:
                            input.sourceTrusteeCoefficientCommitmentRecords,
                        coefficientCommitments: input.coefficientCommitments,
                    }),
                deriveThresholdShareCommitmentsFromTransport: (
                    input,
                ): BgvThresholdShareCommitmentTransportDerivation =>
                    executeCommand<BgvThresholdShareCommitmentTransportDerivation>(
                        {
                            command:
                                'DeriveThresholdShareCommitmentsFromTransport',
                            setupContext: input.setupContext,
                            publicMatrixSeedHash: input.publicMatrixSeedHash,
                            vssCoefficientCommitmentRoot:
                                input.vssCoefficientCommitmentRoot,
                            sourceTrusteeCoefficientCommitmentRecords:
                                input.sourceTrusteeCoefficientCommitmentRecords,
                            transportedVssCoefficientCommitmentMaterial:
                                input.transportedVssCoefficientCommitmentMaterial,
                        },
                    ),
                beginThresholdShareCommitmentsFromTransportStream: (
                    input,
                ): BgvThresholdShareCommitmentTransportStreamBegin =>
                    executeCommand<BgvThresholdShareCommitmentTransportStreamBegin>(
                        {
                            command:
                                'BeginThresholdShareCommitmentsFromTransportStream',
                            derivationId: input.derivationId,
                            setupContext: input.setupContext,
                            publicMatrixSeedHash: input.publicMatrixSeedHash,
                            transportedVssCoefficientCommitmentMaterial:
                                input.transportedVssCoefficientCommitmentMaterial,
                        },
                    ),
                absorbThresholdShareCommitmentsFromTransportStreamChunk: (
                    input,
                ): BgvThresholdShareCommitmentTransportStreamChunkAbsorption =>
                    executeCommand<BgvThresholdShareCommitmentTransportStreamChunkAbsorption>(
                        {
                            command:
                                'AbsorbThresholdShareCommitmentsFromTransportStreamChunk',
                            derivationId: input.derivationId,
                            chunkIndex: input.chunkIndex,
                            bytesHex: input.bytesHex,
                        },
                    ),
                finishThresholdShareCommitmentsFromTransportStream: (
                    input,
                ): BgvThresholdShareCommitmentTransportStreamDerivation =>
                    executeCommand<BgvThresholdShareCommitmentTransportStreamDerivation>(
                        {
                            command:
                                'FinishThresholdShareCommitmentsFromTransportStream',
                            derivationId: input.derivationId,
                            vssCoefficientCommitmentRoot:
                                input.vssCoefficientCommitmentRoot,
                            sourceTrusteeCoefficientCommitmentRecords:
                                input.sourceTrusteeCoefficientCommitmentRecords,
                        },
                    ),
                verifyLocalTrusteeSetupState: (
                    input,
                ): BgvLocalTrusteeSetupStateVerification =>
                    executeCommand<BgvLocalTrusteeSetupStateVerification>({
                        command: 'VerifyLocalTrusteeSetupState',
                        setupContext: input.setupContext,
                        localStateCommitment: input.localStateCommitment,
                    }),
                encodeBgvBatchPlaintext: (
                    input,
                ): BgvBatchPlaintextEncoding | BgvProfileRejection =>
                    executeCommand<
                        BgvBatchPlaintextEncoding | BgvProfileRejection
                    >({
                        command: 'EncodeBgvBatchPlaintext',
                        slots: input.slots,
                        level: input.level,
                        layoutBinding: input.layoutBinding,
                        includeCanonicalBytesHex:
                            input.includeCanonicalBytesHex,
                    }),
                validateBgvPlaintextObject: (
                    input,
                ): BgvObjectValidation | BgvProfileRejection =>
                    executeCommand<BgvObjectValidation | BgvProfileRejection>({
                        command: 'ValidateBgvPlaintextObject',
                        canonicalBytesHex: input.canonicalBytesHex,
                        expectedPlaintextRoot: input.expectedPlaintextRoot,
                    }),
                validateBgvCiphertextObject: (
                    input,
                ): BgvObjectValidation | BgvProfileRejection =>
                    executeCommand<BgvObjectValidation | BgvProfileRejection>({
                        command: 'ValidateBgvCiphertextObject',
                        canonicalBytesHex: input.canonicalBytesHex,
                        expectedCiphertextRoot: input.expectedCiphertextRoot,
                    }),
                generateBgvCiphertextConventionFixture: (
                    input,
                ): BgvCiphertextConventionFixture | BgvProfileRejection =>
                    executeCommand<
                        BgvCiphertextConventionFixture | BgvProfileRejection
                    >({
                        command: 'GenerateBgvCiphertextConventionFixture',
                        leftSlots: input.leftSlots,
                        rightSlots: input.rightSlots,
                        includeCanonicalBytesHex:
                            input.includeCanonicalBytesHex,
                    }),
                generateBgvBaseConversionFixture: (
                    input,
                ): BgvBaseConversionFixture | BgvProfileRejection =>
                    executeCommand<
                        BgvBaseConversionFixture | BgvProfileRejection
                    >({
                        command: 'GenerateBgvBaseConversionFixture',
                        slots: input.slots,
                    }),
                analyzeBgvCanonicalObject: (
                    input,
                ): BgvCanonicalObjectAnalysis | BgvProfileRejection =>
                    executeCommand<
                        BgvCanonicalObjectAnalysis | BgvProfileRejection
                    >({
                        command: 'AnalyzeBgvCanonicalObject',
                        canonicalBytesHex: input.canonicalBytesHex,
                    }),
                rejectBgvReferenceOracleArtifact: (
                    input,
                ): BgvReferenceOracleRejection =>
                    executeCommand<BgvReferenceOracleRejection>({
                        command: 'RejectBgvReferenceOracleArtifact',
                        artifact: input.artifact,
                    }),
            };
        })().catch((error: unknown) => {
            // Clear the cached promise on failure so a later call can retry
            // instantiation instead of permanently re-throwing the cached rejection.
            kernelPromise = undefined;
            throw error;
        });

        return kernelPromise;
    };
};
