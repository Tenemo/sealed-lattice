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
    BgvCollectiveSetupParametersDescription,
    BgvCollectiveSetupPublicDerivations,
    BgvCollectiveSetupVerification,
    BgvTrusteeEvaluationKeyProofGeneration,
    BgvEvaluatorOperationValidation,
    BgvLocalTrusteeSetupStateVerification,
    BgvObjectValidation,
    BgvPassiveSetupPackage,
    BgvPassiveSetupVerification,
    BgvPrivateVssShareEnvelopeVerification,
    BgvPrivateVssShareProofGeneration,
    BgvOperationRejection,
    BgvRnsParametersDescription,
    BgvSameSecretBridgeProofGeneration,
    BgvVssPublicCommitmentOpeningComputation,
    BgvVssShareLinkageProofGeneration,
    BgvSetupCommitmentOpeningComputation,
    BgvSetupProofMaterialTransportStreamBegin,
    BgvSetupProofMaterialTransportStreamChunkAbsorption,
    BgvSetupProofMaterialTransportStreamVerification,
    BgvTargetDecryptionReleaseSetupContext,
    BgvTargetDecryptionResultReleaseBegin,
    BgvTargetDecryptionResultReleaseShareAbsorption,
    BgvTargetDecryptionResultReleaseCompletion,
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
            // This guards a single synchronous allocate/run/free cycle only; multi-call transport streams are kept separate by their kernel-side id, not by this flag.
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
            // Accepted setup is real protocol input, not a fixture, so a fixture-shaped rejection is surfaced as a rejected protocol object rather than leaking the kernel fixture error code.
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
                deriveCanonicalObjectHash: (input): ProtocolHash =>
                    executeCommand<{
                        readonly canonicalObjectHash: ProtocolHash;
                    }>({
                        command: 'DeriveCanonicalObjectHash',
                        value: input.value,
                    }).canonicalObjectHash,
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
                describeBgvRnsParameters: (): BgvRnsParametersDescription =>
                    executeCommand<BgvRnsParametersDescription>({
                        command: 'DescribeBgvRnsParameters',
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
                describeCollectiveBgvSetupParameters: (
                    input,
                ): BgvCollectiveSetupParametersDescription =>
                    executeCommand<BgvCollectiveSetupParametersDescription>({
                        command: 'DescribeCollectiveBgvSetupParameters',
                        ...(input?.participantCount === undefined
                            ? {}
                            : { participantCount: input.participantCount }),
                    }),
                deriveCollectiveBgvSetupPublicDerivations: (
                    input,
                ): BgvCollectiveSetupPublicDerivations =>
                    executeCommand<BgvCollectiveSetupPublicDerivations>({
                        command: 'DeriveCollectiveBgvSetupPublicDerivations',
                        publicMatrixSeedHash: input.publicMatrixSeedHash,
                        ...(input.decryptionThreshold === undefined
                            ? {}
                            : {
                                  decryptionThreshold:
                                      input.decryptionThreshold,
                              }),
                    }),
                generateBgvPassiveSetup: (input): BgvPassiveSetupPackage =>
                    executeCommand<BgvPassiveSetupPackage>({
                        command: 'GenerateBgvPassiveSetup',
                        ceremonyId: input.ceremonyId,
                        manifestHash: input.manifestHash,
                        rosterHash: input.rosterHash,
                        thresholdParametersHash: input.thresholdParametersHash,
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
                            verifiedSetupProofMaterials:
                                input.verifiedSetupProofMaterials,
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
                        proofRandomnessSeedHex: input.proofRandomnessSeedHex,
                        proofRandomnessNonceHex: input.proofRandomnessNonceHex,
                    }),
                generateTrusteeEvaluationKeyProof: (
                    input,
                ): BgvTrusteeEvaluationKeyProofGeneration =>
                    executeCommand<BgvTrusteeEvaluationKeyProofGeneration>({
                        command: 'GenerateTrusteeEvaluationKeyProof',
                        context: input.context,
                        ringDegree: input.ringDegree,
                        keys: input.keys,
                        sameSecretLinkage: input.sameSecretLinkage,
                        sameSecretBridge: input.sameSecretBridge,
                        secretCoefficients: input.secretCoefficients,
                        errorCoefficientsByKey: input.errorCoefficientsByKey,
                        negativeIndicatorCoefficients:
                            input.negativeIndicatorCoefficients,
                        openingRandomnessByLimb: input.openingRandomnessByLimb,
                        proofRandomnessSeedHex: input.proofRandomnessSeedHex,
                        proofRandomnessNonceHex: input.proofRandomnessNonceHex,
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
                computeVssPublicCommitmentFromOpening: (
                    input,
                ): BgvVssPublicCommitmentOpeningComputation =>
                    executeCommand<BgvVssPublicCommitmentOpeningComputation>({
                        command: 'ComputeVssPublicCommitmentFromOpening',
                        commitmentRole: input.commitmentRole,
                        commitmentContext: input.commitmentContext,
                        publicMatrixSeedHash: input.publicMatrixSeedHash,
                        rnsLimbIndex: input.rnsLimbIndex,
                        rnsPrime: input.rnsPrime,
                        ringDegree: input.ringDegree,
                        ...(input.messageCoefficientBound === undefined
                            ? {}
                            : {
                                  messageCoefficientBound:
                                      input.messageCoefficientBound,
                              }),
                        messageCoefficients: input.messageCoefficients,
                        messageDigitColumns: input.messageDigitColumns,
                        randomnessByColumn: input.randomnessByColumn,
                    }),
                generateVssShareLinkageProof: (
                    input,
                ): BgvVssShareLinkageProofGeneration =>
                    executeCommand<BgvVssShareLinkageProofGeneration>({
                        command: 'GenerateVssShareLinkageProof',
                        context: input.context,
                        ringDegree: input.ringDegree,
                        vssShareLinkage: input.vssShareLinkage,
                        coefficientMessagesByShamirIndex:
                            input.coefficientMessagesByShamirIndex,
                        recipientShareMessages: input.recipientShareMessages,
                        coefficientOpeningRandomnessByShamirIndex:
                            input.coefficientOpeningRandomnessByShamirIndex,
                        recipientShareOpeningRandomness:
                            input.recipientShareOpeningRandomness,
                        carryWitnesses: input.carryWitnesses,
                        recipientShareMessagesByItem:
                            input.recipientShareMessagesByItem,
                        recipientShareOpeningRandomnessByItem:
                            input.recipientShareOpeningRandomnessByItem,
                        carryWitnessesByItem: input.carryWitnessesByItem,
                        proofRandomnessSeedHex: input.proofRandomnessSeedHex,
                        proofRandomnessNonceHex: input.proofRandomnessNonceHex,
                    }),
                generateSameSecretBridgeProof: (
                    input,
                ): BgvSameSecretBridgeProofGeneration =>
                    executeCommand<BgvSameSecretBridgeProofGeneration>({
                        command: 'GenerateSameSecretBridgeProof',
                        context: input.context,
                        ringDegree: input.ringDegree,
                        sameSecretBridge: input.sameSecretBridge,
                        secretCoefficients: input.secretCoefficients,
                        negativeIndicatorCoefficients:
                            input.negativeIndicatorCoefficients,
                        openingRandomnessByLimb: input.openingRandomnessByLimb,
                        proofRandomnessSeedHex: input.proofRandomnessSeedHex,
                        proofRandomnessNonceHex: input.proofRandomnessNonceHex,
                    }),
                beginSetupProofMaterialTransportStream: (
                    input,
                ): BgvSetupProofMaterialTransportStreamBegin =>
                    executeCommand<BgvSetupProofMaterialTransportStreamBegin>({
                        command: 'BeginSetupProofMaterialTransportStream',
                        verificationId: input.verificationId,
                        transportedSetupProofMaterial:
                            input.transportedSetupProofMaterial,
                    }),
                absorbSetupProofMaterialTransportStreamChunk: (
                    input,
                ): BgvSetupProofMaterialTransportStreamChunkAbsorption =>
                    executeCommand<BgvSetupProofMaterialTransportStreamChunkAbsorption>(
                        {
                            command:
                                'AbsorbSetupProofMaterialTransportStreamChunk',
                            verificationId: input.verificationId,
                            chunkIndex: input.chunkIndex,
                            bytesHex: input.bytesHex,
                        },
                    ),
                finishSetupProofMaterialTransportStream: (
                    input,
                ): BgvSetupProofMaterialTransportStreamVerification =>
                    executeCommand<BgvSetupProofMaterialTransportStreamVerification>(
                        {
                            command: 'FinishSetupProofMaterialTransportStream',
                            verificationId: input.verificationId,
                        },
                    ),
                deriveBgvTargetDecryptionResultReleaseSetupContext: (
                    input,
                ): BgvTargetDecryptionReleaseSetupContext =>
                    executeCommand<BgvTargetDecryptionReleaseSetupContext>({
                        command:
                            'DeriveBgvTargetDecryptionResultReleaseSetupContext',
                        setupPackage: input.setupPackage,
                    }),
                beginBgvTargetDecryptionResultRelease: (
                    input,
                ): BgvTargetDecryptionResultReleaseBegin =>
                    executeCommand<BgvTargetDecryptionResultReleaseBegin>({
                        command: 'BeginBgvTargetDecryptionResultRelease',
                        releaseVerificationId: input.releaseVerificationId,
                        releaseSetupContext: input.releaseSetupContext,
                        targetAcceptedRecord: input.targetAcceptedRecord,
                        targetCiphertexts: input.targetCiphertexts,
                        targetCiphertextBinding: input.targetCiphertextBinding,
                        targetShareProfile: input.targetShareProfile,
                    }),
                absorbBgvTargetDecryptionResultReleaseShare: (
                    input,
                ): BgvTargetDecryptionResultReleaseShareAbsorption =>
                    executeCommand<BgvTargetDecryptionResultReleaseShareAbsorption>(
                        {
                            command:
                                'AbsorbBgvTargetDecryptionResultReleaseShare',
                            releaseVerificationId: input.releaseVerificationId,
                            targetShareProof: input.targetShareProof,
                        },
                    ),
                finishBgvTargetDecryptionResultRelease: (
                    input,
                ): BgvTargetDecryptionResultReleaseCompletion =>
                    executeCommand<BgvTargetDecryptionResultReleaseCompletion>({
                        command: 'FinishBgvTargetDecryptionResultRelease',
                        releaseVerificationId: input.releaseVerificationId,
                    }),
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
                ): BgvBatchPlaintextEncoding | BgvOperationRejection =>
                    executeCommand<
                        BgvBatchPlaintextEncoding | BgvOperationRejection
                    >({
                        command: 'EncodeBgvBatchPlaintext',
                        slots: input.slots,
                        level: input.level,
                        includeCanonicalBytesHex:
                            input.includeCanonicalBytesHex,
                    }),
                validateBgvPlaintextObject: (
                    input,
                ): BgvObjectValidation | BgvOperationRejection =>
                    executeCommand<BgvObjectValidation | BgvOperationRejection>(
                        {
                            command: 'ValidateBgvPlaintextObject',
                            canonicalBytesHex: input.canonicalBytesHex,
                            expectedPlaintextRoot: input.expectedPlaintextRoot,
                        },
                    ),
                validateBgvCiphertextObject: (
                    input,
                ): BgvObjectValidation | BgvOperationRejection =>
                    executeCommand<BgvObjectValidation | BgvOperationRejection>(
                        {
                            command: 'ValidateBgvCiphertextObject',
                            canonicalBytesHex: input.canonicalBytesHex,
                            expectedCiphertextRoot:
                                input.expectedCiphertextRoot,
                        },
                    ),
                generateBgvCiphertextConventionFixture: (
                    input,
                ): BgvCiphertextConventionFixture | BgvOperationRejection =>
                    executeCommand<
                        BgvCiphertextConventionFixture | BgvOperationRejection
                    >({
                        command: 'GenerateBgvCiphertextConventionFixture',
                        leftSlots: input.leftSlots,
                        rightSlots: input.rightSlots,
                        includeCanonicalBytesHex:
                            input.includeCanonicalBytesHex,
                    }),
                generateBgvBaseConversionFixture: (
                    input,
                ): BgvBaseConversionFixture | BgvOperationRejection =>
                    executeCommand<
                        BgvBaseConversionFixture | BgvOperationRejection
                    >({
                        command: 'GenerateBgvBaseConversionFixture',
                        slots: input.slots,
                    }),
                analyzeBgvCanonicalObject: (
                    input,
                ): BgvCanonicalObjectAnalysis | BgvOperationRejection =>
                    executeCommand<
                        BgvCanonicalObjectAnalysis | BgvOperationRejection
                    >({
                        command: 'AnalyzeBgvCanonicalObject',
                        canonicalBytesHex: input.canonicalBytesHex,
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
