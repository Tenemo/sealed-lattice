import type {
    FieldElement,
    ProtocolHash,
    TranscriptCoreAnalysis,
    TranscriptCoreFixtureVerification,
} from '@sealed-lattice/types';

import type {
    BallotPrivacyEncodedRelationVectorVerification,
    BallotPrivacyKernelVerification,
    BallotPrivacyLinearProofVectorVerification,
    BallotPrivacyProofBackendStatus,
    BallotPrivacyProofGeneration,
    BallotPrivacyReceiverKeyProofGeneration,
    BallotPrivacyReceiverKeyProofGenerationPreparation,
    BallotPrivacyReceiverKeyVectorVerification,
    BgvCanonicalObjectAnalysis,
    BgvBaseConversionFixture,
    BgvBatchPlaintextEncoding,
    BgvCiphertextConventionFixture,
    BgvEvaluatorOperationValidation,
    BgvObjectValidation,
    BgvPassiveSetupPackage,
    BgvPassiveSetupVerification,
    BgvProfileRejection,
    BgvReferenceOracleRejection,
    BgvRnsProfileDescription,
    TopKEvaluatorDevelopmentEvaluation,
    TopKEvaluatorEncryptedAggregateEvaluation,
    TranscriptCoreKernel,
    TranscriptCoreKernelCommand,
    TranscriptCoreKernelExports,
    TranscriptCorePlaintextComparison,
} from './kernel-contracts.js';
import {
    componentProverRandomnessHexes,
    suppliedOrFreshBridgeRandomness,
    suppliedOrFreshRandomnessHex,
} from './kernel-contracts.js';
import type { TranscriptCoreKernelLoaderOptions } from './kernel-runtime.js';
import {
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
                describeBallotPrivacyProofBackend:
                    (): BallotPrivacyProofBackendStatus =>
                        executeCommand<BallotPrivacyProofBackendStatus>({
                            command: 'DescribeBallotPrivacyProofBackend',
                        }),
                verifyBallotPrivacyLinearProofVector: (
                    input,
                ): BallotPrivacyLinearProofVectorVerification =>
                    executeCommand<BallotPrivacyLinearProofVectorVerification>({
                        command: 'VerifyBallotPrivacyLinearProofVector',
                        vectorCase: input.vectorCase,
                    }),
                verifyBallotPrivacyEncodedRelationVector: (
                    input,
                ): BallotPrivacyEncodedRelationVectorVerification =>
                    executeCommand<BallotPrivacyEncodedRelationVectorVerification>(
                        {
                            command: 'VerifyBallotPrivacyEncodedRelationVector',
                            vectorCase: input.vectorCase,
                        },
                    ),
                verifyBallotPrivacyReceiverKeyVector: (
                    input,
                ): BallotPrivacyReceiverKeyVectorVerification =>
                    executeCommand<BallotPrivacyReceiverKeyVectorVerification>({
                        command: 'VerifyBallotPrivacyReceiverKeyVector',
                        vectorCase: input.vectorCase,
                    }),
                verifyReceiverKeyProof: (
                    input,
                ): BallotPrivacyKernelVerification =>
                    executeCommand<BallotPrivacyKernelVerification>({
                        command: 'VerifyReceiverKeyProof',
                        linearStatement: input.linearStatement,
                        parameterSet: input.parameterSet,
                        proofBytesHex: input.proofBytesHex,
                        proofEncoding: input.proofEncoding,
                        publicRandomnessHex: input.publicRandomnessHex,
                        receiverKeyProof: input.receiverKeyProof,
                    }),
                prepareReceiverKeyProofGeneration: (
                    input,
                ): BallotPrivacyReceiverKeyProofGenerationPreparation =>
                    executeCommand<BallotPrivacyReceiverKeyProofGenerationPreparation>(
                        {
                            command: 'PrepareReceiverKeyProofGeneration',
                            linearStatement: input.linearStatement,
                            parameterSet: input.parameterSet,
                            proofEncoding: input.proofEncoding,
                            publicRandomnessHex: input.publicRandomnessHex,
                            secretState: input.secretState,
                            proverRandomnessHex: input.proverRandomnessHex,
                        },
                    ),
                generateReceiverKeyProof: (
                    input,
                ): BallotPrivacyReceiverKeyProofGeneration =>
                    executeCommand<BallotPrivacyReceiverKeyProofGeneration>({
                        command: 'GenerateReceiverKeyProof',
                        linearStatement: input.linearStatement,
                        parameterSet: input.parameterSet,
                        proofEncoding: input.proofEncoding,
                        publicRandomnessHex: suppliedOrFreshRandomnessHex(
                            input.publicRandomnessHex,
                        ),
                        secretState: input.secretState,
                        proverRandomnessHex: suppliedOrFreshRandomnessHex(
                            input.proverRandomnessHex,
                        ),
                    }),
                generateBallotProof: (input): BallotPrivacyProofGeneration =>
                    executeCommand<BallotPrivacyProofGeneration>({
                        command: 'GenerateBallotProof',
                        linearStatement: input.linearStatement,
                        parameterSet: input.parameterSet,
                        proofEncoding: input.proofEncoding,
                        publicRandomnessHex: suppliedOrFreshRandomnessHex(
                            input.publicRandomnessHex,
                        ),
                        secretState: input.secretState,
                        proverRandomnessHex: suppliedOrFreshRandomnessHex(
                            input.proverRandomnessHex,
                        ),
                    }),
                generateBallotComponentProof: (
                    input,
                ): BallotPrivacyProofGeneration =>
                    executeCommand<BallotPrivacyProofGeneration>({
                        command: 'GenerateBallotComponentProof',
                        componentId: input.componentId,
                        proofInput: input.proofInput,
                        secretState: input.secretState,
                        proverRandomnessHex: suppliedOrFreshRandomnessHex(
                            input.proverRandomnessHex,
                        ),
                    }),
                generateBallotProofRecord: (
                    input,
                ): BallotPrivacyProofGeneration =>
                    executeCommand<BallotPrivacyProofGeneration>({
                        command: 'GenerateBallotProofRecord',
                        statement: input.statement,
                        linearStatement: input.linearStatement,
                        parameterSet: input.parameterSet,
                        proofEncoding: input.proofEncoding,
                        publicRandomnessHex: suppliedOrFreshRandomnessHex(
                            input.publicRandomnessHex,
                        ),
                        componentBundleStatement:
                            input.componentBundleStatement,
                        componentProofInputs: input.componentProofInputs,
                        secretState: input.secretState,
                        proverRandomnessHex: suppliedOrFreshRandomnessHex(
                            input.proverRandomnessHex,
                        ),
                        componentProverRandomnessHexes:
                            componentProverRandomnessHexes(
                                input.componentProofInputs,
                                input.componentProverRandomnessHexes,
                            ),
                        componentSecretStates: input.componentSecretStates,
                        casualMicroRosterAcknowledged:
                            input.casualMicroRosterAcknowledged,
                    }),
                verifyBallotProof: (input): BallotPrivacyKernelVerification =>
                    executeCommand<BallotPrivacyKernelVerification>({
                        command: 'VerifyBallotProof',
                        ballotProof: input.ballotProof,
                        componentBundleStatement:
                            input.componentBundleStatement,
                        componentProofBundle: input.componentProofBundle,
                        componentProofInputs: input.componentProofInputs,
                        dynamicRosterProfileEvidence:
                            input.dynamicRosterProfileEvidence,
                        linearStatement: input.linearStatement,
                        parameterSet: input.parameterSet,
                        proofBytesHex: input.proofBytesHex,
                        proofEncoding: input.proofEncoding,
                        publicRandomnessHex: input.publicRandomnessHex,
                        statement: input.statement,
                        casualMicroRosterAcknowledged:
                            input.casualMicroRosterAcknowledged,
                    }),
                verifyClaimBearingBallotPackage: (
                    input,
                ): BallotPrivacyKernelVerification =>
                    executeCommand<BallotPrivacyKernelVerification>({
                        command: 'VerifyClaimBearingBallotPackage',
                        ballotPackage: input.ballotPackage,
                        dynamicRosterProfileEvidence:
                            input.dynamicRosterProfileEvidence,
                        casualMicroRosterAcknowledged:
                            input.casualMicroRosterAcknowledged,
                    }),
                generateAggregateDerivationProof: (
                    input,
                ): BallotPrivacyProofGeneration =>
                    executeCommand<BallotPrivacyProofGeneration>({
                        command: 'GenerateAggregateDerivationProof',
                        proofInput: input.proofInput,
                        secretState: input.secretState,
                        proverRandomnessHex: suppliedOrFreshRandomnessHex(
                            input.proverRandomnessHex,
                        ),
                    }),
                verifyAggregateDerivationProof: (
                    input,
                ): BallotPrivacyKernelVerification =>
                    executeCommand<BallotPrivacyKernelVerification>({
                        command: 'VerifyAggregateDerivationProof',
                        closeRecord: input.closeRecord,
                        component: input.component,
                        contributorActionContext:
                            input.contributorActionContext,
                        countedBallotPackages: input.countedBallotPackages,
                        casualMicroRosterAcknowledged:
                            input.casualMicroRosterAcknowledged,
                    }),
                generateAggregateBridgeEncryption: (input) => {
                    const proverRandomness = suppliedOrFreshBridgeRandomness(
                        input.proverRandomnessHex,
                        input.developmentRandomnessOverrideAcknowledged,
                    );
                    const encryptionRandomness =
                        suppliedOrFreshBridgeRandomness(
                            input.encryptionRandomnessSeedHex,
                            input.developmentRandomnessOverrideAcknowledged,
                        );

                    return executeCommand({
                        command: 'GenerateAggregateBridgeEncryption',
                        aggregateSelectionPolicyHash:
                            input.aggregateSelectionPolicyHash,
                        aggregateDerivationComponent:
                            input.aggregateDerivationComponent,
                        aggregateWitness: input.aggregateWitness,
                        bridgeWitnessPrivacyProfileHash:
                            input.bridgeWitnessPrivacyProfileHash,
                        heParamHash: input.heParamHash,
                        setupPackage: input.setupPackage,
                        proverRandomnessHex: proverRandomness.randomnessHex,
                        proverRandomnessSource:
                            proverRandomness.randomnessSource,
                        encryptionRandomnessSeedHex:
                            encryptionRandomness.randomnessHex,
                        encryptionRandomnessSeedSource:
                            encryptionRandomness.randomnessSource,
                        developmentRandomnessOverrideAcknowledged:
                            input.developmentRandomnessOverrideAcknowledged,
                        includeCanonicalBytesHex:
                            input.includeCanonicalBytesHex,
                    });
                },
                evaluateAggregateBridgeRelation: (input) => {
                    const proverRandomness = suppliedOrFreshBridgeRandomness(
                        input.proverRandomnessHex,
                        input.developmentRandomnessOverrideAcknowledged,
                    );
                    const encryptionRandomness =
                        suppliedOrFreshBridgeRandomness(
                            input.encryptionRandomnessSeedHex,
                            input.developmentRandomnessOverrideAcknowledged,
                        );

                    return executeCommand({
                        command: 'EvaluateAggregateBridgeRelation',
                        aggregateSelectionPolicyHash:
                            input.aggregateSelectionPolicyHash,
                        aggregateDerivationComponent:
                            input.aggregateDerivationComponent,
                        aggregateWitness: input.aggregateWitness,
                        bridgeEncryption: input.bridgeEncryption,
                        bridgeWitnessPrivacyProfileHash:
                            input.bridgeWitnessPrivacyProfileHash,
                        heParamHash: input.heParamHash,
                        setupPackage: input.setupPackage,
                        proverRandomnessHex: proverRandomness.randomnessHex,
                        proverRandomnessSource:
                            proverRandomness.randomnessSource,
                        encryptionRandomnessSeedHex:
                            encryptionRandomness.randomnessHex,
                        encryptionRandomnessSeedSource:
                            encryptionRandomness.randomnessSource,
                        developmentRandomnessOverrideAcknowledged:
                            input.developmentRandomnessOverrideAcknowledged,
                    });
                },
                verifyAggregateBridgeEncryption: (input) =>
                    executeCommand({
                        command: 'VerifyAggregateBridgeEncryption',
                        aggregateSelectionPolicyHash:
                            input.aggregateSelectionPolicyHash,
                        aggregateDerivationComponent:
                            input.aggregateDerivationComponent,
                        bridgeEncryption: input.bridgeEncryption,
                        bridgeWitnessPrivacyProfileHash:
                            input.bridgeWitnessPrivacyProfileHash,
                        heParamHash: input.heParamHash,
                        setupPackage: input.setupPackage,
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
                runDevelopmentTopKEvaluation: (
                    input,
                ): TopKEvaluatorDevelopmentEvaluation =>
                    executeCommand<TopKEvaluatorDevelopmentEvaluation>({
                        command: 'RunDevelopmentTopKEvaluation',
                        ...input,
                    }),
                runEncryptedAggregateTopKEvaluation: (
                    input,
                ): TopKEvaluatorEncryptedAggregateEvaluation =>
                    executeCommand<TopKEvaluatorEncryptedAggregateEvaluation>({
                        command: 'RunEncryptedAggregateTopKEvaluation',
                        ...input,
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
