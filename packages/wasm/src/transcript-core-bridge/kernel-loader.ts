import type {
    FieldElement,
    ProtocolDigest,
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
    BgvBaseConversionFixture,
    BgvBatchPlaintextEncoding,
    BgvCiphertextConventionFixture,
    BgvObjectValidation,
    BgvReferenceOracleRejection,
    BgvRnsProfileReport,
    TranscriptCoreKernel,
    TranscriptCoreKernelCommand,
    TranscriptCoreKernelExports,
    TranscriptCorePlaintextComparison,
} from './kernel-contracts.js';
import {
    componentProverRandomnessHexes,
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
            ) as (pointer: number, length: number) => void;
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
                deriveProtocolDigest: (input): ProtocolDigest =>
                    executeCommand<{ readonly protocolDigest: ProtocolDigest }>(
                        {
                            command: 'DeriveProtocolDigest',
                            namespace: input.namespace,
                            value: input.value,
                        },
                    ).protocolDigest,
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
                        unsafeSmallRosterAcknowledged:
                            input.unsafeSmallRosterAcknowledged,
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
                        unsafeSmallRosterAcknowledged:
                            input.unsafeSmallRosterAcknowledged,
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
                        unsafeSmallRosterAcknowledged:
                            input.unsafeSmallRosterAcknowledged,
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
                        unsafeSmallRosterAcknowledged:
                            input.unsafeSmallRosterAcknowledged,
                    }),
                describeBgvRnsProfile: (): BgvRnsProfileReport =>
                    executeCommand<BgvRnsProfileReport>({
                        command: 'DescribeBgvRnsProfile',
                    }),
                describeBgvOperationRegistry: (): unknown =>
                    executeCommand<unknown>({
                        command: 'DescribeBgvOperationRegistry',
                    }),
                generateBgvBackendReport: (): unknown =>
                    executeCommand<unknown>({
                        command: 'GenerateBgvBackendReport',
                    }),
                encodeBgvBatchPlaintext: (input): BgvBatchPlaintextEncoding =>
                    executeCommand<BgvBatchPlaintextEncoding>({
                        command: 'EncodeBgvBatchPlaintext',
                        slots: input.slots,
                        level: input.level,
                        layoutBinding: input.layoutBinding,
                        includeCanonicalBytesHex:
                            input.includeCanonicalBytesHex,
                    }),
                validateBgvPlaintextObject: (input): BgvObjectValidation =>
                    executeCommand<BgvObjectValidation>({
                        command: 'ValidateBgvPlaintextObject',
                        canonicalBytesHex: input.canonicalBytesHex,
                        expectedPlaintextRoot: input.expectedPlaintextRoot,
                    }),
                validateBgvCiphertextObject: (input): BgvObjectValidation =>
                    executeCommand<BgvObjectValidation>({
                        command: 'ValidateBgvCiphertextObject',
                        canonicalBytesHex: input.canonicalBytesHex,
                        expectedCiphertextRoot: input.expectedCiphertextRoot,
                    }),
                generateBgvCiphertextConventionFixture: (
                    input,
                ): BgvCiphertextConventionFixture =>
                    executeCommand<BgvCiphertextConventionFixture>({
                        command: 'GenerateBgvCiphertextConventionFixture',
                        leftSlots: input.leftSlots,
                        rightSlots: input.rightSlots,
                        includeCanonicalBytesHex:
                            input.includeCanonicalBytesHex,
                    }),
                generateBgvBaseConversionFixture: (
                    input,
                ): BgvBaseConversionFixture =>
                    executeCommand<BgvBaseConversionFixture>({
                        command: 'GenerateBgvBaseConversionFixture',
                        slots: input.slots,
                    }),
                analyzeBgvCanonicalObject: (input): unknown =>
                    executeCommand<unknown>({
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
            kernelPromise = undefined;
            throw error;
        });

        return kernelPromise;
    };
};
