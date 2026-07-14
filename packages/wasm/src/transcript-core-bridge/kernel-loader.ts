import type { ProtocolHash } from '@sealed-lattice/types';

import { registerStateVerifierKernelContext } from '../state-verifier-runtime.js';

import type {
    BgvCollectiveSetupParametersDescription,
    BgvTrusteeEvaluationKeyProofGeneration,
    BgvTrusteeEvaluationKeyStatementDescription,
    BgvLocalTrusteeSetupStateVerification,
    BgvRnsParametersDescription,
    BgvSameSecretBridgeProofGeneration,
    BgvVssCommittedMaterialCommitmentComputation,
    BgvVssShareLinkageProofGeneration,
    DecodedActionRandomnessDerivationInput,
    BgvSetupCommitmentOpeningComputation,
    BgvTargetDecryptionShare,
    BgvTargetDecryptionShareProofMaterial,
    DecodedMailboxAssociatedData,
    DecodedMailboxKeyScheduleInput,
    DecodedPrivateRandomBlockInput,
    DecodedPrivateRandomCursor,
    DecodedSignedMailboxEnvelope,
    DecodedStreamDescriptor,
    EncodedMailboxAssociatedData,
    EncodedMailboxKeyScheduleInput,
    EncodedActionRandomnessDerivationInput,
    EncodedPrivateRandomBlockInput,
    EncodedPrivateRandomCursor,
    EncodedSignedMailboxEnvelope,
    EncodedStreamDescriptor,
    GeneratedProofSuiteCandidate,
    CanonicalFoundationValueValidation,
    TranscriptCoreKernel,
} from './kernel-contracts.js';
import type { TranscriptCoreKernelLoaderOptions } from './kernel-runtime.js';
import {
    instantiateTranscriptCoreKernelCommandRuntime,
    resolveOptionalNumberExport,
} from './kernel-runtime.js';
import { registerLocalStorageRootKernelContext } from './local-storage-root-kernel-context.js';
import {
    createCachedKernelLoader,
    createPublishedSdkKernelBindings,
} from './published-sdk-kernel-loader.js';
import { registerKernelContexts } from './register-kernel-contexts.js';

export const createTranscriptCoreKernelLoader = (
    transcriptCoreKernelUrl: URL,
    options: TranscriptCoreKernelLoaderOptions = {},
): (() => Promise<TranscriptCoreKernel>) =>
    createCachedKernelLoader(async (): Promise<TranscriptCoreKernel> => {
        const runtime = await instantiateTranscriptCoreKernelCommandRuntime(
            transcriptCoreKernelUrl,
            options,
        );
        const {
            allocate,
            deallocate,
            executeCommand,
            memory,
            runExclusive: runExclusiveKernelOperation,
            wasmExports: exports,
        } = runtime;
        const localStorageRootCommand = resolveOptionalNumberExport(
            exports,
            'sealed_lattice_local_storage_root_command',
        );
        const stateVerifierBegin = resolveOptionalNumberExport(
            exports,
            'sealed_lattice_state_verifier_begin',
        );
        const stateVerifierCancel = resolveOptionalNumberExport(
            exports,
            'sealed_lattice_state_verifier_cancel',
        );
        const stateVerifierCertifyIntent = resolveOptionalNumberExport(
            exports,
            'sealed_lattice_state_verifier_certify_intent',
        );
        const stateVerifierCertifyUnorderedVotes = resolveOptionalNumberExport(
            exports,
            'sealed_lattice_state_verifier_certify_unordered_votes',
        );
        const stateVerifierDescribe = resolveOptionalNumberExport(
            exports,
            'sealed_lattice_state_verifier_describe',
        );
        const stateVerifierRelease = resolveOptionalNumberExport(
            exports,
            'sealed_lattice_state_verifier_release',
        );
        const stateVerifierFinishOutput = resolveOptionalNumberExport(
            exports,
            'sealed_lattice_state_verifier_finish_output',
        );
        const stateVerifierPrepareOutput = resolveOptionalNumberExport(
            exports,
            'sealed_lattice_state_verifier_prepare_output',
        );
        const stateVerifierPrepareRecovery = resolveOptionalNumberExport(
            exports,
            'sealed_lattice_state_verifier_prepare_recovery',
        );
        const stateVerifierPrepareReservation = resolveOptionalNumberExport(
            exports,
            'sealed_lattice_state_verifier_prepare_reservation',
        );
        const stateVerifierPrepareWitnessVote = resolveOptionalNumberExport(
            exports,
            'sealed_lattice_state_verifier_prepare_witness_vote',
        );
        const stateVerifierFinishWitnessVote = resolveOptionalNumberExport(
            exports,
            'sealed_lattice_state_verifier_finish_witness_vote',
        );
        const stateVerifierVerifyRecovery = resolveOptionalNumberExport(
            exports,
            'sealed_lattice_state_verifier_verify_recovery',
        );
        const stateVerifierVerifyReservation = resolveOptionalNumberExport(
            exports,
            'sealed_lattice_state_verifier_verify_reservation',
        );
        const kernel: TranscriptCoreKernel = {
            ...createPublishedSdkKernelBindings(runtime, () => kernel),
            deriveCanonicalObjectHash: (input): ProtocolHash =>
                executeCommand<{
                    readonly canonicalObjectHash: ProtocolHash;
                }>({
                    command: 'DeriveCanonicalObjectHash',
                    value: input.value,
                }).canonicalObjectHash,
            validateCanonicalFoundationValue: (input) =>
                executeCommand<CanonicalFoundationValueValidation>({
                    command: 'ValidateCanonicalFoundationValue',
                    ...input,
                }),
            deriveCeremonyContextHash: (value): ProtocolHash =>
                executeCommand<{
                    readonly ceremonyContextHash: ProtocolHash;
                }>({
                    command: 'DeriveCeremonyContextHash',
                    value,
                }).ceremonyContextHash,
            deriveActionContextHash: (value): ProtocolHash =>
                executeCommand<{
                    readonly actionContextHash: ProtocolHash;
                }>({
                    command: 'DeriveActionContextHash',
                    value,
                }).actionContextHash,
            encodeMailboxKeyScheduleInput: (value) =>
                executeCommand<EncodedMailboxKeyScheduleInput>({
                    command: 'EncodeMailboxKeyScheduleInput',
                    value,
                }),
            decodeMailboxKeyScheduleInput: (input) =>
                executeCommand<DecodedMailboxKeyScheduleInput>({
                    command: 'DecodeMailboxKeyScheduleInput',
                    canonicalBytesHex: input.canonicalBytesHex,
                }),
            encodeMailboxAssociatedData: (value) =>
                executeCommand<EncodedMailboxAssociatedData>({
                    command: 'EncodeMailboxAssociatedData',
                    value,
                }),
            decodeMailboxAssociatedData: (input) =>
                executeCommand<DecodedMailboxAssociatedData>({
                    command: 'DecodeMailboxAssociatedData',
                    canonicalBytesHex: input.canonicalBytesHex,
                }),
            encodeStreamDescriptor: (value) =>
                executeCommand<EncodedStreamDescriptor>({
                    command: 'EncodeStreamDescriptor',
                    value,
                }),
            decodeStreamDescriptor: (input) =>
                executeCommand<DecodedStreamDescriptor>({
                    command: 'DecodeStreamDescriptor',
                    canonicalBytesHex: input.canonicalBytesHex,
                }),
            deriveSetupMailboxSlotHash: (value): ProtocolHash =>
                executeCommand<{
                    readonly setupMailboxSlotHash: ProtocolHash;
                }>({
                    command: 'DeriveSetupMailboxSlotHash',
                    value,
                }).setupMailboxSlotHash,
            encodeActionRandomnessDerivationInput: (value) =>
                executeCommand<EncodedActionRandomnessDerivationInput>({
                    command: 'EncodeActionRandomnessDerivationInput',
                    value,
                }),
            decodeActionRandomnessDerivationInput: (input) =>
                executeCommand<DecodedActionRandomnessDerivationInput>({
                    command: 'DecodeActionRandomnessDerivationInput',
                    canonicalBytesHex: input.canonicalBytesHex,
                }),
            deriveActionRandomnessCommitment: (input): ProtocolHash =>
                executeCommand<{
                    readonly actionRandomnessCommitment: ProtocolHash;
                }>({
                    command: 'DeriveActionRandomnessCommitment',
                    actionRandomnessRootHex: input.actionRandomnessRootHex,
                    value: input.value,
                }).actionRandomnessCommitment,
            encodePrivateRandomBlockInput: (value) =>
                executeCommand<EncodedPrivateRandomBlockInput>({
                    command: 'EncodePrivateRandomBlockInput',
                    value,
                }),
            decodePrivateRandomBlockInput: (input) =>
                executeCommand<DecodedPrivateRandomBlockInput>({
                    command: 'DecodePrivateRandomBlockInput',
                    canonicalBytesHex: input.canonicalBytesHex,
                }),
            encodePrivateRandomCursor: (value) =>
                executeCommand<EncodedPrivateRandomCursor>({
                    command: 'EncodePrivateRandomCursor',
                    value,
                }),
            decodePrivateRandomCursor: (input) =>
                executeCommand<DecodedPrivateRandomCursor>({
                    command: 'DecodePrivateRandomCursor',
                    canonicalBytesHex: input.canonicalBytesHex,
                }),
            generateProofSuiteCandidate: () =>
                executeCommand<GeneratedProofSuiteCandidate>({
                    command: 'GenerateProofSuiteCandidate',
                }),
            encodeSignedMailboxEnvelope: (value) =>
                executeCommand<EncodedSignedMailboxEnvelope>({
                    command: 'EncodeSignedMailboxEnvelope',
                    value,
                }),
            decodeSignedMailboxEnvelope: (input) =>
                executeCommand<DecodedSignedMailboxEnvelope>({
                    command: 'DecodeSignedMailboxEnvelope',
                    canonicalBytesHex: input.canonicalBytesHex,
                }),
            deriveMailboxKemCiphertextHash: (input): ProtocolHash =>
                executeCommand<{
                    readonly kemCiphertextHash: ProtocolHash;
                }>({
                    command: 'DeriveMailboxKemCiphertextHash',
                    kemCiphertextHex: input.kemCiphertextHex,
                }).kemCiphertextHash,
            deriveMailboxEnvelopeHash: (value): ProtocolHash =>
                executeCommand<{
                    readonly envelopeHash: ProtocolHash;
                }>({
                    command: 'DeriveMailboxEnvelopeHash',
                    value,
                }).envelopeHash,
            generateBgvTargetDecryptionShareFromLocalShare: (
                input,
            ): BgvTargetDecryptionShare =>
                executeCommand<BgvTargetDecryptionShare>({
                    command: 'GenerateBgvTargetDecryptionShareFromLocalShare',
                    setupPackage: input.setupPackage,
                    targetAcceptedRecord: input.targetAcceptedRecord,
                    targetCiphertexts: input.targetCiphertexts,
                    targetCiphertextBinding: input.targetCiphertextBinding,
                    targetShareProfile: input.targetShareProfile,
                    trusteeIdentity: input.trusteeIdentity,
                    localTargetShareWitness: input.localTargetShareWitness,
                }),
            generateBgvTargetDecryptionShareProofMaterialFromLocalWitness: (
                input,
            ): BgvTargetDecryptionShareProofMaterial =>
                executeCommand<BgvTargetDecryptionShareProofMaterial>({
                    command:
                        'GenerateBgvTargetDecryptionShareProofMaterialFromLocalWitness',
                    setupPackage: input.setupPackage,
                    targetAcceptedRecord: input.targetAcceptedRecord,
                    targetCiphertexts: input.targetCiphertexts,
                    targetCiphertextBinding: input.targetCiphertextBinding,
                    targetShareProfile: input.targetShareProfile,
                    trusteeIdentity: input.trusteeIdentity,
                    localTargetShareWitness: input.localTargetShareWitness,
                    targetDecryptionShare: input.targetDecryptionShare,
                    proofStatement: input.proofStatement,
                    proofRandomnessSeedHex: input.proofRandomnessSeedHex,
                    proofRandomnessNonceHex: input.proofRandomnessNonceHex,
                }),
            describeBgvRnsParameters: (): BgvRnsParametersDescription =>
                executeCommand<BgvRnsParametersDescription>({
                    command: 'DescribeBgvRnsParameters',
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
            generateTrusteeEvaluationKeyProof: (
                input,
            ): BgvTrusteeEvaluationKeyProofGeneration => {
                if (input.statementFamily === 'public-key-share') {
                    return executeCommand<BgvTrusteeEvaluationKeyProofGeneration>(
                        {
                            command: 'GenerateTrusteeEvaluationKeyProof',
                            context: input.context,
                            ringDegree: input.ringDegree,
                            keys: input.keys,
                            sameSecretBridge: input.sameSecretBridge,
                            secretCoefficients: input.secretCoefficients,
                            errorCoefficientsByKey:
                                input.errorCoefficientsByKey,
                            negativeIndicatorCoefficients:
                                input.negativeIndicatorCoefficients,
                            vssCommittedMaterialSeedsByBoundMessage:
                                input.vssCommittedMaterialSeedsByBoundMessage,
                            vssCommittedMaterialContextHashesByBoundMessage:
                                input.vssCommittedMaterialContextHashesByBoundMessage,
                            proofRandomnessSeedHex:
                                input.proofRandomnessSeedHex,
                            proofRandomnessNonceHex:
                                input.proofRandomnessNonceHex,
                        },
                    );
                }
                return executeCommand<BgvTrusteeEvaluationKeyProofGeneration>({
                    command: 'GenerateTrusteeEvaluationKeyProof',
                    context: input.context,
                    ringDegree: input.ringDegree,
                    keys: input.keys,
                    sameSecretLinkage: input.sameSecretLinkage,
                    secretCoefficients: input.secretCoefficients,
                    errorCoefficientsByKey: input.errorCoefficientsByKey,
                    negativeIndicatorCoefficients:
                        input.negativeIndicatorCoefficients,
                    openingRandomnessByLimb: input.openingRandomnessByLimb,
                    proofRandomnessSeedHex: input.proofRandomnessSeedHex,
                    proofRandomnessNonceHex: input.proofRandomnessNonceHex,
                });
            },
            describeTrusteeEvaluationKeyStatement: (
                input,
            ): BgvTrusteeEvaluationKeyStatementDescription => {
                if (input.statementFamily === 'public-key-share') {
                    return executeCommand<BgvTrusteeEvaluationKeyStatementDescription>(
                        {
                            command: 'DescribeTrusteeEvaluationKeyStatement',
                            context: input.context,
                            ringDegree: input.ringDegree,
                            keys: input.keys,
                            sameSecretBridge: input.sameSecretBridge,
                        },
                    );
                }
                return executeCommand<BgvTrusteeEvaluationKeyStatementDescription>(
                    {
                        command: 'DescribeTrusteeEvaluationKeyStatement',
                        context: input.context,
                        ringDegree: input.ringDegree,
                        keys: input.keys,
                        sameSecretLinkage: input.sameSecretLinkage,
                    },
                );
            },
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
            computeVssCommittedMaterialCommitment: (
                input,
            ): BgvVssCommittedMaterialCommitmentComputation =>
                executeCommand<BgvVssCommittedMaterialCommitmentComputation>({
                    command: 'ComputeVssCommittedMaterialCommitment',
                    commitmentRole: input.commitmentRole,
                    commitmentContext: input.commitmentContext,
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
                    materialSeedHex: input.materialSeedHex,
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
                    recipientShareMessagesByItem:
                        input.recipientShareMessagesByItem,
                    carryWitnessesByItem: input.carryWitnessesByItem,
                    vssCommittedMaterialSeedsByBoundMessage:
                        input.vssCommittedMaterialSeedsByBoundMessage,
                    vssCommittedMaterialContextHashesByBoundMessage:
                        input.vssCommittedMaterialContextHashesByBoundMessage,
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
                    sameSecretLinkage: input.sameSecretLinkage,
                    sameSecretBridge: input.sameSecretBridge,
                    secretCoefficients: input.secretCoefficients,
                    negativeIndicatorCoefficients:
                        input.negativeIndicatorCoefficients,
                    openingRandomnessByLimb: input.openingRandomnessByLimb,
                    vssCommittedMaterialSeedsByBoundMessage:
                        input.vssCommittedMaterialSeedsByBoundMessage,
                    vssCommittedMaterialContextHashesByBoundMessage:
                        input.vssCommittedMaterialContextHashesByBoundMessage,
                    proofRandomnessSeedHex: input.proofRandomnessSeedHex,
                    proofRandomnessNonceHex: input.proofRandomnessNonceHex,
                }),
            verifyLocalTrusteeSetupState: (
                input,
            ): BgvLocalTrusteeSetupStateVerification =>
                executeCommand<BgvLocalTrusteeSetupStateVerification>({
                    command: 'VerifyLocalTrusteeSetupState',
                    setupContext: input.setupContext,
                    localStateCommitment: input.localStateCommitment,
                }),
        };
        registerKernelContexts(kernel, runtime);
        if (localStorageRootCommand !== undefined) {
            registerLocalStorageRootKernelContext(kernel, {
                allocate,
                command: localStorageRootCommand,
                deallocate,
                memory,
                runExclusive: runExclusiveKernelOperation,
            });
        }
        if (
            stateVerifierBegin !== undefined &&
            stateVerifierCancel !== undefined &&
            stateVerifierCertifyIntent !== undefined &&
            stateVerifierCertifyUnorderedVotes !== undefined &&
            stateVerifierDescribe !== undefined &&
            stateVerifierRelease !== undefined &&
            stateVerifierFinishOutput !== undefined &&
            stateVerifierPrepareOutput !== undefined &&
            stateVerifierPrepareRecovery !== undefined &&
            stateVerifierPrepareReservation !== undefined &&
            stateVerifierPrepareWitnessVote !== undefined &&
            stateVerifierFinishWitnessVote !== undefined &&
            stateVerifierVerifyRecovery !== undefined &&
            stateVerifierVerifyReservation !== undefined
        ) {
            registerStateVerifierKernelContext(kernel, {
                allocate,
                begin: stateVerifierBegin,
                cancel: stateVerifierCancel,
                certifyIntent: stateVerifierCertifyIntent,
                certifyUnorderedVotes: stateVerifierCertifyUnorderedVotes,
                deallocate,
                describe: stateVerifierDescribe,
                memory,
                release: stateVerifierRelease,
                runExclusive: runExclusiveKernelOperation,
                finishOutput: stateVerifierFinishOutput,
                finishWitnessVote: stateVerifierFinishWitnessVote,
                prepareOutput: stateVerifierPrepareOutput,
                prepareRecovery: stateVerifierPrepareRecovery,
                prepareReservation: stateVerifierPrepareReservation,
                prepareWitnessVote: stateVerifierPrepareWitnessVote,
                verifyRecovery: stateVerifierVerifyRecovery,
                verifyReservation: stateVerifierVerifyReservation,
            });
        }
        return kernel;
    });
