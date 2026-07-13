import type { ProtocolHash } from '@sealed-lattice/types';

import { registerStateVerifierKernelContext } from '../state-verifier-runtime.js';

import type {
    BgvCollectiveSetupParametersDescription,
    BgvTrusteeEvaluationKeyProofGeneration,
    BgvTrusteeEvaluationKeyStatementDescription,
    BgvLocalTrusteeSetupStateVerification,
    BgvPassiveSetupPackage,
    BgvPrivateVssShareProofGeneration,
    BgvRnsParametersDescription,
    BgvSameSecretBridgeProofGeneration,
    BgvVssCommittedMaterialCommitmentComputation,
    BgvVssShareLinkageProofGeneration,
    BgvSetupCommitmentOpeningComputation,
    BgvTargetDecryptionShare,
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
            const stateVerifierVerifyRecovery = resolveOptionalNumberExport(
                exports,
                'sealed_lattice_state_verifier_verify_recovery',
            );
            const stateVerifierVerifyReservation = resolveOptionalNumberExport(
                exports,
                'sealed_lattice_state_verifier_verify_reservation',
            );
            let kernel: TranscriptCoreKernel;
            kernel = {
                ...createPublishedSdkKernelBindings(runtime, () => kernel),
                deriveCanonicalObjectHash: (input): ProtocolHash =>
                    executeCommand<{
                        readonly canonicalObjectHash: ProtocolHash;
                    }>({
                        command: 'DeriveCanonicalObjectHash',
                        value: input.value,
                    }).canonicalObjectHash,
                generateBgvTargetDecryptionShareFromLocalShare: (
                    input,
                ): BgvTargetDecryptionShare =>
                    executeCommand<BgvTargetDecryptionShare>({
                        command:
                            'GenerateBgvTargetDecryptionShareFromLocalShare',
                        setupPackage: input.setupPackage,
                        targetAcceptedRecord: input.targetAcceptedRecord,
                        targetCiphertexts: input.targetCiphertexts,
                        targetCiphertextBinding: input.targetCiphertextBinding,
                        targetShareProfile: input.targetShareProfile,
                        trusteeIdentity: input.trusteeIdentity,
                        localTargetShareWitness: input.localTargetShareWitness,
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
                verifyBgvPassiveSetup: (input): void =>
                    executeCommand<void>({
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
                        vssCommittedMaterialSeedsByBoundMessage:
                            input.vssCommittedMaterialSeedsByBoundMessage,
                        vssCommittedMaterialContextHashesByBoundMessage:
                            input.vssCommittedMaterialContextHashesByBoundMessage,
                        proofRandomnessSeedHex: input.proofRandomnessSeedHex,
                        proofRandomnessNonceHex: input.proofRandomnessNonceHex,
                    }),
                describeTrusteeEvaluationKeyStatement: (
                    input,
                ): BgvTrusteeEvaluationKeyStatementDescription =>
                    executeCommand<BgvTrusteeEvaluationKeyStatementDescription>(
                        {
                            command: 'DescribeTrusteeEvaluationKeyStatement',
                            context: input.context,
                            ringDegree: input.ringDegree,
                            keys: input.keys,
                            sameSecretLinkage: input.sameSecretLinkage,
                            sameSecretBridge: input.sameSecretBridge,
                        },
                    ),
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
                    executeCommand<BgvVssCommittedMaterialCommitmentComputation>(
                        {
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
                        },
                    ),
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
                stateVerifierRelease !== undefined &&
                stateVerifierFinishOutput !== undefined &&
                stateVerifierPrepareOutput !== undefined &&
                stateVerifierPrepareRecovery !== undefined &&
                stateVerifierPrepareReservation !== undefined &&
                stateVerifierVerifyRecovery !== undefined &&
                stateVerifierVerifyReservation !== undefined
            ) {
                registerStateVerifierKernelContext(kernel, {
                    allocate,
                    begin: stateVerifierBegin,
                    cancel: stateVerifierCancel,
                    certifyIntent: stateVerifierCertifyIntent,
                    deallocate,
                    memory,
                    release: stateVerifierRelease,
                    runExclusive: runExclusiveKernelOperation,
                    finishOutput: stateVerifierFinishOutput,
                    prepareOutput: stateVerifierPrepareOutput,
                    prepareRecovery: stateVerifierPrepareRecovery,
                    prepareReservation: stateVerifierPrepareReservation,
                    verifyRecovery: stateVerifierVerifyRecovery,
                    verifyReservation: stateVerifierVerifyReservation,
                });
            }
            return kernel;
        });
