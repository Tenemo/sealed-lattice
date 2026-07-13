import type { ParticipantIdentity, ProtocolHash } from '@sealed-lattice/types';
import {
    foundationProfile,
    parseParticipantIdentity,
} from '@sealed-lattice/types';

import { openAcceptedSetupSession } from '../accepted-setup-session-runtime.js';
import { registerStateVerifierKernelContext } from '../state-verifier-runtime.js';

import type {
    BgvBatchPlaintextEncoding,
    BgvCollectiveSetupParametersDescription,
    BgvTrusteeEvaluationKeyProofGeneration,
    BgvTrusteeEvaluationKeyStatementDescription,
    BgvLocalTrusteeSetupStateVerification,
    BgvObjectValidation,
    BgvPassiveSetupPackage,
    BgvPrivateVssShareEnvelopeVerification,
    BgvPrivateVssShareProofGeneration,
    BgvRnsParametersDescription,
    BgvSameSecretBridgeProofGeneration,
    BgvVssCommittedMaterialCommitmentComputation,
    BgvVssShareLinkageProofGeneration,
    BgvSetupCommitmentOpeningComputation,
    BgvTargetDecryptionReleaseSetupContext,
    BgvTargetDecryptionShare,
    BgvTargetDecryptionShareProofMaterial,
    BgvTargetDecryptionResultReleaseBegin,
    BgvTargetDecryptionResultReleaseShareAbsorption,
    BgvTargetDecryptionResultReleaseCompletion,
    FoundationCanonicalTupleValidation,
    FoundationSchemaObjectValidation,
    TranscriptCoreKernel,
} from './kernel-contracts.js';
import { bytesToHex } from './kernel-contracts.js';
import type { TranscriptCoreKernelLoaderOptions } from './kernel-runtime.js';
import {
    TranscriptCoreKernelCommandError,
    instantiateTranscriptCoreKernelCommandRuntime,
    resolveOptionalNumberExport,
} from './kernel-runtime.js';
import { registerLocalStorageRootKernelContext } from './local-storage-root-kernel-context.js';
import { registerKernelContexts } from './register-kernel-contexts.js';

const maximumFoundationSchemaObjectByteLength =
    foundationProfile.maximumCopiedBufferByteLength;

const typedArrayPrototype = Reflect.getPrototypeOf(Uint8Array.prototype);

const isUint8Array = (value: unknown): value is Uint8Array =>
    ArrayBuffer.isView(value) &&
    typedArrayPrototype !== null &&
    Reflect.get(typedArrayPrototype, Symbol.toStringTag, value) ===
        'Uint8Array';

export const createTranscriptCoreKernelLoader = (
    transcriptCoreKernelUrl: URL,
    options: TranscriptCoreKernelLoaderOptions = {},
): (() => Promise<TranscriptCoreKernel>) => {
    let kernelPromise: Promise<TranscriptCoreKernel> | undefined;

    return async (): Promise<TranscriptCoreKernel> => {
        kernelPromise ??= (async (): Promise<TranscriptCoreKernel> => {
            const runtime = await instantiateTranscriptCoreKernelCommandRuntime(
                transcriptCoreKernelUrl,
                options,
            );
            const {
                allocate,
                deallocate,
                executeCommand,
                exportedFunctionNames,
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
            const stateVerifierRelease = resolveOptionalNumberExport(
                exports,
                'sealed_lattice_state_verifier_release',
            );
            const stateVerifierFinishOutput = resolveOptionalNumberExport(
                exports,
                'sealed_lattice_state_verifier_finish_output',
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
                beginAcceptedSetupSession: () =>
                    openAcceptedSetupSession(kernel),
                exportedFunctionNames,
                computeFoundationHash512: (input): ProtocolHash =>
                    executeCommand<{ readonly hash512: ProtocolHash }>({
                        command: 'ComputeFoundationHash512',
                        domain: input.domain,
                        canonicalItemsTupleHex: input.canonicalItemsTupleHex,
                    }).hash512,
                deriveFoundationParticipantIdentity: (
                    input,
                ): ParticipantIdentity => {
                    const response = executeCommand<{
                        readonly participantIdentity: unknown;
                    }>({
                        command: 'DeriveFoundationParticipantIdentity',
                        signingVerificationKeyHex:
                            input.signingVerificationKeyHex,
                    });

                    return parseParticipantIdentity(
                        response.participantIdentity,
                    );
                },
                deriveCanonicalObjectHash: (input): ProtocolHash =>
                    executeCommand<{
                        readonly canonicalObjectHash: ProtocolHash;
                    }>({
                        command: 'DeriveCanonicalObjectHash',
                        value: input.value,
                    }).canonicalObjectHash,
                validateFoundationCanonicalTuple: (
                    input,
                ): FoundationCanonicalTupleValidation =>
                    executeCommand<FoundationCanonicalTupleValidation>({
                        command: 'ValidateFoundationCanonicalTuple',
                        canonicalTupleHex: input.canonicalTupleHex,
                    }),
                validateFoundationSchemaObject: (
                    input,
                ): FoundationSchemaObjectValidation => {
                    if (!isUint8Array(input.canonicalBytes)) {
                        throw new TranscriptCoreKernelCommandError({
                            code: 'InvalidProtocolObject',
                            message:
                                'foundation schema object must be a Uint8Array',
                        });
                    }
                    if (
                        input.canonicalBytes.byteLength >
                        maximumFoundationSchemaObjectByteLength
                    ) {
                        throw new TranscriptCoreKernelCommandError({
                            code: 'MalformedLength',
                            message:
                                'foundation schema object exceeds the accepted byte length',
                        });
                    }
                    const canonicalBytes = new Uint8Array(
                        input.canonicalBytes.byteLength,
                    );
                    canonicalBytes.set(input.canonicalBytes);
                    return executeCommand<FoundationSchemaObjectValidation>({
                        command: 'ValidateFoundationSchemaObject',
                        canonicalObjectHex: bytesToHex(canonicalBytes),
                    });
                },
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
                encodeBgvBatchPlaintext: (input): BgvBatchPlaintextEncoding =>
                    executeCommand<BgvBatchPlaintextEncoding>({
                        command: 'EncodeBgvBatchPlaintext',
                        slots: input.slots,
                        level: input.level,
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
                stateVerifierRelease !== undefined &&
                stateVerifierFinishOutput !== undefined &&
                stateVerifierVerifyRecovery !== undefined &&
                stateVerifierVerifyReservation !== undefined
            ) {
                registerStateVerifierKernelContext(kernel, {
                    allocate,
                    begin: stateVerifierBegin,
                    cancel: stateVerifierCancel,
                    deallocate,
                    memory,
                    release: stateVerifierRelease,
                    runExclusive: runExclusiveKernelOperation,
                    finishOutput: stateVerifierFinishOutput,
                    verifyRecovery: stateVerifierVerifyRecovery,
                    verifyReservation: stateVerifierVerifyReservation,
                });
            }
            return kernel;
        })().catch((error: unknown) => {
            // Clear the cached promise on failure so a later call can retry
            // instantiation instead of permanently re-throwing the cached rejection.
            kernelPromise = undefined;
            throw error;
        });

        return kernelPromise;
    };
};
