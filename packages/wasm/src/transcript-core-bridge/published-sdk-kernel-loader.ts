import { openAcceptedSetupSession } from '../accepted-setup-session-runtime.js';

import type { PublishedSdkKernel } from './kernel-contracts.js';
import type {
    TranscriptCoreKernelCommandRuntime,
    TranscriptCoreKernelLoaderOptions,
} from './kernel-runtime.js';
import { instantiateTranscriptCoreKernelCommandRuntime } from './kernel-runtime.js';
import { registerKernelContexts } from './register-kernel-contexts.js';

const publishedSdkKernel = (
    runtime: TranscriptCoreKernelCommandRuntime,
): PublishedSdkKernel => {
    const kernel: PublishedSdkKernel = {
        beginAcceptedSetupSession: () => openAcceptedSetupSession(kernel),
        exportedFunctionNames: runtime.exportedFunctionNames,
        generateBgvTargetDecryptionShareProofMaterialFromLocalWitness: (
            input,
        ) =>
            runtime.executeCommand<
                ReturnType<
                    PublishedSdkKernel['generateBgvTargetDecryptionShareProofMaterialFromLocalWitness']
                >
            >({
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
        verifyPrivateVssShareEnvelope: (input) =>
            runtime.executeCommand<
                ReturnType<PublishedSdkKernel['verifyPrivateVssShareEnvelope']>
            >({
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
                expectedPrivateEnvelopeHash: input.expectedPrivateEnvelopeHash,
                expectedLocalVerificationRoot:
                    input.expectedLocalVerificationRoot,
            }),
        deriveBgvTargetDecryptionResultReleaseSetupContext: (input) =>
            runtime.executeCommand<
                ReturnType<
                    PublishedSdkKernel['deriveBgvTargetDecryptionResultReleaseSetupContext']
                >
            >({
                command: 'DeriveBgvTargetDecryptionResultReleaseSetupContext',
                setupPackage: input.setupPackage,
            }),
        beginBgvTargetDecryptionResultRelease: (input) =>
            runtime.executeCommand<
                ReturnType<
                    PublishedSdkKernel['beginBgvTargetDecryptionResultRelease']
                >
            >({
                command: 'BeginBgvTargetDecryptionResultRelease',
                releaseVerificationId: input.releaseVerificationId,
                releaseSetupContext: input.releaseSetupContext,
                targetAcceptedRecord: input.targetAcceptedRecord,
                targetCiphertexts: input.targetCiphertexts,
                targetCiphertextBinding: input.targetCiphertextBinding,
                targetShareProfile: input.targetShareProfile,
            }),
        absorbBgvTargetDecryptionResultReleaseShare: (input) =>
            runtime.executeCommand<
                ReturnType<
                    PublishedSdkKernel['absorbBgvTargetDecryptionResultReleaseShare']
                >
            >({
                command: 'AbsorbBgvTargetDecryptionResultReleaseShare',
                releaseVerificationId: input.releaseVerificationId,
                targetShareProof: input.targetShareProof,
            }),
        finishBgvTargetDecryptionResultRelease: (input) =>
            runtime.executeCommand<
                ReturnType<
                    PublishedSdkKernel['finishBgvTargetDecryptionResultRelease']
                >
            >({
                command: 'FinishBgvTargetDecryptionResultRelease',
                releaseVerificationId: input.releaseVerificationId,
            }),
    };
    registerKernelContexts(kernel, runtime);

    return kernel;
};

export const createPublishedSdkKernelLoader = (
    transcriptCoreKernelUrl: URL,
    options: TranscriptCoreKernelLoaderOptions = {},
): (() => Promise<PublishedSdkKernel>) => {
    let kernelPromise: Promise<PublishedSdkKernel> | undefined;

    return async (): Promise<PublishedSdkKernel> => {
        kernelPromise ??= instantiateTranscriptCoreKernelCommandRuntime(
            transcriptCoreKernelUrl,
            options,
        )
            .then(publishedSdkKernel)
            .catch((error: unknown) => {
                kernelPromise = undefined;
                throw error;
            });

        return kernelPromise;
    };
};
