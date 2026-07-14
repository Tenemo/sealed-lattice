import { openAcceptedSetupSession } from '../accepted-setup-session-runtime.js';

import type { PublishedSdkKernel } from './kernel-contracts.js';
import type {
    TranscriptCoreKernelCommandRuntime,
    TranscriptCoreKernelLoaderOptions,
} from './kernel-runtime.js';
import { instantiateTranscriptCoreKernelCommandRuntime } from './kernel-runtime.js';
import { registerKernelContexts } from './register-kernel-contexts.js';

export const createCachedKernelLoader = <Kernel>(
    loadKernel: () => Promise<Kernel>,
): (() => Promise<Kernel>) => {
    let kernelPromise: Promise<Kernel> | undefined;

    return async (): Promise<Kernel> => {
        kernelPromise ??= loadKernel().catch((error: unknown) => {
            kernelPromise = undefined;
            throw error;
        });

        return kernelPromise;
    };
};

export const createPublishedSdkKernelBindings = (
    runtime: TranscriptCoreKernelCommandRuntime,
    getKernel: () => PublishedSdkKernel,
): PublishedSdkKernel => {
    return {
        beginAcceptedSetupSession: () => openAcceptedSetupSession(getKernel()),
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
                expectedPrivateEnvelopeHash: input.expectedPrivateEnvelopeHash,
                expectedLocalVerificationRoot:
                    input.expectedLocalVerificationRoot,
            }),
        beginBgvTargetDecryptionResultRelease: (input) =>
            runtime.executeCommand<
                ReturnType<
                    PublishedSdkKernel['beginBgvTargetDecryptionResultRelease']
                >
            >({
                command: 'BeginBgvTargetDecryptionResultRelease',
                releaseVerificationId: input.releaseVerificationId,
                acceptedSetupHandle: input.acceptedSetupHandle,
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
};

export const createPublishedSdkKernelLoader = (
    transcriptCoreKernelUrl: URL,
    options: TranscriptCoreKernelLoaderOptions = {},
): (() => Promise<PublishedSdkKernel>) => {
    return createCachedKernelLoader(async () => {
        const runtime = await instantiateTranscriptCoreKernelCommandRuntime(
            transcriptCoreKernelUrl,
            options,
        );
        const kernel = createPublishedSdkKernelBindings(runtime, () => kernel);
        registerKernelContexts(kernel, runtime);

        return kernel;
    });
};
