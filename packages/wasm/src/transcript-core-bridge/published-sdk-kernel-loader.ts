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
): PublishedSdkKernel => {
    return {
        encodeFoundationManifest: (input) =>
            runtime.executeCommand<
                ReturnType<PublishedSdkKernel['encodeFoundationManifest']>
            >({
                command: 'EncodeFoundationManifest',
                displayTitleUtf8Hex: input.displayTitleUtf8Hex,
                optionDefinitions: input.optionDefinitions,
            }),
        verifyFoundationManifest: (input) =>
            runtime.executeCommand<
                ReturnType<PublishedSdkKernel['verifyFoundationManifest']>
            >({
                command: 'VerifyFoundationManifest',
                canonicalBytesHex: input.canonicalBytesHex,
            }),
        encodeFoundationActionDefinition: (input) =>
            runtime.executeCommand<
                ReturnType<
                    PublishedSdkKernel['encodeFoundationActionDefinition']
                >
            >({
                command: 'EncodeFoundationActionDefinition',
                submissionCutoffUnixMilliseconds:
                    input.submissionCutoffUnixMilliseconds,
                topCount: input.topCount,
            }),
        verifyFoundationActionDefinition: (input) =>
            runtime.executeCommand<
                ReturnType<
                    PublishedSdkKernel['verifyFoundationActionDefinition']
                >
            >({
                command: 'VerifyFoundationActionDefinition',
                canonicalBytesHex: input.canonicalBytesHex,
            }),
        encodeFoundationBoardPolicy: (input) =>
            runtime.executeCommand<
                ReturnType<PublishedSdkKernel['encodeFoundationBoardPolicy']>
            >({
                command: 'EncodeFoundationBoardPolicy',
                boardOriginIdentifier: input.boardOriginIdentifier,
            }),
        verifyFoundationBoardPolicy: (input) =>
            runtime.executeCommand<
                ReturnType<PublishedSdkKernel['verifyFoundationBoardPolicy']>
            >({
                command: 'VerifyFoundationBoardPolicy',
                canonicalBytesHex: input.canonicalBytesHex,
            }),
        verifyFoundationSuiteRecord: (input) =>
            runtime.executeCommand<
                ReturnType<PublishedSdkKernel['verifyFoundationSuiteRecord']>
            >({
                command: 'VerifyFoundationSuiteRecord',
                canonicalBytesHex: input.canonicalBytesHex,
            }),
        verifyFoundationCeremonyContext: (input) =>
            runtime.executeCommand<
                ReturnType<
                    PublishedSdkKernel['verifyFoundationCeremonyContext']
                >
            >({
                command: 'VerifyFoundationCeremonyContext',
                canonicalManifestBytesHex: input.canonicalManifestBytesHex,
                canonicalRosterBytesHex: input.canonicalRosterBytesHex,
                canonicalSuiteRecordBytesHex:
                    input.canonicalSuiteRecordBytesHex,
                ceremonyIdentifier: input.ceremonyIdentifier,
                expectedSuiteId: input.expectedSuiteId,
            }),
        verifyFoundationActionContext: (input) =>
            runtime.executeCommand<
                ReturnType<PublishedSdkKernel['verifyFoundationActionContext']>
            >({
                command: 'VerifyFoundationActionContext',
                actionIdentifier: input.actionIdentifier,
                canonicalActionDefinitionBytesHex:
                    input.canonicalActionDefinitionBytesHex,
                canonicalBoardPolicyBytesHex:
                    input.canonicalBoardPolicyBytesHex,
                canonicalManifestBytesHex: input.canonicalManifestBytesHex,
                canonicalRosterBytesHex: input.canonicalRosterBytesHex,
                canonicalSuiteRecordBytesHex:
                    input.canonicalSuiteRecordBytesHex,
                ceremonyIdentifier: input.ceremonyIdentifier,
                expectedCeremonyContextHash: input.expectedCeremonyContextHash,
                expectedSuiteId: input.expectedSuiteId,
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
        const kernel = createPublishedSdkKernelBindings(runtime);
        registerKernelContexts(kernel, runtime);

        return kernel;
    });
};
