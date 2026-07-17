import type { TranscriptCoreKernelCommandRuntime } from './kernel-runtime.js';

const contexts = new WeakMap<object, TranscriptCoreKernelCommandRuntime>();

export const registerCommonProofKernelContext = (
    kernel: object,
    context: TranscriptCoreKernelCommandRuntime,
): void => {
    contexts.set(kernel, context);
};

export const resolveCommonProofKernelContext = (
    kernel: object,
): TranscriptCoreKernelCommandRuntime | undefined => contexts.get(kernel);
