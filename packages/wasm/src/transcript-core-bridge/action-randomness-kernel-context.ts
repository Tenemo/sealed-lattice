import type {
    TranscriptCoreKernel,
    TranscriptCoreKernelContextOwner,
} from './kernel-types.js';

export type ActionRandomnessKernelContext = Readonly<{
    allocate(length: number): number;
    command(
        command: number,
        inputPointer: number,
        inputLength: number,
        statusPointer: number,
        outputLengthPointer: number,
    ): number;
    deallocate(pointer: number, length: number): void;
    memory: WebAssembly.Memory;
    runExclusive<Result>(
        operationName: string,
        operation: () => Result,
    ): Result;
}>;

const contexts = new WeakMap<object, ActionRandomnessKernelContext>();

export const registerActionRandomnessKernelContext = (
    kernel: TranscriptCoreKernelContextOwner,
    context: ActionRandomnessKernelContext,
): void => {
    contexts.set(kernel, context);
};

export const resolveActionRandomnessKernelContext = (
    kernel: TranscriptCoreKernel,
): ActionRandomnessKernelContext | undefined => contexts.get(kernel);
