import type { TranscriptCoreKernel } from './kernel-types.js';

export type LocalStorageRootKernelContext = Readonly<{
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

const contexts = new WeakMap<
    TranscriptCoreKernel,
    LocalStorageRootKernelContext
>();

export const registerLocalStorageRootKernelContext = (
    kernel: TranscriptCoreKernel,
    context: LocalStorageRootKernelContext,
): void => {
    contexts.set(kernel, context);
};

export const resolveLocalStorageRootKernelContext = (
    kernel: TranscriptCoreKernel,
): LocalStorageRootKernelContext | undefined => contexts.get(kernel);
