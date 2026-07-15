import {
    CanonicalStreamCleanupError,
    CanonicalStreamInternalError,
} from './canonical-stream-runtime.js';
import type {
    AcceptedSetupSession,
    BgvCollectiveSetupVerification,
    BgvCollectiveSetupVerificationInput,
    TranscriptCoreKernelCommand,
    TranscriptCoreKernelContextOwner,
} from './transcript-core-bridge/kernel-types.js';

const wasm32WordByteLength = 4;

type AcceptedSetupCanonicalStreamBeginInput = Readonly<{
    readonly chunkCountPointer: number;
    readonly descriptorLength: number;
    readonly descriptorPointer: number;
    readonly familyCode: number;
    readonly materialRootLength: number;
    readonly materialRootPointer: number;
    readonly statusPointer: number;
    readonly totalByteLengthPointer: number;
}>;

type AcceptedSetupSessionKernelContext = Readonly<{
    allocate(length: number): number;
    begin(statusPointer: number): number;
    beginCanonicalStream(
        sessionHandle: number,
        familyCode: number,
        materialRootPointer: number,
        materialRootLength: number,
        descriptorPointer: number,
        descriptorLength: number,
        statusPointer: number,
        totalByteLengthPointer: number,
        chunkCountPointer: number,
    ): number;
    cancel(sessionHandle: number): number;
    deallocate(pointer: number, length: number): void;
    executeCommand(
        request: TranscriptCoreKernelCommand,
        sessionHandle: number,
        beforeKernelInvocation: () => void,
    ): BgvCollectiveSetupVerification;
    readonly memory: WebAssembly.Memory;
    runExclusive<Result>(
        operationName: string,
        operation: () => Result,
    ): Result;
}>;

const kernelContexts = new WeakMap<
    TranscriptCoreKernelContextOwner,
    AcceptedSetupSessionKernelContext
>();

const sessionImplementations = new WeakMap<
    AcceptedSetupSession,
    AcceptedSetupSessionImplementation
>();

class AcceptedSetupSessionImplementation implements AcceptedSetupSession {
    readonly #context: AcceptedSetupSessionKernelContext;
    readonly #sessionHandle: number;
    #active = true;

    public constructor(
        context: AcceptedSetupSessionKernelContext,
        sessionHandle: number,
    ) {
        this.#context = context;
        this.#sessionHandle = sessionHandle;
    }

    public beginCanonicalStream(
        input: AcceptedSetupCanonicalStreamBeginInput,
    ): number {
        this.#requireActive();
        return this.#context.beginCanonicalStream(
            this.#sessionHandle,
            input.familyCode,
            input.materialRootPointer,
            input.materialRootLength,
            input.descriptorPointer,
            input.descriptorLength,
            input.statusPointer,
            input.totalByteLengthPointer,
            input.chunkCountPointer,
        );
    }

    public cancel(): void {
        if (!this.#active) {
            return;
        }
        this.#active = false;
        const status = this.#context.runExclusive(
            'accepted-setup session cancellation',
            () => this.#context.cancel(this.#sessionHandle),
        );
        if (status >>> 0 !== 0) {
            throw new CanonicalStreamInternalError(
                'The WASM kernel refused an active accepted-setup session cancellation.',
            );
        }
    }

    public verifyCollectiveBgvSetup(
        input: BgvCollectiveSetupVerificationInput,
    ): BgvCollectiveSetupVerification {
        this.#requireActive();
        let terminalKernelInvoked = false;
        try {
            return this.#context.executeCommand(
                {
                    command: 'VerifyCollectiveBgvSetup',
                    setupPackage: input.setupPackage,
                    expectedSetupPackageHash: input.expectedSetupPackageHash,
                    expectedManifestHash: input.expectedManifestHash,
                    expectedRosterHash: input.expectedRosterHash,
                },
                this.#sessionHandle,
                () => {
                    terminalKernelInvoked = true;
                },
            );
        } catch (operationFailure) {
            if (!terminalKernelInvoked) {
                try {
                    this.cancel();
                } catch (cleanupFailure) {
                    throw new CanonicalStreamCleanupError(
                        operationFailure,
                        cleanupFailure,
                    );
                }
            }
            throw operationFailure;
        } finally {
            if (terminalKernelInvoked) {
                this.#active = false;
            }
        }
    }

    #requireActive(): void {
        if (!this.#active) {
            throw new CanonicalStreamInternalError(
                'The accepted-setup session is no longer active.',
            );
        }
    }
}

export const registerAcceptedSetupSessionKernelContext = (
    kernel: TranscriptCoreKernelContextOwner,
    context: AcceptedSetupSessionKernelContext,
): void => {
    kernelContexts.set(kernel, context);
};

export const openAcceptedSetupSession = (
    kernel: TranscriptCoreKernelContextOwner,
): AcceptedSetupSession => {
    const context = kernelContexts.get(kernel);
    if (context === undefined) {
        throw new CanonicalStreamInternalError(
            'The transcript-core kernel has no accepted-setup session boundary.',
        );
    }
    let sessionHandle = 0;
    let statusPointer = 0;
    try {
        statusPointer = context.allocate(wasm32WordByteLength) >>> 0;
        if (statusPointer === 0) {
            throw new CanonicalStreamInternalError(
                'The WASM kernel returned a null accepted-setup status allocation.',
            );
        }
        sessionHandle = context.runExclusive(
            'accepted-setup session begin',
            () => context.begin(statusPointer),
        );
        const status = new DataView(
            context.memory.buffer,
            statusPointer,
            wasm32WordByteLength,
        ).getUint32(0, true);
        if (status !== 0 || sessionHandle === 0) {
            throw new CanonicalStreamInternalError(
                'The WASM kernel could not open an accepted-setup session.',
            );
        }
        const session = new AcceptedSetupSessionImplementation(
            context,
            sessionHandle,
        );
        sessionImplementations.set(session, session);
        sessionHandle = 0;
        return session;
    } catch (operationFailure) {
        if (sessionHandle !== 0) {
            try {
                context.runExclusive(
                    'accepted-setup failed begin cleanup',
                    () => context.cancel(sessionHandle),
                );
            } catch (cleanupFailure) {
                throw new CanonicalStreamCleanupError(
                    operationFailure,
                    cleanupFailure,
                );
            }
        }
        throw operationFailure;
    } finally {
        if (statusPointer !== 0) {
            context.deallocate(statusPointer, wasm32WordByteLength);
        }
    }
};

export const beginAcceptedSetupCanonicalStream = (
    session: AcceptedSetupSession,
    input: AcceptedSetupCanonicalStreamBeginInput,
): number => {
    const implementation = sessionImplementations.get(session);
    if (implementation === undefined) {
        throw new CanonicalStreamInternalError(
            'The accepted-setup session does not belong to this WASM runtime.',
        );
    }
    return implementation.beginCanonicalStream(input);
};
