import {
    CanonicalStreamCleanupError,
    CanonicalStreamInternalError,
} from './canonical-stream-runtime.js';
import { copyIntoKernelMemory } from './transcript-core-bridge/kernel-runtime.js';
import type {
    AcceptedSetupSession,
    BgvCollectiveSetupVerification,
    BgvCollectiveSetupVerificationInput,
    TranscriptCoreKernelCommand,
    TranscriptCoreKernelContextOwner,
} from './transcript-core-bridge/kernel-types.js';

const capabilityByteLength = 32;
const wasm32WordByteLength = 4;

type AcceptedSetupCanonicalStreamBeginInput = Readonly<{
    readonly chunkCountPointer: number;
    readonly descriptorLength: number;
    readonly descriptorPointer: number;
    readonly familyCode: number;
    readonly materialRootLength: number;
    readonly materialRootPointer: number;
    readonly statusPointer: number;
    readonly streamCapabilityLength: number;
    readonly streamCapabilityPointer: number;
    readonly totalByteLengthPointer: number;
}>;

type AcceptedSetupSessionKernelContext = Readonly<{
    allocate(length: number): number;
    begin(
        capabilityPointer: number,
        capabilityLength: number,
        statusPointer: number,
    ): number;
    beginCanonicalStream(
        sessionHandle: number,
        setupCapabilityPointer: number,
        setupCapabilityLength: number,
        familyCode: number,
        materialRootPointer: number,
        materialRootLength: number,
        descriptorPointer: number,
        descriptorLength: number,
        streamCapabilityPointer: number,
        streamCapabilityLength: number,
        statusPointer: number,
        totalByteLengthPointer: number,
        chunkCountPointer: number,
    ): number;
    cancel(
        sessionHandle: number,
        capabilityPointer: number,
        capabilityLength: number,
    ): number;
    deallocate(pointer: number, length: number): void;
    executeCommand(
        request: TranscriptCoreKernelCommand,
        sessionHandle: number,
        capabilityPointer: number,
        capabilityLength: number,
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

const defaultFillRandomValues = (
    destination: Uint8Array<ArrayBuffer>,
): void => {
    const cryptoProvider = globalThis.crypto;
    if (cryptoProvider === undefined) {
        throw new CanonicalStreamInternalError(
            'Web Crypto getRandomValues is required for accepted-setup session capabilities.',
        );
    }
    cryptoProvider.getRandomValues(destination);
};

class AcceptedSetupSessionImplementation implements AcceptedSetupSession {
    readonly #capabilityPointer: number;
    readonly #context: AcceptedSetupSessionKernelContext;
    readonly #sessionHandle: number;
    #active = true;

    public constructor(
        context: AcceptedSetupSessionKernelContext,
        sessionHandle: number,
        capabilityPointer: number,
    ) {
        this.#context = context;
        this.#sessionHandle = sessionHandle;
        this.#capabilityPointer = capabilityPointer;
    }

    public beginCanonicalStream(
        input: AcceptedSetupCanonicalStreamBeginInput,
    ): number {
        this.#requireActive();
        return this.#context.beginCanonicalStream(
            this.#sessionHandle,
            this.#capabilityPointer,
            capabilityByteLength,
            input.familyCode,
            input.materialRootPointer,
            input.materialRootLength,
            input.descriptorPointer,
            input.descriptorLength,
            input.streamCapabilityPointer,
            input.streamCapabilityLength,
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
        try {
            const status = this.#context.runExclusive(
                'accepted-setup session cancellation',
                () =>
                    this.#context.cancel(
                        this.#sessionHandle,
                        this.#capabilityPointer,
                        capabilityByteLength,
                    ),
            );
            if (status >>> 0 !== 0) {
                throw new CanonicalStreamInternalError(
                    'The WASM kernel refused an active accepted-setup session cancellation.',
                );
            }
        } finally {
            this.#releaseCapability();
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
                    transportedPublicKeyShareMaterial:
                        input.transportedPublicKeyShareMaterial,
                    transportedPublicKeyShareProofMaterial:
                        input.transportedPublicKeyShareProofMaterial,
                    transportedEvaluationKeyShareProofMaterial:
                        input.transportedEvaluationKeyShareProofMaterial,
                    transportedVssShareLinkageProofMaterial:
                        input.transportedVssShareLinkageProofMaterial,
                    transportedSameSecretBridgeProofMaterial:
                        input.transportedSameSecretBridgeProofMaterial,
                    transportedEvaluationKeyShareComponentMaterial:
                        input.transportedEvaluationKeyShareComponentMaterial,
                },
                this.#sessionHandle,
                this.#capabilityPointer,
                capabilityByteLength,
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
                this.#releaseCapability();
            }
        }
    }

    #releaseCapability(): void {
        new Uint8Array(
            this.#context.memory.buffer,
            this.#capabilityPointer,
            capabilityByteLength,
        ).fill(0);
        this.#context.deallocate(this.#capabilityPointer, capabilityByteLength);
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
    const capability = new Uint8Array(capabilityByteLength);
    defaultFillRandomValues(capability);
    let capabilityPointer = 0;
    let sessionHandle = 0;
    let statusPointer = 0;
    try {
        capabilityPointer = copyIntoKernelMemory(
            context.memory,
            context.allocate,
            capability,
        );
        statusPointer = context.allocate(wasm32WordByteLength) >>> 0;
        if (statusPointer === 0) {
            throw new CanonicalStreamInternalError(
                'The WASM kernel returned a null accepted-setup status allocation.',
            );
        }
        sessionHandle = context.runExclusive(
            'accepted-setup session begin',
            () =>
                context.begin(
                    capabilityPointer,
                    capabilityByteLength,
                    statusPointer,
                ),
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
            capabilityPointer,
        );
        sessionImplementations.set(session, session);
        capabilityPointer = 0;
        sessionHandle = 0;
        return session;
    } catch (operationFailure) {
        if (sessionHandle !== 0 && capabilityPointer !== 0) {
            try {
                context.runExclusive(
                    'accepted-setup failed begin cleanup',
                    () =>
                        context.cancel(
                            sessionHandle,
                            capabilityPointer,
                            capabilityByteLength,
                        ),
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
        capability.fill(0);
        if (statusPointer !== 0) {
            context.deallocate(statusPointer, wasm32WordByteLength);
        }
        if (capabilityPointer !== 0) {
            new Uint8Array(
                context.memory.buffer,
                capabilityPointer,
                capabilityByteLength,
            ).fill(0);
            context.deallocate(capabilityPointer, capabilityByteLength);
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
