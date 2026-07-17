import {
    BrowserActionStorageCustodyError,
    type BrowserActionProofAttemptBinding,
    type BrowserActionRandomnessRecordContext,
    type BrowserActionRandomnessReservationCertificationInput,
    type BrowserActionRandomnessReservationIntentProductionInput,
    type BrowserActionRandomnessReservationIntentWitnessVerificationInput,
    type BrowserActionRandomnessReservationVerificationInput,
    type BrowserActionRandomnessReservationWitnessVoteProductionInput,
    type BrowserActionStateReservationVerificationInput,
    type BrowserActionStateVerifierSessionInput,
    type BrowserActionStorageRootBinding,
    type BrowserActionStorageWorkerKernel,
    type BrowserAuthenticatedRepairProtectionInput,
    type BrowserLocalRecordIdentifierInput,
    type BrowserLocalRecordOpenInput,
    type BrowserLocalRecordSealInput,
    type BrowserOpenedActionRandomnessSession,
    type BrowserProducedActionRandomnessReservation,
    type BrowserProducedActionRandomnessReservationIntent,
    type BrowserSealedActionRandomnessSession,
    type BrowserTargetReleaseAttemptInput,
    type UntrustedExpectedStorageRootCommitment,
    type VerificationResult,
    type WorkerBrowserFoundationInitializationPreparationInput,
    type WorkerDerivedBrowserFoundationInitializationRecords,
    type WorkerOpenedBrowserAuthenticatedRepairProtection,
    type WorkerPreparedBrowserFoundationInitialization,
    type WorkerPreparedDeviceWrappingState,
} from '@sealed-lattice/types';

import type {
    CommonProofApplicationFreshnessCoordinate,
    VerifiedCommonProofCapability,
} from '../common-proof-worker-runtime.js';
import type { VerifiedStateDurableBinding } from '../state-verifier-runtime.js';
import { resolveActionRandomnessKernelContext } from '../transcript-core-bridge/action-randomness-kernel-context.js';
import type { TranscriptCoreKernel } from '../transcript-core-bridge/kernel-types.js';
import { resolveLocalStorageRootKernelContext } from '../transcript-core-bridge/local-storage-root-kernel-context.js';

import {
    type ClosedWorkerPreparedCommonProofApplication,
    type ClosedWorkerSetupMailboxRandomnessOperations,
    type ClosedWorkerStructuredCommitmentOpeningOperations,
    type WorkerActionRandomnessKernelRunner,
    type WorkerActionRandomnessRecordContext,
    type WorkerFoundationStateProducerRunner,
    type WorkerSealedActionRandomnessSession,
    type WorkerSetupMailboxRandomnessInput,
    type WorkerStructuredCommitmentOpeningInput,
    closedWorkerCommonProofScratchStorage,
    requireClosedWorkerCommonProofScratchStorage,
    workerActionRandomnessKernelRunners,
    workerCommonProofApplicationRunners,
    workerFoundationStateProducerRunners,
} from './authorities.js';
import { WasmBrowserActionStorageWorkerKernel } from './runtime.js';
type TerminalSetupCheckpointKernelCommandRunner = Readonly<{
    run(command: number, input: Uint8Array): Promise<Uint8Array<ArrayBuffer>>;
    sampleEntropy(
        byteLength: number,
        label: string,
    ): Promise<Uint8Array<ArrayBuffer>>;
}>;

const terminalSetupCheckpointKernelCommandRunners = new WeakMap<
    BrowserActionStorageWorkerKernel,
    TerminalSetupCheckpointKernelCommandRunner
>();

class DeferredWasmBrowserActionStorageWorkerKernel implements BrowserActionStorageWorkerKernel {
    readonly #workerKernel: Promise<BrowserActionStorageWorkerKernel>;

    public constructor(
        workerKernel: Promise<BrowserActionStorageWorkerKernel>,
    ) {
        this.#workerKernel = workerKernel;
        closedWorkerCommonProofScratchStorage.set(this, {
            deriveRecordIdentifier: async (operationInput) =>
                requireClosedWorkerCommonProofScratchStorage(
                    await this.#workerKernel,
                ).deriveRecordIdentifier(operationInput),
            openRecord: async (operationInput) =>
                requireClosedWorkerCommonProofScratchStorage(
                    await this.#workerKernel,
                ).openRecord(operationInput),
            sealRecord: async (operationInput) =>
                requireClosedWorkerCommonProofScratchStorage(
                    await this.#workerKernel,
                ).sealRecord(operationInput),
        });
    }

    public async createAndStageDeviceWrappingState(input: {
        binding: BrowserActionStorageRootBinding;
    }): Promise<WorkerPreparedDeviceWrappingState> {
        return (await this.#workerKernel).createAndStageDeviceWrappingState(
            input,
        );
    }

    public async stageDeviceWrappingStateOpen(input: {
        binding: BrowserActionStorageRootBinding;
        untrustedExpectedCommitment: UntrustedExpectedStorageRootCommitment;
        state: WorkerPreparedDeviceWrappingState;
    }): Promise<void> {
        return (await this.#workerKernel).stageDeviceWrappingStateOpen(input);
    }

    public async commitStagedActionStorageRoot(): Promise<void> {
        return (await this.#workerKernel).commitStagedActionStorageRoot();
    }

    public async discardStagedActionStorageRoot(): Promise<void> {
        return (await this.#workerKernel).discardStagedActionStorageRoot();
    }

    public async destroyActiveActionStorageRoot(): Promise<void> {
        return (await this.#workerKernel).destroyActiveActionStorageRoot();
    }

    public async deriveActiveLocalRecordIdentifier(
        input: BrowserLocalRecordIdentifierInput,
    ): Promise<Uint8Array> {
        return (await this.#workerKernel).deriveActiveLocalRecordIdentifier(
            input,
        );
    }

    public async sealActiveLocalRecord(
        input: BrowserLocalRecordSealInput,
    ): Promise<Uint8Array> {
        return (await this.#workerKernel).sealActiveLocalRecord(input);
    }

    public async openActiveLocalRecord(
        input: BrowserLocalRecordOpenInput,
    ): Promise<Uint8Array> {
        return (await this.#workerKernel).openActiveLocalRecord(input);
    }

    public async hashActiveLocalRecordEnvelope(
        envelope: Uint8Array,
    ): Promise<Uint8Array> {
        return (await this.#workerKernel).hashActiveLocalRecordEnvelope(
            envelope,
        );
    }

    public async openActiveAuthenticatedRepairProtection(
        input: BrowserAuthenticatedRepairProtectionInput,
    ): Promise<WorkerOpenedBrowserAuthenticatedRepairProtection> {
        return (
            await this.#workerKernel
        ).openActiveAuthenticatedRepairProtection(input);
    }

    public async sealAuthenticatedRepairHead(input: {
        plaintext: Uint8Array;
        repairProtectionSessionIdentifier: string;
    }): Promise<Uint8Array> {
        return (await this.#workerKernel).sealAuthenticatedRepairHead(input);
    }

    public async openAuthenticatedRepairHead(input: {
        canonicalEnvelope: Uint8Array;
        repairProtectionSessionIdentifier: string;
    }): Promise<Uint8Array> {
        return (await this.#workerKernel).openAuthenticatedRepairHead(input);
    }

    public async deriveAuthenticatedRepairHeadDigest(input: {
        sealedHeadBytes: Uint8Array;
        repairProtectionSessionIdentifier: string;
    }): Promise<Uint8Array> {
        return (await this.#workerKernel).deriveAuthenticatedRepairHeadDigest(
            input,
        );
    }

    public async closeAuthenticatedRepairProtection(
        identifier: string,
    ): Promise<void> {
        return (await this.#workerKernel).closeAuthenticatedRepairProtection(
            identifier,
        );
    }

    public async prepareBrowserFoundationInitialization(
        input: WorkerBrowserFoundationInitializationPreparationInput,
    ): Promise<WorkerPreparedBrowserFoundationInitialization> {
        return (
            await this.#workerKernel
        ).prepareBrowserFoundationInitialization(input);
    }

    public async deriveBrowserFoundationInitializationRecords(
        input: WorkerBrowserFoundationInitializationPreparationInput,
    ): Promise<WorkerDerivedBrowserFoundationInitializationRecords> {
        return (
            await this.#workerKernel
        ).deriveBrowserFoundationInitializationRecords(input);
    }

    public async openActionStateVerifierSession(
        input: BrowserActionStateVerifierSessionInput,
    ): Promise<VerificationResult<string>> {
        return (await this.#workerKernel).openActionStateVerifierSession(input);
    }

    public async verifyActionStateReservation(
        input: BrowserActionStateReservationVerificationInput,
    ): Promise<VerificationResult<string>> {
        return (await this.#workerKernel).verifyActionStateReservation(input);
    }

    public async verifyActionRandomnessReservation(
        input: BrowserActionRandomnessReservationVerificationInput,
    ): Promise<VerificationResult<string>> {
        return (await this.#workerKernel).verifyActionRandomnessReservation(
            input,
        );
    }

    public async releaseActionStateObject(identifier: string): Promise<void> {
        return (await this.#workerKernel).releaseActionStateObject(identifier);
    }

    public async closeActionStateVerifierSession(
        identifier: string,
    ): Promise<void> {
        return (await this.#workerKernel).closeActionStateVerifierSession(
            identifier,
        );
    }

    public async createAndSealActionRandomness(
        input: BrowserActionRandomnessRecordContext,
    ): Promise<BrowserSealedActionRandomnessSession> {
        return (await this.#workerKernel).createAndSealActionRandomness(input);
    }

    public async openSealedActionRandomness(
        input: BrowserActionRandomnessRecordContext &
            Readonly<{
                actionRandomnessCommitment: Uint8Array;
                canonicalEnvelope: Uint8Array;
            }>,
    ): Promise<BrowserOpenedActionRandomnessSession> {
        return (await this.#workerKernel).openSealedActionRandomness(input);
    }

    public async closeActionRandomness(identifier: string): Promise<void> {
        return (await this.#workerKernel).closeActionRandomness(identifier);
    }

    public async deriveTargetReleaseAttempt(
        input: BrowserTargetReleaseAttemptInput,
    ): Promise<BrowserActionProofAttemptBinding> {
        return (await this.#workerKernel).deriveTargetReleaseAttempt(input);
    }
}

const resolveWorkerCryptoProvider = (): Crypto => {
    const resolvedCryptoProvider = globalThis.crypto;
    if (
        resolvedCryptoProvider === undefined ||
        typeof resolvedCryptoProvider.getRandomValues !== 'function' ||
        resolvedCryptoProvider.subtle === undefined
    ) {
        throw new BrowserActionStorageCustodyError(
            'Unavailable',
            'WebCrypto is required for local storage-root custody.',
        );
    }

    return resolvedCryptoProvider;
};

const createWorkerKernelFromLoadedKernel = (input: {
    cryptoProvider: Crypto;
    kernel: TranscriptCoreKernel;
}): BrowserActionStorageWorkerKernel => {
    const context = resolveLocalStorageRootKernelContext(input.kernel);
    if (context === undefined) {
        throw new BrowserActionStorageCustodyError(
            'Unavailable',
            'The loaded WASM kernel does not expose the local storage-root runtime.',
        );
    }
    const actionRandomnessContext = resolveActionRandomnessKernelContext(
        input.kernel,
    );
    if (actionRandomnessContext === undefined) {
        throw new BrowserActionStorageCustodyError(
            'Unavailable',
            'The loaded WASM kernel does not expose action-randomness custody.',
        );
    }

    const workerKernel = new WasmBrowserActionStorageWorkerKernel({
        actionRandomnessContext,
        context,
        cryptoProvider: input.cryptoProvider,
        kernel: input.kernel,
    });
    terminalSetupCheckpointKernelCommandRunners.set(workerKernel, {
        run: (command, commandInput) =>
            workerKernel.runTerminalSetupCheckpointCommand(
                command,
                commandInput,
            ),
        sampleEntropy: (byteLength, label) =>
            workerKernel.sampleTerminalSetupCheckpointEntropy(
                byteLength,
                label,
            ),
    });
    workerActionRandomnessKernelRunners.set(workerKernel, {
        close: (sessionIdentifier) =>
            workerKernel.closeActionRandomness(sessionIdentifier),
        createAndSeal: (operationInput) =>
            workerKernel.createAndSealActionRandomness(operationInput),
        openSetupMailboxRandomness: (operationInput) =>
            Promise.resolve().then(() =>
                workerKernel.openClosedSetupMailboxRandomness(operationInput),
            ),
        openStructuredCommitmentOpenings: (operationInput) =>
            Promise.resolve().then(() =>
                workerKernel.openClosedStructuredCommitmentOpenings(
                    operationInput,
                ),
            ),
        durableBindingForStateObject: (stateObjectIdentifier) =>
            workerKernel.durableBindingForStateObject(stateObjectIdentifier),
        openSealed: (operationInput) =>
            workerKernel.openSealedActionRandomness(operationInput),
    });
    workerFoundationStateProducerRunners.set(workerKernel, {
        certifyReservation: (operationInput) =>
            workerKernel.certifyActionRandomnessReservation(operationInput),
        produceIntent: (operationInput) =>
            workerKernel.produceActionRandomnessReservationIntent(
                operationInput,
            ),
        produceWitnessVote: (operationInput) =>
            workerKernel.produceActionRandomnessReservationWitnessVote(
                operationInput,
            ),
        verifyIntentForWitness: (operationInput) =>
            workerKernel.verifyActionRandomnessReservationIntentForWitness(
                operationInput,
            ),
    });
    workerCommonProofApplicationRunners.set(workerKernel, {
        prepare: (capability, predecessor) =>
            workerKernel.prepareClosedCommonProofApplication(
                capability,
                predecessor,
            ),
    });
    return workerKernel;
};

const isKernelPromise = (
    kernel: TranscriptCoreKernel | PromiseLike<TranscriptCoreKernel>,
): kernel is PromiseLike<TranscriptCoreKernel> =>
    typeof kernel === 'object' &&
    kernel !== null &&
    'then' in kernel &&
    typeof kernel.then === 'function';

/**
 * Creates the worker-owned storage-root kernel. Passing the loader promise lets
 * a module worker install its message host before WASM loading yields, so the
 * first channel request cannot be delivered before the worker listener exists.
 */
export const createWasmBrowserActionStorageWorkerKernel = (input: {
    kernel: TranscriptCoreKernel | PromiseLike<TranscriptCoreKernel>;
}): BrowserActionStorageWorkerKernel => {
    const cryptoProvider = resolveWorkerCryptoProvider();
    if (!isKernelPromise(input.kernel)) {
        return createWorkerKernelFromLoadedKernel({
            cryptoProvider,
            kernel: input.kernel,
        });
    }

    const resolvedWorkerKernel = Promise.resolve(input.kernel)
        .then((kernel) =>
            createWorkerKernelFromLoadedKernel({ cryptoProvider, kernel }),
        )
        .catch((error: unknown) => {
            if (error instanceof BrowserActionStorageCustodyError) {
                throw error;
            }
            throw new BrowserActionStorageCustodyError(
                'Unavailable',
                'The WebAssembly storage-root kernel could not be loaded.',
                error,
            );
        });
    // Observe startup failure immediately. Operations still await the original
    // rejected promise and receive the typed error above.
    void resolvedWorkerKernel.catch(() => undefined);
    const deferredWorkerKernel =
        new DeferredWasmBrowserActionStorageWorkerKernel(resolvedWorkerKernel);
    terminalSetupCheckpointKernelCommandRunners.set(deferredWorkerKernel, {
        run: async (command, commandInput) =>
            runTerminalSetupCheckpointKernelCommand(
                await resolvedWorkerKernel,
                command,
                commandInput,
            ),
        sampleEntropy: async (byteLength, label) =>
            sampleTerminalSetupCheckpointEntropy(
                await resolvedWorkerKernel,
                byteLength,
                label,
            ),
    });
    workerActionRandomnessKernelRunners.set(deferredWorkerKernel, {
        close: async (sessionIdentifier) =>
            closeWorkerActionRandomness(
                await resolvedWorkerKernel,
                sessionIdentifier,
            ),
        createAndSeal: async (operationInput) =>
            createAndSealWorkerActionRandomness(
                await resolvedWorkerKernel,
                operationInput,
            ),
        openSetupMailboxRandomness: async (operationInput) =>
            openClosedWorkerSetupMailboxRandomness(
                await resolvedWorkerKernel,
                operationInput,
            ),
        openStructuredCommitmentOpenings: async (operationInput) =>
            openClosedWorkerStructuredCommitmentOpenings(
                await resolvedWorkerKernel,
                operationInput,
            ),
        durableBindingForStateObject: async (stateObjectIdentifier) =>
            openClosedWorkerVerifiedStateDurableBinding(
                await resolvedWorkerKernel,
                stateObjectIdentifier,
            ),
        openSealed: async (operationInput) =>
            openSealedWorkerActionRandomness(
                await resolvedWorkerKernel,
                operationInput,
            ),
    });
    workerFoundationStateProducerRunners.set(deferredWorkerKernel, {
        certifyReservation: async (operationInput) =>
            certifyClosedWorkerActionRandomnessReservation(
                await resolvedWorkerKernel,
                operationInput,
            ),
        produceIntent: async (operationInput) =>
            produceClosedWorkerActionRandomnessReservationIntent(
                await resolvedWorkerKernel,
                operationInput,
            ),
        produceWitnessVote: async (operationInput) =>
            produceClosedWorkerActionRandomnessReservationWitnessVote(
                await resolvedWorkerKernel,
                operationInput,
            ),
        verifyIntentForWitness: async (operationInput) =>
            verifyClosedWorkerActionRandomnessReservationIntentForWitness(
                await resolvedWorkerKernel,
                operationInput,
            ),
    });
    workerCommonProofApplicationRunners.set(deferredWorkerKernel, {
        prepare: async (capability, predecessor) =>
            prepareClosedWorkerVerifiedCommonProofApplication(
                await resolvedWorkerKernel,
                capability,
                predecessor,
            ),
    });
    return deferredWorkerKernel;
};

const requireWorkerActionRandomnessRunner = (
    workerKernel: BrowserActionStorageWorkerKernel,
): WorkerActionRandomnessKernelRunner => {
    const runner = workerActionRandomnessKernelRunners.get(workerKernel);
    if (runner === undefined) {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            'The action storage worker does not belong to this WASM runtime.',
        );
    }
    return runner;
};

const requireWorkerFoundationStateProducerRunner = (
    workerKernel: BrowserActionStorageWorkerKernel,
): WorkerFoundationStateProducerRunner => {
    const runner = workerFoundationStateProducerRunners.get(workerKernel);
    if (runner === undefined) {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            'The action storage worker has no closed foundation state producer.',
        );
    }
    return runner;
};

export const produceClosedWorkerActionRandomnessReservationIntent = (
    workerKernel: BrowserActionStorageWorkerKernel,
    input: BrowserActionRandomnessReservationIntentProductionInput,
): Promise<
    VerificationResult<BrowserProducedActionRandomnessReservationIntent>
> =>
    requireWorkerFoundationStateProducerRunner(workerKernel).produceIntent(
        input,
    );

export const verifyClosedWorkerActionRandomnessReservationIntentForWitness = (
    workerKernel: BrowserActionStorageWorkerKernel,
    input: BrowserActionRandomnessReservationIntentWitnessVerificationInput,
): Promise<VerificationResult<string>> =>
    requireWorkerFoundationStateProducerRunner(
        workerKernel,
    ).verifyIntentForWitness(input);

export const produceClosedWorkerActionRandomnessReservationWitnessVote = (
    workerKernel: BrowserActionStorageWorkerKernel,
    input: BrowserActionRandomnessReservationWitnessVoteProductionInput,
): Promise<VerificationResult<Uint8Array>> =>
    requireWorkerFoundationStateProducerRunner(workerKernel).produceWitnessVote(
        input,
    );

export const certifyClosedWorkerActionRandomnessReservation = (
    workerKernel: BrowserActionStorageWorkerKernel,
    input: BrowserActionRandomnessReservationCertificationInput,
): Promise<VerificationResult<BrowserProducedActionRandomnessReservation>> =>
    requireWorkerFoundationStateProducerRunner(workerKernel).certifyReservation(
        input,
    );

export const createAndSealWorkerActionRandomness = (
    workerKernel: BrowserActionStorageWorkerKernel,
    input: WorkerActionRandomnessRecordContext,
): Promise<WorkerSealedActionRandomnessSession> =>
    requireWorkerActionRandomnessRunner(workerKernel).createAndSeal(input);

export const openSealedWorkerActionRandomness = (
    workerKernel: BrowserActionStorageWorkerKernel,
    input: WorkerActionRandomnessRecordContext &
        Readonly<{
            actionRandomnessCommitment: Uint8Array;
            canonicalEnvelope: Uint8Array;
        }>,
): Promise<BrowserOpenedActionRandomnessSession> =>
    requireWorkerActionRandomnessRunner(workerKernel).openSealed(input);

export const closeWorkerActionRandomness = (
    workerKernel: BrowserActionStorageWorkerKernel,
    sessionIdentifier: string,
): Promise<void> =>
    requireWorkerActionRandomnessRunner(workerKernel).close(sessionIdentifier);

export const openClosedWorkerSetupMailboxRandomness = (
    workerKernel: BrowserActionStorageWorkerKernel,
    input: WorkerSetupMailboxRandomnessInput,
): Promise<ClosedWorkerSetupMailboxRandomnessOperations> => {
    if (typeof globalThis.document !== 'undefined') {
        throw new BrowserActionStorageCustodyError(
            'Unavailable',
            'Setup-mailbox randomness may only be consumed inside the dedicated custody worker.',
        );
    }
    return requireWorkerActionRandomnessRunner(
        workerKernel,
    ).openSetupMailboxRandomness(input);
};

export const openClosedWorkerStructuredCommitmentOpenings = (
    workerKernel: BrowserActionStorageWorkerKernel,
    input: WorkerStructuredCommitmentOpeningInput,
): Promise<ClosedWorkerStructuredCommitmentOpeningOperations> => {
    if (typeof globalThis.document !== 'undefined') {
        throw new BrowserActionStorageCustodyError(
            'Unavailable',
            'Structured-commitment openings may only be consumed inside the dedicated custody worker.',
        );
    }
    return requireWorkerActionRandomnessRunner(
        workerKernel,
    ).openStructuredCommitmentOpenings(input);
};

export const prepareClosedWorkerVerifiedCommonProofApplication = (
    workerKernel: BrowserActionStorageWorkerKernel,
    capability: VerifiedCommonProofCapability,
    predecessor: CommonProofApplicationFreshnessCoordinate,
): Promise<ClosedWorkerPreparedCommonProofApplication> => {
    if (typeof globalThis.document !== 'undefined') {
        throw new BrowserActionStorageCustodyError(
            'Unavailable',
            'Verified common-proof authority may only be applied inside the dedicated custody worker.',
        );
    }
    const runner = workerCommonProofApplicationRunners.get(workerKernel);
    if (runner === undefined) {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            'The action storage worker does not belong to this WASM runtime.',
        );
    }
    return runner.prepare(capability, predecessor);
};

export const openClosedWorkerVerifiedStateDurableBinding = (
    workerKernel: BrowserActionStorageWorkerKernel,
    stateObjectIdentifier: string,
): Promise<VerificationResult<VerifiedStateDurableBinding>> => {
    if (typeof globalThis.document !== 'undefined') {
        throw new BrowserActionStorageCustodyError(
            'Unavailable',
            'Verified state durable bindings may only be consumed inside the dedicated custody worker.',
        );
    }
    return requireWorkerActionRandomnessRunner(
        workerKernel,
    ).durableBindingForStateObject(stateObjectIdentifier);
};

const runTerminalSetupCheckpointKernelCommand = async (
    workerKernel: BrowserActionStorageWorkerKernel,
    command: number,
    input: Uint8Array,
): Promise<Uint8Array<ArrayBuffer>> => {
    const runner =
        terminalSetupCheckpointKernelCommandRunners.get(workerKernel);
    if (runner === undefined) {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            'The action storage worker does not belong to this WASM runtime.',
        );
    }

    return runner.run(command, input);
};

const sampleTerminalSetupCheckpointEntropy = async (
    workerKernel: BrowserActionStorageWorkerKernel,
    byteLength: number,
    label: string,
): Promise<Uint8Array<ArrayBuffer>> => {
    const runner =
        terminalSetupCheckpointKernelCommandRunners.get(workerKernel);
    if (runner === undefined) {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            'The action storage worker does not belong to this WASM runtime.',
        );
    }

    return runner.sampleEntropy(byteLength, label);
};
