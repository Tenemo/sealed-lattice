import type {
    FinalitySignatureCarrier,
    SourceCarrier,
} from './finality-runtime.js';
import type {
    ConfirmedActionKeyRoster,
    PrivatePreparationActionContext,
    PrivatePreparationConsumption,
    PrivatePreparationWorkerInitialization,
    PrivatePreparationWorkerRequest,
    PrivatePreparationWorkerResponse,
    PublishedFinalityPackage,
    PublishedPreparationPackage,
    PublishedSourcePackage,
    PublishedTallyActivation,
    PublishedTallyActivationChunk,
    RegisteredActionKeys,
    SourcePublicationChoice,
    TallyEvaluationProgress,
} from './private-preparation-worker-protocol.js';
import type { SignedActivationManifest } from './tally-activation-runtime.js';

type PendingRequest = Readonly<{
    reject(error: Error): void;
    resolve(result: unknown): void;
}>;

const copyBytes = (bytes: Uint8Array): Uint8Array => Uint8Array.from(bytes);

const copyActionContext = (
    context: PrivatePreparationActionContext,
): PrivatePreparationActionContext => ({
    actionProposalIdentity: copyBytes(context.actionProposalIdentity),
    predecessorIdentity: copyBytes(context.predecessorIdentity),
    participantPosition: context.participantPosition,
});

const copyActionKeySetBodies = (bodies: readonly Uint8Array[]): Uint8Array[] =>
    bodies.map(copyBytes);

const copySources = (sources: readonly SourceCarrier[]): SourceCarrier[] =>
    sources.map((source) => ({
        declaration: source.declaration,
        body: copyBytes(source.body),
        signature: copyBytes(source.signature),
    }));

const copyFinalitySignatures = (
    signatures: readonly FinalitySignatureCarrier[],
): FinalitySignatureCarrier[] =>
    signatures.map((signature) => ({
        signerPosition: signature.signerPosition,
        signature: copyBytes(signature.signature),
    }));

const copyActivationManifests = (
    manifests: readonly SignedActivationManifest[],
): SignedActivationManifest[] =>
    manifests.map((manifest) => ({
        body: copyBytes(manifest.body),
        signature: copyBytes(manifest.signature),
    }));

const copySourceChoice = (
    choice: SourcePublicationChoice,
): SourcePublicationChoice =>
    choice.declaration === 'abstain'
        ? { declaration: 'abstain' }
        : {
              declaration: 'submit',
              scoreEncodings: copyBytes(choice.scoreEncodings),
          };

const collectRequestTransferables = (
    request: PrivatePreparationWorkerRequest,
): Transferable[] => {
    const transferables: Transferable[] = [];
    const collect = (bytes: Uint8Array): void => {
        if (bytes.buffer instanceof ArrayBuffer) {
            transferables.push(bytes.buffer);
        }
    };
    if (request.operation === 'initialize') {
        collect(request.input.runtimeIdentity);
        collect(request.input.candidateBuildIdentity);
        return transferables;
    }
    collect(request.input.actionProposalIdentity);
    collect(request.input.predecessorIdentity);
    if ('actionKeySetBodies' in request.input) {
        for (const body of request.input.actionKeySetBodies) {
            collect(body);
        }
    }
    if (request.operation === 'consume-private-preparation') {
        collect(request.input.parentBody);
        collect(request.input.parentSignature);
        collect(request.input.privateBody);
    }
    if (request.operation === 'create-source-package') {
        for (const parent of request.input.preparationParents) {
            collect(parent.body);
            collect(parent.signature);
        }
        if (request.input.choice.declaration === 'submit') {
            collect(request.input.choice.scoreEncodings);
        }
    }
    if (
        request.operation === 'create-finality-signature' ||
        request.operation === 'create-tally-activation' ||
        request.operation === 'finalize-no-result' ||
        request.operation === 'advance-tally'
    ) {
        for (const source of request.input.sources) {
            collect(source.body);
            collect(source.signature);
        }
    }
    if (
        request.operation === 'create-tally-activation' ||
        request.operation === 'finalize-no-result' ||
        request.operation === 'advance-tally'
    ) {
        for (const signature of request.input.finalitySignatures) {
            collect(signature.signature);
        }
    }
    if (request.operation === 'advance-tally') {
        for (const manifest of request.input.activationManifests) {
            collect(manifest.body);
            collect(manifest.signature);
        }
        for (const chunk of request.input.chunks) {
            collect(chunk);
        }
    }
    return transferables;
};

export class PrivatePreparationWorkerClient {
    readonly #worker: Worker;
    readonly #pending = new Map<number, PendingRequest>();
    #nextRequestIdentifier = 1;
    #closed = false;

    private constructor(worker: Worker) {
        this.#worker = worker;
        worker.addEventListener(
            'message',
            (event: MessageEvent<PrivatePreparationWorkerResponse>) => {
                const response = event.data;
                const pending = this.#pending.get(response.requestId);
                if (pending === undefined) {
                    this.failAll(
                        new Error(
                            'The private-preparation worker returned an unknown request identity.',
                        ),
                    );
                    return;
                }
                this.#pending.delete(response.requestId);
                if (response.ok) {
                    pending.resolve(response.result);
                } else {
                    const error = new Error(response.error.message);
                    error.name = response.error.code;
                    pending.reject(error);
                }
            },
        );
        const fail = (): void => {
            this.failAll(
                new Error('The private-preparation worker became unavailable.'),
            );
        };
        worker.addEventListener('error', fail);
        worker.addEventListener('messageerror', fail);
    }

    static async create(
        workerUrl: URL,
        initialization: PrivatePreparationWorkerInitialization,
    ): Promise<PrivatePreparationWorkerClient> {
        const client = new PrivatePreparationWorkerClient(
            new Worker(workerUrl, { type: 'module' }),
        );
        try {
            await client.send({
                operation: 'initialize',
                input: {
                    databaseName: initialization.databaseName,
                    kernelUrl: initialization.kernelUrl,
                    kernelOptions: { ...initialization.kernelOptions },
                    runtimeIdentity: copyBytes(initialization.runtimeIdentity),
                    candidateBuildIdentity: copyBytes(
                        initialization.candidateBuildIdentity,
                    ),
                },
            });
            return client;
        } catch (error) {
            client.close();
            throw error;
        }
    }

    close(): void {
        if (this.#closed) {
            return;
        }
        this.#closed = true;
        this.#worker.terminate();
        this.failAll(new Error('The private-preparation worker was closed.'));
    }

    registerActionKeys(
        context: PrivatePreparationActionContext,
    ): Promise<RegisteredActionKeys> {
        return this.send({
            operation: 'register-action-keys',
            input: copyActionContext(context),
        });
    }

    confirmActionKeyRoster(
        context: PrivatePreparationActionContext,
        actionKeySetBodies: readonly Uint8Array[],
    ): Promise<ConfirmedActionKeyRoster> {
        return this.send({
            operation: 'confirm-action-key-roster',
            input: {
                ...copyActionContext(context),
                actionKeySetBodies: copyActionKeySetBodies(actionKeySetBodies),
            },
        });
    }

    createPreparationPackage(
        context: PrivatePreparationActionContext,
        actionKeySetBodies: readonly Uint8Array[],
        preparationAttempt: number,
    ): Promise<PublishedPreparationPackage> {
        return this.send({
            operation: 'create-preparation-package',
            input: {
                ...copyActionContext(context),
                actionKeySetBodies: copyActionKeySetBodies(actionKeySetBodies),
                preparationAttempt,
            },
        });
    }

    consumePrivatePreparation(
        context: PrivatePreparationActionContext,
        actionKeySetBodies: readonly Uint8Array[],
        preparationAttempt: number,
        parentBody: Uint8Array,
        parentSignature: Uint8Array,
        privateBody: Uint8Array,
    ): Promise<PrivatePreparationConsumption> {
        return this.send({
            operation: 'consume-private-preparation',
            input: {
                ...copyActionContext(context),
                actionKeySetBodies: copyActionKeySetBodies(actionKeySetBodies),
                preparationAttempt,
                parentBody: copyBytes(parentBody),
                parentSignature: copyBytes(parentSignature),
                privateBody: copyBytes(privateBody),
            },
        });
    }

    createSourcePackage(
        context: PrivatePreparationActionContext,
        actionKeySetBodies: readonly Uint8Array[],
        preparationAttempt: number,
        preparationParents: readonly Readonly<{
            body: Uint8Array;
            signature: Uint8Array;
        }>[],
        choice: SourcePublicationChoice,
    ): Promise<PublishedSourcePackage> {
        return this.send({
            operation: 'create-source-package',
            input: {
                ...copyActionContext(context),
                actionKeySetBodies: copyActionKeySetBodies(actionKeySetBodies),
                preparationAttempt,
                preparationParents: preparationParents.map((parent) => ({
                    body: copyBytes(parent.body),
                    signature: copyBytes(parent.signature),
                })),
                choice: copySourceChoice(choice),
            },
        });
    }

    createFinalitySignature(
        context: PrivatePreparationActionContext,
        actionKeySetBodies: readonly Uint8Array[],
        preparationAttempt: number,
        sources: readonly SourceCarrier[],
        topCount: number,
    ): Promise<PublishedFinalityPackage> {
        return this.send({
            operation: 'create-finality-signature',
            input: {
                ...copyActionContext(context),
                actionKeySetBodies: copyActionKeySetBodies(actionKeySetBodies),
                preparationAttempt,
                sources: copySources(sources),
                topCount,
            },
        });
    }

    createTallyActivation(
        context: PrivatePreparationActionContext,
        actionKeySetBodies: readonly Uint8Array[],
        preparationAttempt: number,
        sources: readonly SourceCarrier[],
        finalitySignatures: readonly FinalitySignatureCarrier[],
        topCount: number,
    ): Promise<PublishedTallyActivation> {
        return this.send({
            operation: 'create-tally-activation',
            input: {
                ...copyActionContext(context),
                actionKeySetBodies: copyActionKeySetBodies(actionKeySetBodies),
                preparationAttempt,
                sources: copySources(sources),
                finalitySignatures: copyFinalitySignatures(finalitySignatures),
                topCount,
            },
        });
    }

    finalizeNoResult(
        context: PrivatePreparationActionContext,
        actionKeySetBodies: readonly Uint8Array[],
        preparationAttempt: number,
        sources: readonly SourceCarrier[],
        finalitySignatures: readonly FinalitySignatureCarrier[],
        topCount: number,
    ): Promise<TallyEvaluationProgress> {
        return this.send({
            operation: 'finalize-no-result',
            input: {
                ...copyActionContext(context),
                actionKeySetBodies: copyActionKeySetBodies(actionKeySetBodies),
                preparationAttempt,
                sources: copySources(sources),
                finalitySignatures: copyFinalitySignatures(finalitySignatures),
                topCount,
            },
        });
    }

    readTallyActivationChunk(
        context: PrivatePreparationActionContext,
        chunkIndex: number,
    ): Promise<PublishedTallyActivationChunk> {
        return this.send({
            operation: 'read-tally-activation-chunk',
            input: { ...copyActionContext(context), chunkIndex },
        });
    }

    advanceTally(
        context: PrivatePreparationActionContext,
        actionKeySetBodies: readonly Uint8Array[],
        preparationAttempt: number,
        sources: readonly SourceCarrier[],
        finalitySignatures: readonly FinalitySignatureCarrier[],
        topCount: number,
        activationManifests: readonly SignedActivationManifest[],
        rangeIndex: number,
        chunks: readonly Uint8Array[],
    ): Promise<TallyEvaluationProgress> {
        return this.send({
            operation: 'advance-tally',
            input: {
                ...copyActionContext(context),
                actionKeySetBodies: copyActionKeySetBodies(actionKeySetBodies),
                preparationAttempt,
                sources: copySources(sources),
                finalitySignatures: copyFinalitySignatures(finalitySignatures),
                topCount,
                activationManifests:
                    copyActivationManifests(activationManifests),
                rangeIndex,
                chunks: chunks.map(copyBytes),
            },
        });
    }

    readTallyResult(
        context: PrivatePreparationActionContext,
    ): Promise<TallyEvaluationProgress> {
        return this.send({
            operation: 'read-tally-result',
            input: copyActionContext(context),
        });
    }

    private send<Result>(
        request: Omit<PrivatePreparationWorkerRequest, 'requestId'>,
    ): Promise<Result> {
        if (this.#closed) {
            return Promise.reject(
                new Error('The private-preparation worker is closed.'),
            );
        }
        const requestId = this.#nextRequestIdentifier;
        this.#nextRequestIdentifier += 1;
        const completeRequest = {
            ...request,
            requestId,
        } as PrivatePreparationWorkerRequest;
        return new Promise<Result>((resolve, reject) => {
            this.#pending.set(requestId, {
                resolve: (result) => {
                    resolve(result as Result);
                },
                reject,
            });
            try {
                this.#worker.postMessage(
                    completeRequest,
                    collectRequestTransferables(completeRequest),
                );
            } catch (error: unknown) {
                this.#pending.delete(requestId);
                reject(
                    error instanceof Error
                        ? error
                        : new Error('The worker request could not be sent.'),
                );
            }
        });
    }

    private failAll(error: Error): void {
        for (const pending of this.#pending.values()) {
            pending.reject(error);
        }
        this.#pending.clear();
    }
}
