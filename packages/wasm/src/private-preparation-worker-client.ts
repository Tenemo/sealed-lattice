import type {
    ConfirmedActionKeyRoster,
    PrivatePreparationActionContext,
    PrivatePreparationConsumption,
    PrivatePreparationWorkerInitialization,
    PrivatePreparationWorkerRequest,
    PrivatePreparationWorkerResponse,
    PublishedPreparationPackage,
    PublishedSourcePackage,
    RegisteredActionKeys,
    SourcePublicationChoice,
} from './private-preparation-worker-protocol.js';

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
                choice: { ...choice },
            },
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
