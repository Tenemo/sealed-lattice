import type {
    FinalitySignatureCarrier,
    SourceCarrier,
} from './finality-runtime.js';
import type {
    PrivatePreparationActionContext,
    PrivatePreparationConsumption,
    PrivatePreparationWorkerInitialization,
    PrivatePreparationWorkerRequest,
    PrivatePreparationWorkerResponse,
    PaddedTallyEvaluationStep,
    PaddedTallyWorkerInitialization,
    PublishedFinalityPackage,
    PublishedPaddedTallyChunk,
    PublishedPreparationPackage,
    PublishedSourcePackage,
    SourcePublicationChoice,
    TallyEvaluationProgress,
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
    actionDefinitionIdentity: copyBytes(context.actionDefinitionIdentity),
    predecessorIdentity: copyBytes(context.predecessorIdentity),
    participantPosition: context.participantPosition,
});

const copyCanonicalRosterBytes = (bytes: Uint8Array): Uint8Array =>
    copyBytes(bytes);

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
    collect(request.input.actionDefinitionIdentity);
    collect(request.input.predecessorIdentity);
    if ('canonicalRosterBytes' in request.input) {
        collect(request.input.canonicalRosterBytes);
    }
    if (request.operation === 'create-preparation-package') {
        collect(request.input.signingSecretKey);
        collect(request.input.mailboxDecapsulationKey);
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
    if (request.operation === 'initialize-padded-tally-generation') {
        for (const parent of request.input.preparationParents) {
            collect(parent.body);
            collect(parent.signature);
        }
        for (const source of request.input.sources) {
            collect(source.body);
            collect(source.signature);
        }
        for (const signature of request.input.finalitySignatures) {
            collect(signature.signature);
        }
    }
    if (request.operation === 'initialize-padded-tally-evaluation') {
        for (const signature of request.input.finalitySignatures) {
            collect(signature.signature);
        }
        for (const manifest of request.input.manifests) collect(manifest);
        for (const signature of request.input.activationSignatures) {
            collect(signature);
        }
    }
    if (request.operation === 'evaluate-padded-tally-chunk') {
        for (const chunk of request.input.chunks) collect(chunk);
    }
    if (
        request.operation === 'create-finality-signature' ||
        request.operation === 'finalize-no-result'
    ) {
        for (const source of request.input.sources) {
            collect(source.body);
            collect(source.signature);
        }
    }
    if (request.operation === 'finalize-no-result') {
        for (const signature of request.input.finalitySignatures) {
            collect(signature.signature);
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

    createPreparationPackage(
        context: PrivatePreparationActionContext,
        canonicalRosterBytes: Uint8Array,
        signingSecretKey: Uint8Array,
        mailboxDecapsulationKey: Uint8Array,
        preparationAttempt: number,
    ): Promise<PublishedPreparationPackage> {
        return this.send({
            operation: 'create-preparation-package',
            input: {
                ...copyActionContext(context),
                canonicalRosterBytes:
                    copyCanonicalRosterBytes(canonicalRosterBytes),
                signingSecretKey: copyBytes(signingSecretKey),
                mailboxDecapsulationKey: copyBytes(mailboxDecapsulationKey),
                preparationAttempt,
            },
        });
    }

    consumePrivatePreparation(
        context: PrivatePreparationActionContext,
        canonicalRosterBytes: Uint8Array,
        preparationAttempt: number,
        parentBody: Uint8Array,
        parentSignature: Uint8Array,
        privateBody: Uint8Array,
    ): Promise<PrivatePreparationConsumption> {
        return this.send({
            operation: 'consume-private-preparation',
            input: {
                ...copyActionContext(context),
                canonicalRosterBytes:
                    copyCanonicalRosterBytes(canonicalRosterBytes),
                preparationAttempt,
                parentBody: copyBytes(parentBody),
                parentSignature: copyBytes(parentSignature),
                privateBody: copyBytes(privateBody),
            },
        });
    }

    createSourcePackage(
        context: PrivatePreparationActionContext,
        canonicalRosterBytes: Uint8Array,
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
                canonicalRosterBytes:
                    copyCanonicalRosterBytes(canonicalRosterBytes),
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
        canonicalRosterBytes: Uint8Array,
        preparationAttempt: number,
        sources: readonly SourceCarrier[],
        topCount: number,
    ): Promise<PublishedFinalityPackage> {
        return this.send({
            operation: 'create-finality-signature',
            input: {
                ...copyActionContext(context),
                canonicalRosterBytes:
                    copyCanonicalRosterBytes(canonicalRosterBytes),
                preparationAttempt,
                sources: copySources(sources),
                topCount,
            },
        });
    }

    finalizeNoResult(
        context: PrivatePreparationActionContext,
        canonicalRosterBytes: Uint8Array,
        preparationAttempt: number,
        sources: readonly SourceCarrier[],
        finalitySignatures: readonly FinalitySignatureCarrier[],
        topCount: number,
    ): Promise<TallyEvaluationProgress> {
        return this.send({
            operation: 'finalize-no-result',
            input: {
                ...copyActionContext(context),
                canonicalRosterBytes:
                    copyCanonicalRosterBytes(canonicalRosterBytes),
                preparationAttempt,
                sources: copySources(sources),
                finalitySignatures: copyFinalitySignatures(finalitySignatures),
                topCount,
            },
        });
    }

    initializePaddedTallyGeneration(
        context: PrivatePreparationActionContext,
        canonicalRosterBytes: Uint8Array,
        preparationAttempt: number,
        preparationParents: readonly Readonly<{
            body: Uint8Array;
            signature: Uint8Array;
        }>[],
        sources: readonly SourceCarrier[],
        finalitySignatures: readonly FinalitySignatureCarrier[],
        topCount: number,
    ): Promise<PaddedTallyWorkerInitialization> {
        return this.send({
            operation: 'initialize-padded-tally-generation',
            input: {
                ...copyActionContext(context),
                canonicalRosterBytes:
                    copyCanonicalRosterBytes(canonicalRosterBytes),
                preparationAttempt,
                preparationParents: preparationParents.map((parent) => ({
                    body: copyBytes(parent.body),
                    signature: copyBytes(parent.signature),
                })),
                sources: copySources(sources),
                finalitySignatures: copyFinalitySignatures(finalitySignatures),
                topCount,
            },
        });
    }

    createPaddedTallyChunk(
        context: PrivatePreparationActionContext,
        expectedChunkOrdinal: number,
    ): Promise<PublishedPaddedTallyChunk> {
        return this.send({
            operation: 'create-padded-tally-chunk',
            input: {
                ...copyActionContext(context),
                expectedChunkOrdinal,
            },
        });
    }

    initializePaddedTallyEvaluation(
        context: PrivatePreparationActionContext,
        canonicalRosterBytes: Uint8Array,
        finalitySignatures: readonly FinalitySignatureCarrier[],
        manifests: readonly Uint8Array[],
        activationSignatures: readonly Uint8Array[],
    ): Promise<PaddedTallyWorkerInitialization> {
        return this.send({
            operation: 'initialize-padded-tally-evaluation',
            input: {
                ...copyActionContext(context),
                canonicalRosterBytes:
                    copyCanonicalRosterBytes(canonicalRosterBytes),
                finalitySignatures: copyFinalitySignatures(finalitySignatures),
                manifests: manifests.map(copyBytes),
                activationSignatures: activationSignatures.map(copyBytes),
            },
        });
    }

    evaluatePaddedTallyChunk(
        context: PrivatePreparationActionContext,
        expectedChunkOrdinal: number,
        chunks: readonly Uint8Array[],
    ): Promise<PaddedTallyEvaluationStep> {
        return this.send({
            operation: 'evaluate-padded-tally-chunk',
            input: {
                ...copyActionContext(context),
                expectedChunkOrdinal,
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
