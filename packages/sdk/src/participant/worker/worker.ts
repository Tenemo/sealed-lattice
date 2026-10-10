import { errorMessage } from './module/context.js';
import {
    helperRole,
    listenAsHelper,
} from './module/parallel-helper-instance.js';
import { startParallelHelpers } from './module/parallel-helpers.js';
import type { ParallelHelpers } from './module/parallel-helpers.js';
import type { ParticipantModule } from './module/participant-module.js';
import { readParticipantLimits } from './module/runtime-bounds.js';
import type { PublicRelay } from './relay/relay.js';
import {
    deliverModule,
    instantiateForOperation,
    isSupportedBrowser,
    operationMemory,
} from './runtime/module-delivery.js';
import { executeOperation } from './runtime/operations.js';
import {
    isVerification,
    isWellFormed,
    isWellFormedVerification,
    refused,
} from './runtime/worker-messages.js';
import type {
    VerificationCommand,
    WorkerCommand,
    WorkerResult,
} from './runtime/worker-messages.js';
import { fromHexadecimal } from './shared/bytes.js';
import { classifyFailure, pendingCause } from './shared/failures.js';
import { verifyPublishedOutcome } from './stages/outcome-verifier.js';
import { EvaluationRetained } from './stages/target-vote/target.js';
import {
    deleteWorkingStorage,
    namespacedName,
    openParticipantDatabase,
} from './storage/database.js';
import { stopParticipant } from './storage/stop.js';

// The operations that evaluate the ranking program, whose helpers keep the
// evaluation's tables and the polynomials its multiplications keep.
const evaluatingOperations: ReadonlySet<string> = new Set([
    'sign-target',
    'release',
    'compute-result',
]);

const run = async (
    command: WorkerCommand,
    helperPorts: readonly MessagePort[],
): Promise<WorkerResult> => {
    if (!isSupportedBrowser()) return refused('unsupported browser');
    if (!isWellFormed(command)) return refused('invalid request');
    const relay: PublicRelay = { base: command.relay };
    let database: IDBDatabase | undefined;
    let helpers: ParallelHelpers | undefined;
    let authorityStarted = false;
    try {
        const delivered = await deliverModule(command);
        const compiledModule = await WebAssembly.compile(delivered.bytes);
        const evaluation = evaluatingOperations.has(command.operation);
        const started = startParallelHelpers(
            compiledModule,
            helperPorts,
            evaluation,
        );
        database = await openParticipantDatabase(command.namespace);
        helpers = await started;
        const opened = database;
        const parallel = helpers;
        return await navigator.locks.request(
            namespacedName('sealed-lattice-participant', command.namespace),
            async (): Promise<WorkerResult> => {
                let module: ParticipantModule | undefined;
                try {
                    const instance = await instantiateForOperation(
                        compiledModule,
                        parallel,
                        evaluation,
                    );
                    module = instance.module;
                    const result = await executeOperation(
                        {
                            namespace: command.namespace,
                            database: opened,
                            module,
                            handlers: instance.handlers,
                            parallel,
                            runtime: delivered.runtime,
                            limits: readParticipantLimits(module),
                            separateEvaluation:
                                command.separateEvaluation === true,
                        },
                        relay,
                        command,
                        () => {
                            authorityStarted = true;
                        },
                    );
                    return result.status === 'completed'
                        ? {
                              status: 'completed',
                              details: {
                                  ...result.details,
                                  memory: operationMemory(
                                      module,
                                      parallel,
                                      evaluation,
                                  ),
                              },
                          }
                        : result;
                } catch (error) {
                    // The worker's memory, and its helpers', ends with them,
                    // so the page runs the rest of an operation that
                    // retained the target it evaluated in fresh ones.
                    if (
                        error instanceof EvaluationRetained &&
                        module !== undefined
                    )
                        return {
                            status: 'evaluated',
                            memory: operationMemory(
                                module,
                                parallel,
                                evaluation,
                            ),
                        };
                    // A malformed request is refused before the operation
                    // changes anything. A local failure after authority
                    // started stops the participant before any other
                    // operation takes the lock. A failed helper, an exhausted
                    // memory bound and a module call that ended without
                    // returning touch no retained state and leave the
                    // participant pending. Enrollment converts failures after
                    // its intent but before retaining its secrets into local
                    // state loss instead.
                    const outcome = classifyFailure(error, authorityStarted);
                    if (outcome.status === 'refused')
                        return refused(outcome.reason);
                    if (outcome.status === 'pending') throw error;
                    const stopPersistence = await stopParticipant(opened);
                    return {
                        status: 'stopped',
                        detail: errorMessage(error),
                        stopPersistence,
                    };
                }
            },
        );
    } catch (error) {
        // An unrecognized participant database is refused before anything is
        // written to it. Public input, pending storage, resource and module
        // failures and failures before authority started leave the
        // participant pending.
        const outcome = classifyFailure(error, false);
        if (outcome.status === 'refused') return refused(outcome.reason);
        return {
            status: 'pending',
            cause: pendingCause(error),
            detail: errorMessage(error),
        };
    } finally {
        helpers?.stop();
        database?.close();
    }
};

// A verification's public working storage, named apart from every
// participant's, since no participant namespace has a full stop.
const verificationNamespace = (poll: string) => 'verification.' + poll;

const runVerification = async (
    command: VerificationCommand,
    helperPorts: readonly MessagePort[],
): Promise<WorkerResult> => {
    if (!isSupportedBrowser()) return refused('unsupported browser');
    if (!isWellFormedVerification(command)) return refused('invalid request');
    let helpers: ParallelHelpers | undefined;
    try {
        const delivered = await deliverModule(command);
        const compiledModule = await WebAssembly.compile(delivered.bytes);
        helpers = await startParallelHelpers(compiledModule, helperPorts, true);
        const parallel = helpers;
        const namespace = verificationNamespace(command.poll);
        return await navigator.locks.request(
            namespacedName('sealed-lattice-verification', namespace),
            async (): Promise<WorkerResult> => {
                const { module, handlers } = await instantiateForOperation(
                    compiledModule,
                    parallel,
                    true,
                );
                try {
                    const outcome = await verifyPublishedOutcome(
                        {
                            namespace,
                            module,
                            handlers,
                            parallel,
                            runtime: delivered.runtime,
                            limits: readParticipantLimits(module),
                        },
                        { base: command.relay },
                        fromHexadecimal(command.poll),
                    );
                    return {
                        status: 'completed',
                        details: {
                            poll: command.poll,
                            ...outcome,
                            memory: operationMemory(module, parallel, true),
                        },
                    };
                } finally {
                    await deleteWorkingStorage(namespace);
                }
            },
        );
    } catch (error) {
        return {
            status: 'pending',
            cause: pendingCause(error),
            detail: errorMessage(error),
        };
    } finally {
        helpers?.stop();
    }
};

self.onmessage = (
    event: MessageEvent<
        WorkerCommand | VerificationCommand | typeof helperRole
    >,
) => {
    if (event.data === helperRole) {
        self.onmessage = null;
        listenAsHelper(event.ports[0]);
        self.postMessage(true);
        return;
    }
    const command = event.data;
    void (
        isVerification(command)
            ? runVerification(command, event.ports)
            : run(command, event.ports)
    ).then(
        (result) => self.postMessage(result),
        (error: unknown) =>
            self.postMessage({
                status: 'pending',
                cause: pendingCause(error),
                detail: errorMessage(error),
            }),
    );
};
