import assert from 'node:assert/strict';
import { setTimeout as delay } from 'node:timers/promises';

import { chunkBytes } from '#packages/sdk/src/participant/worker/module/runtime-bounds.js';
import { compileParticipantRuntimeProfile } from '#tests/participant-runtime-bounds-model.js';
import type { ActiveLocalRunLog } from '#tools/ci/local-run-log.js';
import {
    type Relay,
    haltingClient,
} from '#tools/ci/participant-browser-relay.js';
import type { ParticipantRequests } from '#tools/ci/participant-browser-requests.js';
import type { ParticipantStateFaults } from '#tools/ci/participant-browser-state-faults.js';
import {
    type CohortState,
    type ParticipantOperation,
    type InParticipantBrowser,
} from '#tools/ci/participant-cohort-state.js';
import {
    type ProofCompletionCut,
    type ProofCompletionHaltObservation,
    type ProofCompletionSlotObservation,
    type PreparationCut,
    proofCompletionHaltingClient,
    preparationHaltingClient,
    validateProofCompletionObservation,
} from '#tools/ci/participant-proof-completion.js';
import { assembleParticipantRuntime } from '#tools/ci/participant-runtime-assembly.js';

export const createParticipantInterruptions = ({
    honest,
    halting,
    runtime,
    inBrowser,
    request,
    headGeneration,
    endBrowser,
    recoveryOperations,
    log,
    browsers,
    participantBrowser,
    storedRecords,
    proofCompletionClients,
    retainedHead,
    bounds,
    deliveredRecords,
}: Readonly<{
    honest: (position: number) => boolean;
    halting: Relay['halting'];
    runtime: Awaited<ReturnType<typeof assembleParticipantRuntime>>['runtime'];
    inBrowser: InParticipantBrowser;
    request: ParticipantRequests['request'];
    headGeneration: ParticipantStateFaults['headGeneration'];
    endBrowser: ParticipantStateFaults['endBrowser'];
    recoveryOperations: ParticipantRequests['recoveryOperations'];
    log: ActiveLocalRunLog;
    browsers: CohortState['browsers'];
    participantBrowser: (position: number) => string;
    storedRecords: ParticipantStateFaults['storedRecords'];
    proofCompletionClients:
        | ReadonlyMap<
              ProofCompletionCut,
              ReturnType<typeof proofCompletionHaltingClient>
          >
        | undefined;
    retainedHead: ParticipantStateFaults['retainedHead'];
    bounds: ReturnType<typeof compileParticipantRuntimeProfile>;
    deliveredRecords: Relay['delivered'];
}>) => {
    // Installs a halting client by reloading the idle page. The
    // requested protocol cut performs the crash; arming a hook must
    // not add another crash during inspection or browser recovery.
    const armHalt = async (position: number, generation: number) => {
        assert.ok(honest(position), 'Only an honest client halts.');
        halting.set(position, haltingClient(runtime.worker, generation));
        await inBrowser(position, undefined, (chrome) => chrome.reload());
    };
    // Runs an operation in a halting client. The browser crashes once
    // its participant enters the generation, with no shutdown work
    // after that commit, and the next visit runs the runtime's own
    // worker again.
    const interruptions: {
        position: number;
        operation: ParticipantOperation;
        generation: number;
        // The records an interrupted operation had stored ahead of
        // its next root.
        staged?: Readonly<{ store: string; records: number }>;
        // The public record the relay had delivered to the
        // interrupted operation.
        delivered?: string;
        preparation?: PreparationCut;
    }[] = [];
    const interrupt = async (
        position: number,
        operation: ParticipantOperation,
        parameters: Record<string, unknown>,
        generation: number,
    ) => {
        if (halting.get(position)?.generation !== generation)
            await armHalt(position, generation);
        try {
            const halted = request(position, operation, parameters);
            for (;;) {
                const settled = await Promise.race([
                    halted.then(
                        (result) => JSON.stringify(result),
                        (error: unknown) => String(error),
                    ),
                    delay(500, undefined),
                ]);
                assert.equal(
                    settled,
                    undefined,
                    `${operation} at position ${String(position)} ended before generation ${String(generation)}: ${String(settled)}`,
                );
                if ((await headGeneration(position)) === generation) break;
            }
            await endBrowser(position);
            await assert.rejects(halted);
        } finally {
            halting.delete(position);
        }
        recoveryOperations.set(position, operation);
        interruptions.push({ position, operation, generation });
        log.writeEvent({
            eventType: 'participant-interruption',
            details: { position, operation, generation },
        });
    };
    const interruptPreparation = async (
        position: number,
        operation: ParticipantOperation,
        cut: PreparationCut,
    ) => {
        assert.ok(honest(position));
        halting.set(position, preparationHaltingClient(runtime.worker, cut));
        await inBrowser(position, undefined, (chrome) => chrome.reload());
        try {
            const pending = request(position, operation);
            for (;;) {
                const outcome = await Promise.race([
                    pending.then(
                        (result) => JSON.stringify(result),
                        (error: unknown) => String(error),
                    ),
                    delay(250, undefined),
                ]);
                assert.equal(
                    outcome,
                    undefined,
                    `${operation} ended before ${cut.kind} phase ${String(cut.phase)}: ${String(outcome)}`,
                );
                const reached = await inBrowser(position, undefined, (chrome) =>
                    chrome.evaluate('window.preparationHalt'),
                );
                if (reached !== null && reached !== undefined) {
                    assert.deepEqual(reached, {
                        type: 'participant-preparation-halt',
                        ...cut,
                    });
                    break;
                }
            }
            assert.equal(await headGeneration(position), 4);
            await endBrowser(position);
            await assert.rejects(pending);
        } finally {
            halting.delete(position);
        }
        recoveryOperations.set(position, operation);
        interruptions.push({
            position,
            operation,
            generation: 4,
            preparation: cut,
        });
        log.writeEvent({
            eventType: 'participant-preparation-interruption',
            details: { position, operation, ...cut },
        });
    };
    // Ends a participant's running operation without a crash inside
    // one of Chrome's storage writes: the page unloads, which ends the
    // operation and its storage transactions, and the browser then
    // closes. A crash there can leave a cut write-ahead log record that
    // Chrome reuses, so that a later crash makes it delete the store.
    const stopOperation = async (position: number) => {
        await inBrowser(position, undefined, (chrome) => chrome.unload());
        await browsers.close(participantBrowser(position));
    };
    // Interrupts a participant's operation once, in the generation it
    // durably entered, it has reached a point ahead of its next root,
    // and records that point. The next visit discards what the
    // operation stored and runs it again from its retained state.
    const interruptWhen = async (
        position: number,
        operation: ParticipantOperation,
        generation: number,
        reached: () => Promise<boolean>,
        point: () => Promise<
            Pick<(typeof interruptions)[number], 'staged' | 'delivered'>
        >,
    ) => {
        const interrupted = request(position, operation);
        for (;;) {
            const outcome = await Promise.race([
                interrupted.then(
                    () => 'settled',
                    () => 'settled',
                ),
                delay(250, 'waiting'),
            ]);
            assert.equal(
                outcome,
                'waiting',
                `${operation} at position ${String(position)} ended before its interruption in generation ${String(generation)}.`,
            );
            if (
                (await headGeneration(position)) === generation &&
                (await reached())
            )
                break;
        }
        await stopOperation(position);
        await assert.rejects(interrupted);
        assert.equal(
            await headGeneration(position),
            generation,
            'The interrupted operation committed its next root first.',
        );
        const details = {
            position,
            operation,
            generation,
            ...(await point()),
        };
        recoveryOperations.set(position, operation);
        interruptions.push(details);
        log.writeEvent({
            eventType: 'participant-interruption',
            details,
        });
    };
    // Interrupts an operation once it stored at least the given
    // records in one store.
    const interruptStaged = (
        position: number,
        operation: ParticipantOperation,
        generation: number,
        store: string,
        records: number,
    ) =>
        interruptWhen(
            position,
            operation,
            generation,
            async () => (await storedRecords(position, store)) >= records,
            async () => ({
                staged: {
                    store,
                    records: await storedRecords(position, store),
                },
            }),
        );
    const proofCompletionInterruptions: {
        position: number;
        observation: Readonly<{
            slots: readonly ProofCompletionSlotObservation[];
            halt: ProofCompletionHaltObservation;
        }>;
        head: Readonly<{
            generation: number;
            hash: string;
            runtime: string;
        }>;
        checkpointRecords: number;
        originalWorkerSha512: string;
        instrumentedWorkerSha512: string;
        instrumentationMilliseconds: number;
    }[] = [];
    const interruptProofCompletion = async (
        position: number,
        cut: ProofCompletionCut,
    ) => {
        const client = proofCompletionClients?.get(cut);
        assert.ok(client);
        halting.set(position, client);
        await inBrowser(position, undefined, (chrome) => chrome.reload());
        try {
            const before = await retainedHead(position);
            assert.equal(before.generation, 4);
            const checkpointRecords = await storedRecords(
                position,
                'checkpoint',
            );
            assert.ok(checkpointRecords > 0);
            const interrupted = request(position, 'contribute');
            let observation: {
                slots: ProofCompletionSlotObservation[];
                halt: ProofCompletionHaltObservation | null;
            };
            for (;;) {
                const settled = await Promise.race([
                    interrupted.then(
                        () => true,
                        () => true,
                    ),
                    delay(250, false),
                ]);
                assert.equal(
                    settled,
                    false,
                    'Contribution ended without reaching the requested proof completion cut; no reseed or skipped case is allowed.',
                );
                observation = (await inBrowser(position, undefined, (chrome) =>
                    chrome.evaluate('window.proofCompletionReplay'),
                )) as typeof observation;
                if (observation.halt !== null) break;
            }
            assert.ok(observation.halt);
            assert.equal(observation.halt.cut, cut);
            const captured = {
                slots: observation.slots,
                halt: observation.halt,
            };
            validateProofCompletionObservation(
                captured,
                bounds.contribution,
                chunkBytes,
            );
            assert.deepEqual(
                await retainedHead(position),
                before,
                'Proof completion changed its original continuation root before the cut.',
            );
            assert.equal(
                await storedRecords(position, 'checkpoint'),
                checkpointRecords,
            );
            assert.equal(
                await storedRecords(position, 'contribution'),
                bounds.contribution.publicRecords.length +
                    captured.slots.length,
            );
            await endBrowser(position);
            await assert.rejects(interrupted);
            const entry = {
                position,
                observation: captured,
                head: before,
                checkpointRecords,
                originalWorkerSha512: client.originalDigest,
                instrumentedWorkerSha512: client.digest,
                instrumentationMilliseconds: captured.slots.reduce(
                    (sum, slot) => sum + slot.instrumentationMilliseconds,
                    0,
                ),
            };
            proofCompletionInterruptions.push(entry);
            interruptions.push({
                position,
                operation: 'contribute',
                generation: 4,
                preparation: { kind: 'contribution', phase: 6 },
                staged: {
                    store: 'contribution',
                    records:
                        bounds.contribution.publicRecords.length +
                        captured.slots.length,
                },
            });
            recoveryOperations.set(position, 'contribute');
            log.writeEvent({
                eventType: 'participant-proof-completion-interruption',
                details: entry,
            });
        } finally {
            halting.delete(position);
        }
    };
    // Interrupts an operation once the relay delivered it the named
    // public record.
    const interruptDelivered = (
        position: number,
        operation: ParticipantOperation,
        generation: number,
        name: string,
    ) => {
        deliveredRecords[position].clear();
        return interruptWhen(
            position,
            operation,
            generation,
            () => Promise.resolve(deliveredRecords[position].has(name)),
            () => Promise.resolve({ delivered: name }),
        );
    };
    return {
        interruptions,
        interrupt,
        interruptPreparation,
        interruptStaged,
        proofCompletionInterruptions,
        interruptProofCompletion,
        interruptDelivered,
    };
};
