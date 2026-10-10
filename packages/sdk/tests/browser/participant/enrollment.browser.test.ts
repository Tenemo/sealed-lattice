import { afterEach, describe, expect, it, vi } from 'vitest';

import type { ParticipantContext } from '#packages/sdk/src/participant/worker/module/context.js';
import {
    custodyIdentity,
    custodyPurpose,
} from '#packages/sdk/src/participant/worker/module/custody-identity.js';
import { noParallelHelpers } from '#packages/sdk/src/participant/worker/module/parallel-helpers.js';
import { instantiateParticipantModule } from '#packages/sdk/src/participant/worker/module/participant-module.js';
import { readParticipantLimits } from '#packages/sdk/src/participant/worker/module/runtime-bounds.js';
import {
    encodeText,
    hexadecimal,
} from '#packages/sdk/src/participant/worker/shared/bytes.js';
import {
    ModuleFailure,
    ResourceFailure,
    StorageFailure,
} from '#packages/sdk/src/participant/worker/shared/failures.js';
import { createEnrollment } from '#packages/sdk/src/participant/worker/stages/enrollment/enrollment.js';
import {
    isParticipantHead,
    isRootKey,
    openParticipantDatabase,
    snapshotParticipant,
} from '#packages/sdk/src/participant/worker/storage/database.js';
import {
    openRoot,
    rootAssociatedData,
} from '#packages/sdk/src/participant/worker/storage/root.js';

const databases: IDBDatabase[] = [];
const compiledModule = await WebAssembly.compile(
    await (
        await fetch(new URL('../../../dist/participant.wasm', import.meta.url))
    ).arrayBuffer(),
);
const enrollment = {
    role: 'organizer',
    question: 'Which option?',
    options: ['First', 'Second'],
    topCount: 1,
    maximumParticipants: 3,
    username: 'Organizer',
} as const;

const fixture = async (): Promise<ParticipantContext> => {
    const namespace = 'enrollment-' + crypto.randomUUID();
    const database = await openParticipantDatabase(namespace);
    databases.push(database);
    const { module, handlers } = await instantiateParticipantModule(
        compiledModule,
        noParallelHelpers,
    );
    expect(module.worker_reserve(0, 0)).toBe(0);
    const limits = readParticipantLimits(module);
    vi.spyOn(navigator.storage, 'estimate').mockResolvedValue({
        usage: 0,
        quota: 2 * limits.registration.publicKeyBytes,
    });
    return {
        namespace,
        database,
        module,
        handlers,
        parallel: noParallelHelpers,
        runtime: new Uint8Array(64).fill(7),
        limits,
        separateEvaluation: false,
    };
};

afterEach(async () => {
    vi.restoreAllMocks();
    for (const database of databases.splice(0)) {
        database.close();
        await new Promise<void>((resolve, reject) => {
            const request = indexedDB.deleteDatabase(database.name);
            request.onsuccess = () => resolve();
            request.onerror = () =>
                reject(request.error ?? new Error('Fixture cleanup failed.'));
        });
    }
});

// Validation, identity hashing, intent encryption and persistence use the
// real module, WebCrypto and IndexedDB. Only private credential generation
// is intercepted, so these boundary tests do not run a full enrollment proof.
describe('enrollment interruption custody', () => {
    it('preserves a pre-intent module failure and leaves enrollment retryable', async () => {
        const context = await fixture();
        const failure = new ModuleFailure('Validation module interrupted.');
        const started = vi.fn();
        const validate = context.module.validate_organizer;
        const failing = {
            ...context,
            module: {
                ...context.module,
                validate_organizer: (length: number) => {
                    expect(validate(length)).toBe(0);
                    throw failure;
                },
            },
        };
        await expect(
            createEnrollment(failing, enrollment, started),
        ).rejects.toBe(failure);
        expect(started).not.toHaveBeenCalled();
        const { counts } = await snapshotParticipant(context.database);
        expect(Object.values(counts).every((count) => count === 0)).toBe(true);

        // Another call is still validated, rather than refused as occupied.
        await expect(
            createEnrollment(failing, enrollment, started),
        ).rejects.toBe(failure);
    });

    it('reports loss of unpublished secrets after an authentic intent for every transient failure class', async () => {
        for (const failure of [
            new ModuleFailure('Credential module interrupted.'),
            new ResourceFailure('Credential memory exhausted.'),
            new StorageFailure('Credential output could not be retained.'),
        ]) {
            const context = await fixture();
            const started = vi.fn();
            const prepare = vi.fn(() => {
                throw failure;
            });
            const failing = {
                ...context,
                module: { ...context.module, prepare_organizer: prepare },
            };
            const rejected = await createEnrollment(
                failing,
                enrollment,
                started,
            ).catch((error: unknown) => error);
            expect(rejected).toBeInstanceOf(Error);
            expect(rejected).not.toBeInstanceOf(ModuleFailure);
            expect(rejected).not.toBeInstanceOf(ResourceFailure);
            expect(rejected).not.toBeInstanceOf(StorageFailure);
            expect(rejected).toHaveProperty('cause', failure);
            expect((rejected as Error).message).toContain(
                'Enrollment stopped before its required secrets were retained',
            );
            expect(started).toHaveBeenCalledOnce();
            expect(prepare).toHaveBeenCalledOnce();

            const snapshot = await snapshotParticipant(context.database);
            if (
                !isParticipantHead(snapshot.head) ||
                !isRootKey(snapshot.key) ||
                !(snapshot.root instanceof Uint8Array)
            )
                throw new Error('The enrollment intent was not retained.');
            expect(snapshot.head.generation).toBe(0);
            expect(snapshot.head.hash).toBe(
                hexadecimal(
                    custodyIdentity(
                        context.module,
                        custodyPurpose.root,
                        snapshot.root,
                    ),
                ),
            );
            const intent = await openRoot(
                snapshot.key,
                0,
                rootAssociatedData(context.runtime),
                snapshot.root,
            );
            expect(intent.subarray(0, 4)).toEqual(encodeText('INI2'));
            expect(intent.length).toBe(68);
            expect(snapshot.counts.data).toBe(0);

            // The failed attempt cannot create a replacement credential.
            await expect(
                createEnrollment(failing, enrollment, started),
            ).resolves.toBe('participant exists');
            expect(prepare).toHaveBeenCalledOnce();
        }
    });
});
