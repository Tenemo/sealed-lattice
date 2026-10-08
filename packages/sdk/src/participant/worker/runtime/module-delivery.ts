import { participantRuntimeLabel } from '../module/custody-identity.js';
import type { ParallelHelpers } from '../module/parallel-helpers.js';
import {
    instantiateParticipantModule,
    requireInputCapacities,
} from '../module/participant-module.js';
import type { ParticipantModule } from '../module/participant-module.js';
import { readBounded } from '../relay/relay.js';
import {
    concatenate,
    encodeText,
    fromHexadecimal,
    hexadecimal,
} from '../shared/bytes.js';
import { PublicInputFailure } from '../shared/failures.js';
import { largestBufferInputBytes } from '../stages/target-vote/target.js';

import type { WorkerCommand } from './worker-messages.js';

const maximumModuleBytes = 8_388_608;

// Every operation needs a secure context, Web Locks, WebCrypto and
// IndexedDB.
export const isSupportedBrowser = () =>
    isSecureContext &&
    typeof navigator.locks === 'object' &&
    typeof crypto.subtle === 'object' &&
    typeof indexedDB === 'object';

// The pinned module digest gates execution. The runtime identity combines it
// with the pinned source and worker digests and binds protocol contexts and
// retained state; it is distinct from module-owned protocol object identities.
const deliveryDigest = async (bytes: Uint8Array<ArrayBuffer>) =>
    new Uint8Array(await crypto.subtle.digest('SHA-512', bytes));

// Fetches the module, which must have the pinned digest, and recomputes the
// runtime identity from it and the pinned source and worker digests.
export const deliverModule = async (
    command: Pick<WorkerCommand, 'module' | 'identity'>,
) => {
    const bytes = await readBounded(command.module, maximumModuleBytes);
    const digest = await deliveryDigest(bytes);
    if (hexadecimal(digest) !== command.identity.module)
        throw new PublicInputFailure('The participant module changed.');
    const runtime = await deliveryDigest(
        concatenate(
            encodeText(participantRuntimeLabel),
            fromHexadecimal(command.identity.source),
            digest,
            fromHexadecimal(command.identity.worker),
        ),
    );
    return { bytes, runtime };
};

// Instantiates the module for one operation. The worker's share of the
// operation's memory plan, whose other shares the started helpers hold,
// bounds its instance before the first allocation.
export const instantiateForOperation = async (
    compiledModule: WebAssembly.Module,
    parallel: ParallelHelpers,
    evaluation: boolean,
) => {
    const instance = await instantiateParticipantModule(
        compiledModule,
        parallel,
    );
    if (
        instance.module.worker_reserve(parallel.count, evaluation ? 1 : 0) !== 0
    )
        throw new Error('The participant module refused its memory plan.');
    requireInputCapacities(
        instance.module,
        largestBufferInputBytes(instance.module),
    );
    return instance;
};

// The WebAssembly memory a completed operation held: the worker instance's
// linear memory and how far its allocations reached, and its helpers' and
// the shared arena's, beside the bounds of the operation's memory plan.
export const operationMemory = (
    module: ParticipantModule,
    helpers: ParallelHelpers,
    evaluation: boolean,
) => ({
    workerBytes: module.memory.buffer.byteLength,
    workerUsedBytes: module.linear_memory_high_water() >>> 0,
    workerBoundBytes:
        module.worker_memory_bound(helpers.count, evaluation ? 1 : 0) >>> 0,
    helpers: helpers.count,
    helperBoundBytes:
        module.helper_memory_bound(helpers.count, evaluation ? 1 : 0) >>> 0,
    ...helpers.memory(),
});
export type OperationMemory = ReturnType<typeof operationMemory>;
