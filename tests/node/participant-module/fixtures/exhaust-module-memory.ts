import { readFile } from 'node:fs/promises';

import { noParallelHelpers } from '#packages/sdk/src/participant/worker/module/parallel-helpers.js';
import { instantiateParticipantModule } from '#packages/sdk/src/participant/worker/module/participant-module.js';
import { ResourceFailure } from '#packages/sdk/src/participant/worker/shared/failures.js';

const modulePath = process.argv[2];
if (modulePath === undefined) throw new Error('The module path is required.');
const bytes = await readFile(modulePath);
const { module } = await instantiateParticipantModule(
    await WebAssembly.compile(bytes),
    noParallelHelpers,
);
const failureOf = (call: () => unknown) => {
    try {
        call();
    } catch (error) {
        return error;
    }
    return undefined;
};
const first = failureOf(() => module.custody_identity_begin(0, 0));
const later = failureOf(() => module.custody_identity_input_capacity());
process.stdout.write(
    JSON.stringify({
        resource: first instanceof ResourceFailure,
        message: first instanceof Error ? first.message : undefined,
        same: later === first,
    }),
);
