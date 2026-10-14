import assert from 'node:assert/strict';
import { deserialize, serialize } from 'node:v8';

import type { TestProject } from 'vitest/node';

import { listSupportedProfiles } from '#tests/supported-profile-model.js';

declare module 'vitest' {
    export interface ProvidedContext {
        supportedProfiles?: string;
    }
}

// A run that selects the Node project by name, as the check's Node lane does,
// derives every supported profile once and passes the serialized list to each
// test file, whose setup primes the model's caches with it. A run of chosen
// files derives only the profiles they use.
export default (project: TestProject): void => {
    if (!project.vitest.config.project.includes('node')) return;
    const profiles = listSupportedProfiles();
    const serialized = serialize(profiles);
    assert.deepStrictEqual(deserialize(serialized), profiles);
    project.provide('supportedProfiles', serialized.toString('base64'));
};
