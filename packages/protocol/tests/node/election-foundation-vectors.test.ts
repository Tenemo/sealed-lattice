import type { PollSpecInput } from '@sealed-lattice/types';
import { describe, expect, it } from 'vitest';

import { validatePollSpec } from '#packages/protocol/src/index';
import pollSpecsJson from '#test-vectors/election-foundation/poll-specs.json';

type PollSpecVector = {
    readonly caseName: string;
    readonly input: PollSpecInput;
    readonly expectedOk: boolean;
    readonly expectedErrorCodes?: readonly string[];
};

type PollSpecVectors = {
    readonly schemaVersion: 1;
    readonly cases: readonly PollSpecVector[];
};

const pollSpecs = pollSpecsJson as PollSpecVectors;

describe('election foundation test vectors', () => {
    it('matches poll-spec validation vectors', () => {
        for (const vector of pollSpecs.cases) {
            const validation = validatePollSpec(vector.input);
            const actualErrorCodes = validation.ok
                ? undefined
                : validation.errors.map((error) => error.code);

            expect(validation.ok, vector.caseName).toBe(vector.expectedOk);
            expect(actualErrorCodes, vector.caseName).toEqual(
                vector.expectedErrorCodes,
            );
        }
    });
});
