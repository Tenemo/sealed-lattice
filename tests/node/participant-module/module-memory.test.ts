import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import binaryen from 'binaryen';
import { describe, expect, it } from 'vitest';

import {
    distribution,
    moduleBytes,
} from '#tests/node/participant-module/packaged-participant-fixture.js';

describe('participant module memory', () => {
    it('ends the call that exhausts the linear-memory bound with a resource failure, and its instance refuses every later call', () => {
        const parsed = binaryen.readBinary(moduleBytes);
        const initialPages = parsed.getMemoryInfo().initial;
        parsed.dispose();
        // The engine refuses every growth beyond one page, which the
        // instance's first allocation needs.
        const child = spawnSync(
            process.execPath,
            [
                `--wasm-max-mem-pages=${String(initialPages + 1)}`,
                '--import',
                'tsx',
                fileURLToPath(
                    new URL(
                        './fixtures/exhaust-module-memory.ts',
                        import.meta.url,
                    ),
                ),
                fileURLToPath(new URL('participant.wasm', distribution)),
            ],
            { encoding: 'utf8' },
        );
        expect(child.status, child.stderr).toBe(0);
        const outcome = JSON.parse(child.stdout) as {
            resource: boolean;
            message: string;
            same: boolean;
        };
        expect(outcome.resource).toBe(true);
        expect(outcome.message).toMatch(
            /^The participant module exhausted its memory bound, \d+ bytes requested\.$/u,
        );
        expect(outcome.same).toBe(true);
    });
});
