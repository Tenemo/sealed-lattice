import { describe, expect, it } from 'vitest';

import { loadTranscriptCoreKernel } from '#packages/wasm/src/index';

const hash512Pattern = /^[a-f0-9]{128}$/u;

describe('transcript-core kernel in browsers', () => {
    it('loads the transcript-core module and runs a command through browser WASM', async () => {
        const kernel = await loadTranscriptCoreKernel();

        expect(kernel.exportedFunctionNames).toEqual(
            expect.arrayContaining([
                'memory',
                'sealed_lattice_allocate',
                'sealed_lattice_deallocate',
                'sealed_lattice_transcript_core_command_with_length',
            ]),
        );

        const pollSpecHash = kernel.deriveCanonicalObjectHash({
            value: { objectType: 'PollSpec', poll: 'main' },
        });

        expect(pollSpecHash).toMatch(hash512Pattern);
    });
});
