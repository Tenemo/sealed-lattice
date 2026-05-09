import type {
    GoldenTranscriptCoreFixture,
    MalformedObjectFixture,
} from '@sealed-lattice/protocol';
import { describe, expect, it } from 'vitest';

import goldenTranscriptCoreFixturesJson from '../../../../test-vectors/transcript-core/golden-transcript-core.json';
import malformedObjectFixturesJson from '../../../../test-vectors/transcript-core/malformed-objects.json';
import {
    loadTranscriptCoreKernel,
    TranscriptCoreKernelCommandError,
} from '../../src/index';

type NamedFixture = {
    readonly caseName: string;
};

const goldenTranscriptCoreFixtures =
    goldenTranscriptCoreFixturesJson as readonly GoldenTranscriptCoreFixture[];
const malformedObjectFixtures =
    malformedObjectFixturesJson as readonly MalformedObjectFixture[];

const findFixture = <Fixture extends NamedFixture>(
    fixtures: readonly Fixture[],
    caseName: string,
): Fixture => {
    const fixture = fixtures.find(
        (candidate) => candidate.caseName === caseName,
    );
    if (fixture === undefined) {
        throw new Error(`Missing fixture: ${caseName}`);
    }

    return fixture;
};

const resultComputedPassiveFixture = findFixture(
    goldenTranscriptCoreFixtures,
    'result-computed-passive-mhe-transcript-core',
);
const invalidEnumFixture = findFixture(malformedObjectFixtures, 'invalid-enum');

describe('transcript-core kernel in browsers', () => {
    it('loads the transcript-core module and exposes command exports', async () => {
        const kernel = await loadTranscriptCoreKernel();

        expect(kernel.exportedFunctionNames).toEqual(
            expect.arrayContaining([
                'memory',
                'sealed_lattice_allocate',
                'sealed_lattice_deallocate',
                'sealed_lattice_last_output_length',
                'sealed_lattice_transcript_core_command',
            ]),
        );
    });

    it('verifies the golden transcript-core fixture', async () => {
        const kernel = await loadTranscriptCoreKernel();

        expect(kernel.verifyFixture(resultComputedPassiveFixture)).toEqual({
            verified: true,
            caseName: 'result-computed-passive-mhe-transcript-core',
            objectHash512: resultComputedPassiveFixture.expectedObjectHash512,
            chunkRoot: resultComputedPassiveFixture.expectedChunkRoot,
            statusLabels: resultComputedPassiveFixture.expectedStatusLabels,
        });
    });

    it('rejects malformed canonical bytes with the same error code', async () => {
        const kernel = await loadTranscriptCoreKernel();

        expect(() =>
            kernel.analyzeCanonicalObject({
                canonicalBytesHex: invalidEnumFixture.canonicalBytesHex,
                chunkSize: 8,
            }),
        ).toThrow(TranscriptCoreKernelCommandError);
    });
});
