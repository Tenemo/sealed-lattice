import { describe, expect, it } from 'vitest';

import {
    loadMalformedObjectFixtures,
    loadTranscriptCoreReplayFixture,
} from '#tests/support/transcript-core-fixtures';
import { verifyTranscriptCoreFixture } from 'sealed-lattice';

describe('transcript-core fixtures', () => {
    it('verifies the replay fixture through the public package API', async () => {
        const replayFixture = await loadTranscriptCoreReplayFixture();

        await expect(
            verifyTranscriptCoreFixture(replayFixture.fixture),
        ).resolves.toEqual({
            caseName: 'fully-verified-passive-mhe-prototype-transcript-core',
            label: 'TranscriptCoreVerified',
            objectHash512: replayFixture.fixture.expectedObjectHash512,
            chunkRoot: replayFixture.fixture.expectedChunkRoot,
            statusLabels: replayFixture.expectedStatusLabels,
        });
    });

    it('reports deterministic rejection labels through the public package API', async () => {
        const malformedFixtures = await loadMalformedObjectFixtures();
        const invalidEnumFixture = malformedFixtures.find(
            (fixture) => fixture.caseName === 'invalid-enum',
        );
        if (invalidEnumFixture === undefined) {
            throw new Error('Missing invalid-enum fixture.');
        }

        await expect(
            verifyTranscriptCoreFixture(invalidEnumFixture),
        ).resolves.toEqual({
            caseName: 'invalid-enum',
            label: 'TranscriptCoreRejected',
            statusLabels: [],
            rejection: {
                code: 'InvalidEnum',
            },
        });
    });
});
