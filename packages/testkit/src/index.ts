import { readFile } from 'node:fs/promises';
import path from 'node:path';

import type {
    GoldenTranscriptCoreFixture,
    MalformedObjectFixture,
    TranscriptCoreReplayFixture,
} from '@sealed-lattice/protocol';

const loadJsonFixture = async <Fixture>(
    ...pathSegments: readonly string[]
): Promise<Fixture> => {
    const fixturePath = path.resolve(
        process.cwd(),
        'test-vectors',
        ...pathSegments,
    );
    const fixtureContents = await readFile(fixturePath, 'utf8');

    return JSON.parse(fixtureContents) as Fixture;
};

export const loadGoldenTranscriptCoreFixtures = async (): Promise<
    readonly GoldenTranscriptCoreFixture[]
> =>
    loadJsonFixture<readonly GoldenTranscriptCoreFixture[]>(
        'transcript-core',
        'golden-transcript-core.json',
    );

export const loadMalformedObjectFixtures = async (): Promise<
    readonly MalformedObjectFixture[]
> =>
    loadJsonFixture<readonly MalformedObjectFixture[]>(
        'transcript-core',
        'malformed-objects.json',
    );

export const loadTranscriptCoreReplayFixture =
    async (): Promise<TranscriptCoreReplayFixture> =>
        loadJsonFixture<TranscriptCoreReplayFixture>(
            'transcript-core',
            'transcript-core-replay.json',
        );
