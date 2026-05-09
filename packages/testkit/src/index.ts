import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import type {
    GoldenTranscriptCoreFixture,
    MalformedObjectFixture,
    TranscriptCoreReplayFixture,
} from '@sealed-lattice/protocol';

const testVectorsRootDirectoryPath = fileURLToPath(
    new URL('../../../test-vectors/', import.meta.url),
);

const loadJsonFixture = async <Fixture>(
    ...pathSegments: readonly string[]
): Promise<Fixture> => {
    const fixturePath = path.resolve(
        testVectorsRootDirectoryPath,
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
