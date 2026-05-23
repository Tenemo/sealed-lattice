import type {
    GoldenTranscriptCoreFixture,
    MalformedObjectFixture,
} from '@sealed-lattice/types';
import { describe, expect, it } from 'vitest';

import {
    loadTranscriptCoreKernel,
    TranscriptCoreKernelCommandError,
} from '../../src/index';

import goldenTranscriptCoreFixturesJson from '#test-vectors/transcript-core/golden-transcript-core.json';
import malformedObjectFixturesJson from '#test-vectors/transcript-core/malformed-objects.json';

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

const fullyVerifiedDevelopmentIntegrationFixture = findFixture(
    goldenTranscriptCoreFixtures,
    'fully-verified-development-integration-transcript-core',
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
                'sealed_lattice_transcript_core_command_with_length',
            ]),
        );
    });

    it('verifies the golden transcript-core fixture', async () => {
        const kernel = await loadTranscriptCoreKernel();

        expect(
            kernel.verifyFixture(fullyVerifiedDevelopmentIntegrationFixture),
        ).toEqual({
            verified: true,
            caseName: 'fully-verified-development-integration-transcript-core',
            objectHash512:
                fullyVerifiedDevelopmentIntegrationFixture.expectedObjectHash512,
            chunkRoot:
                fullyVerifiedDevelopmentIntegrationFixture.expectedChunkRoot,
            statusLabels:
                fullyVerifiedDevelopmentIntegrationFixture.expectedStatusLabels,
        });
    });

    it('derives protocol digest and field checks through WASM', async () => {
        const kernel = await loadTranscriptCoreKernel();

        expect(
            kernel.deriveProtocolDigest({
                namespace: 'PollSpecDigest',
                value: { poll: 'main' },
            }),
        ).toBe(
            '423c71de65abadb5adc05d9b6b704252420bb738af888c62614c8afc53a2be808662585305e76738b23e4f20154f8779e3827c0c8f313455d84675924f4a2c83',
        );
        expect(
            kernel.interpolateShamirConstantTerm({
                sharePoints: [
                    { rosterPosition: 1, value: 15 },
                    { rosterPosition: 2, value: 25 },
                ],
            }),
        ).toBe(5);
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
