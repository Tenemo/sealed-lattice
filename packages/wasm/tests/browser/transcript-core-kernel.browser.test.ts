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
const browserM7BgvVectors = {
    profileDigest:
        'd875931773a704df5f3b5d3dad4ef526bbe671a66465b75c19b2c1190929f86326822cd3ede1233eba2905a4b3c086e0426af5a3f7150f537d76b8349f73b3c2',
    batchLayoutBindingDigest:
        '14e66d0972e0a8afc5799add5cea3d09c3ae1f08c6850558d988e47b8f953dc847922c1fba7b372051a565e6b7e1ea5a2f6a864f31dc3b26607c933d9b462e8f',
    encodedPlaintextRoot:
        '59a29e210357f4e860c4c7b44b541956fc2d2ca425eefcb344dbd303420ffa44419674197bf746a0ca4dee937832b925a34ac008194c411c96ad9c6f94285c75',
    encodedPlaintextHash:
        '73a193fc97dad594fe063c04e1b0184d57901441ac520e8355f0e176378c1e1877bc86be1ebf9d873c7007551024cdb08b4af32935e7b56993e233c5a1771b70',
} as const;

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

    it('produces byte-identical BGV canonical roots through browser WASM', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const profile = kernel.describeBgvRnsProfile();
        const encodedResult = kernel.encodeBgvBatchPlaintext({
            slots: [0, 1, 65_536, 17, 99],
            level: 0,
            layoutBinding: profile.batchLayoutBinding,
            includeCanonicalBytesHex: true,
        });

        expect(profile.profileDigest).toBe(browserM7BgvVectors.profileDigest);
        expect(profile.batchLayoutBindingDigest).toBe(
            browserM7BgvVectors.batchLayoutBindingDigest,
        );
        expect(encodedResult).not.toMatchObject({ ok: false });
        const encoded = encodedResult as {
            readonly canonicalBytesHex: string;
            readonly canonicalBytesHash512: string;
            readonly canonicalByteLength: number;
            readonly plaintextRoot: string;
        };

        expect(encoded.plaintextRoot).toBe(
            browserM7BgvVectors.encodedPlaintextRoot,
        );
        expect(encoded.canonicalBytesHash512).toBe(
            browserM7BgvVectors.encodedPlaintextHash,
        );
        expect(encoded.canonicalByteLength).toBe(90_441);
        expect(
            kernel.validateBgvPlaintextObject({
                canonicalBytesHex: encoded.canonicalBytesHex,
                expectedPlaintextRoot: encoded.plaintextRoot,
            }),
        ).toMatchObject({
            ok: true,
            objectKind: 'plaintext',
            plaintextRoot: browserM7BgvVectors.encodedPlaintextRoot,
        });
    });
});
