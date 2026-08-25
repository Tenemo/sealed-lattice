import { readFile } from 'node:fs/promises';

import { describe, expect, it } from 'vitest';

import {
    configurableOptionCountRange,
    configurableParticipantCountRange,
    deriveFoundationRosterParameters,
    foundationProfile,
    isProtocolHash,
    refusalReasonCodes,
} from '@sealed-lattice/types';

describe('foundation contract', () => {
    it('pins the complete selected foundation profile', () => {
        expect(foundationProfile).toEqual({
            activeFaultBound: 3,
            candidateViewQuorum: 7,
            finalityQuorum: 7,
            maximumCanonicalStreamByteLength: 4_294_967_291,
            maximumCopiedBufferByteLength: 8_388_608,
            maximumIdentifierByteLength: 128,
            maximumScore: 10,
            maximumWasmMemoryByteLength: 671_088_640,
            minimumScore: 1,
            optionCount: 10,
            participantCount: 10,
            protocolName: 'sealed-lattice',
            protocolVersion: 1,
            reconstructionThreshold: 4,
            stateWitnessQuorum: 7,
            streamChunkByteLength: 1_048_576,
        });
    });

    it('publishes the bounded option-count family separately from the selected profile', () => {
        expect(configurableOptionCountRange).toEqual({
            maximum: 20,
            minimum: 2,
        });
        expect(foundationProfile.optionCount).toBe(10);
    });

    it('derives the configurable roster family without selecting it', () => {
        expect(configurableParticipantCountRange).toEqual({
            maximum: 20,
            minimum: 3,
        });
        expect(deriveFoundationRosterParameters(10)).toEqual({
            activeFaultBound: 3,
            candidateViewQuorum: 7,
            finalityQuorum: 7,
            participantCount: 10,
            reconstructionThreshold: 4,
            stateWitnessQuorum: 7,
        });

        for (
            let participantCount = configurableParticipantCountRange.minimum;
            participantCount <= configurableParticipantCountRange.maximum;
            participantCount += 1
        ) {
            const parameters =
                deriveFoundationRosterParameters(participantCount);
            expect(parameters.activeFaultBound).toBe(
                Math.floor((participantCount - 1) / 3),
            );
            expect(parameters.reconstructionThreshold).toBe(
                Math.floor(participantCount / 3) + 1,
            );
            const expectedQuorum =
                Math.floor(
                    (participantCount + parameters.activeFaultBound) / 2,
                ) + 1;
            expect(parameters.finalityQuorum).toBe(expectedQuorum);
            expect(parameters.candidateViewQuorum).toBe(expectedQuorum);
            expect(parameters.stateWitnessQuorum).toBe(expectedQuorum);
            expect(participantCount).toBeGreaterThan(
                3 * parameters.activeFaultBound,
            );
            expect(
                2 * parameters.candidateViewQuorum - participantCount,
            ).toBeGreaterThan(parameters.activeFaultBound);
            expect(
                2 * parameters.finalityQuorum - participantCount,
            ).toBeGreaterThan(parameters.activeFaultBound);
            expect(
                2 * parameters.stateWitnessQuorum - (participantCount - 1),
            ).toBeGreaterThan(parameters.activeFaultBound + 1);
            expect(parameters.stateWitnessQuorum).toBeLessThanOrEqual(
                participantCount - 1,
            );
        }

        for (const invalidParticipantCount of [
            2,
            21,
            3.5,
            Number.NaN,
            Number.POSITIVE_INFINITY,
        ]) {
            expect(() =>
                deriveFoundationRosterParameters(invalidParticipantCount),
            ).toThrow(/integer from 3 through 20/u);
        }
    });

    it('matches the shared refusal-reason registry', async () => {
        const vectorUrl = new URL(
            '../../../../test-vectors/foundation-refusal-reasons.json',
            import.meta.url,
        );
        const expected = JSON.parse(
            await readFile(vectorUrl, 'utf8'),
        ) as readonly Readonly<{ code: number; name: string }>[];

        expect(
            Object.entries(refusalReasonCodes).map(([name, code]) => ({
                code,
                name,
            })),
        ).toEqual(expected);
    });

    it('recognizes only canonical protocol hashes', () => {
        for (const canonicalHash of [
            '0'.repeat(128),
            'f'.repeat(128),
            '0123456789abcdef'.repeat(8),
        ]) {
            expect(isProtocolHash(canonicalHash)).toBe(true);
        }

        for (const invalidHash of [
            '',
            'a'.repeat(127),
            'a'.repeat(129),
            'A'.repeat(128),
            ` ${'a'.repeat(128)}`,
            `${'a'.repeat(128)}\n`,
            0,
            undefined,
            {},
        ]) {
            expect(isProtocolHash(invalidHash)).toBe(false);
        }
    });
});
