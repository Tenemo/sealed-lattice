import { readFile } from 'node:fs/promises';

import { describe, expect, expectTypeOf, it } from 'vitest';

import {
    foundationProfile,
    isParticipantIdentity,
    isProtocolHash,
    parseParticipantIdentity,
    refusalReasonCodes,
    type ParticipantIdentity,
    type ProtocolHash,
} from '@sealed-lattice/types';

describe('foundation contract', () => {
    it('pins the complete supported foundation profile', () => {
        expect(foundationProfile).toEqual({
            activeFaultBound: 3,
            finalityQuorum: 7,
            maximumCanonicalStreamByteLength: 2_147_483_648,
            maximumCopiedBufferByteLength: 1_572_864,
            maximumIdentifierByteLength: 128,
            maximumScore: 10,
            maximumWasmMemoryByteLength: 402_653_184,
            minimumScore: 1,
            optionCount: 20,
            participantCount: 10,
            protocolName: 'sealed-lattice',
            protocolVersion: 1,
            reconstructionThreshold: 4,
            stateWitnessQuorum: 7,
            streamChunkByteLength: 1_048_576,
        });
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

    it('parses only the canonical participant identity string form', () => {
        const canonicalIdentities = [
            '0'.repeat(128),
            'f'.repeat(128),
            '0123456789abcdef'.repeat(8),
        ];
        for (const canonicalIdentity of canonicalIdentities) {
            const identity = parseParticipantIdentity(canonicalIdentity);
            const compatibleProtocolHash: ProtocolHash = identity;

            expect(identity).toBe(canonicalIdentity);
            expect(compatibleProtocolHash).toBe(canonicalIdentity);
            expect(isParticipantIdentity(identity)).toBe(true);
            expectTypeOf(identity).toEqualTypeOf<ParticipantIdentity>();
        }
        expectTypeOf<ProtocolHash>().not.toMatchTypeOf<ParticipantIdentity>();
    });

    it('refuses malformed and noncanonical participant identities', () => {
        const canonicalIdentity = 'a'.repeat(128);
        const invalidIdentities: readonly unknown[] = [
            '',
            canonicalIdentity.slice(1),
            `${canonicalIdentity}0`,
            `A${canonicalIdentity.slice(1)}`,
            `g${canonicalIdentity.slice(1)}`,
            ` ${canonicalIdentity.slice(1)}`,
            `${canonicalIdentity.slice(0, -1)}\n`,
            ` ${canonicalIdentity}`,
            `${canonicalIdentity}\n`,
            `ａ${canonicalIdentity.slice(1)}`,
            0,
            undefined,
            {},
        ];

        for (const invalidIdentity of invalidIdentities) {
            expect(isParticipantIdentity(invalidIdentity)).toBe(false);
            expect(() => parseParticipantIdentity(invalidIdentity)).toThrow(
                /128 lowercase hexadecimal/u,
            );
        }
    });
});
