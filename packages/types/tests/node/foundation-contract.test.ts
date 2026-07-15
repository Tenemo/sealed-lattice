import { describe, expect, expectTypeOf, it } from 'vitest';

import {
    isParticipantIdentity,
    isProtocolHash,
    parseParticipantIdentity,
    type ParticipantIdentity,
    type ProtocolHash,
} from '@sealed-lattice/types';

describe('foundation contract', () => {
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
