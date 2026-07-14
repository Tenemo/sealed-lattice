import { describe, expect, it } from 'vitest';

import { deriveCanonicalObjectHash } from '#packages/crypto/src/index';
import { deriveCollectiveBgvSetupRosterHash } from '#packages/protocol/src/roster/hashes';

describe('collective setup roster hash', () => {
    it('is independent of supplied entry order', () => {
        const entries = [
            {
                rosterPosition: 2,
                trusteeIdentity: 'trustee-2',
                signingPublicKeyHash: 'c'.repeat(128),
            },
            {
                rosterPosition: 0,
                trusteeIdentity: 'trustee-0',
                signingPublicKeyHash: 'a'.repeat(128),
            },
            {
                rosterPosition: 1,
                trusteeIdentity: 'trustee-1',
                signingPublicKeyHash: 'b'.repeat(128),
            },
        ] as const;
        const expectedHash = deriveCanonicalObjectHash({
            objectType: 'CollectiveBgvSetupRoster',
            rosterEntries: [
                {
                    objectType: 'CollectiveBgvSetupRosterEntry',
                    rosterPosition: 0,
                    trusteeIdentity: 'trustee-0',
                    signingPublicKeyHash: 'a'.repeat(128),
                },
                {
                    objectType: 'CollectiveBgvSetupRosterEntry',
                    rosterPosition: 1,
                    trusteeIdentity: 'trustee-1',
                    signingPublicKeyHash: 'b'.repeat(128),
                },
                {
                    objectType: 'CollectiveBgvSetupRosterEntry',
                    rosterPosition: 2,
                    trusteeIdentity: 'trustee-2',
                    signingPublicKeyHash: 'c'.repeat(128),
                },
            ],
        });

        expect(deriveCollectiveBgvSetupRosterHash(entries)).toBe(expectedHash);
        expect(deriveCollectiveBgvSetupRosterHash([...entries].reverse())).toBe(
            expectedHash,
        );
    });

    it('rejects malformed entries and duplicate roster positions', () => {
        expect(() => deriveCollectiveBgvSetupRosterHash(null as never)).toThrow(
            /must be an array/u,
        );
        expect(() =>
            deriveCollectiveBgvSetupRosterHash([null as never]),
        ).toThrow(/must be an object/u);
        expect(() =>
            deriveCollectiveBgvSetupRosterHash([
                {
                    rosterPosition: -1,
                    trusteeIdentity: 'trustee-0',
                    signingPublicKeyHash: 'a'.repeat(128),
                },
            ]),
        ).toThrow(/rosterPosition/u);
        expect(() =>
            deriveCollectiveBgvSetupRosterHash([
                {
                    rosterPosition: 0,
                    trusteeIdentity: '',
                    signingPublicKeyHash: 'a'.repeat(128),
                },
            ]),
        ).toThrow(/trusteeIdentity/u);
        expect(() =>
            deriveCollectiveBgvSetupRosterHash([
                {
                    rosterPosition: 0,
                    trusteeIdentity: 'trustee-0',
                    signingPublicKeyHash: 'a'.repeat(128),
                },
                {
                    rosterPosition: 0,
                    trusteeIdentity: 'trustee-1',
                    signingPublicKeyHash: 'b'.repeat(128),
                },
            ]),
        ).toThrow(/distinct roster positions/u);
        expect(() =>
            deriveCollectiveBgvSetupRosterHash([
                {
                    rosterPosition: 0,
                    trusteeIdentity: 'trustee-0',
                    signingPublicKeyHash: 'not-a-protocol-hash',
                },
            ]),
        ).toThrow(/signingPublicKeyHash/u);
    });
});
