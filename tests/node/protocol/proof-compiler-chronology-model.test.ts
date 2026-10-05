import { describe, expect, it } from 'vitest';

import { compileComposedSecurityLedger } from '#tests/composed-security-ledger-model.js';
import {
    compileProofCompilerChronology,
    proofPurposes,
} from '#tests/proof-compiler-chronology-model.js';
import { framedProofHashBytes } from '#tests/proof-hash-work-model.js';
import { deriveSupportedProfile } from '#tests/supported-profile-model.js';
import { proofCompilerCaps } from '#tests/wide-challenge-compiler-model.js';

const population = compileComposedSecurityLedger().maximumCredentialPopulation;

// Every position in the first max(f + 1, 2)+f may prove an offer, with
// f = floor((n - 1) / 3); every position may prove its ballot and
// release.
const setupContributors = (participantCount: number) =>
    BigInt(
        Math.max(Math.floor((participantCount - 1) / 3) + 1, 2) +
            Math.floor((participantCount - 1) / 3),
    );
const rosterRoles = (participantCount: number) =>
    2n * BigInt(participantCount) + setupContributors(participantCount);

describe('proof compiler chronology', () => {
    it('emits one proof and one programmed message per proving position and purpose', () => {
        for (const [participantCount, optionCount] of [
            [3, 2],
            [10, 10],
            [20, 20],
        ]) {
            const chronology = compileProofCompilerChronology(
                deriveSupportedProfile(participantCount, optionCount),
            );
            expect(proofPurposes).toHaveLength(3);
            expect(chronology.honestRegistrations).toBe(
                BigInt(participantCount),
            );
            expect(chronology.honestProofs).toBe(rosterRoles(participantCount));
            expect(chronology.acceptedRoles).toBe(
                rosterRoles(participantCount),
            );
            expect(chronology.programmedMessages).toBe(chronology.honestProofs);
            expect(chronology.withinCaps).toBe(true);
        }
    });

    it('keeps unused registrations in the population without inventing proofs', () => {
        const profile = deriveSupportedProfile(20, 20);
        // Original registrations remain in the population even when this roster
        // uses none of their proof-producing slots.
        const chronology = compileProofCompilerChronology(profile, population);
        // Thirteen eligible setup, twenty ballot and twenty release proofs.
        const rosterProofs = 13n + 2n * 20n;
        expect(chronology.honestRegistrations).toBe(population);
        expect(chronology.rosters).toBe(1n);
        expect(chronology.honestProofs).toBe(rosterProofs);
        expect(chronology.acceptedRoles).toBe(rosterRoles(20));
        expect(chronology.programmedMessages).toBe(chronology.honestProofs);
        expect(chronology.withinCaps).toBe(true);
        expect(() => compileProofCompilerChronology(profile, 19n)).toThrow(
            'The registrations must cover the roster.',
        );
        expect(() =>
            compileProofCompilerChronology(profile, population, 0n),
        ).toThrow('A poll completes at least one roster.');
    });

    it('counts the rosters a corrupt organizer can complete from the population', () => {
        // Each honest registration confirms at most one roster, and a roster
        // with at most f corrupt members has n-f honest ones, so only as many
        // rosters of one size as the population fills can reach an opening.
        for (const [participantCount, corrupt] of [
            [3, 0],
            [4, 1],
            [19, 6],
            [20, 6],
        ] as const) {
            const profile = deriveSupportedProfile(participantCount, 10);
            const honestMembers = BigInt(participantCount - corrupt);
            const filled = population / honestMembers;
            const chronology = compileProofCompilerChronology(
                profile,
                population,
                population,
            );
            expect(chronology.rosters).toBe(filled);
            // Every honest member adds a ballot and release proof and every
            // honest setup contributor a setup proof, and every roster
            // accepts one role per purpose and proving position.
            const bounded = (count: bigint) =>
                count < population ? count : population;
            expect(chronology.honestProofs).toBe(
                2n * bounded(filled * BigInt(participantCount)) +
                    bounded(filled * setupContributors(participantCount)),
            );
            expect(chronology.acceptedRoles).toBe(
                rosterRoles(participantCount) * filled,
            );
            // A smaller roster count caps the rosters instead.
            expect(
                compileProofCompilerChronology(profile, population, 2n)
                    .acceptedRoles,
            ).toBe(2n * rosterRoles(participantCount));
        }
        // Roles beyond the compiler's role budget leave its caps.
        const profile = deriveSupportedProfile(3, 2);
        const registrations =
            3n * (proofCompilerCaps.roleBudget / rosterRoles(3) + 1n);
        const beyond = compileProofCompilerChronology(
            profile,
            registrations,
            registrations,
        );
        expect(beyond.acceptedRoles).toBeGreaterThan(
            proofCompilerCaps.roleBudget,
        );
        expect(beyond.withinCaps).toBe(false);
    });

    it('counts every tree node and message root of the emitted proof domain', () => {
        const chronology = compileProofCompilerChronology(
            deriveSupportedProfile(10, 10),
        );
        // Three trees over the 2^18 evaluation domain, one FRI tree per fold
        // down to four leaves, and one salted root per prover message.
        let nodes = 3n * ((1n << 19n) - 1n);
        for (let exponent = 17n; exponent >= 2n; exponent--)
            nodes += (1n << (exponent + 1n)) - 1n;
        const folds = 17n;
        expect(chronology.committedNodesPerProof).toBe(nodes + folds + 3n);
        expect(chronology.committedNodesPerProof).toBeLessThanOrEqual(
            proofCompilerCaps.committedNodeBudget,
        );
    });

    it('bounds the widest salted input of every role without its salt', () => {
        const profile = deriveSupportedProfile(20, 20);
        const chronology = compileProofCompilerChronology(profile);
        expect(chronology.roles.map((role) => role.role)).toEqual([
            'setup',
            'ballot',
            'release',
        ]);
        const saltBytes = proofCompilerCaps.saltBits / 8n;
        for (const role of chronology.roles) {
            // A leaf input has a four-byte length before each of its role,
            // position, index, salt and data parts, after its framed domain.
            const shortest =
                64n +
                framedProofHashBytes('bounded-proof/leaf', [
                    1n,
                    4n,
                    4n,
                    saltBytes,
                    1n,
                ]);
            expect(role.widestNonSaltInputBits).toBeGreaterThan(
                8n * (shortest - saltBytes),
            );
        }
        expect(chronology.widestNonSaltInputBits).toBe(
            chronology.roles.reduce(
                (maximum, role) =>
                    role.widestNonSaltInputBits > maximum
                        ? role.widestNonSaltInputBits
                        : maximum,
                0n,
            ),
        );
        expect(chronology.widestNonSaltInputBits).toBeLessThanOrEqual(
            proofCompilerCaps.maximumNonSaltInputBits,
        );
    });
});
