import { describe, expect, it } from 'vitest';

import {
    compileProofCompilerChronology,
    proofPurposes,
} from '#tests/proof-compiler-chronology-model.js';
import { framedProofHashBytes } from '#tests/proof-hash-work-model.js';
import { deriveSupportedProfile } from '#tests/supported-profile-model.js';
import { proofCompilerCaps } from '#tests/wide-challenge-compiler-model.js';

describe('proof compiler chronology', () => {
    it('emits one proof and one programmed message per participant and purpose', () => {
        for (const [participantCount, optionCount] of [
            [3, 2],
            [10, 10],
            [20, 20],
        ]) {
            const chronology = compileProofCompilerChronology(
                deriveSupportedProfile(participantCount, optionCount),
            );
            expect(proofPurposes).toHaveLength(4);
            expect(chronology.honestProofsPerPurpose).toBe(
                BigInt(participantCount),
            );
            expect(chronology.honestProofs).toBe(4n * BigInt(participantCount));
            expect(chronology.acceptedRoles).toBe(
                4n * BigInt(participantCount),
            );
            expect(chronology.programmedMessages).toBe(chronology.honestProofs);
            expect(chronology.withinCaps).toBe(true);
        }
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
            'registration',
            'setup',
            'ballot',
            'release',
        ]);
        const saltBytes = proofCompilerCaps.saltBits / 8n;
        for (const role of chronology.roles) {
            // A leaf input has a four-byte length before each of its role,
            // position, index, salt and data parts, after its framed domain.
            const shortest = framedProofHashBytes('bounded-proof/leaf', [
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

    it('depends on replaying rather than regenerating proofs after a restart', () => {
        const chronology = compileProofCompilerChronology(
            deriveSupportedProfile(20, 20),
        );
        // Eighty slots within 65,536 proofs allow 819 generations per slot;
        // regenerating each proof at every restart would exceed the role
        // union at the 820th.
        const failingGenerations = 820n;
        expect(chronology.honestProofs * failingGenerations).toBeGreaterThan(
            proofCompilerCaps.roleBudget,
        );
        expect(
            chronology.honestProofs * (failingGenerations - 1n),
        ).toBeLessThanOrEqual(proofCompilerCaps.roleBudget);
        expect(chronology.programmedMessages).toBeLessThanOrEqual(
            proofCompilerCaps.programmedMessageBudget,
        );
    });
});
