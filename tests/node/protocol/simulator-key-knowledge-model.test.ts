import { describe, expect, it } from 'vitest';

import {
    availableExtractionRecipients,
    compileSimulatorKeyKnowledgeCensus,
    inputRecoveryReductions,
    verifyInputRecoveryKnowledge,
} from '#tests/simulator-key-knowledge-model.js';

describe('simulator trapdoor availability', () => {
    it('uses the other good decryption key in each complete reduction game', () => {
        for (const reduction of inputRecoveryReductions) {
            expect(verifyInputRecoveryKnowledge(reduction)).toBe(true);
            expect(
                verifyInputRecoveryKnowledge({
                    ...reduction,
                    releaseSimulationAlreadyInstalled: false,
                }),
            ).toBe(false);
        }
        for (const reduction of inputRecoveryReductions.filter(
            (value) =>
                value.unknownKey === 'fhe' || value.unknownKey === 'auxiliary',
        )) {
            const challengedKey = reduction.unknownKey;
            if (challengedKey !== 'fhe' && challengedKey !== 'auxiliary')
                throw new Error('Expected an encryption-key challenge.');
            expect(
                verifyInputRecoveryKnowledge({
                    ...reduction,
                    recovery: challengedKey,
                }),
            ).toBe(false);
        }
    });

    it('retains enough known honest recipients for every single-key embedding', () => {
        for (const profile of compileSimulatorKeyKnowledgeCensus()) {
            expect(profile.knownHonestWithOneChallenge).toBeGreaterThanOrEqual(
                profile.threshold,
            );
            const corrupted = new Set(
                Array.from({ length: profile.faults }, (_, index) => index),
            );
            for (
                let challenge = profile.faults;
                challenge < profile.participants;
                challenge++
            ) {
                const selected = availableExtractionRecipients(
                    profile.participants,
                    corrupted,
                    new Set([challenge]),
                );
                expect(selected).toHaveLength(profile.threshold);
                expect(
                    selected?.every(
                        (index) => !corrupted.has(index) && index !== challenge,
                    ),
                ).toBe(true);
            }
        }
    });

    it('brute-forces every allowed corruption set and honest challenge through ten participants', () => {
        for (let count = 3; count <= 10; count++)
            for (let mask = 0; mask < 2 ** count; mask++) {
                const corrupted = new Set(
                    Array.from({ length: count }, (_, index) => index).filter(
                        (index) => mask & (1 << index),
                    ),
                );
                if (corrupted.size > Math.floor((count - 1) / 3)) continue;
                for (let challenge = 0; challenge < count; challenge++) {
                    if (corrupted.has(challenge)) continue;
                    const selected = availableExtractionRecipients(
                        count,
                        corrupted,
                        new Set([challenge]),
                    );
                    expect(selected).toHaveLength(
                        Math.floor((count - 1) / 3) + 1,
                    );
                    expect(selected).not.toContain(challenge);
                    expect(
                        selected?.some((index) => corrupted.has(index)),
                    ).toBe(false);
                }
            }
    });

    it('does not silently use a challenge secret when too many keys are unknown', () => {
        expect(
            availableExtractionRecipients(4, new Set([0]), new Set([1, 2])),
        ).toBeUndefined();
        expect(
            availableExtractionRecipients(
                10,
                new Set([0, 1, 2]),
                new Set([3, 4, 5, 6]),
            ),
        ).toBeUndefined();
        expect(() =>
            availableExtractionRecipients(10, new Set([0]), new Set([0])),
        ).toThrow('Invalid');
    });
});
