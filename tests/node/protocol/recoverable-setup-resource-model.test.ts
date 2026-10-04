import { describe, expect, it } from 'vitest';

import { auxiliaryInputEncryptionParameters } from '#tests/auxiliary-input-encryption-parameters.js';
import { contributionBodyHeaderBytes } from '#tests/contribution-body-model.js';
import { fixedModulusBfvInputs } from '#tests/fixed-modulus-bfv-model.js';
import { compileFullWordProofLayout } from '#tests/full-word-proof-layout-model.js';
import {
    compileRecoverableSetupResourceScreen,
    compileRecoverableSeedSharingProofResources,
} from '#tests/recoverable-setup-resource-model.js';
import { compileRegistrationKeyRelationCensus } from '#tests/registration-key-relation-model.js';
import { deriveSupportedProfile } from '#tests/supported-profile-model.js';

describe('recoverable setup resource screen', () => {
    it('distinguishes every eligible upload from the fixed selected subset', () => {
        // Independently enumerated candidate sizes and ECHO/READY thresholds
        // from the frozen fault rule and candidate's fixed-pool definition.
        for (const [
            participants,
            faults,
            selected,
            eligible,
            echo,
            relay,
            delivery,
        ] of [
            [3, 0, 2, 2, 3, 1, 1],
            [4, 1, 2, 3, 3, 2, 3],
            [6, 1, 2, 3, 5, 2, 3],
            [7, 2, 3, 5, 5, 3, 5],
            [10, 3, 4, 7, 7, 4, 7],
            [20, 6, 7, 13, 14, 7, 13],
        ]) {
            const screen = compileRecoverableSetupResourceScreen(
                participants,
                2,
            );
            expect(screen).toMatchObject({
                maximumFaultCount: faults,
                selectedContributorCount: selected,
                eligibleContributorCount: eligible,
                echoThreshold: echo,
                readyRelayThreshold: relay,
                readyDeliveryThreshold: delivery,
                eligibleSeedShareCiphertextCount: BigInt(
                    eligible * participants,
                ),
                selectedSeedShareCiphertextCount: BigInt(
                    selected * participants,
                ),
            });
        }
    });

    it('counts unchanged inner encodings and both recipient ciphertext polynomials from independent operands', () => {
        const recipient = compileRegistrationKeyRelationCensus();
        const coefficientBytes = (modulus: bigint) =>
            1n + BigInt(Math.ceil(modulus.toString(2).length / 8));
        // The original recipient-key encoder separately fixes its full
        // polynomial width; do not derive the expected value from the screen.
        expect(recipient.degree * coefficientBytes(recipient.modulus)).toBe(
            recipient.publicKeyBytes,
        );
        for (const [participants, options, selected, eligible] of [
            [3, 2, 2, 2],
            [4, 20, 2, 3],
            [10, 10, 4, 7],
            [20, 20, 7, 13],
        ]) {
            const profile = deriveSupportedProfile(participants, options);
            const proof = compileFullWordProofLayout(profile);
            // Four emitted FHE polynomials per gadget, two encrypted-share
            // polynomials per recipient, and one auxiliary polynomial.
            const polynomialBytes =
                4n *
                    profile.gadgetLength *
                    fixedModulusBfvInputs.polynomialDegree *
                    coefficientBytes(profile.ciphertext.modulus) +
                2n * BigInt(participants) * recipient.publicKeyBytes +
                auxiliaryInputEncryptionParameters.degree *
                    coefficientBytes(
                        auxiliaryInputEncryptionParameters.modulus,
                    );
            const bodyBytes =
                contributionBodyHeaderBytes +
                polynomialBytes +
                proof.maximumMultiproofBytes;
            const ciphertextBytesPerOffer =
                2n * BigInt(participants) * recipient.publicKeyBytes;
            const screen = compileRecoverableSetupResourceScreen(
                participants,
                options,
            );
            expect(screen.maximumInnerBodyBytes).toBe(bodyBytes);
            expect(screen.maximumSelectedInnerBodyCorpusBytes).toBe(
                BigInt(selected) * bodyBytes,
            );
            expect(screen.maximumEligibleInnerBodyCorpusBytes).toBe(
                BigInt(eligible) * bodyBytes,
            );
            expect(screen.selectedSeedShareCiphertextBytes).toBe(
                BigInt(selected) * ciphertextBytesPerOffer,
            );
            expect(screen.eligibleSeedShareCiphertextBytes).toBe(
                BigInt(eligible) * ciphertextBytesPerOffer,
            );
            expect(screen.maximumSelectedBodyAndSeedCiphertextBytes).toBe(
                BigInt(selected) * (bodyBytes + ciphertextBytesPerOffer),
            );
            expect(screen.maximumEligibleBodyAndSeedCiphertextBytes).toBe(
                BigInt(eligible) * (bodyBytes + ciphertextBytesPerOffer),
            );
        }
    });

    it('rejects unsupported, fractional and unsafe profile inputs', () => {
        for (const participants of [-1, 0, 2, 3.5, 21, NaN, Infinity, 2 ** 53])
            expect(() =>
                compileRecoverableSetupResourceScreen(participants, 2),
            ).toThrow();
        for (const options of [-1, 0, 1, 2.5, 21, NaN, Infinity, 2 ** 53])
            expect(() =>
                compileRecoverableSetupResourceScreen(3, options),
            ).toThrow();
    });

    it('counts the actual seed, sharing limbs and both encryption-equation witness families', () => {
        const reduced = compileRecoverableSeedSharingProofResources(
            4,
            2,
            256n,
            4n,
        );
        const full = compileRecoverableSeedSharingProofResources(4, 2);
        // One (96,12)-bit sharing coefficient has seven word columns and
        // one narrow lookup. Each recipient adds seven words, two narrow
        // error lookups and two sparse indicators. The seed adds one Boolean.
        expect(reduced.relation).toEqual({
            wordColumns: 35,
            booleanColumns: 9,
            narrowWordColumns: 9,
            lookupEntries: 44,
            disjointPairs: 4,
            supportRows: 8,
            errorColumns: 8,
            affineRows: 4104n,
        });
        expect(reduced.signedVariableWidths).toEqual([
            96,
            12,
            ...Array.from({ length: 4 }, () => [16, 32, 7, 16, 16, 7]).flat(),
        ]);
        // These fixed engine dimensions come from its independently
        // maintained common-agreement parameters, not the physical fixture.
        expect(reduced.systematicSize).toBe(65536n);
        expect(reduced.verificationDomainSize).toBe(262144n);
        expect(reduced.maskDimension).toBe(1409n);
        expect(reduced.queryCount).toBe(704);
        expect(reduced.layout.maximumMultiproofBytes).toBe(12_186_464n);
        expect(full.layout).toEqual(reduced.layout);
        expect(full.relation.affineRows).toBe(1_048_584n);
        expect(full.seedBits).toBe(512n);
        expect(reduced.residentOperatorBytes).toBe(44n * 256n * 48n);
        expect(full.residentOperatorBytes).toBe(44n * 65536n * 48n);
        // At ten participants, three (96,16)-bit sharing coefficients add
        // 21 words; ten recipients add 70 words and 20 narrow error lookups.
        expect(
            compileRecoverableSeedSharingProofResources(10, 10).relation,
        ).toEqual({
            wordColumns: 91,
            booleanColumns: 21,
            narrowWordColumns: 20,
            lookupEntries: 111,
            disjointPairs: 10,
            supportRows: 20,
            errorColumns: 20,
            affineRows: 2_621_460n,
        });
        // The largest roster's (95,21)-bit pairs add 20 Boolean remainder
        // columns each; each 33-bit constant-equation carry adds one more.
        expect(
            compileRecoverableSeedSharingProofResources(20, 20).relation,
        ).toEqual({
            wordColumns: 176,
            booleanColumns: 181,
            narrowWordColumns: 40,
            lookupEntries: 216,
            disjointPairs: 20,
            supportRows: 40,
            errorColumns: 40,
            affineRows: 5_242_920n,
        });
    });

    it('refuses a physical ring or seed that cannot use the common strided relation', () => {
        for (const degree of [0n, 128n, 255n, 257n, 131072n])
            expect(() =>
                compileRecoverableSeedSharingProofResources(4, 2, degree, 4n),
            ).toThrow();
        for (const seedBits of [0n, -1n, 257n])
            expect(() =>
                compileRecoverableSeedSharingProofResources(
                    4,
                    2,
                    256n,
                    seedBits,
                ),
            ).toThrow();
    });
});
