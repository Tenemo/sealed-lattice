import { describe, expect, it } from 'vitest';

import { contributionBodyHeaderBytes } from '#tests/contribution-body-model.js';
import { fixedModulusBfvInputs } from '#tests/fixed-modulus-bfv-model.js';
import {
    compileFullWordProofLayout,
    compileWordProofLayout,
} from '#tests/full-word-proof-layout-model.js';
import { compilePublicPolynomialOperatorBuffers } from '#tests/public-polynomial-operator-resource-model.js';
import {
    compileBoundedOpeningShareProofResources,
    compilePublicOperatorScreenResources,
    compileRecoverableSetupResourceScreen,
    compileRecoverableSeedSharingProofResources,
} from '#tests/recoverable-setup-resource-model.js';
import { compileRegistrationKeyRelationCensus } from '#tests/registration-key-relation-model.js';
import { deriveSupportedProfile } from '#tests/supported-profile-model.js';

describe('recoverable setup resource screen', () => {
    it.each([
        ['seed', 44, 18, 13],
        ['opening', 13, 11, 6],
    ] as const)(
        'bounds the streamed %s operator screen and exact report schema',
        (kind, columns, physicalCount, polynomials) => {
            const screen = compilePublicOperatorScreenResources(kind);
            expect(screen.degree).toBe(65536n);
            expect(screen.seedBits).toBe(512n);
            expect(screen.columns).toBe(columns);
            expect(screen.polynomialCount).toBe(polynomials);
            expect(screen.queryCount).toBe(2 * 704);
            expect(screen.queries).toHaveLength(2 * 704);
            expect(new Set(screen.queries).size).toBe(2 * 704);
            expect(
                screen.queries.every(
                    (value, index) =>
                        index === 0 || value > screen.queries[index - 1],
                ),
            ).toBe(true);
            for (let index = 0; index < 704; index++)
                expect(
                    screen.queries[index + 704] - screen.queries[index],
                ).toBe(131072);
            for (const boundary of [
                0, 1, 65535, 65536, 65537, 131070, 131071, 262143,
            ])
                expect(screen.queries).toContain(boundary);
            expect(screen.physicalSamples).toHaveLength(physicalCount);
            expect(screen.querySamples).toHaveLength(8);
            expect(
                screen.physicalSamples.every(
                    ({ column, index }) => column < columns && index < 65536,
                ),
            ).toBe(true);
            expect(
                screen.querySamples.every(
                    ({ column, index }) =>
                        column < columns && screen.queries.includes(index),
                ),
            ).toBe(true);
            // OPR1, eight u32 operands, three extension values, two hashes,
            // two u32 sample counts, then (column,index,extension) records.
            const header = 4n + 8n * 4n + 3n * (3n * 16n) + 2n * 64n + 2n * 4n;
            expect(screen.reportHeaderBytes).toBe(header);
            expect(screen.sampleBytes).toBe(2n * 4n + 3n * 16n);
            expect(screen.reportBytes).toBe(
                header + BigInt(physicalCount + 8) * 56n,
            );
            expect(screen.outputCapacity).toBe(
                header + BigInt(3 + 8 + 3 + 4 + 8) * 56n,
            );
            expect(screen.planningBytes).toBe(
                screen.stages.reduce(
                    (maximum, { bytes }) => (bytes > maximum ? bytes : maximum),
                    0n,
                ) +
                    64n * 1024n * 1024n,
            );
            expect(screen.maximumInputChunkBytes).toBe((1048576n / 21n) * 21n);
            expect(screen.residentOperatorBytes).toBe(
                BigInt(kind === 'seed' ? 7 : 1) * 65536n * 48n,
            );
            expect(screen.planningBytes).toBeLessThan(1n << 30n);
        },
    );
    it('counts the exact bounded opening fixture framing and sequential proving stages', () => {
        const fixture = compileBoundedOpeningShareProofResources();
        // Independent schema inventory: magic, seven u32 parameters, 20-byte
        // modulus; source poll/roster/body hashes + author, or opening
        // descriptor digest + recipient. Source operands are not uploaded anew.
        const shape = 4n + 7n * 4n + 20n;
        const source = shape + 3n * 64n + 2n + 13n * 256n * 21n;
        const opening = shape + 64n + 2n + 6n * 256n * 21n + 2n * 256n * 15n;
        expect(fixture.seedStatementBytes).toBe(source);
        expect(fixture.openingStatementBytes).toBe(opening);
        expect(fixture.residentOperatorBytes).toBe(256n * 48n);
        expect(fixture.opening.operatorBuildBufferBytes).toBe(
            2n * 256n * 48n + 256n * 21n,
        );
        expect(fixture.derivedEquationCoefficientAllowanceBytes).toBe(
            256n * 1024n,
        );
        expect(fixture.retainedSourceCoefficientAllowanceBytes).toBe(
            2n * 13n * 256n * 1024n,
        );
        expect(fixture.nativeProofPlanningBytes).toBe(
            fixture.secondSourceStageBytes > fixture.openingStageBytes
                ? fixture.secondSourceStageBytes
                : fixture.openingStageBytes,
        );
        expect(fixture.nativeProofPlanningBytes).toBeLessThan(
            fixture.secondSourceStageBytes + fixture.openingStageBytes,
        );
        // One new outer proof and two opening proofs, with their statements;
        // three copied source proofs belong to the separate input inventory.
        expect(fixture.maximumNewArtifactBytes).toBe(
            compileWordProofLayout(44, 44).maximumMultiproofBytes +
                2n * compileWordProofLayout(13, 10).maximumMultiproofBytes +
                source +
                2n * opening,
        );
    });
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
            // polynomials per recipient; the fixed auxiliary pair is absent.
            const polynomialBytes =
                4n *
                    profile.gadgetLength *
                    fixedModulusBfvInputs.polynomialDegree *
                    coefficientBytes(profile.ciphertext.modulus) +
                2n * BigInt(participants) * recipient.publicKeyBytes;
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

    it('counts each recipient opening batch once and does not upload predecessor polynomials again', () => {
        for (const [participants, options, selected] of [
            [4, 2, 2],
            [10, 10, 4],
            [20, 20, 7],
        ]) {
            const screen = compileRecoverableSetupResourceScreen(
                participants,
                options,
            );
            const profile = deriveSupportedProfile(participants, options);
            const maximumShare =
                1n + BigInt(selected - 1) * profile.shareLifting.sharingRadius;
            const coefficientBytes =
                1n + BigInt(Math.ceil(maximumShare.toString(2).length / 8));
            // Registration (16,16,7), then one (16,16,17) triple per
            // selected package: each final bit is Boolean, not a new word.
            const columns = 5 + 4 * selected;
            const lookups = 4 + 3 * selected;
            const proof = compileWordProofLayout(columns, lookups);
            const shares =
                BigInt(selected) *
                fixedModulusBfvInputs.polynomialDegree *
                coefficientBytes;
            const batch = shares + proof.maximumMultiproofBytes;
            expect(screen.maximumOpeningBatchPayloadBytes).toBe(batch);
            expect(screen.maximumAllOpeningBatchPayloadBytes).toBe(
                BigInt(participants) * batch,
            );
            expect(screen.maximumThresholdOpeningBatchPayloadBytes).toBe(
                BigInt(selected) * batch,
            );
            expect(
                screen.openingProof.expandedStatementPolynomialBytes,
            ).toBeGreaterThan(shares);
            expect(screen.maximumPreparationPayloadSubtotalBytes).toBe(
                screen.maximumEligibleBodyCiphertextAndOuterProofBytes +
                    BigInt(participants) * batch,
            );
        }
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
        // Four public keys, one common adjoint, one sharing basis and seed
        // prefix remain; geometric word columns share descriptor terms.
        expect(reduced.residentValueColumns).toBe(7);
        expect(reduced.residentOperatorBytes).toBe(7n * 256n * 48n);
        expect(full.residentOperatorBytes).toBe(7n * 65536n * 48n);
        expect(
            compileRecoverableSeedSharingProofResources(10, 10)
                .residentValueColumns,
        ).toBe(10 + 1 + 3 + 1);
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

    it('retains parser, encoding, geometric-query and transform buffers after factorization', () => {
        const reduced = compilePublicPolynomialOperatorBuffers(
            256n,
            21n,
            44,
            7,
            7,
        );
        const full = compilePublicPolynomialOperatorBuffers(
            65536n,
            21n,
            44,
            7,
            7,
        );
        expect(reduced.operatorBuildBufferBytes).toBe(
            7n * 256n * 48n + 256n * 21n,
        );
        expect(reduced.serializedOperatorColumnBytes).toBe(256n * 48n);
        // Reduced Powers and Ones are both transformed. Full-degree Ones
        // are evaluated directly, leaving only the Powers vector to expand.
        expect(reduced.queryValueColumns).toBe(9);
        expect(full.queryValueColumns).toBe(8);
        expect(reduced.queryValuesBytes).toBe(9n * 256n * 48n);
        expect(full.queryValuesBytes).toBe(8n * 65536n * 48n);
        expect(full.operatorEncodingChunkBytes).toBe((1048576n / 21n) * 21n);
        expect(reduced.queryOutputBytes).toBe((44n + 9n) * 1408n * 48n);
        expect(reduced.queryTemporaryBytes).toBe(
            256n * 48n + 255n * 16n + 1408n * (24n + 48n),
        );
        expect(reduced.operatorQueryBufferBytes).toBe(
            9n * 256n * 48n +
                53n * 1408n * 48n +
                256n * 48n +
                255n * 16n +
                1408n * (24n + 48n + 4n),
        );
        for (const [degree, width, columns, retained, building] of [
            [0n, 21n, 44, 7, 7],
            [255n, 21n, 44, 7, 7],
            [131072n, 21n, 44, 7, 7],
            [256n, 0n, 44, 7, 7],
            [256n, 1048577n, 44, 7, 7],
            [256n, 21n, 0, 7, 7],
            [256n, 21n, 44, 0, 7],
            [256n, 21n, 44, 7, 6],
            [256n, 21n, 44, 7, 7.5],
        ] as const)
            expect(() =>
                compilePublicPolynomialOperatorBuffers(
                    degree,
                    width,
                    columns,
                    retained,
                    building,
                ),
            ).toThrow('shape');
    });
});
