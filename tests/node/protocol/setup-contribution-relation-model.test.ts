import { describe, expect, it } from 'vitest';

import { fixedModulusBfvInputs } from '#tests/fixed-modulus-bfv-model.js';
import { createSetupContributionRelationModel } from '#tests/setup-contribution-relation-model.js';
import {
    compileSetupContributionRelationCensus,
    compileSetupContributionColumnLayout,
    deriveSetupContributionShape,
} from '#tests/setup-relation/shape.js';
import { compileSmallLimbProofFieldCensus } from '#tests/small-limb-proof-field-model.js';
import {
    completionProfile,
    deriveSupportedProfile,
} from '#tests/supported-profile-model.js';

describe('complete setup contribution relation in a reduced ring', () => {
    it('refuses public limbs outside the canonical modulus even when the lifted equations are unchanged', () => {
        const model = createSetupContributionRelationModel(completionProfile());
        for (const equation of model.equations) {
            for (const coefficients of [
                equation.publicValue,
                ...equation.convolution.map(
                    (term) => term.publicCoefficients as bigint[],
                ),
            ]) {
                const original = coefficients[0];
                coefficients[0] +=
                    (original < 0n ? -1n : 1n) *
                    (1n << BigInt(96 * equation.limbs));
                expect(
                    model.rows().every((row) => model.evaluateRow(row) === 0n),
                ).toBe(true);
                expect(model.verify(), equation.name).toBe(false);
                coefficients[0] = original;
            }
        }
        expect(model.verify()).toBe(true);
    });

    it('refuses incomplete public polynomials before evaluating the relation', () => {
        const model = createSetupContributionRelationModel(completionProfile());
        model.equations[0].publicValue.pop();
        expect(model.verify()).toBe(false);
    });

    it('satisfies every integer row and decrypts every share at both interval endpoints and varied inputs', () => {
        for (const seed of [0n, 1n, 23n, 987654321n]) {
            const model = createSetupContributionRelationModel(
                completionProfile(),
                seed,
            );
            expect(model.verify()).toBe(true);
            expect(
                model.rows().every((row) => model.evaluateRow(row) === 0n),
            ).toBe(true);
            expect(model.rows()).toHaveLength((36 * 8 + 20 * 2 + 2) * 16 + 26);
            expect(model.decryptedShares).toEqual(model.expectedShares);
            expect(model.equations).toHaveLength(36 + 20 + 2);
        }
    });

    it('derives the executed layout in closed form at the boundary profiles', () => {
        for (const [participantCount, optionCount] of [
            [3, 2],
            [4, 20],
            [16, 2],
            [20, 20],
        ]) {
            const profile = deriveSupportedProfile(
                participantCount,
                optionCount,
            );
            const model = createSetupContributionRelationModel(profile);
            expect(model.verify()).toBe(true);
            expect(model.decryptedShares).toEqual(model.expectedShares);
            expect(model.equations).toHaveLength(
                4 * Number(profile.gadgetLength) + 2 * participantCount + 2,
            );
            const layout = compileSetupContributionColumnLayout(profile);
            const shape = deriveSetupContributionShape(profile);
            expect(layout.wordColumns).toBe(shape.wordColumns);
            expect(layout.booleanColumns).toBe(shape.booleanColumns);
            expect(layout.lookups).toHaveLength(shape.lookupEntries);
            expect(layout.disjointBooleanPairs).toHaveLength(
                shape.disjointPairs,
            );
            expect(
                model.columns.filter((column) => column.bits === 7),
            ).toHaveLength(shape.errorColumns);
            // Each limb equation has one row per ring coefficient.
            const limbEquations =
                (model.rows().length - shape.supportRows) / model.degree;
            expect(
                BigInt(limbEquations) * fixedModulusBfvInputs.polynomialDegree +
                    BigInt(shape.supportRows),
            ).toBe(shape.affineRows);
        }
    });

    it('derives the full operator inventory from the exercised equation families', () => {
        expect(
            compileSetupContributionRelationCensus(completionProfile()),
        ).toEqual({
            // Each 112-bit sharing coefficient fills seven words.
            wordColumns: 36 * 9 + 3 * 7 + 10 * 7 + 4,
            booleanColumns: 2 * (2 + 10 + 1),
            errorColumns: 36 + 2 * 10 + 2,
            disjointPairs: 13,
            supportRows: 26,
            affineRows: BigInt((36 * 8 + 20 * 2 + 2) * 65536 + 26),
            lookupEntries: 419 + 58,
            fullAffineCoefficientByteLength: 445n * 65536n * (3n * 16n),
            singlePublicAdjointCoefficientByteLength: 65536n * (3n * 16n),
            largestPublicPolynomialByteLength: 65536n * (1n + 96n),
            maximumPublicQueryCount: 2 * 704,
            publicQueryValueByteLength: 2n * 704n * (3n * 16n),
            fullAffineQueryValueByteLength: 445n * 2n * 704n * (3n * 16n),
            publicQueryTransformVectorByteLength:
                2n * 65536n * (3n * 16n) + 32768n * 16n + 1408n * 48n,
            fullRingQueryCosets: 4n,
            expandedStatementPolynomialCount: 63n + 31n + 4n,
            expandedStatementHeaderByteLength: 4n + 96n,
            expandedStatementByteLength:
                4n +
                96n +
                63n * 65536n * 97n +
                31n * 65536n * 21n +
                4n * 65536n * 6n,
            maximumEncodedOperatorByteLength:
                64n + 2n * 48n + 445n * 1408n * 48n,
            maximumIntegerLimbConvolutionMagnitude: 1024n * ((1n << 96n) - 1n),
            syntheticWitnessHeaderByteLength: 4n + 3n * 4n + 64n,
            syntheticWitnessByteLength: 80n + 445n * 65536n * 2n,
        });
    });

    it('orders word and Boolean columns and constrains each narrow error in that order', () => {
        const layout =
            compileSetupContributionColumnLayout(completionProfile());
        expect(
            [...layout.modelToCanonicalColumn].sort(
                (left, right) => left - right,
            ),
        ).toEqual(Array.from({ length: 445 }, (_unused, index) => index));
        expect(layout.lookups.slice(0, 419)).toEqual(
            Array.from({ length: 419 }, (_unused, column) => ({
                column,
                scale: 1n,
            })),
        );
        const errorColumns = [
            ...Array.from({ length: 36 }, (_unused, index) => 29 + 9 * index),
            ...Array.from({ length: 10 }, (_unused, index) => [
                348 + 7 * index,
                351 + 7 * index,
            ]).flat(),
            416,
            418,
        ];
        expect(layout.lookups.slice(419)).toEqual(
            errorColumns.map((column) => ({ column, scale: 512n })),
        );
        expect(layout.disjointBooleanPairs).toEqual(
            Array.from({ length: 13 }, (_unused, index) => [
                419 + 2 * index,
                420 + 2 * index,
            ]),
        );
    });

    it('refuses full resident affine coefficients at the absolute WASM bound', () => {
        const census =
            compileSetupContributionRelationCensus(completionProfile());
        expect(census.fullAffineCoefficientByteLength).toBeGreaterThan(
            671_088_640n,
        );
        expect(
            census.singlePublicAdjointCoefficientByteLength + 1_048_576n,
        ).toBeLessThan(671_088_640n);
    });

    it('binds low and high public limbs in every key and ciphertext equation', () => {
        const model = createSetupContributionRelationModel(
            completionProfile(),
            5n,
        );
        for (const equation of model.equations) {
            const original = equation.publicValue[3];
            for (const delta of [1n, 1n << BigInt(96 * (equation.limbs - 1))]) {
                equation.publicValue[3] = original + delta;
                expect(model.verify(), equation.name).toBe(false);
            }
            equation.publicValue[3] = original;
        }
        expect(model.verify()).toBe(true);
    });

    it('uses the same common encryption coordinate for encryption and first relinearization', () => {
        const model = createSetupContributionRelationModel(completionProfile());
        for (let gadget = 0; gadget < 9; gadget++) {
            const encryption = model.equations[4 * gadget];
            const relinearization = model.equations[4 * gadget + 1];
            expect(encryption.convolution[0].publicCoefficients).toBe(
                relinearization.convolution[0].publicCoefficients,
            );
        }
    });

    it('matches every entry of the independently assembled affine transpose, including degenerate challenges', () => {
        const model = createSetupContributionRelationModel(
            completionProfile(),
            17n,
        );
        const prime = compileSmallLimbProofFieldCensus().modulus;
        const modulo = (value: bigint) => ((value % prime) + prime) % prime;
        const rows = model.rows();
        for (const alpha of [0n, 1n, 2n, 97n, prime / 2n, prime - 1n]) {
            const coefficients = model.columns.map(() =>
                Array.from({ length: model.degree }, () => 0n),
            );
            let target = 0n,
                weight = 1n;
            for (const row of rows) {
                target = modulo(target - weight * row.constant);
                for (const term of row.terms)
                    coefficients[term.column][term.position] = modulo(
                        coefficients[term.column][term.position] +
                            weight * term.factor,
                    );
                weight = (weight * alpha) % prime;
            }
            expect(model.transpose(alpha)).toEqual({ coefficients, target });
        }
    });

    it('refuses an altered shared constant and an altered wide coefficient', () => {
        const model = createSetupContributionRelationModel(completionProfile());
        for (const name of [
            'FHE secret/positive',
            'sharing coefficient 1/low/word-0',
            'sharing coefficient 3/high/word-0',
        ]) {
            const column = model.columns.find(
                (candidate) => candidate.name === name,
            )!;
            const original = column.values[0];
            column.values[0] = original ^ 1n;
            expect(model.verify(), name).toBe(false);
            column.values[0] = original;
        }
        expect(model.verify()).toBe(true);
    });

    it('refuses range violations and overlapping signs in the retained FHE auxiliary secret', () => {
        const model = createSetupContributionRelationModel(completionProfile());
        const error = model.columns.find((column) => column.bits === 7)!;
        const originalError = error.values[0];
        error.values[0] = 128n;
        expect(model.verify()).toBe(false);
        error.values[0] = originalError;
        const positive = model.columns.find(
            (column) => column.name === 'FHE auxiliary secret/positive',
        )!;
        const negative = model.columns.find(
            (column) => column.name === 'FHE auxiliary secret/negative',
        )!;
        const active = positive.values.findIndex((value) => value === 1n);
        negative.values[active] = 1n;
        expect(model.verify()).toBe(false);
        negative.values[active] = 0n;
        expect(model.verify()).toBe(true);
    });
    it('binds each registered source ciphertext to the original secret and first error', () => {
        const model = createSetupContributionRelationModel(
            completionProfile(),
            23n,
        );
        expect(model.sourceEquations).toHaveLength(2);
        for (const equation of model.sourceEquations) {
            const original = equation.publicValue[1];
            equation.publicValue[1]++;
            expect(model.verify(), equation.name).toBe(false);
            equation.publicValue[1] = original;
            const error = model.columns[equation.error.terms[0].column];
            const saved = error.values[1];
            error.values[1] = 128n;
            expect(model.verify()).toBe(false);
            error.values[1] = saved;
        }
        // A source ephemeral coefficient outside the honest embedding is
        // still a proof variable, not an ignored position.
        const positive = model.columns[model.sourceEphemeral.terms[0].column];
        const active = positive.values.findIndex((value) => value === 1n);
        positive.values[active] = 0n;
        positive.values[1] = 1n;
        expect(model.verify()).toBe(false);
        positive.values[1] = 0n;
        positive.values[active] = 1n;
        expect(model.verify()).toBe(true);
    });
    it('checks source equations over the full ambient support rather than only the honest embedding', () => {
        const model = createSetupContributionRelationModel(
            completionProfile(),
            31n,
        );
        const read = (
            variable: typeof model.sourceEphemeral,
            position: number,
        ) =>
            variable.terms.reduce(
                (value, term) =>
                    value +
                    term.factor *
                        model.columns[term.column].values[
                            position * variable.stride
                        ],
                variable.offset,
            );
        for (const term of model.sourceEphemeral.terms) {
            const column = model.columns[term.column];
            column.values = [
                column.values[column.values.length - 1],
                ...column.values.slice(0, -1),
            ];
        }
        for (const equation of model.sourceEquations) {
            const common = equation.convolution[0].publicCoefficients;
            for (let position = 0; position < model.degree; position++) {
                let raw = equation.offset?.[position] ?? 0n;
                raw += read(equation.error, position);
                for (const term of equation.direct)
                    raw += term.factor * read(term.variable, position);
                for (let shift = 0; shift < model.degree; shift++) {
                    const target =
                        (position - shift + model.degree) % model.degree;
                    raw +=
                        common[target] *
                        read(model.sourceEphemeral, shift) *
                        (position < shift ? -1n : 1n);
                }
                let canonical =
                    ((raw % equation.modulus) + equation.modulus) %
                    equation.modulus;
                if (canonical > equation.modulus / 2n)
                    canonical -= equation.modulus;
                equation.publicValue[position] = canonical;
                const quotient = (raw - canonical) / equation.modulus;
                model.columns[equation.quotient.terms[0].column].values[
                    position
                ] = quotient - equation.quotient.offset;
            }
        }
        expect(model.verify()).toBe(true);
        for (const term of model.sourceEphemeral.terms)
            expect(
                model.columns[term.column].values.some(
                    (value, position) => position % 2 === 1 && value === 1n,
                ),
            ).toBe(true);
    });
});
