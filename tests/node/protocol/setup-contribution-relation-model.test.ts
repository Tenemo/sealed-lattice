import { describe, expect, it } from 'vitest';

import {
    compileSetupContributionRelationCensus,
    compileSetupContributionColumnLayout,
    createSetupContributionRelationModel,
} from '#tests/setup-contribution-relation-model.js';
import { compileSmallLimbProofFieldCensus } from '#tests/small-limb-proof-field-model.js';

describe('complete setup contribution relation in a reduced ring', () => {
    it('rejects public limbs outside the canonical modulus even when the lifted equations are unchanged', () => {
        const model = createSetupContributionRelationModel();
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

    it('rejects incomplete public polynomials before evaluating the relation', () => {
        const model = createSetupContributionRelationModel();
        model.equations[0].publicValue.pop();
        expect(model.verify()).toBe(false);
    });

    it('satisfies every integer row and decrypts every share at both interval endpoints and varied inputs', () => {
        for (const seed of [0n, 1n, 23n, 987654321n]) {
            const model = createSetupContributionRelationModel(seed);
            expect(model.verify()).toBe(true);
            expect(
                model.rows().every((row) => model.evaluateRow(row) === 0n),
            ).toBe(true);
            expect(model.rows()).toHaveLength((24 * 9 + 20 * 2) * 16 + 8 + 26);
            expect(model.decryptedShares).toEqual(model.expectedShares);
            expect(model.equations).toHaveLength(24 + 20 + 1);
        }
    });

    it('derives the full operator inventory from the exercised equation families', () => {
        expect(compileSetupContributionRelationCensus()).toEqual({
            wordColumns: 24 * 10 + 3 * 7 + 10 * 7 + 2,
            booleanColumns: 2 * (2 + 10 + 1) + 3 * 2,
            errorColumns: 24 + 2 * 10 + 1,
            disjointPairs: 13,
            supportRows: 26,
            affineRows: BigInt((24 * 9 + 20 * 2) * 65536 + 4096 + 26),
            lookupEntries: 333 + 45,
            fullAffineCoefficientByteLength: 365n * 65536n * (3n * 16n),
            singlePublicAdjointCoefficientByteLength: 65536n * (3n * 16n),
            largestPublicPolynomialByteLength: 65536n * (1n + 108n),
            maximumPublicQueryCount: 2 * 704,
            publicQueryValueByteLength: 2n * 704n * (3n * 16n),
            fullAffineQueryValueByteLength: 365n * 2n * 704n * (3n * 16n),
            publicQueryTransformVectorByteLength:
                2n * 65536n * (3n * 16n) + 32768n * 16n + 1408n * 48n,
            fullRingQueryCosets: 4n,
            auxiliaryQueryCosets: 64n,
            expandedStatementPolynomialCount: 42n + 31n + 2n,
            expandedStatementHeaderByteLength: 4n + 8n + 108n + 20n + 5n,
            expandedStatementByteLength:
                145n +
                42n * 65536n * 109n +
                31n * 65536n * 21n +
                2n * 4096n * 6n,
            maximumEncodedOperatorByteLength:
                64n + 2n * 48n + 365n * 1408n * 48n,
        });
    });

    it('orders word and Boolean columns and constrains each narrow error in that order', () => {
        const layout = compileSetupContributionColumnLayout();
        expect(
            [...layout.modelToCanonicalColumn].sort(
                (left, right) => left - right,
            ),
        ).toEqual(Array.from({ length: 365 }, (_unused, index) => index));
        expect(layout.lookups.slice(0, 333)).toEqual(
            Array.from({ length: 333 }, (_unused, column) => ({
                column,
                scale: 1n,
            })),
        );
        const errorColumns = [
            ...Array.from({ length: 24 }, (_unused, index) => 30 + 10 * index),
            ...Array.from({ length: 10 }, (_unused, index) => [
                264 + 7 * index,
                267 + 7 * index,
            ]).flat(),
            332,
        ];
        expect(layout.lookups.slice(333)).toEqual(
            errorColumns.map((column) => ({ column, scale: 512n })),
        );
        expect(layout.disjointBooleanPairs).toEqual(
            Array.from({ length: 13 }, (_unused, index) => [
                333 + 2 * index,
                334 + 2 * index,
            ]),
        );
    });

    it('rejects full resident affine coefficients at the absolute WASM bound', () => {
        const census = compileSetupContributionRelationCensus();
        expect(census.fullAffineCoefficientByteLength).toBeGreaterThan(
            671_088_640n,
        );
        expect(
            census.singlePublicAdjointCoefficientByteLength + 1_048_576n,
        ).toBeLessThan(671_088_640n);
    });

    it('binds low and high public limbs in every key and ciphertext equation', () => {
        const model = createSetupContributionRelationModel(5n);
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
        const model = createSetupContributionRelationModel();
        for (let gadget = 0; gadget < 6; gadget++) {
            const encryption = model.equations[4 * gadget];
            const relinearization = model.equations[4 * gadget + 1];
            expect(encryption.convolution[0].publicCoefficients).toBe(
                relinearization.convolution[0].publicCoefficients,
            );
        }
    });

    it('matches every entry of the independently assembled affine transpose, including degenerate challenges', () => {
        const model = createSetupContributionRelationModel(17n);
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

    it('rejects an altered shared constant and an altered wide coefficient', () => {
        const model = createSetupContributionRelationModel();
        for (const name of [
            'FHE secret/positive',
            'sharing coefficient 1/word-0',
            'sharing coefficient 3/bit-113',
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

    it('rejects range violations and support moved from active auxiliary positions to padding', () => {
        const model = createSetupContributionRelationModel();
        const error = model.columns.find((column) => column.bits === 7)!;
        const originalError = error.values[0];
        error.values[0] = 128n;
        expect(model.verify()).toBe(false);
        error.values[0] = originalError;
        const positive = model.columns[model.auxiliarySecretColumns[0]];
        const active = positive.values.findIndex(
            (value, position) => position % 2 === 0 && value === 1n,
        );
        positive.values[active] = 0n;
        positive.values[active + 1] = 1n;
        expect(model.verify()).toBe(false);
        positive.values[active] = 1n;
        positive.values[active + 1] = 0n;
        expect(model.verify()).toBe(true);
    });
});
