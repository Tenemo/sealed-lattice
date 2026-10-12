import { describe, expect, it } from 'vitest';

import { auxiliaryInputEncryptionParameters } from '#tests/auxiliary-input-encryption-parameters.js';
import {
    compileBallotEncryptionColumnLayout,
    createBallotEncryptionRelationModel,
} from '#tests/ballot-encryption-relation-model.js';
import {
    compileLinkedReleaseColumnLayout,
    createLinkedReleaseRelationModel,
} from '#tests/linked-release-relation-model.js';
import {
    applyRelationOperator,
    ballotRelationOperator,
    evaluateRelationOperator,
    relationOperatorColumns,
    releaseRelationOperator,
    setupRelationOperator,
} from '#tests/relation-operator-model.js';
import {
    compileSetupContributionColumnLayout,
    createSetupContributionRelationModel,
} from '#tests/setup-contribution-relation-model.js';
import {
    deriveSupportedProfile,
    type SupportedProfile,
} from '#tests/supported-profile-model.js';
import { shareEncryptionParameters } from '#tests/wide-share-lifting-model.js';
import {
    evaluateSystematicColumns,
    wordFieldArithmetic,
    wordProofDomain,
    type Extension,
} from '#tests/word-verifier-reference-model.js';

const { one, multiply } = wordFieldArithmetic;
const power = (value: Extension, exponent: number) => {
    let result = one;
    for (let index = 0; index < exponent; index++)
        result = multiply(result, value);
    return result;
};
const alpha: Extension = [
    0x1d3f_47a9_5c2b_8e61n,
    0x6b2e_91c4_07f3_5a8dn,
    0x2c85_e4b7_19a0_d36fn,
];
const byteLength = (value: bigint) => Math.ceil(value.toString(2).length / 8);
const littleEndian = (value: bigint, bytes: number) => {
    const output = Buffer.alloc(bytes);
    for (let index = 0, rest = value; index < bytes; index++, rest >>= 8n)
        output[index] = Number(rest & 255n);
    return output;
};
// Each coefficient as a sign byte and its little-endian magnitude in the
// modulus's byte length.
const encode = (values: readonly bigint[], modulus: bigint) =>
    Buffer.concat(
        values.map((value) =>
            Buffer.concat([
                Buffer.of(value < 0n ? 1 : 0),
                littleEndian(value < 0n ? -value : value, byteLength(modulus)),
            ]),
        ),
    );
// The 16-bit words of a signed variable offset by half its range.
const words = (values: readonly bigint[], bits: number, count: number) =>
    Array.from({ length: count }, (_unused, word) =>
        values.map(
            (value) =>
                ((value + (1n << BigInt(bits - 1))) >> BigInt(16 * word)) &
                0xffffn,
        ),
    );
const signs = (values: readonly bigint[]) => [
    values.map((value) => BigInt(value === 1n)),
    values.map((value) => BigInt(value === -1n)),
];
const changed = (
    witness: readonly (readonly bigint[])[],
    column: number,
    row: number,
) =>
    witness.map((values, index) =>
        index === column
            ? values.map((value, position) =>
                  position === row ? value ^ 1n : value,
              )
            : values,
    );
// Flips the low magnitude bit of a coefficient record.
const changedStatement = (statement: Buffer, record: number) => {
    const copy = Buffer.from(statement);
    copy[record + 1] ^= 1;
    return copy;
};

const ballotLayout = {
    degree: 64,
    auxiliaryDegree: 8,
    fheHalfSupport: 2,
    auxiliaryHalfSupport: 2,
};
const reducedBallot = (profile: SupportedProfile) => {
    const model = createBallotEncryptionRelationModel(profile, [7n, 3n]);
    expect(model.verify()).toBe(true);
    const layout = compileBallotEncryptionColumnLayout(profile);
    const index = (name: string) =>
        layout.columns.findIndex((value) => value.name === name);
    const witness = layout.columns.map(() =>
        Array.from({ length: ballotLayout.degree }, () => 0n),
    );
    const place = (name: string, values: readonly bigint[], stride = 1) =>
        values.forEach(
            (value, position) =>
                (witness[index(name)][stride * position] = value),
        );
    const auxiliary = model.auxiliaryCiphertext;
    const auxiliaryStride = ballotLayout.degree / ballotLayout.auxiliaryDegree;
    for (const component of [0, 1]) {
        place(
            `fhe-quotient-${component}`,
            words(model.fhe.quotients[component], 16, 1)[0],
        );
        place(
            `fhe-error-${component}`,
            words(model.fhe.errors[component], 7, 1)[0],
        );
        model.carries[component].forEach((carries, carry) =>
            place(`fhe-carry-${component}-${carry}`, words(carries, 16, 1)[0]),
        );
        place(
            `auxiliary-quotient-${component}`,
            words(auxiliary.quotients[component], 16, 1)[0],
            auxiliaryStride,
        );
        place(
            `auxiliary-error-${component}`,
            words(auxiliary.errors[component], 7, 1)[0],
            auxiliaryStride,
        );
    }
    place('plaintext-lower-word', model.plaintextWords);
    place('plaintext-high-bit', model.plaintextHighBits);
    place('packing-quotient', words(model.packingQuotient, 16, 1)[0]);
    place('score-minus-one', model.scoreWords);
    const [fhePositive, fheNegative] = signs(model.fhe.ephemeral);
    place('fhe-positive-support', fhePositive);
    place('fhe-negative-support', fheNegative);
    const [auxiliaryPositive, auxiliaryNegative] = signs(auxiliary.ephemeral);
    place('auxiliary-positive-support', auxiliaryPositive, auxiliaryStride);
    place('auxiliary-negative-support', auxiliaryNegative, auxiliaryStride);
    const modulus = profile.ciphertext.modulus;
    const auxiliaryModulus = auxiliaryInputEncryptionParameters.modulus;
    const header = Buffer.concat([
        Buffer.from('LBS1', 'latin1'),
        Buffer.alloc(64, 1),
        Buffer.alloc(64, 7),
        littleEndian(BigInt(profile.participantCount - 1), 2),
        Buffer.of(profile.optionCount, 1),
    ]);
    const statement = Buffer.concat([
        header,
        ...[model.fhe.common, model.fhe.publicKey, ...model.fhe.ciphertext].map(
            (values) => encode(values, modulus),
        ),
        ...[auxiliary.common, auxiliary.publicKey, ...auxiliary.ciphertext].map(
            (values) => encode(values, auxiliaryModulus),
        ),
    ]);
    return { model, index, witness, header, statement };
};

const releaseLayout = { degree: 16, recipientHalfSupport: 2 };
const reducedRelease = (profile: SupportedProfile, seed: bigint) => {
    const model = createLinkedReleaseRelationModel(profile, seed);
    expect(model.verify()).toBe(true);
    const layout = compileLinkedReleaseColumnLayout(profile);
    const values = new Map<string, readonly bigint[]>([
        ['key-quotient', model.keyQuotient],
        ['key-carry', model.keyCarry],
        ['key-error', model.keyError],
        ['aggregate-share', model.share],
        ['decoding-error', model.decodingError],
        ['decoding-quotient', model.decodingQuotient],
        ['decoding-carry', model.decodingCarry],
        ['release-noise', model.noise],
        ['release-quotient', model.releaseQuotient],
        ...model.releaseCarries.map(
            (carry, index) => [`release-carry-${index}`, carry] as const,
        ),
    ]);
    const witness = [
        ...layout.columns.flatMap(({ name, bits, wordCount }) =>
            words(values.get(name)!, bits, wordCount),
        ),
        ...signs(model.recipientSecret),
    ];
    expect(witness.length).toBe(layout.wordColumns + layout.booleanColumns);
    const shareModulus = shareEncryptionParameters.modulus;
    const releaseModulus = profile.release.modulus;
    const statement = Buffer.concat([
        Buffer.from('LRS1', 'latin1'),
        Buffer.alloc(3 * 64, 5),
        littleEndian(0n, 2),
        ...[
            model.common,
            model.publicKey,
            model.encryptedConstant,
            model.encryptedLinear,
        ].map((polynomial) => encode(polynomial, shareModulus)),
        ...[model.targetLinear, model.partial].map((polynomial) =>
            encode(polynomial, releaseModulus),
        ),
    ]);
    return { model, layout, witness, statement };
};

const setupLayout = { degree: 16, fheHalfSupport: 2, shareHalfSupport: 2 };
const reducedSetup = (profile: SupportedProfile) => {
    const model = createSetupContributionRelationModel(profile);
    expect(model.verify()).toBe(true);
    const { modelToCanonicalColumn } =
        compileSetupContributionColumnLayout(profile);
    const witness: bigint[][] = [];
    model.columns.forEach(
        (column, index) =>
            (witness[modelToCanonicalColumn[index]] = column.values),
    );
    const equation = (name: string) => {
        const found = model.equations.find((value) => value.name === name);
        expect(found).toBeDefined();
        return found!;
    };
    const common = (name: string) =>
        equation(name).convolution[0].publicCoefficients;
    const modulus = profile.ciphertext.modulus;
    const shareModulus = shareEncryptionParameters.modulus;
    const fhePolynomials = Array.from(
        { length: Number(profile.gadgetLength) },
        (_unused, gadget) => {
            // Both the encryption and the first relinearization multiply
            // the gadget coordinate's first common polynomial.
            expect(common(`first relinearization/${gadget}`)).toBe(
                common(`encryption/${gadget}`),
            );
            return [
                common(`encryption/${gadget}`),
                equation(`encryption/${gadget}`).publicValue,
                equation(`first relinearization/${gadget}`).publicValue,
                common(`second relinearization/${gadget}`),
                equation(`second relinearization/${gadget}`).publicValue,
                common(`automorphism/${gadget}`),
                equation(`automorphism/${gadget}`).publicValue,
            ];
        },
    ).flat();
    const sharePolynomials = [
        common('encrypted-share-0/linear'),
        ...Array.from(
            { length: profile.participantCount },
            (_unused, recipient) => [
                common(`encrypted-share-${recipient}/constant`),
                equation(`encrypted-share-${recipient}/constant`).publicValue,
                equation(`encrypted-share-${recipient}/linear`).publicValue,
            ],
        ).flat(),
    ];
    const header = Buffer.concat([
        Buffer.from('SCO2', 'latin1'),
        littleEndian(BigInt(setupLayout.degree), 4),
        littleEndian(modulus, byteLength(modulus)),
        littleEndian(shareModulus, byteLength(shareModulus)),
    ]);
    const statement = Buffer.concat([
        header,
        ...fhePolynomials.map((values) => encode(values, modulus)),
        ...sharePolynomials.map((values) => encode(values, shareModulus)),
    ]);
    return {
        model,
        modelToCanonicalColumn,
        witness,
        header,
        statement,
        fheBytes:
            fhePolynomials.length *
            setupLayout.degree *
            (1 + byteLength(modulus)),
    };
};

describe('relation operator model', () => {
    it('meets every reduced ballot relation row at its satisfying witness', () => {
        for (const participantCount of [3, 13, 20]) {
            const profile = deriveSupportedProfile(participantCount, 2);
            const { index, witness, header, statement } =
                reducedBallot(profile);
            const operator = ballotRelationOperator(
                profile,
                statement,
                alpha,
                ballotLayout,
            );
            expect(applyRelationOperator(operator, witness)).toEqual(
                operator.target,
            );
            const limbs = Math.ceil(
                profile.ciphertext.modulus.toString(2).length / 96,
            );
            expect(operator.lookupWeight).toEqual(
                power(alpha, (2 * limbs + 1) * 64 + 2 * 8 + 4),
            );
            // A changed score, carry, auxiliary quotient or support bit, or
            // a changed ciphertext coefficient, no longer meets it.
            for (const [column, row] of [
                [index('score-minus-one'), 1],
                [index(`fhe-carry-1-${limbs - 2}`), 9],
                [index('auxiliary-quotient-0'), 16],
                [index('fhe-negative-support'), 40],
            ] as const)
                expect(
                    applyRelationOperator(
                        operator,
                        changed(witness, column, row),
                    ),
                ).not.toEqual(operator.target);
            const record = 1 + byteLength(profile.ciphertext.modulus);
            const other = ballotRelationOperator(
                profile,
                changedStatement(
                    statement,
                    header.length + 2 * 64 * record + 5 * record,
                ),
                alpha,
                ballotLayout,
            );
            expect(applyRelationOperator(other, witness)).not.toEqual(
                other.target,
            );
        }
    });

    it('meets every reduced release relation row at its satisfying witness', () => {
        for (const [participantCount, optionCount, seed] of [
            [3, 2, 1n],
            [13, 4, 0n],
            [20, 20, 1n],
        ] as const) {
            const profile = deriveSupportedProfile(
                participantCount,
                optionCount,
            );
            const { layout, witness, statement } = reducedRelease(
                profile,
                seed,
            );
            const operator = releaseRelationOperator(
                profile,
                statement,
                alpha,
                releaseLayout,
            );
            expect(applyRelationOperator(operator, witness)).toEqual(
                operator.target,
            );
            expect(operator.lookupWeight).toEqual(
                power(alpha, (4 + profile.releaseLifting.outputLimbs) * 16 + 2),
            );
            // The last word of each variable.
            const last = (name: string) => {
                const found = layout.columns.find(
                    (value) => value.name === name,
                )!;
                return found.firstColumn + found.wordCount - 1;
            };
            for (const [column, row] of [
                [last('release-noise'), 3],
                [last('aggregate-share'), 11],
                [last('release-carry-0'), 0],
                [last('decoding-carry'), 7],
                [layout.positiveSecretColumn, 9],
            ] as const)
                expect(
                    applyRelationOperator(
                        operator,
                        changed(witness, column, row),
                    ),
                ).not.toEqual(operator.target);
            const other = releaseRelationOperator(
                profile,
                changedStatement(
                    statement,
                    statement.length -
                        2 * (1 + byteLength(profile.release.modulus)),
                ),
                alpha,
                releaseLayout,
            );
            expect(applyRelationOperator(other, witness)).not.toEqual(
                other.target,
            );
        }
    });

    it('equals the reduced setup relation transpose and meets its satisfying witness', () => {
        for (const [participantCount, optionCount] of [
            [3, 2],
            [13, 2],
            [20, 20],
        ]) {
            const profile = deriveSupportedProfile(
                participantCount,
                optionCount,
            );
            const {
                model,
                modelToCanonicalColumn,
                witness,
                statement,
                fheBytes,
                header,
            } = reducedSetup(profile);
            // At a base-field challenge every coefficient and the target
            // equal the dense transpose of the relation rows.
            const challenge = 0x5a17_3c9e_2b84_f601n;
            const transposed = model.transpose(challenge);
            const base = setupRelationOperator(
                profile,
                statement,
                [challenge, 0n, 0n],
                setupLayout,
            );
            const columns = relationOperatorColumns(base, setupLayout.degree);
            transposed.coefficients.forEach((coefficients, index) =>
                expect(columns[modelToCanonicalColumn[index]]).toEqual(
                    coefficients.map((value) => [value, 0n, 0n]),
                ),
            );
            expect(base.target).toEqual([transposed.target, 0n, 0n]);
            // At an extension challenge the satisfying witness meets it.
            const operator = setupRelationOperator(
                profile,
                statement,
                alpha,
                setupLayout,
            );
            expect(applyRelationOperator(operator, witness)).toEqual(
                operator.target,
            );
            expect(operator.lookupWeight).toEqual(
                power(alpha, model.rows().length),
            );
            const named = (name: string) =>
                modelToCanonicalColumn[
                    model.columns.findIndex((value) => value.name === name)
                ];
            for (const [column, row] of [
                [named('encryption/0/error/word-0'), 4],
                [named('sharing coefficient 1/high/word-0'), 13],
                [
                    named(
                        `encrypted-share-${participantCount - 1}/linear/quotient/word-0`,
                    ),
                    2,
                ],
            ] as const)
                expect(
                    applyRelationOperator(
                        operator,
                        changed(witness, column, row),
                    ),
                ).not.toEqual(operator.target);
            const record = 1 + byteLength(shareEncryptionParameters.modulus);
            const other = setupRelationOperator(
                profile,
                changedStatement(
                    statement,
                    header.length + fheBytes + 17 * record,
                ),
                alpha,
                setupLayout,
            );
            expect(applyRelationOperator(other, witness)).not.toEqual(
                other.target,
            );
        }
    });

    it('evaluates every term at the queried points as the interpolated columns do', () => {
        const profile = deriveSupportedProfile(3, 2);
        const operators = [
            releaseRelationOperator(
                profile,
                reducedRelease(profile, 0n).statement,
                alpha,
                releaseLayout,
            ),
            releaseRelationOperator(
                profile,
                reducedRelease(profile, 1n).statement,
                alpha,
                releaseLayout,
            ),
            setupRelationOperator(
                profile,
                reducedSetup(profile).statement,
                alpha,
                setupLayout,
            ),
            ballotRelationOperator(
                profile,
                reducedBallot(profile).statement,
                alpha,
                ballotLayout,
            ),
        ];
        // Operators at one challenge share the evaluations of its powers
        // and of ones through the cache.
        const cache = new Map<string, readonly Extension[]>();
        for (const operator of operators) {
            const systematic = operator === operators[3] ? 64 : 16;
            const domain = wordProofDomain(systematic, 1);
            const positions = Array.from(
                { length: domain.domain },
                (_unused, index) => index,
            );
            const expected = evaluateSystematicColumns(
                domain,
                relationOperatorColumns(operator, systematic),
                positions,
            );
            expect(
                evaluateRelationOperator(operator, domain, positions)
                    .coefficients,
            ).toEqual(expected);
            expect(
                evaluateRelationOperator(operator, domain, positions, cache)
                    .coefficients,
            ).toEqual(expected);
        }
        expect(cache.size).toBeGreaterThan(0);
    });

    it('refuses statements of another shape, header or coefficient encoding', () => {
        const profile = deriveSupportedProfile(3, 2);
        const { header, statement } = reducedBallot(profile);
        const ballot = (bytes: Buffer) =>
            ballotRelationOperator(profile, bytes, alpha, ballotLayout);
        expect(() => ballot(statement.subarray(1))).toThrow('wrong length');
        expect(() => ballot(Buffer.concat([statement, Buffer.of(0)]))).toThrow(
            'wrong length',
        );
        for (const [offset, value] of [
            [0, 0x4d],
            [132, profile.participantCount],
            [134, 3],
            [135, 0],
            [135, 3],
        ] as const) {
            const copy = Buffer.from(statement);
            copy[offset] = value;
            expect(() => ballot(copy)).toThrow('header differs');
        }
        const width = 1 + byteLength(profile.ciphertext.modulus);
        const half = (profile.ciphertext.modulus - 1n) / 2n;
        for (const record of [
            Buffer.concat([Buffer.of(2), littleEndian(1n, width - 1)]),
            Buffer.concat([Buffer.of(1), littleEndian(0n, width - 1)]),
            Buffer.concat([Buffer.of(0), littleEndian(half + 1n, width - 1)]),
        ]) {
            const copy = Buffer.from(statement);
            record.copy(copy, header.length + 3 * width);
            expect(() => ballot(copy)).toThrow('not canonical');
        }
        // A magnitude of exactly half the modulus is canonical.
        const edge = Buffer.from(statement);
        Buffer.concat([Buffer.of(1), littleEndian(half, width - 1)]).copy(
            edge,
            header.length,
        );
        expect(() => ballot(edge)).not.toThrow();
        const release = reducedRelease(profile, 1n).statement;
        const position = Buffer.from(release);
        position.writeUInt16LE(profile.participantCount, 4 + 3 * 64);
        expect(() =>
            releaseRelationOperator(profile, position, alpha, releaseLayout),
        ).toThrow('header differs');
        const setup = reducedSetup(profile).statement;
        expect(() =>
            setupRelationOperator(profile, setup, alpha, {
                ...setupLayout,
                degree: 32,
            }),
        ).toThrow('wrong length');
        const degree = Buffer.from(setup);
        degree[4] ^= 1;
        expect(() =>
            setupRelationOperator(profile, degree, alpha, setupLayout),
        ).toThrow('header differs');
    });
});
