import assert from 'node:assert/strict';

import { auxiliaryInputEncryptionParameters } from '#tests/auxiliary-input-encryption-parameters.js';
import {
    ballotPackingMatrix,
    compileBallotEncryptionColumnLayout,
} from '#tests/ballot-encryption-relation-model.js';
import { fixedModulusBfvInputs } from '#tests/fixed-modulus-bfv-model.js';
import { compileLinkedReleaseColumnLayout } from '#tests/linked-release-relation-model.js';
import {
    deriveSetupContributionShape,
    setupEquationWidths,
} from '#tests/setup-contribution-relation-model.js';
import {
    interpolationRingDegree,
    type SupportedProfile,
} from '#tests/supported-profile-model.js';
import { shareEncryptionParameters } from '#tests/wide-share-lifting-model.js';
import {
    evaluateSystematicColumns,
    wordFieldArithmetic,
    type Extension,
    type WordProofDomain,
} from '#tests/word-verifier-reference-model.js';

// The affine operator of the setup, ballot and release relations, built
// from a canonical public statement at the affine challenge alpha. Row r of
// a relation has weight alpha^r, so a witness column's coefficient at a row
// is the alpha-weighted sum of its factors in every relation row, and the
// target is the alpha-weighted sum of the rows' public constants. The limb
// rows of one equation lie one ring degree apart, so a public operand
// enters through its fingerprint: its signed limbs weighted by the powers
// of alpha^degree. A product of a public polynomial with a secret ring
// element gives that element the polynomial's negacyclic adjoint. The
// operator keeps each public column with the weight it gives every witness
// column, which is how a verifier evaluates it at queried points.

const { modulus, zero, one, base, add, subtract, multiply, scale, equal } =
    wordFieldArithmetic;
const negate = (value: Extension) => subtract(zero, value);
const power = (value: Extension, exponent: number): Extension => {
    let result = one;
    let current = value;
    for (let remaining = exponent; remaining > 0; remaining >>= 1) {
        if ((remaining & 1) === 1) result = multiply(result, current);
        current = multiply(current, current);
    }
    return result;
};
const powers = (alpha: Extension, count: number) => {
    const values: Extension[] = [];
    for (let index = 0, current = one; index < count; index++) {
        values.push(current);
        current = multiply(current, alpha);
    }
    return values;
};
const residue = (value: bigint) => ((value % modulus) + modulus) % modulus;
const bitLength = (value: bigint) => value.toString(2).length;
const byteLength = (value: bigint) => Math.ceil(bitLength(value) / 8);
const littleEndian = (value: bigint, bytes: number) => {
    const output = Buffer.alloc(bytes);
    for (let index = 0, rest = value; index < bytes; index++, rest >>= 8n)
        output[index] = Number(rest & 255n);
    return output;
};

// A public column places its values at every (systematic / degree)-th row:
// the powers of alpha at each position's automorphism image and negacyclic
// shift, negated past the degree; ones; or public values.
type PublicColumn =
    | Readonly<{
          kind: 'geometric';
          degree: number;
          automorphism: number;
          shift: number;
      }>
    | Readonly<{ kind: 'ones'; degree: number }>
    | Readonly<{ kind: 'values'; values: readonly Extension[] }>;
type OperatorTerm = Readonly<{
    key: string;
    public: PublicColumn;
    weights: ReadonlyMap<number, Extension>;
}>;
type RelationOperator = Readonly<{
    alpha: Extension;
    columns: number;
    terms: readonly OperatorTerm[];
    target: Extension;
    lookupWeight: Extension;
}>;
const publicColumnValues = (
    column: PublicColumn,
    alpha: Extension,
): readonly Extension[] => {
    switch (column.kind) {
        case 'values':
            return column.values;
        case 'ones':
            return Array.from({ length: column.degree }, () => one);
        case 'geometric': {
            const { degree, automorphism, shift } = column;
            const table = powers(alpha, degree);
            return Array.from({ length: degree }, (_unused, position) => {
                const exponent =
                    (position * automorphism + shift) % (2 * degree);
                const value = table[exponent % degree];
                return exponent < degree ? value : negate(value);
            });
        }
    }
};

// A signed variable: its columns with their factors, and the offset by
// which its value lies below their weighted sum.
type Variable = Readonly<{
    terms: readonly (readonly [number, bigint])[];
    offset: bigint;
}>;
const column = (index: number): Variable => ({
    terms: [[index, 1n]],
    offset: 0n,
});
// A sparse ternary element: its positive minus its negative Boolean column.
const sparse = (positive: number): Variable => ({
    terms: [
        [positive, 1n],
        [positive + 1, -1n],
    ],
    offset: 0n,
});
// A signed variable of one word offset by half its range.
const signedWord = (index: number, bits: number): Variable => ({
    terms: [[index, 1n]],
    offset: -(1n << BigInt(bits - 1)),
});

const createOperatorBuilder = (alpha: Extension, columns: number) => {
    const terms = new Map<
        string,
        { public: PublicColumn; weights: Map<number, Extension> }
    >();
    const sums = new Map<string, Extension>();
    let target = zero;
    // Adds weight times the variable at the public column: each of its
    // columns takes the weight times its factor, and the target takes the
    // offset's share of the column's sum.
    const put = (
        variable: Variable,
        key: string,
        publicColumn: PublicColumn,
        weight: Extension,
    ) => {
        let term = terms.get(key);
        if (term === undefined) {
            term = { public: publicColumn, weights: new Map() };
            terms.set(key, term);
            sums.set(
                key,
                publicColumnValues(publicColumn, alpha).reduce(add, zero),
            );
        }
        assert.equal(term.public, publicColumn, key);
        for (const [index, factor] of variable.terms) {
            assert.ok(Number.isInteger(index) && index >= 0 && index < columns);
            term.weights.set(
                index,
                add(term.weights.get(index) ?? zero, scale(weight, factor)),
            );
        }
        if (variable.offset !== 0n)
            target = add(
                target,
                scale(multiply(weight, sums.get(key)!), -variable.offset),
            );
    };
    const publicColumns = new Map<string, PublicColumn>();
    const shared = (key: string, create: () => PublicColumn) => {
        let publicColumn = publicColumns.get(key);
        if (publicColumn === undefined) {
            publicColumn = create();
            publicColumns.set(key, publicColumn);
        }
        return publicColumn;
    };
    return {
        put,
        putGeometric: (
            variable: Variable,
            degree: number,
            weight: Extension,
            automorphism = 1,
            shift = 0,
        ) => {
            const key = `geometric:${degree}:${automorphism}:${shift}`;
            put(
                variable,
                key,
                shared(key, () => ({
                    kind: 'geometric',
                    degree,
                    automorphism,
                    shift,
                })),
                weight,
            );
        },
        putOnes: (variable: Variable, degree: number, weight: Extension) => {
            const key = `ones:${degree}`;
            put(
                variable,
                key,
                shared(key, () => ({ kind: 'ones', degree })),
                weight,
            );
        },
        addTarget: (value: Extension) => {
            target = add(target, value);
        },
        finish: (lookupWeight: Extension): RelationOperator => ({
            alpha,
            columns,
            terms: [...terms].map(([key, term]) => ({ key, ...term })),
            target,
            lookupWeight,
        }),
    };
};

// One canonical polynomial: each coefficient's fingerprint and their sum
// weighted by the powers of alpha.
type ParsedPolynomial = Readonly<{
    fingerprints: readonly Extension[];
    total: Extension;
}>;
// Reads a statement's polynomials in order. Each coefficient is a sign byte
// and a little-endian magnitude of the modulus's byte length, at most half
// the modulus and never a negative zero. Its fingerprint sums the
// magnitude's limbs at the powers of alpha^degree, negated for a negative
// sign.
const createStatementReader = (
    statement: Uint8Array,
    offset: number,
    alpha: Extension,
) => {
    const bytes = Buffer.from(
        statement.buffer,
        statement.byteOffset,
        statement.byteLength,
    );
    let position = offset;
    return {
        next: (
            degree: number,
            polynomialModulus: bigint,
            limbBits: number,
        ): ParsedPolynomial => {
            const magnitudeBytes = byteLength(polynomialModulus);
            const half = (polynomialModulus - 1n) / 2n;
            const limbPowers = powers(
                power(alpha, degree),
                Math.ceil((8 * magnitudeBytes) / limbBits),
            );
            const width = BigInt(limbBits);
            const mask = (1n << width) - 1n;
            if (position + degree * (1 + magnitudeBytes) > bytes.length)
                throw new RangeError('The statement ends inside a polynomial.');
            const fingerprints: Extension[] = [];
            let total = zero;
            let weight = one;
            for (let index = 0; index < degree; index++) {
                const sign = bytes[position];
                const magnitude = BigInt(
                    `0x${Buffer.from(
                        bytes.subarray(
                            position + 1,
                            position + 1 + magnitudeBytes,
                        ),
                    )
                        .reverse()
                        .toString('hex')}`,
                );
                position += 1 + magnitudeBytes;
                if (
                    sign > 1 ||
                    magnitude > half ||
                    (sign === 1 && magnitude === 0n)
                )
                    throw new RangeError(
                        'A statement coefficient is not canonical.',
                    );
                let first = 0n,
                    second = 0n,
                    third = 0n;
                for (
                    let limb = 0, rest = magnitude;
                    rest > 0n;
                    limb++, rest >>= width
                ) {
                    const value = rest & mask;
                    first += value * limbPowers[limb][0];
                    second += value * limbPowers[limb][1];
                    third += value * limbPowers[limb][2];
                }
                const fingerprint: Extension =
                    sign === 1
                        ? [residue(-first), residue(-second), residue(-third)]
                        : [residue(first), residue(second), residue(third)];
                fingerprints.push(fingerprint);
                total = add(total, multiply(weight, fingerprint));
                weight = multiply(weight, alpha);
            }
            return { fingerprints, total };
        },
        finish: () => assert.equal(position, bytes.length),
    };
};

// The fingerprint of a public integer: its signed limbs at the powers of
// the limb weight.
const fingerprint = (
    value: bigint,
    limbBits: number,
    limbWeight: Extension,
): Extension => {
    const width = BigInt(limbBits);
    const mask = (1n << width) - 1n;
    let result = zero;
    for (
        let rest = value < 0n ? -value : value, weight = one;
        rest > 0n;
        rest >>= width, weight = multiply(weight, limbWeight)
    )
        result = add(result, scale(weight, rest & mask));
    return value < 0n ? negate(result) : result;
};

// Row i of a negacyclic product P*s has weight alpha^i, so s at position j
// takes adjoint[j] = sum_i alpha^i * sign * P[i - j], negative where the
// index wraps. Then adjoint[0] is the polynomial's total and adjoint[j + 1]
// = alpha * adjoint[j] - (alpha^n + 1) * P[n - 1 - j]; after n steps the
// recurrence returns to minus the total.
const negacyclicAdjoint = (
    polynomial: ParsedPolynomial,
    alpha: Extension,
): Extension[] => {
    const { fingerprints, total } = polynomial;
    const degree = fingerprints.length;
    const wrap = add(power(alpha, degree), one);
    const result: Extension[] = [];
    let current = total;
    for (let index = 0; index < degree; index++) {
        result.push(current);
        current = subtract(
            multiply(alpha, current),
            multiply(wrap, fingerprints[degree - 1 - index]),
        );
    }
    assert.ok(equal(current, negate(total)));
    return result;
};
const addWeighted = (
    accumulator: Extension[],
    weight: Extension,
    values: readonly Extension[],
) => {
    assert.equal(values.length, accumulator.length);
    values.forEach(
        (value, index) =>
            (accumulator[index] = add(
                accumulator[index],
                multiply(weight, value),
            )),
    );
};
const zeros = (length: number) => Array.from({ length }, () => zero);

const productionBallotLayout = {
    degree: Number(fixedModulusBfvInputs.polynomialDegree),
    auxiliaryDegree: Number(auxiliaryInputEncryptionParameters.degree),
    fheHalfSupport: Number(fixedModulusBfvInputs.secretSupportWeight / 2n),
    auxiliaryHalfSupport: Number(
        auxiliaryInputEncryptionParameters.support / 2n,
    ),
};
const ballotHeaderBytes = 4 + 64 + 64 + 2 + 1 + 1;

// Rows: each FHE ciphertext component's limbs, one ring degree per limb;
// the packing equation; each auxiliary component; then one row per support
// column. FHE component c is P_c*u + e_c + [c=0]*scale*m - Q*q_c = C_c in
// signed limbs with carries, where P_0 is the key and P_1 the common
// polynomial. The packing row is m - sum_option M_option*score_option -
// t*q = 0. The auxiliary components are single-limb encryptions whose first
// plaintext holds each score at its option's coefficient.
export const ballotRelationOperator = (
    profile: SupportedProfile,
    statement: Uint8Array,
    alpha: Extension,
    layout = productionBallotLayout,
): RelationOperator => {
    const { degree, auxiliaryDegree } = layout;
    const auxiliary = auxiliaryInputEncryptionParameters;
    const ciphertextModulus = profile.ciphertext.modulus;
    const plaintextModulus = fixedModulusBfvInputs.plaintextModulus;
    const limbBits = 96;
    const limbs = Math.ceil(bitLength(ciphertextModulus) / limbBits);
    assert.ok(bitLength(auxiliary.modulus) <= limbBits);
    if (
        statement.length !==
        ballotHeaderBytes +
            4 * degree * (1 + byteLength(ciphertextModulus)) +
            4 * auxiliaryDegree * (1 + byteLength(auxiliary.modulus))
    )
        throw new RangeError('The ballot statement has the wrong length.');
    const header = Buffer.from(statement.subarray(0, ballotHeaderBytes));
    const options = header[134],
        resultLength = header[135];
    if (
        header.toString('latin1', 0, 4) !== 'LBS1' ||
        header.readUInt16LE(132) >= profile.participantCount ||
        options !== profile.optionCount ||
        resultLength === 0 ||
        resultLength > options
    )
        throw new RangeError('The ballot statement header differs.');
    const columnLayout = compileBallotEncryptionColumnLayout(profile);
    const index = (name: string) => {
        const found = columnLayout.columns.findIndex(
            (value) => value.name === name,
        );
        assert.ok(found >= 0, name);
        return found;
    };
    const fheRow = (component: number) => component * limbs * degree;
    const packingRow = 2 * limbs * degree;
    const auxiliaryRow = (component: number) =>
        packingRow + degree + component * auxiliaryDegree;
    const builder = createOperatorBuilder(alpha, columnLayout.columns.length);
    // Each encryption's common polynomial and key enter its ephemeral's
    // adjoint through the second and first component; each ciphertext
    // component enters its equation's target.
    const reader = createStatementReader(statement, ballotHeaderBytes, alpha);
    const fheEphemeral = zeros(degree),
        auxiliaryEphemeral = zeros(auxiliaryDegree);
    for (const [ephemeral, polynomialDegree, polynomialModulus, row] of [
        [fheEphemeral, degree, ciphertextModulus, fheRow],
        [auxiliaryEphemeral, auxiliaryDegree, auxiliary.modulus, auxiliaryRow],
    ] as const) {
        const next = () =>
            reader.next(polynomialDegree, polynomialModulus, limbBits);
        addWeighted(
            ephemeral,
            power(alpha, row(1)),
            negacyclicAdjoint(next(), alpha),
        );
        addWeighted(
            ephemeral,
            power(alpha, row(0)),
            negacyclicAdjoint(next(), alpha),
        );
        for (const component of [0, 1])
            builder.addTarget(
                multiply(power(alpha, row(component)), next().total),
            );
    }
    reader.finish();
    const limbWeight = power(alpha, degree);
    const plaintextScale =
        (ciphertextModulus + plaintextModulus / 2n) / plaintextModulus;
    // The plaintext is its offset lower word plus 65,536 times its high
    // bit.
    const plaintext: Variable = {
        terms: [
            [index('plaintext-lower-word'), 1n],
            [index('plaintext-high-bit'), 65536n],
        ],
        offset: -32768n,
    };
    for (const component of [0, 1]) {
        const weight = power(alpha, fheRow(component));
        builder.putGeometric(
            signedWord(index(`fhe-quotient-${component}`), 16),
            degree,
            negate(
                multiply(
                    weight,
                    fingerprint(ciphertextModulus, limbBits, limbWeight),
                ),
            ),
        );
        builder.putGeometric(
            signedWord(index(`fhe-error-${component}`), 7),
            degree,
            weight,
        );
        for (let carry = 0; carry < limbs - 1; carry++)
            builder.putGeometric(
                signedWord(index(`fhe-carry-${component}-${carry}`), 16),
                degree,
                multiply(
                    multiply(weight, power(limbWeight, carry)),
                    subtract(limbWeight, base(1n << BigInt(limbBits))),
                ),
            );
        if (component === 0)
            builder.putGeometric(
                plaintext,
                degree,
                multiply(
                    weight,
                    fingerprint(plaintextScale, limbBits, limbWeight),
                ),
            );
    }
    const packingWeight = power(alpha, packingRow);
    builder.putGeometric(plaintext, degree, packingWeight);
    builder.putGeometric(
        signedWord(index('packing-quotient'), 16),
        degree,
        scale(packingWeight, -plaintextModulus),
    );
    // The scores column holds each score less one at its option's row.
    const rowPowers = powers(alpha, degree);
    const scores = zeros(degree);
    ballotPackingMatrix(degree, profile.optionCount).columns.forEach(
        (coefficients, option) => {
            let value = zero;
            coefficients.forEach((coefficient, position) => {
                if (coefficient !== 0n)
                    value = add(value, scale(rowPowers[position], coefficient));
            });
            scores[option] = subtract(
                scores[option],
                multiply(packingWeight, value),
            );
        },
    );
    for (const component of [0, 1]) {
        const weight = power(alpha, auxiliaryRow(component));
        builder.putGeometric(
            signedWord(index(`auxiliary-quotient-${component}`), 16),
            auxiliaryDegree,
            scale(weight, -auxiliary.modulus),
        );
        builder.putGeometric(
            signedWord(index(`auxiliary-error-${component}`), 7),
            auxiliaryDegree,
            weight,
        );
        if (component === 0)
            for (let option = 0; option < profile.optionCount; option++)
                scores[option] = add(
                    scores[option],
                    scale(multiply(weight, rowPowers[option]), auxiliary.scale),
                );
    }
    builder.put(
        { terms: [[index('score-minus-one'), 1n]], offset: 1n },
        'scores',
        { kind: 'values', values: scores },
        one,
    );
    builder.put(
        sparse(index('fhe-positive-support')),
        'fhe-ephemeral',
        { kind: 'values', values: fheEphemeral },
        one,
    );
    builder.put(
        sparse(index('auxiliary-positive-support')),
        'auxiliary-ephemeral',
        { kind: 'values', values: auxiliaryEphemeral },
        one,
    );
    // Each support column sums to half of its secret's support.
    let row = auxiliaryRow(2);
    for (const [positive, supportDegree, half] of [
        [index('fhe-positive-support'), degree, layout.fheHalfSupport],
        [
            index('auxiliary-positive-support'),
            auxiliaryDegree,
            layout.auxiliaryHalfSupport,
        ],
    ] as const)
        for (const supportColumn of [positive, positive + 1]) {
            const weight = power(alpha, row++);
            builder.putOnes(column(supportColumn), supportDegree, weight);
            builder.addTarget(scale(weight, BigInt(half)));
        }
    return builder.finish(power(alpha, row));
};

const productionReleaseLayout = {
    degree: Number(fixedModulusBfvInputs.polynomialDegree),
    recipientHalfSupport: Number(
        shareEncryptionParameters.encryptionSupportWeight / 2n,
    ),
};
const releaseHeaderBytes = 4 + 3 * 64 + 2;

// Rows: the recipient key equation's two decoding limbs, the aggregate
// decoding equation's two decoding limbs, every release output limb, then
// one row per support column. A signed variable occupies whole 16-bit words
// of its value offset by half its range; a part of it is offset by half the
// part's range when it is centered. The decoding equation splits the share
// into a centered lower decoding limb and the signed rest, so share = lower
// + radix*upper + radix/2.
export const releaseRelationOperator = (
    profile: SupportedProfile,
    statement: Uint8Array,
    alpha: Extension,
    layout = productionReleaseLayout,
): RelationOperator => {
    const { degree } = layout;
    const share = shareEncryptionParameters;
    const releaseModulus = profile.release.modulus;
    const lifting = profile.releaseLifting;
    const decodingLimbBits = 96;
    const releaseLimbBits = 48;
    if (
        statement.length !==
        releaseHeaderBytes +
            4 * degree * (1 + byteLength(share.modulus)) +
            2 * degree * (1 + byteLength(releaseModulus))
    )
        throw new RangeError('The release statement has the wrong length.');
    const header = Buffer.from(statement.subarray(0, releaseHeaderBytes));
    if (
        header.toString('latin1', 0, 4) !== 'LRS1' ||
        header.readUInt16LE(releaseHeaderBytes - 2) >= profile.participantCount
    )
        throw new RangeError('The release statement header differs.');
    const columnLayout = compileLinkedReleaseColumnLayout(profile);
    const variable = (name: string) => {
        const found = columnLayout.columns.find((value) => value.name === name);
        assert.ok(found !== undefined, name);
        return found;
    };
    const builder = createOperatorBuilder(
        alpha,
        columnLayout.wordColumns + columnLayout.booleanColumns,
    );
    const limbWeight = power(alpha, degree);
    const decoding = power(alpha, 2 * degree);
    const release = power(alpha, 4 * degree);
    // The common polynomial and the aggregate share ciphertext's linear
    // component enter the recipient secret's adjoint; the key and the
    // constant component enter their equations' targets; the target's
    // linear component gives the share its public basis in the release
    // rows, and the partial decryption enters their target.
    const reader = createStatementReader(statement, releaseHeaderBytes, alpha);
    const shareNext = () =>
        reader.next(degree, share.modulus, decodingLimbBits);
    const recipient = negacyclicAdjoint(shareNext(), alpha);
    builder.addTarget(negate(shareNext().total));
    builder.addTarget(negate(multiply(decoding, shareNext().total)));
    addWeighted(recipient, decoding, negacyclicAdjoint(shareNext(), alpha));
    const shareBasis: PublicColumn = {
        kind: 'values',
        values: negacyclicAdjoint(
            reader.next(degree, releaseModulus, releaseLimbBits),
            alpha,
        ),
    };
    builder.addTarget(
        multiply(
            release,
            reader.next(degree, releaseModulus, releaseLimbBits).total,
        ),
    );
    reader.finish();
    // The words of bits first..first+width of a signed variable, offset by
    // half the part's range when it is centered.
    const part = (
        name: string,
        first: number,
        width: number,
        centered: boolean,
    ): Variable => {
        const found = variable(name);
        assert.ok(first % 16 === 0 && first + width <= found.bits);
        return {
            terms: Array.from(
                { length: Math.ceil(width / 16) },
                (_unused, word) =>
                    [
                        found.firstColumn + first / 16 + word,
                        1n << BigInt(16 * word),
                    ] as const,
            ),
            offset: centered ? -(1n << BigInt(width - 1)) : 0n,
        };
    };
    const whole = (name: string) => part(name, 0, variable(name).bits, true);
    // Each release limb of a signed variable: unsigned lower limbs and a
    // centered top limb.
    const releaseLimbs = (name: string) => {
        const bits = variable(name).bits;
        const count = Math.ceil(bits / releaseLimbBits);
        return Array.from({ length: count }, (_unused, limb) => {
            const first = limb * releaseLimbBits;
            const top = limb === count - 1;
            return part(name, first, top ? bits - first : releaseLimbBits, top);
        });
    };
    const decodingCarry = subtract(
        limbWeight,
        base(1n << BigInt(decodingLimbBits)),
    );
    const shareModulus = fingerprint(
        share.modulus,
        decodingLimbBits,
        limbWeight,
    );
    // common*s + key - Q_s*q - e = 0 in two decoding limbs.
    builder.putGeometric(whole('key-quotient'), degree, negate(shareModulus));
    builder.putGeometric(whole('key-carry'), degree, decodingCarry);
    builder.putGeometric(whole('key-error'), degree, negate(one));
    // linear*s + constant - scale*share - Q_s*q - e = 0 in two decoding
    // limbs, with the scaled half radix in the target.
    builder.putGeometric(whole('decoding-error'), degree, negate(decoding));
    builder.putGeometric(
        whole('decoding-quotient'),
        degree,
        negate(multiply(decoding, shareModulus)),
    );
    builder.putGeometric(
        whole('decoding-carry'),
        degree,
        multiply(decoding, decodingCarry),
    );
    const shareBits = variable('aggregate-share').bits;
    builder.putGeometric(
        part('aggregate-share', 0, decodingLimbBits, true),
        degree,
        scale(decoding, -share.scale),
    );
    builder.putGeometric(
        part(
            'aggregate-share',
            decodingLimbBits,
            shareBits - decodingLimbBits,
            true,
        ),
        degree,
        scale(multiply(decoding, limbWeight), -share.scale),
    );
    builder.addTarget(
        multiply(
            multiply(
                decoding,
                fingerprint(
                    share.scale << BigInt(decodingLimbBits - 1),
                    decodingLimbBits,
                    limbWeight,
                ),
            ),
            powers(alpha, degree).reduce(add, zero),
        ),
    );
    // c*(target*share + noise) - partial - Q_r*quotient = 0 in release
    // limbs with carries, where c is the profile's clearing factor.
    const clearing = lifting.clearingFactor;
    releaseLimbs('aggregate-share').forEach((limb, index) =>
        builder.put(
            limb,
            'share-basis',
            shareBasis,
            scale(multiply(release, power(limbWeight, index)), clearing),
        ),
    );
    releaseLimbs('release-noise').forEach((limb, index) =>
        builder.putGeometric(
            limb,
            degree,
            scale(multiply(release, power(limbWeight, index)), clearing),
        ),
    );
    const releaseModulusFingerprint = fingerprint(
        releaseModulus,
        releaseLimbBits,
        limbWeight,
    );
    releaseLimbs('release-quotient').forEach((limb, index) =>
        builder.putGeometric(
            limb,
            degree,
            negate(
                multiply(
                    multiply(release, power(limbWeight, index)),
                    releaseModulusFingerprint,
                ),
            ),
        ),
    );
    for (let carry = 0; carry < lifting.outputLimbs - 1; carry++)
        builder.putGeometric(
            whole(`release-carry-${carry}`),
            degree,
            multiply(
                multiply(release, power(limbWeight, carry)),
                subtract(limbWeight, base(1n << BigInt(releaseLimbBits))),
            ),
        );
    builder.put(
        sparse(columnLayout.positiveSecretColumn),
        'recipient-secret',
        { kind: 'values', values: recipient },
        one,
    );
    const rows = (4 + lifting.outputLimbs) * degree;
    for (const sign of [0, 1]) {
        const weight = power(alpha, rows + sign);
        builder.putOnes(
            column(columnLayout.positiveSecretColumn + sign),
            degree,
            weight,
        );
        builder.addTarget(scale(weight, BigInt(layout.recipientHalfSupport)));
    }
    return builder.finish(power(alpha, rows + 2));
};

const productionSetupLayout = {
    degree: Number(fixedModulusBfvInputs.polynomialDegree),
    fheHalfSupport: Number(fixedModulusBfvInputs.secretSupportWeight / 2n),
    shareHalfSupport: Number(
        shareEncryptionParameters.encryptionSupportWeight / 2n,
    ),
};
const gadgetPolynomials = 7;
const setupHeader = (profile: SupportedProfile, degree: number) =>
    Buffer.concat([
        Buffer.from('SCO2', 'latin1'),
        littleEndian(BigInt(degree), 4),
        ...[profile.ciphertext.modulus, shareEncryptionParameters.modulus].map(
            (value) => littleEndian(value, byteLength(value)),
        ),
    ]);

// Variables in allocation order: the FHE secret, its auxiliary secret and
// each recipient's share ephemeral as positive and negative Boolean columns;
// each sharing coefficient's low and high limb parts; then each equation's
// quotient, carries and error. A signed variable takes whole 16-bit words,
// then one Boolean column per remaining bit, or one narrow word. Rows: for
// each gadget coordinate its encryption, two relinearization and
// automorphism key equations; for each recipient the constant and linear
// components of its share ciphertext; then one row per support column.
export const setupRelationOperator = (
    profile: SupportedProfile,
    statement: Uint8Array,
    alpha: Extension,
    layout = productionSetupLayout,
): RelationOperator => {
    const { degree } = layout;
    const { quotientBits, fheCarryBits, errorBits } = setupEquationWidths;
    const share = shareEncryptionParameters;
    const ciphertextModulus = profile.ciphertext.modulus;
    const fheLimbBits = 96;
    const fheLimbs = Math.ceil(bitLength(ciphertextModulus) / fheLimbBits);
    const { limbBits, carryBits, sharingCoefficientBits } =
        profile.shareLifting;
    const gadgetLength = Number(profile.gadgetLength);
    const participants = profile.participantCount;
    const shareCommon = gadgetPolynomials * gadgetLength;
    const polynomialCount = shareCommon + 3 * participants + 1;
    const header = setupHeader(profile, degree);
    if (
        statement.length !==
        header.length +
            shareCommon * degree * (1 + byteLength(ciphertextModulus)) +
            (polynomialCount - shareCommon) *
                degree *
                (1 + byteLength(share.modulus))
    )
        throw new RangeError('The setup statement has the wrong length.');
    if (!header.equals(statement.subarray(0, header.length)))
        throw new RangeError('The setup statement header differs.');
    const shape = deriveSetupContributionShape(profile);
    const columns = shape.wordColumns + shape.booleanColumns;
    const builder = createOperatorBuilder(alpha, columns);
    let nextWord = 0;
    let nextBoolean = shape.wordColumns;
    const signed = (width: number): Variable => {
        const terms: (readonly [number, bigint])[] = [];
        let remaining = width,
            shift = 0;
        while (remaining >= 16 || shift === 0) {
            const bits = Math.min(16, remaining);
            terms.push([nextWord++, 1n << BigInt(shift)]);
            remaining -= bits;
            shift += bits;
        }
        for (let bit = 0; bit < remaining; bit++)
            terms.push([nextBoolean++, 1n << BigInt(shift + bit)]);
        return { terms, offset: -(1n << BigInt(width - 1)) };
    };
    const supports: (readonly [number, number])[] = [];
    const allocateSparse = (halfSupport: number) => {
        const positive = nextBoolean;
        nextBoolean += 2;
        supports.push([positive, halfSupport], [positive + 1, halfSupport]);
        return sparse(positive);
    };
    const secret = allocateSparse(layout.fheHalfSupport);
    const auxiliary = allocateSparse(layout.fheHalfSupport);
    const ephemerals = Array.from({ length: participants }, () =>
        allocateSparse(layout.shareHalfSupport),
    );
    const sharing = Array.from(
        { length: profile.releaseThreshold - 1 },
        () => ({
            low: signed(limbBits),
            high: signed(sharingCoefficientBits - limbBits),
        }),
    );
    // Each common polynomial's convolved variables and their row weights,
    // and each value polynomial's signed row weights.
    const commonUses = new Map<
        number,
        { variable: Variable; weight: Extension }[]
    >();
    const valueUses = new Map<number, Extension[]>();
    let weight = one;
    const register = (
        commonIndex: number,
        valueIndex: number,
        convolved: Variable,
        valueSign: bigint,
    ) => {
        commonUses.set(commonIndex, [
            ...(commonUses.get(commonIndex) ?? []),
            { variable: convolved, weight },
        ]);
        valueUses.set(valueIndex, [
            ...(valueUses.get(valueIndex) ?? []),
            scale(weight, valueSign),
        ]);
    };
    const limbWeight = power(alpha, degree);
    const fheModulus = fingerprint(ciphertextModulus, fheLimbBits, limbWeight);
    // common*convolved + direct + value - Q*q - error = 0 in FHE limbs.
    const key = (
        commonIndex: number,
        valueIndex: number,
        convolved: Variable,
        direct?: Readonly<{
            variable: Variable;
            factor: Extension;
            automorphism: number;
        }>,
    ) => {
        const quotient = signed(quotientBits);
        const carries = Array.from({ length: fheLimbs - 1 }, () =>
            signed(fheCarryBits),
        );
        const error = signed(errorBits);
        register(commonIndex, valueIndex, convolved, 1n);
        if (direct !== undefined)
            builder.putGeometric(
                direct.variable,
                degree,
                multiply(weight, direct.factor),
                direct.automorphism,
            );
        builder.putGeometric(
            quotient,
            degree,
            negate(multiply(weight, fheModulus)),
        );
        builder.putGeometric(error, degree, negate(weight));
        let factor = subtract(limbWeight, base(1n << BigInt(fheLimbBits)));
        for (const carry of carries) {
            builder.putGeometric(carry, degree, multiply(weight, factor));
            factor = multiply(factor, limbWeight);
        }
        weight = multiply(weight, power(limbWeight, fheLimbs));
    };
    for (let gadget = 0; gadget < gadgetLength; gadget++) {
        const gadgetDigit = fingerprint(
            fixedModulusBfvInputs.gadgetBase ** BigInt(gadget),
            fheLimbBits,
            limbWeight,
        );
        const first = gadgetPolynomials * gadget;
        key(first, first + 1, secret);
        key(first, first + 2, auxiliary, {
            variable: secret,
            factor: negate(gadgetDigit),
            automorphism: 1,
        });
        key(first + 3, first + 4, secret, {
            variable: auxiliary,
            factor: gadgetDigit,
            automorphism: 1,
        });
        key(first + 5, first + 6, secret, {
            variable: secret,
            factor: negate(gadgetDigit),
            automorphism: 5,
        });
    }
    // key*ephemeral + scale*(secret + sum_k sharing_k*Z^(a*(k+1))) +
    // error - Q_s*q = constant, and common*ephemeral + error - Q_s*q =
    // linear, in two share limbs. Each sharing coefficient is low +
    // radix*high + radix/2, so the target takes the halves' images.
    const shareRadix = 1n << BigInt(limbBits);
    const shareModulus = fingerprint(share.modulus, limbBits, limbWeight);
    const pointStride = degree / interpolationRingDegree(participants);
    assert.ok(Number.isInteger(pointStride));
    const rowPowers = powers(alpha, degree);
    const encryptedShare = (
        commonIndex: number,
        valueIndex: number,
        ephemeral: Variable,
        point?: number,
    ) => {
        const quotient = signed(quotientBits);
        const carry = signed(point === undefined ? fheCarryBits : carryBits);
        const error = signed(errorBits);
        register(commonIndex, valueIndex, ephemeral, -1n);
        if (point !== undefined) {
            const messageWeight = scale(weight, share.scale);
            builder.putGeometric(secret, degree, messageWeight);
            const units = Array.from({ length: degree }, () => 0n);
            sharing.forEach(({ low, high }, coefficient) => {
                const shift = (point * (coefficient + 1)) % (2 * degree);
                builder.putGeometric(low, degree, messageWeight, 1, shift);
                builder.putGeometric(
                    high,
                    degree,
                    multiply(messageWeight, limbWeight),
                    1,
                    shift,
                );
                for (let input = 0; input < degree; input++) {
                    const exponent = (input + shift) % (2 * degree);
                    units[exponent % degree] += exponent < degree ? 1n : -1n;
                }
            });
            const unit = share.scale * (shareRadix / 2n);
            const offsets = new Map<bigint, Extension>();
            let offsetSum = zero;
            units.forEach((count, position) => {
                let offset = offsets.get(count);
                if (offset === undefined) {
                    offset = fingerprint(count * unit, limbBits, limbWeight);
                    offsets.set(count, offset);
                }
                offsetSum = add(
                    offsetSum,
                    multiply(rowPowers[position], offset),
                );
            });
            builder.addTarget(negate(multiply(weight, offsetSum)));
        }
        builder.putGeometric(
            quotient,
            degree,
            negate(multiply(weight, shareModulus)),
        );
        builder.putGeometric(
            carry,
            degree,
            multiply(weight, subtract(limbWeight, base(shareRadix))),
        );
        builder.putGeometric(error, degree, weight);
        weight = multiply(weight, multiply(limbWeight, limbWeight));
    };
    ephemerals.forEach((ephemeral, recipient) => {
        const recipientKey = shareCommon + 1 + 3 * recipient;
        encryptedShare(
            recipientKey,
            recipientKey + 1,
            ephemeral,
            recipient * pointStride,
        );
        encryptedShare(shareCommon, recipientKey + 2, ephemeral);
    });
    for (const [supportColumn, half] of supports) {
        builder.putOnes(column(supportColumn), degree, weight);
        builder.addTarget(scale(weight, BigInt(half)));
        weight = multiply(weight, alpha);
    }
    assert.equal(nextWord, shape.wordColumns);
    assert.equal(nextBoolean, columns);
    // Each polynomial is common, entering its convolved variables'
    // adjoints, or a value, entering the target.
    const adjoints = new Map<Variable, Extension[]>();
    const reader = createStatementReader(statement, header.length, alpha);
    for (let index = 0; index < polynomialCount; index++) {
        const fhe = index < shareCommon;
        const polynomial = reader.next(
            degree,
            fhe ? ciphertextModulus : share.modulus,
            fhe ? fheLimbBits : limbBits,
        );
        const uses = commonUses.get(index);
        const values = valueUses.get(index);
        assert.ok((uses === undefined) !== (values === undefined), `${index}`);
        if (uses !== undefined) {
            const adjoint = negacyclicAdjoint(polynomial, alpha);
            for (const use of uses) {
                let accumulator = adjoints.get(use.variable);
                if (accumulator === undefined) {
                    accumulator = zeros(degree);
                    adjoints.set(use.variable, accumulator);
                }
                addWeighted(accumulator, use.weight, adjoint);
            }
        } else
            for (const value of values!)
                builder.addTarget(negate(multiply(value, polynomial.total)));
    }
    reader.finish();
    for (const [variable, values] of adjoints)
        builder.put(
            variable,
            `adjoint:${variable.terms[0][0]}`,
            { kind: 'values', values },
            one,
        );
    return builder.finish(weight);
};

// Each column's coefficient at every row of a systematic subgroup.
export const relationOperatorColumns = (
    operator: RelationOperator,
    systematic: number,
) => {
    const output = Array.from({ length: operator.columns }, () =>
        zeros(systematic),
    );
    for (const term of operator.terms) {
        const values = publicColumnValues(term.public, operator.alpha);
        const stride = systematic / values.length;
        assert.ok(Number.isInteger(stride) && stride >= 1);
        for (const [index, weight] of term.weights)
            values.forEach(
                (value, position) =>
                    (output[index][stride * position] = add(
                        output[index][stride * position],
                        multiply(weight, value),
                    )),
            );
    }
    return output;
};

// Each column's interpolated coefficient at the domain positions: the
// weighted sum of its public columns' interpolants there, where ones on
// every row interpolate to one. Operators at one challenge and positions
// share the evaluations of the challenge's powers and of ones through the
// cache.
export const evaluateRelationOperator = (
    operator: RelationOperator,
    domain: WordProofDomain,
    positions: readonly number[],
    cache = new Map<string, readonly Extension[]>(),
) => {
    const prefix = `${operator.alpha.join(',')}/${domain.systematic}/${positions.join(',')}/`;
    const coefficients = Array.from({ length: operator.columns }, () =>
        positions.map(() => zero),
    );
    for (const term of operator.terms) {
        let values: readonly Extension[] | undefined;
        if (
            term.public.kind === 'ones' &&
            term.public.degree === domain.systematic
        )
            values = positions.map(() => one);
        const cacheKey =
            term.public.kind === 'values' ? undefined : prefix + term.key;
        if (cacheKey !== undefined) values ??= cache.get(cacheKey);
        if (values === undefined) {
            const placed = publicColumnValues(term.public, operator.alpha);
            const stride = domain.systematic / placed.length;
            assert.ok(Number.isInteger(stride) && stride >= 1);
            const dense = zeros(domain.systematic);
            placed.forEach((value, index) => (dense[stride * index] = value));
            values = evaluateSystematicColumns(domain, [dense], positions)[0];
            if (cacheKey !== undefined) cache.set(cacheKey, values);
        }
        for (const [index, weight] of term.weights)
            values.forEach(
                (value, position) =>
                    (coefficients[index][position] = add(
                        coefficients[index][position],
                        multiply(weight, value),
                    )),
            );
    }
    return {
        positions,
        coefficients,
        target: operator.target,
        lookupWeight: operator.lookupWeight,
    };
};

// The operator applied to integer witness columns over the systematic
// subgroup: the alpha-weighted sum of every row's left side.
export const applyRelationOperator = (
    operator: RelationOperator,
    witness: readonly (readonly bigint[])[],
) => {
    assert.equal(witness.length, operator.columns);
    let total = zero;
    for (const term of operator.terms) {
        const values = publicColumnValues(term.public, operator.alpha);
        for (const [index, weight] of term.weights) {
            const stride = witness[index].length / values.length;
            assert.ok(Number.isInteger(stride) && stride >= 1);
            let dot = zero;
            values.forEach(
                (value, position) =>
                    (dot = add(
                        dot,
                        scale(value, witness[index][stride * position]),
                    )),
            );
            total = add(total, multiply(weight, dot));
        }
    }
    return total;
};
