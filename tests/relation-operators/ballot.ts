import assert from 'node:assert/strict';

import { auxiliaryInputEncryptionParameters } from '#tests/auxiliary-input-encryption-parameters.js';
import {
    ballotPackingMatrix,
    compileBallotEncryptionColumnLayout,
} from '#tests/ballot-encryption-relation-model.js';
import { bitLength, byteLength } from '#tests/exact-integer.js';
import { fixedModulusBfvInputs } from '#tests/fixed-modulus-bfv-model.js';
import {
    negate,
    power,
    powers,
    type RelationOperator,
    type Variable,
    column,
    sparse,
    signedWord,
    createOperatorBuilder,
    createStatementReader,
    fingerprint,
    negacyclicAdjoint,
    addWeighted,
    zeros,
} from '#tests/relation-operator-model.js';
import { type SupportedProfile } from '#tests/supported-profile-model.js';
import {
    type Extension,
    wordFieldArithmetic,
} from '#tests/word-proof-reference/field.js';

const { zero, one, base, add, subtract, multiply, scale } = wordFieldArithmetic;

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
