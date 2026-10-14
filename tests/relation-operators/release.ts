import assert from 'node:assert/strict';

import { byteLength } from '#tests/exact-integer.js';
import { fixedModulusBfvInputs } from '#tests/fixed-modulus-bfv-model.js';
import { compileLinkedReleaseColumnLayout } from '#tests/linked-release-relation-model.js';
import {
    zero,
    one,
    base,
    add,
    subtract,
    multiply,
    scale,
    negate,
    power,
    powers,
    type PublicColumn,
    type RelationOperator,
    type Variable,
    column,
    sparse,
    createOperatorBuilder,
    createStatementReader,
    fingerprint,
    negacyclicAdjoint,
    addWeighted,
} from '#tests/relation-operator-model.js';
import { type SupportedProfile } from '#tests/supported-profile-model.js';
import { shareEncryptionParameters } from '#tests/wide-share-lifting-model.js';
import { type Extension } from '#tests/word-proof-reference/field.js';

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
