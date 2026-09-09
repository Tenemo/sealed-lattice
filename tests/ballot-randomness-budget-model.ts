import { auxiliaryInputEncryptionParameters } from '#tests/auxiliary-input-encryption-parameters.js';
import { fixedModulusBfvInputs } from '#tests/fixed-modulus-bfv-model.js';
import { compileBallotWordProofLayout } from '#tests/full-word-proof-layout-model.js';
import { setupGaussianParameters } from '#tests/setup-randomness-model.js';
import { compileSmallLimbProofFieldCensus } from '#tests/small-limb-proof-field-model.js';

const choose = (population: bigint, count: bigint): bigint => {
    let value = 1n;
    for (let index = 1n; index <= count; index++)
        value = (value * (population - index + 1n)) / index;
    return value;
};
const rounded = (bytes: bigint, block: bigint) =>
    ((bytes + block - 1n) / block) * block;
type FailureBound = Readonly<{ numerator: bigint; denominatorBits: bigint }>;
const bitFloor = ({ numerator, denominatorBits }: FailureBound) => {
    let bits = 0n;
    while (numerator << (bits + 1n) <= 1n << denominatorBits) bits++;
    return bits;
};
const combine = (values: readonly FailureBound[]): FailureBound => {
    const denominatorBits = values.reduce(
        (maximum, value) =>
            value.denominatorBits > maximum ? value.denominatorBits : maximum,
        0n,
    );
    return {
        denominatorBits,
        numerator: values.reduce(
            (sum, value) =>
                sum +
                (value.numerator << (denominatorBits - value.denominatorBits)),
            0n,
        ),
    };
};

// A prospective finite journal of actual independent random bytes. The budget
// is consumed by the replay experiment, not a new pseudorandom generator.
export const compileBallotRandomnessBudget = () => {
    const readBytes = 65_536n;
    const exhaustionAllocationBits = 128n;
    const participantCount = fixedModulusBfvInputs.participantCount;
    const field = compileSmallLimbProofFieldCensus();
    const proof = compileBallotWordProofLayout();
    const rejectedFieldValues = (1n << field.modulusBitLength) - field.modulus;
    const proofFailure = (extraReads: bigint): FailureBound => {
        const rejections = extraReads + 1n;
        const budget =
            proof.minimumRequestedRandomBytes + extraReads * readBytes;
        // Counting all budget bytes as candidate field elements deliberately
        // includes salts and unused tails. An adaptive examined subset is smaller.
        const candidates = budget / field.packedFieldElementByteLength;
        return {
            numerator:
                participantCount *
                choose(candidates, rejections) *
                rejectedFieldValues ** rejections,
            denominatorBits: field.modulusBitLength * rejections,
        };
    };
    const sparse = [
        {
            degree: fixedModulusBfvInputs.polynomialDegree,
            support: fixedModulusBfvInputs.secretSupportWeight,
        },
        {
            degree: auxiliaryInputEncryptionParameters.degree,
            support: auxiliaryInputEncryptionParameters.support,
        },
    ].map(({ degree, support }) => {
        if (
            degree <= support ||
            support <= 0n ||
            (degree & (degree - 1n)) !== 0n ||
            (1n << 32n) % degree !== 0n
        )
            throw new Error(
                'The sparse-sampling uniform-index premise failed.',
            );
        const draws = 2n * support;
        const failures = support + 1n;
        const denominatorBits =
            BigInt(degree.toString(2).length - 1) * failures;
        return {
            degree,
            support,
            draws,
            failure: {
                numerator:
                    participantCount *
                    choose(draws, failures) *
                    (support - 1n) ** failures,
                denominatorBits,
            },
        };
    });
    let extraProofReads = 0n;
    while (
        bitFloor(
            combine([
                proofFailure(extraProofReads),
                ...sparse.map((value) => value.failure),
            ]),
        ) < exhaustionAllocationBits
    )
        extraProofReads++;
    const maximumProofBytes =
        proof.minimumRequestedRandomBytes + extraProofReads * readBytes;
    const gaussianBytes =
        2n *
        sparse.reduce((sum, value) => sum + value.degree, 0n) *
        (setupGaussianParameters.sampleBits / 8n);
    const sparseBytes = sparse.reduce(
        (sum, value) => sum + 4n * value.draws,
        0n,
    );
    const maximumEncryptionBytes = rounded(
        gaussianBytes + sparseBytes,
        readBytes,
    );
    const exhaustionBound = combine([
        proofFailure(extraProofReads),
        ...sparse.map((value) => value.failure),
    ]);
    return {
        participantCount,
        readBytes,
        exhaustionAllocationBits,
        extraProofReads,
        maximumProofBytes,
        gaussianBytes,
        sparseBytes,
        maximumEncryptionBytes,
        totalRandomBytes: maximumProofBytes + maximumEncryptionBytes,
        sparse,
        exhaustionBound,
        exhaustionBits: bitFloor(exhaustionBound),
    };
};
