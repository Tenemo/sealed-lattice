import { auxiliaryInputEncryptionParameters } from '#tests/auxiliary-input-encryption-parameters.js';
import { fixedModulusBfvInputs } from '#tests/fixed-modulus-bfv-model.js';

export const sourceCiphertextBytes =
    4n *
    fixedModulusBfvInputs.polynomialDegree *
    (1n +
        BigInt(
            Math.ceil(
                auxiliaryInputEncryptionParameters.modulus.toString(2).length /
                    8,
            ),
        ));
const chunk = 1n << 20n;
const gcd = (left: bigint, right: bigint): bigint =>
    right === 0n ? left : gcd(right, left % right);
export const sourceReadBytes = (() => {
    let largest = 0n;
    for (
        let offset = 0n;
        offset < chunk;
        offset += gcd(chunk, sourceCiphertextBytes)
    ) {
        const bytes =
            ((offset + sourceCiphertextBytes + chunk - 1n) / chunk) * chunk;
        if (bytes > largest) largest = bytes;
    }
    return largest;
})();
export const sourceStatementPolynomialBytes = 2n * sourceCiphertextBytes;
export const sourceStatementPolynomialCount = 8n;
export const sourceOperandPolynomials = (firstExpandedIndex: number) => {
    if (!Number.isSafeInteger(firstExpandedIndex) || firstExpandedIndex < 0)
        throw new RangeError('Invalid first source operand index.');
    return Array.from(
        { length: Number(sourceStatementPolynomialCount) },
        (_, index) => ({
            expandedIndex: firstExpandedIndex + index,
            bytes:
                sourceStatementPolynomialBytes / sourceStatementPolynomialCount,
            coefficients: fixedModulusBfvInputs.polynomialDegree,
        }),
    );
};
// Allow both public source representations beside the new witness columns.
export const sourceWorkingBytes =
    2n * 8n * fixedModulusBfvInputs.polynomialDegree * 8n;
