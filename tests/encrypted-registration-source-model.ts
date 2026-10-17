import { auxiliaryInputEncryptionParameters } from '#tests/auxiliary-input-encryption-parameters.js';
import { fixedModulusBfvInputs } from '#tests/fixed-modulus-bfv-model.js';

export const sourceCiphertextPolynomialCount = 2n;
export const sourcePlaintextModulus = 769n;
export const sourceMessageScale =
    (auxiliaryInputEncryptionParameters.modulus - 1n) / sourcePlaintextModulus;
export const sourceMessageMaximum =
    3n * (2n * fixedModulusBfvInputs.errorBound) - 1n;
export const sourceGoodKeyPhaseError =
    (2n * auxiliaryInputEncryptionParameters.support + 1n) *
    fixedModulusBfvInputs.errorBound;
export const sourceMaximumPhase =
    sourceMessageScale * sourceMessageMaximum + sourceGoodKeyPhaseError;
export const sourceCiphertextBytes =
    sourceCiphertextPolynomialCount *
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
export const sourceStatementPolynomialCount =
    2n * sourceCiphertextPolynomialCount;
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
    2n *
    sourceStatementPolynomialCount *
    fixedModulusBfvInputs.polynomialDegree *
    8n;
