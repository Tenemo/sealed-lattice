import { auxiliaryInputEncryptionParameters } from '#tests/auxiliary-input-encryption-parameters.js';
import { fixedModulusBfvInputs } from '#tests/fixed-modulus-bfv-model.js';
import { compileBallotWordProofLayout } from '#tests/full-word-proof-layout-model.js';
import { compileRegistrationEnrollmentCensus } from '#tests/registration-enrollment-model.js';

export const compileBallotBodyCensus = () => {
    const proof = compileBallotWordProofLayout();
    const polynomialBytes = (degree: bigint, modulus: bigint) =>
        degree * (1n + BigInt(Math.ceil(modulus.toString(2).length / 8)));
    const fheBytes = polynomialBytes(
        fixedModulusBfvInputs.polynomialDegree,
        fixedModulusBfvInputs.ciphertextModulus,
    );
    const auxiliaryBytes = polynomialBytes(
        auxiliaryInputEncryptionParameters.degree,
        auxiliaryInputEncryptionParameters.modulus,
    );
    const polynomials = [
        { expandedIndex: 2, bytes: fheBytes },
        { expandedIndex: 3, bytes: fheBytes },
        { expandedIndex: 6, bytes: auxiliaryBytes },
        { expandedIndex: 7, bytes: auxiliaryBytes },
    ];
    const contextBytes = 4n + 64n + 64n + 2n + 1n + 1n;
    const headerBytes = 4n + 8n + contextBytes;
    const ciphertextBytes = 2n * fheBytes + 2n * auxiliaryBytes;
    const signatureBytes = compileRegistrationEnrollmentCensus().signatureBytes;
    const maximumBodyBytes =
        headerBytes + ciphertextBytes + proof.maximumMultiproofBytes;
    const hashPrefixBytes =
        8n +
        2n * 6n +
        4n +
        BigInt(Buffer.byteLength('sealed-lattice/ballot-body/v1')) +
        4n;
    return {
        polynomials,
        contextBytes,
        headerBytes,
        ciphertextBytes,
        minimumProofBytes: proof.headerBytes,
        maximumProofBytes: proof.maximumMultiproofBytes,
        signatureBytes,
        maximumBodyBytes,
        maximumSignedBodyBytes: maximumBodyBytes + signatureBytes,
        hashPrefixBytes,
        maximumHashInputBytes: hashPrefixBytes + maximumBodyBytes,
        reconstructedInputBytes: ciphertextBytes,
    };
};
