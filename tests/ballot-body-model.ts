import { auxiliaryInputEncryptionParameters } from '#tests/auxiliary-input-encryption-parameters.js';
import { fixedModulusBfvInputs } from '#tests/fixed-modulus-bfv-model.js';
import { compileBallotWordProofLayout } from '#tests/full-word-proof-layout-model.js';
import { compileRegistrationEnrollmentCensus } from '#tests/registration-enrollment-model.js';
import type { SupportedProfile } from '#tests/supported-profile-model.js';

// Marker, poll, inventory, author position, ballot time, body length and
// body identity; the same for every profile.
export const ballotEnvelopeBytes = 4n + 64n + 64n + 2n + 8n + 8n + 64n;

export const compileBallotBodyCensus = (profile: SupportedProfile) => {
    const proof = compileBallotWordProofLayout(profile);
    const polynomialBytes = (degree: bigint, modulus: bigint) =>
        degree * (1n + BigInt(Math.ceil(modulus.toString(2).length / 8)));
    const fheBytes = polynomialBytes(
        fixedModulusBfvInputs.polynomialDegree,
        profile.ciphertext.modulus,
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
    // Only the FHE aggregate key is supplied from certified setup. Both
    // auxiliary coordinates and the FHE common coordinate are derived locally.
    const reconstructedPolynomials = [
        { expandedIndex: 0, bytes: fheBytes },
        { expandedIndex: 1, bytes: fheBytes },
        { expandedIndex: 4, bytes: auxiliaryBytes },
        { expandedIndex: 5, bytes: auxiliaryBytes },
    ];
    const setupKeyPolynomials = [{ expandedIndex: 1, bytes: fheBytes }];
    const contextBytes = 4n + 64n + 64n + 2n + 1n + 1n;
    const proofRoleBytes =
        8n +
        5n * 6n +
        4n +
        BigInt(Buffer.byteLength('sealed-lattice/ballot-proof/v1')) +
        3n * 64n +
        2n;
    const headerBytes = 4n + 8n + contextBytes;
    const ciphertextBytes = 2n * fheBytes + 2n * auxiliaryBytes;
    const signatureBytes = compileRegistrationEnrollmentCensus().signatureBytes;
    const envelopeBytes = ballotEnvelopeBytes;
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
        reconstructedPolynomials,
        setupKeyPolynomials,
        setupKeyInputBytes: fheBytes,
        locallyDerivedInputBytes: fheBytes + 2n * auxiliaryBytes,
        contextBytes,
        proofRoleBytes,
        headerBytes,
        ciphertextBytes,
        minimumProofBytes: proof.headerBytes,
        maximumProofBytes: proof.maximumMultiproofBytes,
        signatureBytes,
        envelopeBytes,
        maximumBodyBytes,
        maximumSignedBodyBytes:
            maximumBodyBytes + envelopeBytes + signatureBytes,
        hashPrefixBytes,
        maximumHashInputBytes: hashPrefixBytes + maximumBodyBytes,
        reconstructedInputBytes: reconstructedPolynomials.reduce(
            (total, polynomial) => total + polynomial.bytes,
            0n,
        ),
    };
};
