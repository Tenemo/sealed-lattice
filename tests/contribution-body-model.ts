import { auxiliaryInputEncryptionParameters } from '#tests/auxiliary-input-encryption-parameters.js';
import { compileCommitmentEquivocationBound } from '#tests/commitment-equivocation-model.js';
import { fixedModulusBfvInputs } from '#tests/fixed-modulus-bfv-model.js';
import { compileFullWordProofLayout } from '#tests/full-word-proof-layout-model.js';
import { compileRegistrationEnrollmentCensus } from '#tests/registration-enrollment-model.js';
import { compileRegistrationKeyRelationCensus } from '#tests/registration-key-relation-model.js';
import { compileRosterProposalCensus } from '#tests/roster-proposal-model.js';

export const contributionBodyHeaderBytes = 4n + 8n;

export const compileContributionBodyCensus = () => {
    const parameters = fixedModulusBfvInputs;
    const participantCount = Number(parameters.participantCount);
    const proof = compileFullWordProofLayout();
    const registration = compileRegistrationEnrollmentCensus();
    const recipient = compileRegistrationKeyRelationCensus();
    const roster = compileRosterProposalCensus(participantCount);
    const commitment = compileCommitmentEquivocationBound(participantCount);
    const polynomialBytes = (degree: bigint, modulus: bigint) =>
        degree * (1n + BigInt(Math.ceil(modulus.toString(2).length / 8)));
    const fhePolynomialBytes = polynomialBytes(
        parameters.polynomialDegree,
        parameters.ciphertextModulus,
    );
    let gadgetCount = 0;
    for (
        let value = 1n;
        value < parameters.ciphertextModulus;
        value *= parameters.gadgetBase
    )
        gadgetCount++;
    const polynomials: { expandedIndex: number; bytes: bigint }[] = [];
    for (let gadget = 0; gadget < gadgetCount; gadget++)
        for (const offset of [1, 2, 4, 6])
            polynomials.push({
                expandedIndex: 7 * gadget + offset,
                bytes: fhePolynomialBytes,
            });
    const sharingStart = 7 * gadgetCount;
    for (let participant = 0; participant < participantCount; participant++)
        for (const offset of [2, 3])
            polynomials.push({
                expandedIndex: sharingStart + 3 * participant + offset,
                bytes: recipient.publicKeyBytes,
            });
    polynomials.push({
        expandedIndex: sharingStart + 3 * participantCount + 2,
        bytes: polynomialBytes(
            auxiliaryInputEncryptionParameters.degree,
            auxiliaryInputEncryptionParameters.modulus,
        ),
    });
    const headerBytes = contributionBodyHeaderBytes;
    const polynomialPayloadBytes = polynomials.reduce(
        (total, polynomial) => total + polynomial.bytes,
        0n,
    );
    const maximumBodyBytes =
        headerBytes + polynomialPayloadBytes + proof.maximumMultiproofBytes;
    const saltBytes = commitment.saltBitLength / 8n;
    const hashPrefixBytes =
        8n +
        5n * 6n +
        4n +
        BigInt(Buffer.byteLength('sealed-lattice/setup-commitment/v1')) +
        registration.signingPublicKeyBytes +
        saltBytes +
        4n +
        roster.roleBytes +
        4n;
    return {
        participantCount,
        polynomials,
        headerBytes,
        polynomialPayloadBytes,
        minimumProofBytes: proof.headerBytes,
        maximumProofBytes: proof.maximumMultiproofBytes,
        maximumBodyBytes,
        saltBytes,
        hashPrefixBytes,
        maximumHashInputBytes: hashPrefixBytes + maximumBodyBytes,
        maximumAllContributorBodies:
            parameters.participantCount * maximumBodyBytes,
    };
};
