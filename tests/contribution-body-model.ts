import { auxiliaryInputEncryptionParameters } from '#tests/auxiliary-input-encryption-parameters.js';
import { compileCommitmentEquivocationBound } from '#tests/commitment-equivocation-model.js';
import { fixedModulusBfvInputs } from '#tests/fixed-modulus-bfv-model.js';
import { compileFullWordProofLayout } from '#tests/full-word-proof-layout-model.js';
import {
    compileRegistrationEnrollmentCensus,
    registrationSigningPublicKeyBytes,
} from '#tests/registration-enrollment-model.js';
import { compileRegistrationKeyRelationCensus } from '#tests/registration-key-relation-model.js';
import { compileRosterProposalCensus } from '#tests/roster-proposal-model.js';

export const contributionBodyHeaderBytes = 4n + 8n;
const commitmentDomain = Buffer.from(
    'sealed-lattice/setup-commitment/v1',
    'ascii',
);

// Independent byte-level extractor label, checked against the actual Rust
// canonical encoder and streaming hasher. It creates no verified body value.
export const contributionSenderPrefix = (publicKey: Uint8Array) => {
    if (BigInt(publicKey.length) !== registrationSigningPublicKeyBytes)
        throw new RangeError('Invalid sender key length.');
    const offset = 8 + 6 + 4 + commitmentDomain.length + 6,
        prefix = Buffer.alloc(offset + publicKey.length);
    prefix.writeUInt16LE(1, 0);
    prefix.writeUInt16LE(1, 2);
    prefix.writeUInt32LE(5, 4);
    prefix.writeUInt16LE(2, 8);
    prefix.writeUInt32LE(4 + commitmentDomain.length, 10);
    prefix.writeUInt32LE(commitmentDomain.length, 14);
    commitmentDomain.copy(prefix, 18);
    prefix.writeUInt16LE(1, 18 + commitmentDomain.length);
    prefix.writeUInt32LE(publicKey.length, 20 + commitmentDomain.length);
    prefix.set(publicKey, offset);
    return prefix;
};

export const matchesContributionSenderPrefix = (
    preimage: Uint8Array,
    publicKey: Uint8Array,
) => {
    const prefix = contributionSenderPrefix(publicKey);
    return (
        preimage.length >= prefix.length &&
        prefix.every((value, index) => value === preimage[index])
    );
};

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
    const senderKeyOffsetBytes = 24n + BigInt(commitmentDomain.length);
    const minimumHashInputBytes =
        hashPrefixBytes +
        headerBytes +
        polynomialPayloadBytes +
        proof.headerBytes;
    const maximumHashInputBytes = hashPrefixBytes + maximumBodyBytes;
    const enclosingExponent = (value: bigint) => {
        let bits = 0n;
        while (1n << bits < value) bits++;
        return bits;
    };
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
        minimumHashInputBytes,
        maximumHashInputBytes,
        senderKeyOffsetBytes,
        senderPrefixBytes:
            senderKeyOffsetBytes + registrationSigningPublicKeyBytes,
        minimumHashInputEnclosingBitExponent: enclosingExponent(
            8n * minimumHashInputBytes,
        ),
        maximumHashInputEnclosingBitExponent: enclosingExponent(
            8n * maximumHashInputBytes,
        ),
        maximumAllContributorBodies:
            parameters.participantCount * maximumBodyBytes,
    };
};
