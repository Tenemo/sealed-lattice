import { fixedModulusBfvInputs } from '#tests/fixed-modulus-bfv-model.js';
import { compileFullWordProofLayout } from '#tests/full-word-proof-layout-model.js';
import { compileRegistrationKeyRelationCensus } from '#tests/registration-key-relation-model.js';
import { sourceOpeningSaltBytes } from '#tests/registration-setup-binding-model.js';
import { compileSetupSelectionCensus } from '#tests/setup-selection-model.js';
import type { SupportedProfile } from '#tests/supported-profile-model.js';

export const contributionBodyHeaderBytes = 4n + 8n + sourceOpeningSaltBytes;
const bodyDomain = Buffer.from('sealed-lattice/contribution-body/v1', 'ascii');

// Ordinary body-hash framing; the source-opening salt is already inside
// SCB2. This calculation creates no contribution verifier capability.
export const contributionBodyHashPrefix = (bodyBytes: number) => {
    if (
        !Number.isSafeInteger(bodyBytes) ||
        bodyBytes < 0 ||
        bodyBytes > 0xffff_fffb
    )
        throw new RangeError('Invalid contribution body length.');
    const prefix = Buffer.alloc(8 + 2 * 6 + 4 + bodyDomain.length + 4);
    prefix.writeUInt16LE(1, 0);
    prefix.writeUInt16LE(1, 2);
    prefix.writeUInt32LE(2, 4);
    prefix.writeUInt16LE(2, 8);
    prefix.writeUInt32LE(4 + bodyDomain.length, 10);
    prefix.writeUInt32LE(bodyDomain.length, 14);
    bodyDomain.copy(prefix, 18);
    prefix.writeUInt16LE(1, 18 + bodyDomain.length);
    prefix.writeUInt32LE(4 + bodyBytes, 20 + bodyDomain.length);
    prefix.writeUInt32LE(bodyBytes, 24 + bodyDomain.length);
    return prefix;
};

export const compileContributionBodyCensus = (profile: SupportedProfile) => {
    const parameters = {
        ...fixedModulusBfvInputs,
        ciphertextModulus: profile.ciphertext.modulus,
    };
    const participantCount = profile.participantCount;
    const proof = compileFullWordProofLayout(profile);
    const recipient = compileRegistrationKeyRelationCensus();
    const selection = compileSetupSelectionCensus(participantCount);
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
    // Each polynomial's coefficient count; its bytes are that count of
    // sign-and-magnitude coefficients of one width.
    const polynomials: {
        expandedIndex: number;
        bytes: bigint;
        coefficients: bigint;
    }[] = [];
    for (let gadget = 0; gadget < gadgetCount; gadget++)
        for (const offset of [1, 2, 4, 6])
            polynomials.push({
                expandedIndex: 7 * gadget + offset,
                bytes: fhePolynomialBytes,
                coefficients: parameters.polynomialDegree,
            });
    const sharingStart = 7 * gadgetCount;
    for (let participant = 0; participant < participantCount; participant++)
        for (const offset of [2, 3])
            polynomials.push({
                expandedIndex: sharingStart + 3 * participant + offset,
                bytes: recipient.publicKeyBytes,
                coefficients: recipient.degree,
            });
    const headerBytes = contributionBodyHeaderBytes;
    const polynomialPayloadBytes = polynomials.reduce(
        (total, polynomial) => total + polynomial.bytes,
        0n,
    );
    const maximumBodyBytes =
        headerBytes + polynomialPayloadBytes + proof.maximumMultiproofBytes;
    const hashPrefixBytes = 8n + 2n * 6n + 4n + BigInt(bodyDomain.length) + 4n;
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
        setupContributorCount: profile.setupContributorCount,
        eligibleContributorCount: selection.eligibleCount,
        polynomials,
        headerBytes,
        polynomialPayloadBytes,
        minimumProofBytes: proof.headerBytes,
        maximumProofBytes: proof.maximumMultiproofBytes,
        maximumBodyBytes,
        sourceOpeningSaltBytes,
        hashPrefixBytes,
        minimumHashInputBytes,
        maximumHashInputBytes,
        minimumHashInputEnclosingBitExponent: enclosingExponent(
            8n * minimumHashInputBytes,
        ),
        maximumHashInputEnclosingBitExponent: enclosingExponent(
            8n * maximumHashInputBytes,
        ),
        maximumSelectedContributionBodies:
            BigInt(profile.setupContributorCount) * maximumBodyBytes,
        maximumEligibleOfferBodies:
            BigInt(selection.eligibleCount) * maximumBodyBytes,
    };
};
