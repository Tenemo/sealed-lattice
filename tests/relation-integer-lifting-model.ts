import assert from 'node:assert/strict';

import { auxiliaryInputEncryptionParameters } from '#tests/auxiliary-input-encryption-parameters.js';
import { compileBallotEncryptionColumnLayout } from '#tests/ballot-encryption-relation-model.js';
import { fixedModulusBfvInputs } from '#tests/fixed-modulus-bfv-model.js';
import { compileLinkedReleaseColumnLayout } from '#tests/linked-release-relation-model.js';
import { setupEquationWidths } from '#tests/setup-contribution-relation-model.js';
import { compileSmallLimbProofFieldCensus } from '#tests/small-limb-proof-field-model.js';
import {
    ballotScoreRange,
    listSupportedProfiles,
    type SupportedProfile,
} from '#tests/supported-profile-model.js';
import { shareEncryptionParameters } from '#tests/wide-share-lifting-model.js';

// An accepted witness satisfies every row over the proof field. A row's
// residual is an integer, so when every in-range witness keeps it below the
// field modulus in magnitude, field equality is integer equality. Limb rows
// then telescope to the original equation when every public operand expands
// completely into the limbs and both end carries are zero. Each family lists
// the magnitude bound of every term of one limb row over the accepted box:
// signed digits of public operands, range-checked variables and their public
// factors. Sparse secrets enter through their exact support sums.

const proofField = compileSmallLimbProofFieldCensus().modulus;
const fheLimbBits = 96;
const signedRadius = (bits: number) => 1n << BigInt(bits - 1);
const largestDigit = (limbBits: number) => (1n << BigInt(limbBits)) - 1n;
const bitLength = (value: bigint) => value.toString(2).length;
const maximum = (...values: readonly bigint[]) =>
    values.reduce((left, right) => (right > left ? right : left));

type LiftingTerm = Readonly<{ term: string; bound: bigint }>;
export type IntegerLiftingFamily = Readonly<{
    relation: 'setup' | 'ballot' | 'release';
    family: string;
    // Rows without limbs hold whole field elements.
    limbBits?: number;
    limbs: number;
    terms: readonly LiftingTerm[];
    // Public operands whose signed digits the limb rows carry.
    publicMagnitudes: readonly Readonly<{
        operand: string;
        magnitude: bigint;
    }>[];
}>;

// The residual bound of one limb row, refused unless it is below the proof
// field and every public operand expands completely into the row's limbs.
export const integerLiftingResidualBound = (family: IntegerLiftingFamily) => {
    const residual = family.terms.reduce((sum, term) => sum + term.bound, 0n);
    if (residual >= proofField)
        throw new RangeError(
            `The ${family.relation} ${family.family} residual reaches the proof field.`,
        );
    for (const { operand, magnitude } of family.publicMagnitudes)
        if (
            family.limbBits === undefined ||
            magnitude >= 1n << BigInt(family.limbBits * family.limbs)
        )
            throw new RangeError(
                `The ${family.relation} ${family.family} limbs do not expand the ${operand}.`,
            );
    return residual;
};

const supportFamily = (
    relation: IntegerLiftingFamily['relation'],
    halfSupport: bigint,
): IntegerLiftingFamily => ({
    relation,
    family: 'support sums',
    limbs: 1,
    terms: [
        {
            term: 'Boolean support column',
            bound: fixedModulusBfvInputs.polynomialDegree,
        },
        { term: 'half support', bound: halfSupport },
    ],
    publicMagnitudes: [],
});

const setupFamilies = (profile: SupportedProfile): IntegerLiftingFamily[] => {
    const { quotientBits, fheCarryBits, errorBits } = setupEquationWidths;
    const modulus = profile.ciphertext.modulus;
    const fheLimbs = Math.ceil(bitLength(modulus) / fheLimbBits);
    const radix = 1n << BigInt(fheLimbBits);
    // Each relinearization and automorphism equation adds one gadget power
    // times a secret coefficient; its signed digits are those of the power.
    const gadgetPowers = Array.from(
        { length: Number(profile.gadgetLength) },
        (_unused, index) => fixedModulusBfvInputs.gadgetBase ** BigInt(index),
    );
    const largestGadgetDigit = maximum(
        ...gadgetPowers.flatMap((power) =>
            Array.from(
                { length: fheLimbs },
                (_unused, limb) => (power / radix ** BigInt(limb)) % radix,
            ),
        ),
    );
    const { limbBits, carryBits, sharingCoefficientBits } =
        profile.shareLifting;
    const shareRadix = 1n << BigInt(limbBits);
    const scale = shareEncryptionParameters.scale;
    const sharingDegree = BigInt(profile.releaseThreshold - 1);
    // The constant share equation carries a public offset of at most this
    // many half radices of the scale.
    const sharingOffset = (sharingDegree * scale * shareRadix) / 2n;
    assert.ok(scale < shareRadix);
    return [
        {
            relation: 'setup',
            family: 'FHE key equations',
            limbBits: fheLimbBits,
            limbs: fheLimbs,
            terms: [
                { term: 'public key digit', bound: largestDigit(fheLimbBits) },
                {
                    term: 'common polynomial product',
                    bound:
                        fixedModulusBfvInputs.secretSupportWeight *
                        largestDigit(fheLimbBits),
                },
                { term: 'gadget product', bound: largestGadgetDigit },
                {
                    term: 'quotient product',
                    bound:
                        signedRadius(quotientBits) * largestDigit(fheLimbBits),
                },
                { term: 'error', bound: signedRadius(errorBits) },
                {
                    term: 'carries',
                    bound:
                        fheLimbs > 1
                            ? signedRadius(fheCarryBits) * (radix + 1n)
                            : 0n,
                },
            ],
            publicMagnitudes: [
                { operand: 'ciphertext modulus', magnitude: modulus },
                {
                    operand: 'largest gadget power',
                    magnitude: gadgetPowers[gadgetPowers.length - 1],
                },
            ],
        },
        {
            relation: 'setup',
            family: 'constant share equations',
            limbBits,
            limbs: 2,
            terms: [
                { term: 'public share digit', bound: largestDigit(limbBits) },
                { term: 'sharing offset digit', bound: largestDigit(limbBits) },
                {
                    term: 'recipient key product',
                    bound:
                        shareEncryptionParameters.encryptionSupportWeight *
                        largestDigit(limbBits),
                },
                { term: 'secret product', bound: scale },
                {
                    term: 'sharing coefficient products',
                    bound:
                        sharingDegree *
                        scale *
                        maximum(
                            signedRadius(limbBits),
                            signedRadius(sharingCoefficientBits - limbBits),
                        ),
                },
                {
                    term: 'quotient product',
                    bound: signedRadius(quotientBits) * largestDigit(limbBits),
                },
                { term: 'error', bound: signedRadius(errorBits) },
                {
                    term: 'carry',
                    bound: signedRadius(carryBits) * (shareRadix + 1n),
                },
            ],
            publicMagnitudes: [
                {
                    operand: 'share modulus',
                    magnitude: shareEncryptionParameters.modulus,
                },
                { operand: 'sharing offset', magnitude: sharingOffset },
            ],
        },
        {
            relation: 'setup',
            family: 'linear share equations',
            limbBits,
            limbs: 2,
            terms: [
                { term: 'public share digit', bound: largestDigit(limbBits) },
                {
                    term: 'common polynomial product',
                    bound:
                        shareEncryptionParameters.encryptionSupportWeight *
                        largestDigit(limbBits),
                },
                {
                    term: 'quotient product',
                    bound: signedRadius(quotientBits) * largestDigit(limbBits),
                },
                { term: 'error', bound: signedRadius(errorBits) },
                {
                    term: 'carry',
                    bound: signedRadius(fheCarryBits) * (shareRadix + 1n),
                },
            ],
            publicMagnitudes: [
                {
                    operand: 'share modulus',
                    magnitude: shareEncryptionParameters.modulus,
                },
            ],
        },
        supportFamily('setup', fixedModulusBfvInputs.secretSupportWeight / 2n),
    ];
};

const ballotFamilies = (profile: SupportedProfile): IntegerLiftingFamily[] => {
    const layout = compileBallotEncryptionColumnLayout(profile);
    // A signed column of range m is offset by half of m + 1.
    const radius = (name: string) => {
        const column = layout.columns.find((value) => value.name === name);
        assert.ok(column !== undefined, name);
        return BigInt(column.maximum + 1) / 2n;
    };
    const modulus = profile.ciphertext.modulus;
    const fheLimbs = Math.ceil(bitLength(modulus) / fheLimbBits);
    const plaintextModulus = fixedModulusBfvInputs.plaintextModulus;
    const scale = (modulus - 1n) / plaintextModulus;
    // The plaintext word and its high bit, whose product is zero, span the
    // centered plaintext interval.
    const plaintext = radius('plaintext-lower-word');
    const auxiliary = auxiliaryInputEncryptionParameters;
    const maximumScore = BigInt(ballotScoreRange.maximum);
    return [
        {
            relation: 'ballot',
            family: 'FHE encryption equations',
            limbBits: fheLimbBits,
            limbs: fheLimbs,
            terms: [
                {
                    term: 'public ciphertext digit',
                    bound: largestDigit(fheLimbBits),
                },
                {
                    term: 'key or common polynomial product',
                    bound:
                        fixedModulusBfvInputs.secretSupportWeight *
                        largestDigit(fheLimbBits),
                },
                {
                    term: 'plaintext product',
                    bound: plaintext * largestDigit(fheLimbBits),
                },
                {
                    term: 'quotient product',
                    bound: radius('fhe-quotient-0') * largestDigit(fheLimbBits),
                },
                { term: 'error', bound: radius('fhe-error-0') },
                {
                    term: 'carries',
                    bound:
                        fheLimbs > 1
                            ? radius('fhe-carry-0-0') *
                              ((1n << BigInt(fheLimbBits)) + 1n)
                            : 0n,
                },
            ],
            publicMagnitudes: [
                { operand: 'ciphertext modulus', magnitude: modulus },
                { operand: 'plaintext scale', magnitude: scale },
            ],
        },
        {
            relation: 'ballot',
            family: 'packing equations',
            limbs: 1,
            terms: [
                { term: 'plaintext', bound: plaintext },
                // Packing-matrix entries are centered modulo the plaintext
                // modulus; every row has one entry per option.
                {
                    term: 'score products',
                    bound:
                        BigInt(profile.optionCount) *
                        (plaintextModulus / 2n) *
                        maximumScore,
                },
                {
                    term: 'quotient product',
                    bound: plaintextModulus * radius('packing-quotient'),
                },
            ],
            publicMagnitudes: [],
        },
        {
            relation: 'ballot',
            family: 'auxiliary encryption equations',
            limbs: 1,
            terms: [
                {
                    term: 'public ciphertext coefficient',
                    bound: auxiliary.modulus / 2n,
                },
                {
                    term: 'key or common polynomial product',
                    bound: auxiliary.support * (auxiliary.modulus / 2n),
                },
                { term: 'score', bound: maximumScore * auxiliary.scale },
                {
                    term: 'quotient product',
                    bound: auxiliary.modulus * radius('auxiliary-quotient-0'),
                },
                { term: 'error', bound: radius('auxiliary-error-0') },
            ],
            publicMagnitudes: [],
        },
        supportFamily(
            'ballot',
            maximum(
                fixedModulusBfvInputs.secretSupportWeight,
                auxiliary.support,
            ) / 2n,
        ),
    ];
};

const releaseFamilies = (profile: SupportedProfile): IntegerLiftingFamily[] => {
    const layout = compileLinkedReleaseColumnLayout(profile);
    const bits = (name: string) => {
        const column = layout.columns.find((value) => value.name === name);
        assert.ok(column !== undefined, name);
        return column.bits;
    };
    const radix = 1n << BigInt(fheLimbBits);
    const share = shareEncryptionParameters;
    const recipientSupport = share.encryptionSupportWeight;
    const lifting = profile.releaseLifting;
    const releaseLimbBits = bitLength(lifting.radix) - 1;
    const releaseDigit = largestDigit(releaseLimbBits);
    // The decoding equation splits the share into a centered lower word and
    // a signed upper part, and adds the scale times half the radix.
    const decodingOffset = (share.scale * radix) / 2n;
    return [
        {
            relation: 'release',
            family: 'recipient-key equations',
            limbBits: fheLimbBits,
            limbs: 2,
            terms: [
                { term: 'public key digit', bound: largestDigit(fheLimbBits) },
                {
                    term: 'common polynomial product',
                    bound: recipientSupport * largestDigit(fheLimbBits),
                },
                {
                    term: 'quotient product',
                    bound:
                        signedRadius(bits('key-quotient')) *
                        largestDigit(fheLimbBits),
                },
                { term: 'error', bound: signedRadius(bits('key-error')) },
                {
                    term: 'carry',
                    bound: signedRadius(bits('key-carry')) * (radix + 1n),
                },
            ],
            publicMagnitudes: [
                { operand: 'share modulus', magnitude: share.modulus },
            ],
        },
        {
            relation: 'release',
            family: 'aggregate decoding equations',
            limbBits: fheLimbBits,
            limbs: 2,
            terms: [
                {
                    term: 'public constant digit',
                    bound: largestDigit(fheLimbBits),
                },
                { term: 'offset digit', bound: largestDigit(fheLimbBits) },
                {
                    term: 'linear component product',
                    bound: recipientSupport * largestDigit(fheLimbBits),
                },
                {
                    term: 'share part product',
                    bound:
                        share.scale *
                        maximum(
                            radix / 2n,
                            signedRadius(bits('aggregate-share') - fheLimbBits),
                        ),
                },
                {
                    term: 'quotient product',
                    bound:
                        signedRadius(bits('decoding-quotient')) *
                        largestDigit(fheLimbBits),
                },
                { term: 'error', bound: signedRadius(bits('decoding-error')) },
                {
                    term: 'carry',
                    bound: signedRadius(bits('decoding-carry')) * (radix + 1n),
                },
            ],
            publicMagnitudes: [
                { operand: 'share modulus', magnitude: share.modulus },
                { operand: 'decoding offset', magnitude: decodingOffset },
            ],
        },
        {
            relation: 'release',
            family: 'partial decryption equations',
            limbBits: releaseLimbBits,
            limbs: lifting.outputLimbs,
            terms: [
                // Each output limb receives at most min(public, private)
                // limb products; the share products are ring convolutions.
                {
                    term: 'share products',
                    bound:
                        lifting.clearingFactor *
                        BigInt(
                            Math.min(lifting.publicLimbs, lifting.shareLimbs),
                        ) *
                        fixedModulusBfvInputs.polynomialDegree *
                        releaseDigit ** 2n,
                },
                {
                    term: 'quotient products',
                    bound:
                        BigInt(
                            Math.min(
                                lifting.publicLimbs,
                                lifting.quotientLimbs,
                            ),
                        ) *
                        releaseDigit ** 2n,
                },
                {
                    term: 'noise digit',
                    bound: lifting.clearingFactor * releaseDigit,
                },
                { term: 'partial release digit', bound: releaseDigit },
                {
                    term: 'carries',
                    bound:
                        signedRadius(bits('release-carry-0')) *
                        (lifting.radix + 1n),
                },
            ],
            publicMagnitudes: [
                {
                    operand: 'release modulus',
                    magnitude: profile.release.modulus,
                },
            ],
        },
        supportFamily('release', recipientSupport / 2n),
    ];
};

export const relationIntegerLiftingFamilies = (
    profile: SupportedProfile,
): readonly IntegerLiftingFamily[] => [
    ...setupFamilies(profile),
    ...ballotFamilies(profile),
    ...releaseFamilies(profile),
];

// log2(field / bound) rounded down to hundredths: the largest k with
// bound^100 * 2^k at most field^100.
const hundredthsBelowField = (bound: bigint) => {
    const scaledBound = bound ** 100n;
    const scaledField = proofField ** 100n;
    let hundredths = BigInt(bitLength(scaledField) - bitLength(scaledBound));
    while (hundredths > 0n && scaledBound << hundredths > scaledField)
        hundredths--;
    while (scaledBound << (hundredths + 1n) <= scaledField) hundredths++;
    return hundredths;
};

// The largest residual bound of each row family over every supported
// profile, with the first profile that attains it.
export const compileRelationIntegerLiftingCensus = () => {
    const families = new Map<
        string,
        {
            relation: IntegerLiftingFamily['relation'];
            family: string;
            limbBits: Set<number>;
            limbs: Set<number>;
            residualBound: bigint;
            participantCount: number;
            optionCount: number;
        }
    >();
    const profiles = listSupportedProfiles();
    for (const profile of profiles)
        for (const family of relationIntegerLiftingFamilies(profile)) {
            const residualBound = integerLiftingResidualBound(family);
            const key = `${family.relation}/${family.family}`;
            const current = families.get(key);
            const limbBits = new Set(current?.limbBits);
            if (family.limbBits !== undefined) limbBits.add(family.limbBits);
            const limbs = new Set([...(current?.limbs ?? []), family.limbs]);
            if (current !== undefined) {
                current.limbBits = limbBits;
                current.limbs = limbs;
                if (residualBound <= current.residualBound) continue;
            }
            families.set(key, {
                relation: family.relation,
                family: family.family,
                limbBits,
                limbs,
                residualBound,
                participantCount: profile.participantCount,
                optionCount: profile.optionCount,
            });
        }
    return {
        profileCount: profiles.length,
        proofField,
        families: [...families.values()].map((family) => ({
            ...family,
            limbBits: [...family.limbBits].sort((left, right) => left - right),
            limbs: [...family.limbs].sort((left, right) => left - right),
            hundredthsBelowField: hundredthsBelowField(family.residualBound),
        })),
    };
};
