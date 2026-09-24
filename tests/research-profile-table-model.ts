import { auxiliaryInputEncryptionParameters } from '#tests/auxiliary-input-encryption-parameters.js';
import {
    compileCommonMatrixSamplingCensus,
    fixedFamilyBitsPerCoefficient,
} from '#tests/common-matrix-sampling-model.js';
import {
    listSupportedProfiles,
    type SupportedProfile,
    type TransformPrime,
} from '#tests/supported-profile-model.js';
import { compileSupportedThresholdCompletionProfiles } from '#tests/threshold-completion-model.js';
import { shareEncryptionParameters } from '#tests/wide-share-lifting-model.js';

// The research crates read the searched parameters of every supported
// profile from this table and derive every other size by closed-form rules.
const researchProfileTableMagic = 'SPT1';
export const researchProfileRecordBytes = 30;

const unsigned = (value: bigint | number, bytes: number): Buffer => {
    let remaining = BigInt(value);
    if (remaining < 0n) throw new RangeError('A table value is negative.');
    const encoded = Buffer.alloc(bytes);
    for (let index = 0; index < bytes; index++) {
        encoded[index] = Number(remaining & 255n);
        remaining >>= 8n;
    }
    if (remaining !== 0n)
        throw new RangeError('A table value exceeds its field width.');
    return encoded;
};
// A one-byte length followed by the little-endian magnitude.
const magnitudeBytes = (value: bigint): Buffer => {
    const length = Math.ceil(value.toString(2).length / 8);
    return Buffer.concat([unsigned(length, 1), unsigned(value, length)]);
};

// A prime of the form oddFactor * 2^exponent + 1 with its Proth witness.
const encodePrime = (prime: TransformPrime): Buffer =>
    Buffer.concat([
        unsigned(prime.exponent, 2),
        unsigned(prime.oddFactor, 4),
        unsigned(prime.witness, 2),
    ]);

const encodeProfile = (profile: SupportedProfile): Buffer => {
    const record = Buffer.concat([
        encodePrime(profile.ciphertext),
        encodePrime(profile.release),
        unsigned(profile.releaseNoiseBits, 2),
        unsigned(profile.releaseLifting.shareBits, 2),
        unsigned(profile.releaseLifting.quotientBits, 2),
        unsigned(
            compileCommonMatrixSamplingCensus(profile).fheBitsPerCoefficient,
            2,
        ),
        unsigned(profile.shareLifting.sharingCoefficientBits, 2),
        unsigned(profile.shareLifting.limbBits, 2),
        unsigned(profile.shareLifting.carryBits, 2),
    ]);
    if (record.length !== researchProfileRecordBytes)
        throw new Error('A profile record has the wrong length.');
    return record;
};

// Header with both profile-independent moduli and the common sample width of
// their families, then one record per profile by participant count and then
// option count over both contiguous ranges, as listSupportedProfiles orders
// them.
export const encodeResearchProfileTable = (): Buffer => {
    const participantCounts = compileSupportedThresholdCompletionProfiles().map(
        (profile) => profile.participantCount,
    );
    const profiles = listSupportedProfiles();
    const optionCounts = profiles
        .filter((profile) => profile.participantCount === participantCounts[0])
        .map((profile) => profile.optionCount);
    profiles.forEach((profile, index) => {
        if (
            profile.participantCount !==
                participantCounts[0] +
                    Math.floor(index / optionCounts.length) ||
            profile.optionCount !==
                optionCounts[0] + (index % optionCounts.length)
        )
            throw new Error('The supported profiles are not contiguous.');
    });
    if (profiles.length !== participantCounts.length * optionCounts.length)
        throw new Error('The supported profiles are not contiguous.');
    return Buffer.concat([
        Buffer.from(researchProfileTableMagic),
        magnitudeBytes(shareEncryptionParameters.modulus),
        magnitudeBytes(auxiliaryInputEncryptionParameters.modulus),
        unsigned(fixedFamilyBitsPerCoefficient, 2),
        unsigned(participantCounts[0], 1),
        unsigned(participantCounts[participantCounts.length - 1], 1),
        unsigned(optionCounts[0], 1),
        unsigned(optionCounts[optionCounts.length - 1], 1),
        ...profiles.map(encodeProfile),
    ]);
};
