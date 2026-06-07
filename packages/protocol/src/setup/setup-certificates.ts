import { deriveProtocolHash } from '@sealed-lattice/crypto';
import type { ProtocolHash } from '@sealed-lattice/types';

type JsonRecord = Record<string, unknown>;

export type CollectiveBgvSetupProfileForCertificates = Readonly<
    JsonRecord & {
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly setupProfileHash: ProtocolHash;
        readonly participantCount: number;
        readonly qDec: number;
        readonly qShare: Readonly<
            JsonRecord & {
                readonly primes: readonly number[];
            }
        >;
        readonly qShareHash: ProtocolHash;
        readonly carryAwareVssShareRelationProfileHash: ProtocolHash;
        readonly commitmentProfile: Readonly<
            JsonRecord & {
                readonly messageEncoding: JsonRecord;
            }
        >;
        readonly commitmentProfileHash: ProtocolHash;
        readonly publicVssCommitmentMaterialSizeProfile: Readonly<
            JsonRecord & {
                readonly fullMaterialCoefficientBytes: number;
            }
        >;
        readonly setupProofProfile: JsonRecord;
        readonly setupProofProfileHash: ProtocolHash;
        readonly setupTransportProfile: JsonRecord;
        readonly setupTransportProfileHash: ProtocolHash;
        readonly evaluatorKeyScheduleProfile: Readonly<
            JsonRecord & {
                readonly relinearizationLevelSchedule: readonly Readonly<{
                    readonly level: number;
                }>[];
                readonly requiredGaloisKeySchedule: readonly Readonly<{
                    readonly level: number;
                }>[];
            }
        >;
        readonly evaluatorKeyScheduleProfileHash: ProtocolHash;
    }
>;

export type BgvRnsProfileForCertificates = Readonly<
    JsonRecord & {
        readonly profile: Readonly<
            JsonRecord & {
                readonly profileId: string;
                readonly backendProfileId: string;
                readonly polynomialDegree: number;
                readonly plaintextModulus: number;
                readonly dataBasisId: string;
                readonly dataPrimes: readonly number[];
                readonly specialPrime: number;
            }
        >;
        readonly securityEstimatorInputHash: string;
    }
>;

export type SetupCertificateTransportInput = Readonly<{
    readonly fullObjectHash: ProtocolHash;
    readonly chunkHashes: readonly ProtocolHash[];
}>;

export type SetupCertificatesInput = Readonly<{
    readonly setupProfile:
        | CollectiveBgvSetupProfileForCertificates
        | JsonRecord;
    readonly bgvProfile: BgvRnsProfileForCertificates | JsonRecord;
    readonly vssCoefficientCommitmentMaterial: JsonRecord;
    readonly transport: SetupCertificateTransportInput;
}>;

export type SetupCommitmentSecurityCertificate = Readonly<
    JsonRecord & {
        readonly objectType: 'SetupCommitmentSecurityCertificate';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly setupCommitmentSecurityCertificateHash: ProtocolHash;
    }
>;

type SetupCommitmentSecurityCertificateBody = Readonly<
    JsonRecord & {
        readonly objectType: 'SetupCommitmentSecurityCertificate';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
    }
>;

export type SetupTransportCertificate = Readonly<
    JsonRecord & {
        readonly objectType: 'SetupTransportCertificate';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly setupTransportCertificateHash: ProtocolHash;
    }
>;

type SetupTransportCertificateBody = Readonly<
    JsonRecord & {
        readonly objectType: 'SetupTransportCertificate';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
    }
>;

export type SetupProofAccountingCertificate = Readonly<
    JsonRecord & {
        readonly objectType: 'SetupProofAccountingCertificate';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly setupProofAccountingCertificateHash: ProtocolHash;
    }
>;

type SetupProofAccountingCertificateBody = Readonly<
    JsonRecord & {
        readonly objectType: 'SetupProofAccountingCertificate';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
    }
>;

export type BgvHeSecurityCertificate = Readonly<
    JsonRecord & {
        readonly objectType: 'BgvHeSecurityCertificate';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly heSecurityCertificateHash: ProtocolHash;
    }
>;

type BgvHeSecurityCertificateBody = Readonly<
    JsonRecord & {
        readonly objectType: 'BgvHeSecurityCertificate';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
    }
>;

export type SetupCertificates = Readonly<{
    readonly setupCommitmentSecurityCertificate: SetupCommitmentSecurityCertificate;
    readonly setupTransportCertificate: SetupTransportCertificate;
    readonly setupProofAccountingCertificate: SetupProofAccountingCertificate;
    readonly heSecurityCertificate: BgvHeSecurityCertificate;
}>;

const setupProfileId = 'CollectiveBgvSetup-v1';
const setupCommitmentProfileId = 'SealedLattice-BDLOP-LNP-Commitment-v1';
const setupProofProfileId = 'SealedLattice-LNP-SetupProof-v1';
const setupProofChallengeDomain =
    'sealed-lattice/collective-bgv-setup/lnp-challenge-v1';
const setupProofChallengeSampler =
    'sealed-lattice-shake256-lazer-autostable-rejection-v1';
const setupProofChallengeSpace =
    'fixed-lnp-small-coefficient-polynomial-challenge-set';
const setupProofChallengeSeedDomain =
    'sealed-lattice/collective-bgv-setup/lnp-challenge-seed-v1';
const setupProofChallengeStreamDomain =
    'sealed-lattice/collective-bgv-setup/lnp-challenge-stream-v1';
const setupProofBytesDomain =
    'sealed-lattice/collective-bgv-setup/lnp-proof-bytes-v1';
const setupProofSerialization = 'binary';
const setupProofByteDecoder = 'sealed-lattice-lnp-tbox-proof-byte-decoder-v1';
const setupProofChallengeSpaceAuditHashNamespace =
    'SetupProofChallengeSpaceAuditHash';
const setupProofChallengeDifferenceInvertibilityStatus =
    'repo-owned-lnp22-small-coefficient-challenge-differences-invertible';
const setupProofBytesAcceptedStatus =
    'private-vss-same-secret-public-key-share-relinearization-and-galois-verifiers-implemented-claim-accounting-pending';
const setupProofFamilies = [
    'vss-opening-carry',
    'same-secret-consistency',
    'public-key-share',
    'relinearization-key-share',
    'galois-key-share',
] as const;
const setupTransportProfileId =
    'sealed-lattice-setup-binary-chunked-transport-v1';
const setupTransportChunkSizeBytes = 1_048_576;
const setupTransportStorageQuotaBytes = 2_147_483_648;
const setupTransportLargestSingleBufferBytes = 1_572_864;
const setupTransportCopyCountLimit = 2;
const setupTransportStreamOrder = 'ascending-chunk-index';
const setupTransportResumePolicy = 'chunk-index-checkpointed-by-hash';
const setupTransportLazyLoadingPolicy = 'root-addressed-large-object-loading';
const setupTransportedObjectLoadingPolicy = 'stream-verified-before-object-use';
const targetDecryptionProfileId = 'BGV-RNS-AsyncTargetDecryption-v1';
const protocolHashPattern = /^[0-9a-f]{128}$/u;

const assertObjectRecord = (value: unknown, fieldName: string): JsonRecord => {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
        throw new TypeError(`${fieldName} must be an object.`);
    }

    return value as JsonRecord;
};

const assertProtocolHash = (value: string, fieldName: string): void => {
    if (!protocolHashPattern.test(value)) {
        throw new TypeError(`${fieldName} must be a protocol hash.`);
    }
};

const stringField = (
    value: Readonly<Record<string, unknown>>,
    fieldName: string,
    objectPath: string,
): string => {
    const fieldValue = value[fieldName];
    if (typeof fieldValue !== 'string' || fieldValue.length === 0) {
        throw new TypeError(`${objectPath}.${fieldName} must be non-empty.`);
    }

    return fieldValue;
};

const hashField = (
    value: Readonly<Record<string, unknown>>,
    fieldName: string,
    objectPath: string,
): ProtocolHash => {
    const fieldValue = stringField(value, fieldName, objectPath);
    assertProtocolHash(fieldValue, `${objectPath}.${fieldName}`);

    return fieldValue;
};

const numberField = (
    value: Readonly<Record<string, unknown>>,
    fieldName: string,
    objectPath: string,
): number => {
    const fieldValue = value[fieldName];
    if (
        typeof fieldValue !== 'number' ||
        !Number.isSafeInteger(fieldValue) ||
        fieldValue < 0
    ) {
        throw new TypeError(
            `${objectPath}.${fieldName} must be a non-negative safe integer.`,
        );
    }

    return fieldValue;
};

const positiveNumberField = (
    value: Readonly<Record<string, unknown>>,
    fieldName: string,
    objectPath: string,
): number => {
    const fieldValue = numberField(value, fieldName, objectPath);
    if (fieldValue <= 0) {
        throw new TypeError(
            `${objectPath}.${fieldName} must be a positive safe integer.`,
        );
    }

    return fieldValue;
};

const objectField = (
    value: Readonly<Record<string, unknown>>,
    fieldName: string,
    objectPath: string,
): JsonRecord =>
    assertObjectRecord(value[fieldName], `${objectPath}.${fieldName}`);

const hashArrayField = (
    value: Readonly<Record<string, unknown>>,
    fieldName: string,
    objectPath: string,
): ProtocolHash[] => {
    const fieldValue = value[fieldName];
    if (!Array.isArray(fieldValue)) {
        throw new TypeError(`${objectPath}.${fieldName} must be an array.`);
    }

    return fieldValue.map((item, itemIndex) => {
        if (typeof item !== 'string') {
            throw new TypeError(
                `${objectPath}.${fieldName}.${String(itemIndex)} must be a protocol hash.`,
            );
        }
        assertProtocolHash(
            item,
            `${objectPath}.${fieldName}.${String(itemIndex)}`,
        );

        return item;
    });
};

const numberArrayField = (
    value: Readonly<Record<string, unknown>>,
    fieldName: string,
    objectPath: string,
): number[] => {
    const fieldValue = value[fieldName];
    if (!Array.isArray(fieldValue)) {
        throw new TypeError(`${objectPath}.${fieldName} must be an array.`);
    }

    return fieldValue.map((item, itemIndex) => {
        if (
            typeof item !== 'number' ||
            !Number.isSafeInteger(item) ||
            item <= 0
        ) {
            throw new TypeError(
                `${objectPath}.${fieldName}.${String(itemIndex)} must be a positive safe integer.`,
            );
        }

        return item;
    });
};

const stringArrayField = (
    value: Readonly<Record<string, unknown>>,
    fieldName: string,
    objectPath: string,
): string[] => {
    const fieldValue = value[fieldName];
    if (!Array.isArray(fieldValue)) {
        throw new TypeError(`${objectPath}.${fieldName} must be an array.`);
    }

    return fieldValue.map((item, itemIndex) => {
        if (typeof item !== 'string' || item.length === 0) {
            throw new TypeError(
                `${objectPath}.${fieldName}.${String(itemIndex)} must be a non-empty string.`,
            );
        }

        return item;
    });
};

const proofFamilyNamesFromProfile = (
    setupProofProfile: Readonly<Record<string, unknown>>,
): string[] => {
    const familyProfiles = setupProofProfile.proofFamilies;
    if (!Array.isArray(familyProfiles)) {
        throw new TypeError(
            'setupProfile.setupProofProfile.proofFamilies must be an array.',
        );
    }

    return familyProfiles.map((familyProfile, familyIndex) =>
        stringField(
            assertObjectRecord(
                familyProfile,
                `setupProfile.setupProofProfile.proofFamilies.${String(familyIndex)}`,
            ),
            'proofFamily',
            `setupProfile.setupProofProfile.proofFamilies.${String(familyIndex)}`,
        ),
    );
};

const assertSetupProofFamiliesMatchProfile = (
    setupProofProfile: Readonly<Record<string, unknown>>,
): void => {
    const profileFamilyNames = proofFamilyNamesFromProfile(setupProofProfile);
    if (
        profileFamilyNames.length !== setupProofFamilies.length ||
        profileFamilyNames.some(
            (familyName, familyIndex) =>
                familyName !== setupProofFamilies[familyIndex],
        )
    ) {
        throw new Error(
            'setupProfile.setupProofProfile.proofFamilies must match the accepted setup proof family order.',
        );
    }
};

const assertDerivedHashMatches = (
    namespace: string,
    value: JsonRecord,
    expectedHash: ProtocolHash,
    fieldName: string,
): void => {
    const observedHash = deriveProtocolHash(namespace, value);
    if (observedHash !== expectedHash) {
        throw new Error(`${fieldName} must match the supplied profile body.`);
    }
};

const scalarPowerSum = (
    coefficientCount: number,
    trusteePoint: number,
): bigint => {
    let scalarSum = 0n;
    let trusteePower = 1n;
    const trusteePointWide = BigInt(trusteePoint);
    for (
        let coefficientIndex = 0;
        coefficientIndex < coefficientCount;
        coefficientIndex += 1
    ) {
        scalarSum += trusteePower;
        if (coefficientIndex + 1 < coefficientCount) {
            trusteePower *= trusteePointWide;
        }
    }

    return scalarSum;
};

const ceilLog2Bigint = (value: bigint): number => {
    if (value <= 1n) {
        return 0;
    }

    return (value - 1n).toString(2).length;
};

const modulusProductDecimal = (moduli: readonly number[]): string =>
    moduli
        .reduce((product, modulus) => product * BigInt(modulus), 1n)
        .toString();

const moduliBitLengthSum = (moduli: readonly number[]): number =>
    moduli.reduce(
        (bitLengthSum, modulus) => bitLengthSum + modulus.toString(2).length,
        0,
    );

const keySwitchComponentPolynomialCount = (
    entries: readonly Readonly<{ readonly level: number }>[],
): number =>
    entries.reduce((total, entry) => {
        if (!Number.isSafeInteger(entry.level) || entry.level < 0) {
            throw new TypeError(
                'evaluatorKeyScheduleProfile levels must be non-negative safe integers.',
            );
        }
        const digitCount = entry.level + 1;

        return total + digitCount * digitCount;
    }, 0);

const setupProfileForCertificates = (
    setupProfileValue: CollectiveBgvSetupProfileForCertificates | JsonRecord,
): CollectiveBgvSetupProfileForCertificates => {
    const setupProfileRecord = assertObjectRecord(
        setupProfileValue,
        'setupProfile',
    );
    if (setupProfileRecord.setupProfileId !== setupProfileId) {
        throw new Error(
            `setupProfile.setupProfileId must be ${setupProfileId}.`,
        );
    }
    const setupProfile =
        setupProfileRecord as CollectiveBgvSetupProfileForCertificates;
    positiveNumberField(setupProfile, 'participantCount', 'setupProfile');
    positiveNumberField(setupProfile, 'qDec', 'setupProfile');
    hashField(setupProfile, 'setupProfileHash', 'setupProfile');
    const qShare = objectField(setupProfile, 'qShare', 'setupProfile');
    const qSharePrimes = numberArrayField(
        qShare,
        'primes',
        'setupProfile.qShare',
    );
    if (qSharePrimes.length === 0) {
        throw new Error('setupProfile.qShare.primes must not be empty.');
    }
    const qShareHash = hashField(setupProfile, 'qShareHash', 'setupProfile');
    assertDerivedHashMatches(
        'QSharePrimeListHash',
        qShare,
        qShareHash,
        'setupProfile.qShareHash',
    );
    hashField(
        setupProfile,
        'carryAwareVssShareRelationProfileHash',
        'setupProfile',
    );
    const commitmentProfile = objectField(
        setupProfile,
        'commitmentProfile',
        'setupProfile',
    );
    objectField(
        commitmentProfile,
        'messageEncoding',
        'setupProfile.commitmentProfile',
    );
    const commitmentProfileHash = hashField(
        setupProfile,
        'commitmentProfileHash',
        'setupProfile',
    );
    assertDerivedHashMatches(
        'SetupCommitmentProfileHash',
        commitmentProfile,
        commitmentProfileHash,
        'setupProfile.commitmentProfileHash',
    );
    const setupProofProfile = objectField(
        setupProfile,
        'setupProofProfile',
        'setupProfile',
    );
    const setupProofProfileHash = hashField(
        setupProfile,
        'setupProofProfileHash',
        'setupProfile',
    );
    assertDerivedHashMatches(
        'SetupProofProfileHash',
        setupProofProfile,
        setupProofProfileHash,
        'setupProfile.setupProofProfileHash',
    );
    const setupTransportProfile = objectField(
        setupProfile,
        'setupTransportProfile',
        'setupProfile',
    );
    const setupTransportProfileHash = hashField(
        setupProfile,
        'setupTransportProfileHash',
        'setupProfile',
    );
    assertDerivedHashMatches(
        'SetupTransportProfileHash',
        setupTransportProfile,
        setupTransportProfileHash,
        'setupProfile.setupTransportProfileHash',
    );
    const evaluatorKeyScheduleProfile = objectField(
        setupProfile,
        'evaluatorKeyScheduleProfile',
        'setupProfile',
    );
    const evaluatorKeyScheduleProfileHash = hashField(
        setupProfile,
        'evaluatorKeyScheduleProfileHash',
        'setupProfile',
    );
    assertDerivedHashMatches(
        'EvaluatorKeyScheduleProfileHash',
        evaluatorKeyScheduleProfile,
        evaluatorKeyScheduleProfileHash,
        'setupProfile.evaluatorKeyScheduleProfileHash',
    );
    const publicVssMaterialSizeProfile = objectField(
        setupProfile,
        'publicVssCommitmentMaterialSizeProfile',
        'setupProfile',
    );
    positiveNumberField(
        publicVssMaterialSizeProfile,
        'fullMaterialCoefficientBytes',
        'setupProfile.publicVssCommitmentMaterialSizeProfile',
    );

    return setupProfile;
};

const bgvProfileForCertificates = (
    bgvProfileValue: BgvRnsProfileForCertificates | JsonRecord,
): BgvRnsProfileForCertificates => {
    const bgvProfile = assertObjectRecord(
        bgvProfileValue,
        'bgvProfile',
    ) as BgvRnsProfileForCertificates;
    const profile = objectField(bgvProfile, 'profile', 'bgvProfile');
    stringField(profile, 'profileId', 'bgvProfile.profile');
    stringField(profile, 'backendProfileId', 'bgvProfile.profile');
    positiveNumberField(profile, 'polynomialDegree', 'bgvProfile.profile');
    positiveNumberField(profile, 'plaintextModulus', 'bgvProfile.profile');
    stringField(profile, 'dataBasisId', 'bgvProfile.profile');
    const dataPrimes = numberArrayField(
        profile,
        'dataPrimes',
        'bgvProfile.profile',
    );
    if (dataPrimes.length === 0) {
        throw new Error('bgvProfile.profile.dataPrimes must not be empty.');
    }
    positiveNumberField(profile, 'specialPrime', 'bgvProfile.profile');
    stringField(bgvProfile, 'securityEstimatorInputHash', 'bgvProfile');

    return bgvProfile;
};

const relinearizationScheduleEntries = (
    setupProfile: CollectiveBgvSetupProfileForCertificates,
): readonly Readonly<{ readonly level: number }>[] => {
    const evaluatorProfile = setupProfile.evaluatorKeyScheduleProfile;
    const entries = evaluatorProfile.relinearizationLevelSchedule;
    if (!Array.isArray(entries)) {
        throw new TypeError(
            'setupProfile.evaluatorKeyScheduleProfile.relinearizationLevelSchedule must be an array.',
        );
    }

    return entries.map((entry, entryIndex) => {
        const entryRecord = assertObjectRecord(
            entry,
            `setupProfile.evaluatorKeyScheduleProfile.relinearizationLevelSchedule.${String(entryIndex)}`,
        );

        return {
            ...entryRecord,
            level: numberField(
                entryRecord,
                'level',
                `setupProfile.evaluatorKeyScheduleProfile.relinearizationLevelSchedule.${String(entryIndex)}`,
            ),
        };
    });
};

const galoisScheduleEntries = (
    setupProfile: CollectiveBgvSetupProfileForCertificates,
): readonly Readonly<{ readonly level: number }>[] => {
    const evaluatorProfile = setupProfile.evaluatorKeyScheduleProfile;
    const entries = evaluatorProfile.requiredGaloisKeySchedule;
    if (!Array.isArray(entries)) {
        throw new TypeError(
            'setupProfile.evaluatorKeyScheduleProfile.requiredGaloisKeySchedule must be an array.',
        );
    }

    return entries.map((entry, entryIndex) => {
        const entryRecord = assertObjectRecord(
            entry,
            `setupProfile.evaluatorKeyScheduleProfile.requiredGaloisKeySchedule.${String(entryIndex)}`,
        );

        return {
            ...entryRecord,
            level: numberField(
                entryRecord,
                'level',
                `setupProfile.evaluatorKeyScheduleProfile.requiredGaloisKeySchedule.${String(entryIndex)}`,
            ),
        };
    });
};

const commitmentModulusLimbs = (
    setupProfile: CollectiveBgvSetupProfileForCertificates,
): unknown => {
    const messageEncoding = setupProfile.commitmentProfile.messageEncoding;
    const limbs = messageEncoding.commitmentModulusLimbs;
    if (!Array.isArray(limbs) || limbs.length === 0) {
        throw new TypeError(
            'setupProfile.commitmentProfile.messageEncoding.commitmentModulusLimbs must be a non-empty array.',
        );
    }

    return limbs;
};

const setupCommitmentSecurityCertificateBody = (
    setupProfile: CollectiveBgvSetupProfileForCertificates,
): SetupCommitmentSecurityCertificateBody => {
    const sourceRnsPrimes = setupProfile.qShare.primes;
    const maxSourceMessageModulus = Math.max(...sourceRnsPrimes);
    const recipientScalarSum = scalarPowerSum(
        setupProfile.qDec,
        setupProfile.participantCount,
    );
    const thresholdScalarSum =
        recipientScalarSum * BigInt(setupProfile.participantCount);
    const commitmentModulusProduct =
        BigInt(sourceRnsPrimes[0]) * BigInt(sourceRnsPrimes[1]);
    const maxRecipientLiftedCoefficient =
        BigInt(maxSourceMessageModulus - 1) * recipientScalarSum;
    const maxThresholdLiftedCoefficient =
        BigInt(maxSourceMessageModulus - 1) * thresholdScalarSum;
    if (maxThresholdLiftedCoefficient >= commitmentModulusProduct) {
        throw new Error(
            'setupProfile commitment modulus product must cover the threshold-share aggregate no-wrap bound.',
        );
    }
    const commitmentModulusProductBits = ceilLog2Bigint(
        commitmentModulusProduct,
    );

    return {
        objectType: 'SetupCommitmentSecurityCertificate',
        objectVersion: 1,
        setupProfileId,
        setupProfileHash: setupProfile.setupProfileHash,
        commitmentProfileId: setupCommitmentProfileId,
        commitmentProfileHash: setupProfile.commitmentProfileHash,
        qShareHash: setupProfile.qShareHash,
        carryAwareVssShareRelationProfileHash:
            setupProfile.carryAwareVssShareRelationProfileHash,
        certificateScope:
            'first-profile-BDLOP-LNP-commitment-parameters-and-opening-bounds',
        acceptedUse: [
            'VSS coefficient commitment records',
            'recipient-local private VSS proof witness checks',
            'verifier-derived threshold-share commitment roots',
            'same-secret trustee commitment roots',
        ],
        nonClosure: [
            'same-secret proof needs repo-owned AB-DLOP/LNP soundness and zero-knowledge accounting plus full tbox closure',
            'public-key share proof needs repo-owned AB-DLOP/LNP soundness and zero-knowledge accounting plus full tbox closure',
            'relinearization and Galois proof bytes need repo-owned AB-DLOP/LNP soundness and zero-knowledge accounting, full tbox closure, profile-scale streaming, and accepted assembly closure',
            'setup-proof Fiat-Shamir/QROM composition certificate remains separate',
        ],
        ringAndMatrixParameters: {
            coefficientRing: 'Z_q[X]/(X^N+1)',
            ringDegree: 32_768,
            sourceRnsLimbCount: sourceRnsPrimes.length,
            sourceRnsPrimes,
            commitmentModulusLimbs: commitmentModulusLimbs(setupProfile),
            commitmentModulusProductDecimal:
                commitmentModulusProduct.toString(),
            commitmentModulusProductCeilBits: commitmentModulusProductBits,
            moduleRank: 2,
            randomnessWidth: 5,
            commitmentRowCount: 3,
            publicMatrixSource:
                'full-roster-common-randomness-XOF-unbiased-residue-stream',
            matrixHashBound: true,
        },
        freshOpeningDistribution: {
            distribution: 'coefficientwise-centered-ternary',
            coefficientSet: [-1, 0, 1],
            infinityNormBound: 1,
            randomnessWidth: 5,
            rawOpeningExported: false,
            perCoefficientOpeningExported: false,
        },
        fullWidthMessageBound: {
            messageSource: 'per-RNS-prime-Shamir-coefficient-ring-element',
            maxSourceMessageModulus,
            maxFreshMessageCoefficientDecimal: String(
                maxSourceMessageModulus - 1,
            ),
            commitmentModulusProductDecimal:
                commitmentModulusProduct.toString(),
            freshMessageNoWrap:
                BigInt(maxSourceMessageModulus - 1) < commitmentModulusProduct,
            status: 'claim-accounting-full-width-per-rns-message-bound-recorded',
        },
        aggregateOpeningBounds: {
            shamirCoefficientCount: setupProfile.qDec,
            maximumTrusteePoint: setupProfile.participantCount,
            recipientScalarPowerSumDecimal: recipientScalarSum.toString(),
            recipientAggregateOpeningInfinityBound: Number(recipientScalarSum),
            maxRecipientLiftedCoefficientDecimal:
                maxRecipientLiftedCoefficient.toString(),
            sourceTrusteeCountForThresholdAggregation:
                setupProfile.participantCount,
            thresholdScalarPowerSumDecimal: thresholdScalarSum.toString(),
            thresholdShareOpeningInfinityBound: Number(thresholdScalarSum),
            maxThresholdLiftedCoefficientDecimal:
                maxThresholdLiftedCoefficient.toString(),
            commitmentModulusProductDecimal:
                commitmentModulusProduct.toString(),
            recipientAndThresholdNoWrap: true,
            boundStatus:
                'claim-accounting-first-profile-homomorphic-opening-bounds-recorded',
        },
        multiOpeningLeakage: {
            recipientAggregateOpeningsArePublic: false,
            recipientAggregateOpeningsAreMailboxPlaintext: false,
            maxCorruptRecipientsBeforeThreshold: setupProfile.qDec - 1,
            shamirPolynomialDegree: setupProfile.qDec - 1,
            rawCoefficientOpeningsExported: false,
            perCoefficientRandomnessExported: false,
            thresholdBoundary:
                'recipient-aggregate-openings-and-carry-witnesses-are-private-proof-witnesses',
            status: 'claim-accounting-active-static-threshold-leakage-bound-recorded',
        },
        bindingAssumption: {
            assumption: 'Module-SIS',
            boundTarget:
                'two-valid-openings-to-one-commitment-yield-short-module-SIS-solution',
            moduleRank: 2,
            randomnessWidth: 5,
            commitmentModulusProductCeilBits: commitmentModulusProductBits,
            extractedOpeningInfinityBound: Number(thresholdScalarSum),
            referenceRows: [
                {
                    document:
                        'LNP22_Lattice-Based Zero-Knowledge Proofs and Applications Shorter, Simpler, and More General',
                    localReferencePath:
                        'reference-documents/LNP22_Lattice-Based Zero-Knowledge Proofs and Applications Shorter, Simpler, and More General.txt',
                    sections: [
                        'Commitment schemes',
                        'Module-SIS and Module-LWE problems',
                        'ABDLOP commitment scheme and proofs of linear relations',
                    ],
                },
                {
                    document:
                        'FPS25_Lattice-Based Zero-Knowledge Proofs in Action Applications to Electronic Voting',
                    localReferencePath:
                        'reference-documents/FPS25_Lattice-Based Zero-Knowledge Proofs in Action Applications to Electronic Voting.txt',
                    sections: [
                        'BDLOP commitment background',
                        'Module-LWE and Module-SIS definitions',
                    ],
                },
            ],
            estimatorStatus:
                'repo-owned-module-sis-parameter-accounting-required',
        },
        hidingAssumption: {
            assumption:
                'Module-LWE with recipient-hidden proof-witness opening leakage boundary',
            openingDistribution: 'coefficientwise-centered-ternary',
            publicMatrixDistribution: 'hash-derived-uniform-residue-stream',
            lowEntropySecretHiding: true,
            statisticalLeakageStatus:
                'repo-owned-recipient-hidden-aggregate-opening-proof-witness-accounting-required',
            estimatorStatus:
                'repo-owned-module-lwe-parameter-accounting-required',
        },
        estimatorRows: [
            {
                rowId: 'first-profile-module-sis-binding-row',
                problem: 'Module-SIS',
                targetSecurityBits: 128,
                ringDegree: 32_768,
                moduleRank: 2,
                modulusCeilBits: commitmentModulusProductBits,
                shortVectorInfinityBoundDecimal: thresholdScalarSum.toString(),
                status: 'claim-accounting-pending',
            },
            {
                rowId: 'first-profile-module-lwe-hiding-row',
                problem: 'Module-LWE',
                targetSecurityBits: 128,
                ringDegree: 32_768,
                moduleRank: 2,
                secretDistribution: 'centered-ternary-opening',
                modulusCeilBits: commitmentModulusProductBits,
                status: 'claim-accounting-pending',
            },
        ],
        certificateStatus:
            'not-claim-bearing-until-repo-owned-parameter-certificate-and-setup-proof-accounting-close',
    };
};

const createSetupCommitmentSecurityCertificate = (
    setupProfile: CollectiveBgvSetupProfileForCertificates,
): SetupCommitmentSecurityCertificate => {
    const certificateBody =
        setupCommitmentSecurityCertificateBody(setupProfile);

    return {
        ...certificateBody,
        setupCommitmentSecurityCertificateHash: deriveProtocolHash(
            'SetupCommitmentSecurityCertificateHash',
            certificateBody,
        ),
    };
};

const setupProofRecordBindingForCertificate = (
    setupProfile: CollectiveBgvSetupProfileForCertificates,
): JsonRecord => {
    const setupProofProfile = setupProfile.setupProofProfile;
    const challengeBinding = objectField(
        setupProofProfile,
        'challengeBinding',
        'setupProfile.setupProofProfile',
    );
    assertSetupProofFamiliesMatchProfile(setupProofProfile);
    const verificationPolicy = objectField(
        setupProofProfile,
        'verificationPolicy',
        'setupProfile.setupProofProfile',
    );

    return {
        objectType: 'SetupProofRecordBinding',
        objectVersion: 1,
        setupProfileId,
        setupProofProfileId: stringField(
            setupProofProfile,
            'profileId',
            'setupProfile.setupProofProfile',
        ),
        setupProofProfileHash: setupProfile.setupProofProfileHash,
        proofSystem: stringField(
            setupProofProfile,
            'proofSystem',
            'setupProfile.setupProofProfile',
        ),
        challengeDomain: stringField(
            challengeBinding,
            'challengeDomain',
            'setupProfile.setupProofProfile.challengeBinding',
        ),
        challengeDomainHash: hashField(
            challengeBinding,
            'challengeDomainHash',
            'setupProfile.setupProofProfile.challengeBinding',
        ),
        challengeBits: numberField(
            challengeBinding,
            'challengeBits',
            'setupProfile.setupProofProfile.challengeBinding',
        ),
        challengeCount: numberField(
            challengeBinding,
            'challengeCount',
            'setupProfile.setupProofProfile.challengeBinding',
        ),
        challengeCoefficientBound: numberField(
            challengeBinding,
            'challengeCoefficientBound',
            'setupProfile.setupProofProfile.challengeBinding',
        ),
        applicationRingDegree: numberField(
            objectField(
                setupProofProfile,
                'relationModel',
                'setupProfile.setupProofProfile',
            ),
            'applicationRingDegree',
            'setupProfile.setupProofProfile.relationModel',
        ),
        lnpTboxProofRingDegree: numberField(
            challengeBinding,
            'lnpTboxProofRingDegree',
            'setupProfile.setupProofProfile.challengeBinding',
        ),
        lnpTboxChallengeLog2Range: numberField(
            challengeBinding,
            'lnpTboxChallengeLog2Range',
            'setupProfile.setupProofProfile.challengeBinding',
        ),
        lnpTboxChallengeEncodedBits: numberField(
            challengeBinding,
            'lnpTboxChallengeEncodedBits',
            'setupProfile.setupProofProfile.challengeBinding',
        ),
        lnpTboxChallengeSpaceBits: numberField(
            challengeBinding,
            'lnpTboxChallengeSpaceBits',
            'setupProfile.setupProofProfile.challengeBinding',
        ),
        challengeSpace: stringField(
            challengeBinding,
            'challengeSpace',
            'setupProfile.setupProofProfile.challengeBinding',
        ),
        challengeSampler: stringField(
            challengeBinding,
            'challengeSampler',
            'setupProfile.setupProofProfile.challengeBinding',
        ),
        challengeSeedDomain: setupProofChallengeSeedDomain,
        challengeStreamDomain: setupProofChallengeStreamDomain,
        challengeDifferenceInvertibilityStatus: stringField(
            challengeBinding,
            'challengeDifferenceInvertibilityStatus',
            'setupProfile.setupProofProfile.challengeBinding',
        ),
        challengeDifferenceInvertibilityAccounting: objectField(
            challengeBinding,
            'challengeDifferenceInvertibilityAccounting',
            'setupProfile.setupProofProfile.challengeBinding',
        ),
        proofBytesDomain: setupProofBytesDomain,
        proofSerialization: setupProofSerialization,
        proofByteDecoder: setupProofByteDecoder,
        privateVssShareTboxParameterProfileHash: hashField(
            setupProofProfile,
            'privateVssShareTboxParameterProfileHash',
            'setupProfile.setupProofProfile',
        ),
        sameSecretTboxParameterProfileHash: hashField(
            setupProofProfile,
            'sameSecretTboxParameterProfileHash',
            'setupProfile.setupProofProfile',
        ),
        publicKeyShareTboxParameterProfileHash: hashField(
            setupProofProfile,
            'publicKeyShareTboxParameterProfileHash',
            'setupProfile.setupProofProfile',
        ),
        relinearizationKeyShareTboxParameterProfileHash: hashField(
            setupProofProfile,
            'relinearizationKeyShareTboxParameterProfileHash',
            'setupProfile.setupProofProfile',
        ),
        galoisKeyShareTboxParameterProfileHash: hashField(
            setupProofProfile,
            'galoisKeyShareTboxParameterProfileHash',
            'setupProfile.setupProofProfile',
        ),
        proofBytesAcceptedStatus: stringField(
            verificationPolicy,
            'proofBytesAcceptedStatus',
            'setupProfile.setupProofProfile.verificationPolicy',
        ),
    };
};

const setupProofAccountingCertificateBody = (
    setupProfile: CollectiveBgvSetupProfileForCertificates,
): SetupProofAccountingCertificateBody => {
    const setupProofProfile = setupProfile.setupProofProfile;
    if (
        stringField(
            setupProofProfile,
            'profileId',
            'setupProfile.setupProofProfile',
        ) !== setupProofProfileId
    ) {
        throw new Error(
            `setupProfile.setupProofProfile.profileId must be ${setupProofProfileId}.`,
        );
    }
    const challengeBinding = objectField(
        setupProofProfile,
        'challengeBinding',
        'setupProfile.setupProofProfile',
    );
    if (
        stringField(
            challengeBinding,
            'challengeDomain',
            'setupProfile.setupProofProfile.challengeBinding',
        ) !== setupProofChallengeDomain
    ) {
        throw new Error(
            `setupProfile.setupProofProfile.challengeBinding.challengeDomain must be ${setupProofChallengeDomain}.`,
        );
    }
    if (
        stringField(
            challengeBinding,
            'challengeSampler',
            'setupProfile.setupProofProfile.challengeBinding',
        ) !== setupProofChallengeSampler
    ) {
        throw new Error(
            `setupProfile.setupProofProfile.challengeBinding.challengeSampler must be ${setupProofChallengeSampler}.`,
        );
    }
    if (
        stringField(
            challengeBinding,
            'challengeSpace',
            'setupProfile.setupProofProfile.challengeBinding',
        ) !== setupProofChallengeSpace
    ) {
        throw new Error(
            `setupProfile.setupProofProfile.challengeBinding.challengeSpace must be ${setupProofChallengeSpace}.`,
        );
    }
    if (
        stringField(
            challengeBinding,
            'challengeDifferenceInvertibilityStatus',
            'setupProfile.setupProofProfile.challengeBinding',
        ) !== setupProofChallengeDifferenceInvertibilityStatus
    ) {
        throw new Error(
            `setupProfile.setupProofProfile.challengeBinding.challengeDifferenceInvertibilityStatus must be ${setupProofChallengeDifferenceInvertibilityStatus}.`,
        );
    }
    const verificationPolicy = objectField(
        setupProofProfile,
        'verificationPolicy',
        'setupProfile.setupProofProfile',
    );
    if (
        stringField(
            verificationPolicy,
            'proofBytesAcceptedStatus',
            'setupProfile.setupProofProfile.verificationPolicy',
        ) !== setupProofBytesAcceptedStatus
    ) {
        throw new Error(
            `setupProfile.setupProofProfile.verificationPolicy.proofBytesAcceptedStatus must be ${setupProofBytesAcceptedStatus}.`,
        );
    }
    const setupProofRecordBinding =
        setupProofRecordBindingForCertificate(setupProfile);
    const challengeSpaceAudit = objectField(
        setupProofProfile,
        'challengeSpaceAudit',
        'setupProfile.setupProofProfile',
    );

    return {
        objectType: 'SetupProofAccountingCertificate',
        objectVersion: 1,
        setupProfileId,
        setupProfileHash: setupProfile.setupProfileHash,
        setupProofProfileId,
        setupProofProfileHash: setupProfile.setupProofProfileHash,
        setupProofRecordBinding,
        setupProofRecordBindingHash: deriveProtocolHash(
            'SetupProofRecordBindingHash',
            setupProofRecordBinding,
        ),
        proofFamilies: setupProofFamilies,
        proofFamilyAccounting: [
            {
                proofFamily: 'vss-opening-carry',
                claimScope:
                    'recipient-local private VSS share proof relation over accepted Q_share limbs',
                accountingStatus:
                    'repo-owned AB-DLOP/LNP soundness and zero-knowledge accounting required before claim-bearing proof acceptance',
            },
            {
                proofFamily: 'same-secret-consistency',
                claimScope:
                    'same trustee secret across accepted VSS constant commitments',
                accountingStatus:
                    'repo-owned AB-DLOP/LNP soundness and zero-knowledge accounting required before claim-bearing proof acceptance',
            },
            {
                proofFamily: 'public-key-share',
                claimScope:
                    'public-key share relation bound to the accepted same-secret proof and public-key material roots',
                accountingStatus:
                    'repo-owned AB-DLOP/LNP soundness and zero-knowledge accounting required before claim-bearing proof acceptance',
            },
            {
                proofFamily: 'relinearization-key-share',
                claimScope:
                    'relinearization key-share relation bound to the same secret, round-one aggregate, and key-switch component roots',
                accountingStatus:
                    'repo-owned AB-DLOP/LNP soundness and zero-knowledge accounting required before claim-bearing proof acceptance',
            },
            {
                proofFamily: 'galois-key-share',
                claimScope:
                    'Galois key-share relation bound to the required automorphism schedule and key-switch component roots',
                accountingStatus:
                    'repo-owned AB-DLOP/LNP soundness and zero-knowledge accounting required before claim-bearing proof acceptance',
            },
        ],
        challengeAccounting: {
            transform: 'Fiat-Shamir',
            challengeDomain: setupProofChallengeDomain,
            challengeDomainHash: hashField(
                challengeBinding,
                'challengeDomainHash',
                'setupProfile.setupProofProfile.challengeBinding',
            ),
            challengeSampler: setupProofChallengeSampler,
            challengeSpace: setupProofChallengeSpace,
            challengeDifferenceInvertibilityStatus:
                setupProofChallengeDifferenceInvertibilityStatus,
            challengeDifferenceInvertibilityAccounting: objectField(
                challengeBinding,
                'challengeDifferenceInvertibilityAccounting',
                'setupProfile.setupProofProfile.challengeBinding',
            ),
            challengeSpaceAudit,
            challengeSpaceAuditHash: deriveProtocolHash(
                setupProofChallengeSpaceAuditHashNamespace,
                challengeSpaceAudit,
            ),
            randomOracleModel:
                'repo-owned Fiat-Shamir/QROM accounting required before claim-bearing proof acceptance',
            qromStatus:
                'repo-owned-qrom-accounting-required-before-claim-closure',
            transcriptBinding: stringArrayField(
                challengeBinding,
                'transcriptBinding',
                'setupProfile.setupProofProfile.challengeBinding',
            ),
        },
        tboxAccounting: {
            tboxProfileHashBinding:
                'all-required-setup-proof-tbox-profile-hashes-bound',
            requiredFamilies: setupProofFamilies,
            status: 'full setup LNP tbox quadratic and range accounting required before claim-bearing proof acceptance',
        },
        completionBoundary:
            'claim-bearing accepted setup is a repo-owned library claim and does not require external validation or a third-party review gate',
        certificateStatus:
            'not-claim-bearing-until-repo-owned-proof-accounting-and-theorem-closure',
    };
};

const createSetupProofAccountingCertificate = (
    setupProfile: CollectiveBgvSetupProfileForCertificates,
): SetupProofAccountingCertificate => {
    const certificateBody = setupProofAccountingCertificateBody(setupProfile);

    return {
        ...certificateBody,
        setupProofAccountingCertificateHash: deriveProtocolHash(
            'SetupProofAccountingCertificateHash',
            certificateBody,
        ),
    };
};

const setupTransportCertificateBody = (
    setupProfile: CollectiveBgvSetupProfileForCertificates,
    vssCoefficientCommitmentMaterial: JsonRecord,
    transportInput: SetupCertificateTransportInput,
): SetupTransportCertificateBody => {
    const publicVssMaterialSizeProfile =
        setupProfile.publicVssCommitmentMaterialSizeProfile;
    const totalByteLength =
        publicVssMaterialSizeProfile.fullMaterialCoefficientBytes;
    const chunkCount = Math.ceil(
        totalByteLength / setupTransportChunkSizeBytes,
    );
    const fullObjectHash = transportInput.fullObjectHash;
    assertProtocolHash(fullObjectHash, 'transport.fullObjectHash');
    const chunkHashes = [...transportInput.chunkHashes];
    chunkHashes.forEach((chunkHash, chunkIndex) => {
        assertProtocolHash(
            chunkHash,
            `transport.chunkHashes.${String(chunkIndex)}`,
        );
    });
    if (chunkHashes.length !== chunkCount) {
        throw new Error(
            'transport.chunkHashes length must match the setup transport chunk count.',
        );
    }
    if (new Set(chunkHashes).size !== chunkHashes.length) {
        throw new Error('transport.chunkHashes must not contain duplicates.');
    }
    const objectRoot = hashField(
        vssCoefficientCommitmentMaterial,
        'vssCoefficientCommitmentMaterialRoot',
        'vssCoefficientCommitmentMaterial',
    );
    const chunkRoot = deriveProtocolHash('SetupTransportChunkManifestRoot', {
        objectType: 'SetupTransportChunkManifest',
        objectVersion: 1,
        setupProfileId,
        transportProfileId: setupTransportProfileId,
        chunkSizeBytes: setupTransportChunkSizeBytes,
        chunkCount,
        totalByteLength,
        chunkHashes,
        fullObjectHash,
    });

    return {
        objectType: 'SetupTransportCertificate',
        objectVersion: 1,
        setupProfileId,
        transportProfileId: setupTransportProfileId,
        setupTransportProfileHash: setupProfile.setupTransportProfileHash,
        largeObjectEncoding: 'binary',
        chunking: 'required',
        chunkSizeBytes: setupTransportChunkSizeBytes,
        chunkCount,
        totalByteLength,
        storageQuotaBytes: setupTransportStorageQuotaBytes,
        largestSingleBufferBytes: setupTransportLargestSingleBufferBytes,
        copyCountLimit: setupTransportCopyCountLimit,
        streamVerificationOrder: setupTransportStreamOrder,
        resumePolicy: setupTransportResumePolicy,
        lazyLoadingPolicy: setupTransportLazyLoadingPolicy,
        transportedObjects: [
            {
                objectType: 'SetupTransportedObject',
                objectVersion: 1,
                objectName: 'vssCoefficientCommitmentMaterial',
                objectRole: 'public-vss-coefficient-commitment-material',
                objectRoot,
                byteLength: totalByteLength,
                chunkStartIndex: 0,
                chunkCount,
                chunkRoot,
                fullObjectHash,
                encoding: 'binary',
                loadingPolicy: setupTransportedObjectLoadingPolicy,
            },
        ],
        chunkHashes,
        chunkRoot,
        fullObjectHash,
    };
};

const createSetupTransportCertificate = (
    setupProfile: CollectiveBgvSetupProfileForCertificates,
    vssCoefficientCommitmentMaterial: JsonRecord,
    transportInput: SetupCertificateTransportInput,
): SetupTransportCertificate => {
    const certificateBody = setupTransportCertificateBody(
        setupProfile,
        vssCoefficientCommitmentMaterial,
        transportInput,
    );

    return {
        ...certificateBody,
        setupTransportCertificateHash: deriveProtocolHash(
            'SetupTransportCertificateHash',
            certificateBody,
        ),
    };
};

const bgvHeSecurityCertificateBody = (
    setupProfile: CollectiveBgvSetupProfileForCertificates,
    bgvProfile: BgvRnsProfileForCertificates,
): BgvHeSecurityCertificateBody => {
    const dataPrimes = bgvProfile.profile.dataPrimes;
    const dataPrimeProductDecimal = modulusProductDecimal(dataPrimes);
    const largestExposedModulusBits = moduliBitLengthSum(dataPrimes);
    const extendedUtilityCeilLog2Product = moduliBitLengthSum([
        ...dataPrimes,
        bgvProfile.profile.specialPrime,
    ]);
    const postQuantumMaximumLogQ = 827;
    const classicalMaximumLogQ = 881;
    const postQuantumAccepted =
        largestExposedModulusBits <= postQuantumMaximumLogQ;
    const classicalAccepted = largestExposedModulusBits <= classicalMaximumLogQ;
    const acceptedForDirectEvaluatorReplay =
        postQuantumAccepted && classicalAccepted;
    const acceptedRelinearizationKeyPolynomials =
        keySwitchComponentPolynomialCount(
            relinearizationScheduleEntries(setupProfile),
        );
    const acceptedGaloisKeyPolynomials = keySwitchComponentPolynomialCount(
        galoisScheduleEntries(setupProfile),
    );

    return {
        objectType: 'BgvHeSecurityCertificate',
        objectVersion: 1,
        setupProfileId,
        profileId: bgvProfile.profile.profileId,
        backendProfileId: bgvProfile.profile.backendProfileId,
        setupProfileHash: setupProfile.setupProfileHash,
        qShareHash: setupProfile.qShareHash,
        setupProofProfileHash: setupProfile.setupProofProfileHash,
        evaluatorKeyScheduleProfileHash:
            setupProfile.evaluatorKeyScheduleProfileHash,
        certificateScope:
            'first-profile-accepted-setup-direct-evaluator-replay-Q-data-boundary',
        reference: {
            document: 'ACC18 Homomorphic Encryption Standard',
            localReferencePath:
                'reference-documents/ACC18_Homomorphic Encryption Standard.txt',
            sections: [
                'Section 2.1.3 secret key distribution',
                'Table 1 BKZ.sieve ternary n=32768 row',
                'Table 2 BKZ.qsieve ternary n=32768 row',
            ],
            tableScope: 'power-of-two cyclotomic RLWE parameter table',
        },
        assessedRing: {
            polynomialDegree: bgvProfile.profile.polynomialDegree,
            plaintextModulus: bgvProfile.profile.plaintextModulus,
            dataBasisId: bgvProfile.profile.dataBasisId,
            dataPrimeCount: dataPrimes.length,
            dataPrimeProductDecimal,
            dataPrimeCeilLog2Product: largestExposedModulusBits,
            qSharePrimeCount: dataPrimes.length,
            qSharePrimeProductDecimal: dataPrimeProductDecimal,
            qShareCeilLog2Product: largestExposedModulusBits,
            specialPrime: bgvProfile.profile.specialPrime,
            extendedUtilityCeilLog2Product,
            extendedUtilityExposureStatus:
                'not-exposed-by-current-accepted-direct-evaluator-replay-material',
            largestExposedBasisClass: 'Q_data',
            largestExposedModulusBits,
        },
        secretDistribution: {
            distributionKind: 'standard-ternary-collective-secret',
            support: [-1, 0, 1],
            isPlainDenseTernary: true,
            estimatorModel: 'HE-standard-ternary',
            source: 'recipient-verified-VSS same-secret commitments',
        },
        errorDistribution: {
            distributionKind: 'centered-binomial-eta2',
            support: [-2, -1, 0, 1, 2],
            keySwitchNoiseDistribution: 'centered-binomial-eta2',
            certificateStatus:
                'accepted-support-recorded-proof-family-checks-still-required',
        },
        publicSampleAccounting: {
            publicKeyCrpPolynomials: 1,
            publicKeyShareCount: setupProfile.participantCount,
            acceptedRelinearizationKeyPolynomials,
            acceptedGaloisKeyPolynomials,
            scheduledRelinearizationLevelCount:
                relinearizationScheduleEntries(setupProfile).length,
            scheduledGaloisKeyCount: galoisScheduleEntries(setupProfile).length,
            evaluationKeyExposureStatus:
                'root-bound-claim-accounting-pending-relinearization-and-galois-key-material-exposed',
            commitmentAndSetupProofPublicMatrices:
                'covered-by-setup-commitment-and-setup-proof profiles, not counted as HE RLWE public-key samples',
        },
        standardRows: {
            postQuantumTernary128: {
                status: postQuantumAccepted
                    ? 'accepted'
                    : 'rejected-largest-exposed-modulus-exceeds-row',
                costModel: 'BKZ.qsieve',
                secretDistribution: 'ternary',
                polynomialDegree: 32_768,
                securityLevelBits: 128,
                maximumLogQ: postQuantumMaximumLogQ,
                largestExposedModulusBits,
                marginBits: Math.max(
                    postQuantumMaximumLogQ - largestExposedModulusBits,
                    0,
                ),
                uSVPBits: '128.1',
                decodingBits: '128.7',
                dualBits: '128.4',
            },
            classicalTernary128: {
                status: classicalAccepted
                    ? 'accepted'
                    : 'rejected-largest-exposed-modulus-exceeds-row',
                costModel: 'BKZ.sieve',
                secretDistribution: 'ternary',
                polynomialDegree: 32_768,
                securityLevelBits: 128,
                maximumLogQ: classicalMaximumLogQ,
                largestExposedModulusBits,
                marginBits: Math.max(
                    classicalMaximumLogQ - largestExposedModulusBits,
                    0,
                ),
                uSVPBits: '128.5',
                decodingBits: '129.1',
                dualBits: '128.5',
            },
        },
        estimatorBinding: {
            status: acceptedForDirectEvaluatorReplay
                ? 'accepted-by-local-HE-standard-table-row'
                : 'rejected-by-local-HE-standard-table-row',
            tool: 'HE-standard published parameter table',
            toolVersion: 'ACC18 local text reference',
            securityEstimatorInputHash: bgvProfile.securityEstimatorInputHash,
            secretModel: 'standard-ternary',
            errorModel: 'centered-binomial-eta2',
            largestExposedModulusBits,
            publicSamplesBound: true,
        },
        targetDecryptionStatus: {
            targetDecryptionProfileId,
            qTargetKnown: false,
            qTargetCoveredByCertificate: false,
            targetC1ThroughC4Covered: false,
            targetDecryptionReadiness:
                'refused-until-q-target-certificate-closes',
        },
        acceptedForDirectEvaluatorReplay,
        acceptedForTargetDecryption: false,
        statusLabels: acceptedForDirectEvaluatorReplay
            ? [
                  'HEStandardPostQuantum128Accepted',
                  'HEStandardClassical128Accepted',
                  'DataBasisLargestExposedModulusAccepted',
                  'SpecialPrimeNotPubliclyExposedOnAcceptedPath',
                  'TargetDecryptionReadinessRefusedUntilQTargetCertificate',
              ]
            : [
                  'HEStandardSecurityRejected',
                  'DataBasisLargestExposedModulusRejected',
              ],
    };
};

const createBgvHeSecurityCertificate = (
    setupProfile: CollectiveBgvSetupProfileForCertificates,
    bgvProfile: BgvRnsProfileForCertificates,
): BgvHeSecurityCertificate => {
    const certificateBody = bgvHeSecurityCertificateBody(
        setupProfile,
        bgvProfile,
    );

    return {
        ...certificateBody,
        heSecurityCertificateHash: deriveProtocolHash(
            'BGVHeSecurityCertificateHash',
            certificateBody,
        ),
    };
};

export const createSetupCertificates = (
    input: SetupCertificatesInput,
): SetupCertificates => {
    const setupProfile = setupProfileForCertificates(input.setupProfile);
    const bgvProfile = bgvProfileForCertificates(input.bgvProfile);
    const vssCoefficientCommitmentMaterial = assertObjectRecord(
        input.vssCoefficientCommitmentMaterial,
        'vssCoefficientCommitmentMaterial',
    );
    const transport = assertObjectRecord(input.transport, 'transport');
    const transportInput = {
        fullObjectHash: hashField(transport, 'fullObjectHash', 'transport'),
        chunkHashes: hashArrayField(transport, 'chunkHashes', 'transport'),
    };

    return {
        setupCommitmentSecurityCertificate:
            createSetupCommitmentSecurityCertificate(setupProfile),
        setupTransportCertificate: createSetupTransportCertificate(
            setupProfile,
            vssCoefficientCommitmentMaterial,
            transportInput,
        ),
        setupProofAccountingCertificate:
            createSetupProofAccountingCertificate(setupProfile),
        heSecurityCertificate: createBgvHeSecurityCertificate(
            setupProfile,
            bgvProfile,
        ),
    };
};
