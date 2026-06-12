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
        readonly acceptedCertificateTemplates?: JsonRecord;
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

export type SetupCertificateTransportedObjectInput = Readonly<{
    readonly objectName: string;
    readonly objectRole: string;
    readonly objectRoot: ProtocolHash;
    readonly byteLength: number;
    readonly fullObjectHash: ProtocolHash;
    readonly chunkRoot: ProtocolHash;
    readonly chunkHashes: readonly ProtocolHash[];
}>;

export type SetupCertificateTransportInput = Readonly<{
    readonly fullObjectHash: ProtocolHash;
    readonly chunkHashes: readonly ProtocolHash[];
    readonly transportedObjects?: readonly SetupCertificateTransportedObjectInput[];
}>;

export type SetupCertificatesInput = Readonly<{
    readonly setupProfile:
        | CollectiveBgvSetupProfileForCertificates
        | JsonRecord;
    readonly bgvProfile: BgvRnsProfileForCertificates | JsonRecord;
    readonly vssCoefficientCommitmentMaterial: JsonRecord;
    readonly transport: SetupCertificateTransportInput;
    readonly trusteeEvaluationKeyProofAccounting?: JsonRecord;
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
const setupProofScalarChallengeBits = 63;
const setupProofScalarChallengeMaximum = (1n << 63n) - 1n;
const privateVssShareMessageMaskBits = 112;
const setupProofMessageMaskBits = 80;
const setupProofWideMaskBits = 80;
const setupProofCarryMaskBits = 64;
const setupProofRingDegree = 32_768;
const setupProofLnpTboxProofRingDegree = 128;
const setupProofLnpTboxChallengeLog2Range = 3;
const setupProofLnpTboxChallengeEncodedBits =
    setupProofLnpTboxProofRingDegree * setupProofLnpTboxChallengeLog2Range;
const setupProofLnpTboxChallengeSpaceBits = 147;
const setupProofCommitmentRandomnessInfinityBound = 1n;
const setupProofSecretInfinityBound = 1n;
const setupProofErrorInfinityBound = 2n;
const setupProofBytesAcceptedStatus =
    'private-vss-same-secret-public-key-share-and-trustee-evaluation-key-proof-bytes-accepted-for-setup-proof-accounting';
const setupProofFamilies = [
    'vss-opening-carry',
    'same-secret-consistency',
    'public-key-share',
] as const;
const succinctEvaluationKeyProofAccountingHashNamespace =
    'SuccinctEvaluationKeyProofAccountingHash';
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

type SetupTransportedObjectRecord = Readonly<{
    readonly objectType: 'SetupTransportedObject';
    readonly objectVersion: 1;
    readonly objectName: string;
    readonly objectRole: string;
    readonly objectRoot: ProtocolHash;
    readonly byteLength: number;
    readonly chunkStartIndex: number;
    readonly chunkCount: number;
    readonly chunkRoot: ProtocolHash;
    readonly chunkHashes: readonly ProtocolHash[];
    readonly fullObjectHash: ProtocolHash;
    readonly encoding: 'binary';
    readonly loadingPolicy: typeof setupTransportedObjectLoadingPolicy;
}>;

const assertObjectRecord = (value: unknown, fieldName: string): JsonRecord => {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
        throw new TypeError(`${fieldName} must be an object.`);
    }

    return value as JsonRecord;
};

const cloneJsonRecord = (value: JsonRecord): JsonRecord =>
    JSON.parse(JSON.stringify(value)) as JsonRecord;

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

const acceptedCertificateTemplate = (
    setupProfile: CollectiveBgvSetupProfileForCertificates,
    templateFieldName: string,
    objectType: string,
    hashFieldName: string,
    hashNamespace: string,
): JsonRecord | null => {
    const templates = setupProfile.acceptedCertificateTemplates;
    if (templates === undefined) {
        return null;
    }
    const certificate = assertObjectRecord(
        templates[templateFieldName],
        `setupProfile.acceptedCertificateTemplates.${templateFieldName}`,
    );
    if (certificate.objectType !== objectType) {
        throw new Error(
            `setupProfile.acceptedCertificateTemplates.${templateFieldName}.objectType must be ${objectType}.`,
        );
    }
    const certificateHash = stringField(
        certificate,
        hashFieldName,
        `setupProfile.acceptedCertificateTemplates.${templateFieldName}`,
    );
    assertProtocolHash(
        certificateHash,
        `setupProfile.acceptedCertificateTemplates.${templateFieldName}.${hashFieldName}`,
    );
    const hashInput = cloneJsonRecord(certificate);
    delete hashInput[hashFieldName];
    if (deriveProtocolHash(hashNamespace, hashInput) !== certificateHash) {
        throw new Error(
            `setupProfile.acceptedCertificateTemplates.${templateFieldName}.${hashFieldName} must match the certificate body.`,
        );
    }

    return cloneJsonRecord(certificate);
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

const setupCertificateTransportedObjectInputs = (
    transport: Readonly<Record<string, unknown>>,
): readonly SetupCertificateTransportedObjectInput[] => {
    const transportedObjects = transport.transportedObjects;
    if (transportedObjects === undefined) {
        return [];
    }
    if (!Array.isArray(transportedObjects)) {
        throw new TypeError('transport.transportedObjects must be an array.');
    }

    return transportedObjects.map((transportedObjectValue, objectIndex) => {
        const objectPath = `transport.transportedObjects.${String(objectIndex)}`;
        const transportedObject = assertObjectRecord(
            transportedObjectValue,
            objectPath,
        );

        return {
            objectName: stringField(
                transportedObject,
                'objectName',
                objectPath,
            ),
            objectRole: stringField(
                transportedObject,
                'objectRole',
                objectPath,
            ),
            objectRoot: hashField(transportedObject, 'objectRoot', objectPath),
            byteLength: positiveNumberField(
                transportedObject,
                'byteLength',
                objectPath,
            ),
            fullObjectHash: hashField(
                transportedObject,
                'fullObjectHash',
                objectPath,
            ),
            chunkRoot: hashField(transportedObject, 'chunkRoot', objectPath),
            chunkHashes: hashArrayField(
                transportedObject,
                'chunkHashes',
                objectPath,
            ),
        };
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
): readonly unknown[] => {
    const messageEncoding = setupProfile.commitmentProfile.messageEncoding;
    const limbs = messageEncoding.commitmentModulusLimbs;
    if (!Array.isArray(limbs) || limbs.length === 0) {
        throw new TypeError(
            'setupProfile.commitmentProfile.messageEncoding.commitmentModulusLimbs must be a non-empty array.',
        );
    }

    return limbs;
};

const commitmentModulusValues = (
    setupProfile: CollectiveBgvSetupProfileForCertificates,
): readonly number[] =>
    commitmentModulusLimbs(setupProfile).map((limb, limbIndex) => {
        const fieldName = `setupProfile.commitmentProfile.messageEncoding.commitmentModulusLimbs.${String(limbIndex)}`;
        if (typeof limb === 'number') {
            if (!Number.isSafeInteger(limb) || limb <= 0) {
                throw new TypeError(
                    `${fieldName} must be a positive safe integer.`,
                );
            }

            return limb;
        }
        const limbRecord = assertObjectRecord(limb, fieldName);

        return positiveNumberField(limbRecord, 'modulus', fieldName);
    });

const commitmentModulusProductForProfile = (
    setupProfile: CollectiveBgvSetupProfileForCertificates,
): bigint =>
    commitmentModulusValues(setupProfile).reduce(
        (product, modulus) => product * BigInt(modulus),
        1n,
    );

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
        commitmentModulusProductForProfile(setupProfile);
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
            'public evaluation-key assembly and setup-package terminal acceptance remain separate from this commitment parameter certificate',
            'profile-scale binary streaming evidence remains separate from this commitment parameter certificate',
            'future target-decryption readiness remains outside this commitment parameter certificate',
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
                'repo-owned-module-sis-parameter-accounting-accepted',
        },
        hidingAssumption: {
            assumption:
                'Module-LWE with recipient-hidden proof-witness opening leakage boundary',
            openingDistribution: 'coefficientwise-centered-ternary',
            publicMatrixDistribution: 'hash-derived-uniform-residue-stream',
            lowEntropySecretHiding: true,
            statisticalLeakageStatus:
                'repo-owned-recipient-hidden-aggregate-opening-proof-witness-accounting-accepted',
            estimatorStatus:
                'repo-owned-module-lwe-parameter-accounting-accepted',
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
                status: 'claim-accounting-accepted',
                accountingBasis:
                    'accepted Module-SIS binding row under LNP22/FPS25 commitment references and no-wrap threshold-opening bounds',
            },
            {
                rowId: 'first-profile-module-lwe-hiding-row',
                problem: 'Module-LWE',
                targetSecurityBits: 128,
                ringDegree: 32_768,
                moduleRank: 2,
                secretDistribution: 'centered-ternary-opening',
                modulusCeilBits: commitmentModulusProductBits,
                status: 'claim-accounting-accepted',
                accountingBasis:
                    'accepted Module-LWE hiding row under LNP22/FPS25/ACC18 references and recipient-hidden opening leakage boundary',
            },
        ],
        certificateStatus:
            'claim-bearing-setup-commitment-parameter-accounting-accepted',
    };
};

const createSetupCommitmentSecurityCertificate = (
    setupProfile: CollectiveBgvSetupProfileForCertificates,
): SetupCommitmentSecurityCertificate => {
    const template = acceptedCertificateTemplate(
        setupProfile,
        'setupCommitmentSecurityCertificate',
        'SetupCommitmentSecurityCertificate',
        'setupCommitmentSecurityCertificateHash',
        'SetupCommitmentSecurityCertificateHash',
    );
    if (template !== null) {
        return template as SetupCommitmentSecurityCertificate;
    }

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
        proofBytesAcceptedStatus: stringField(
            verificationPolicy,
            'proofBytesAcceptedStatus',
            'setupProfile.setupProofProfile.verificationPolicy',
        ),
    };
};

const setupProofFamilyAccounting = (
    trusteeEvaluationKeyProofAccountingHash: ProtocolHash,
): JsonRecord[] => [
    {
        proofFamily: 'vss-opening-carry',
        claimScope:
            'recipient-local private VSS share proof relation over accepted Q_share limbs',
        verifierClosedStatus:
            'relation-transcript-and-bound-checks-verifier-closed',
        verifierClosedChecks: [
            'proof bytes hash, size, statement root, material root, statement-and-relation-bound tbox prefix, and scalar challenge are recomputed from canonical proof material',
            'accepted private VSS tbox parameter profile is pinned, deterministic full-width commitment-prefix bytes are recomputed from statement and relation commitments, h coefficients at positions 0 and d/2 are enforced as zero, LaZer check_z34 seed material, challenge seed, challenge-tail hash, lower-protocol challenge hash, row-domain hash, full-width R/Rprime row-set hashes, signed z3/z4 check-window hashes, and measured z3/z4 norms are record-bound and enforced, generated z3/z4 check-window bounds are enforced, z1/z21 Gaussian L2 bounds and generated hint ranges are enforced, z34-bound lower-protocol challenge sampling is enforced, and generated lower-protocol tbox suffix bytes are decoded and enforced against the relation transcript',
            'four first-profile Shamir coefficient opening responses are checked against accepted coefficient commitments',
            'recipient-point lifted share equality and explicit carry responses are checked coefficientwise before acceptance',
            'message, randomness, and carry responses are checked against fixed first-profile bounds',
        ],
        accountingStatus:
            'repo-owned-soundness-zero-knowledge-and-qrom-accounting-accepted',
        claimAccounting: {
            soundness:
                'LNP22 commit-and-prove extractor accounting is accepted for the recipient-local carry-aware VSS relation because statement binding, first-message commitments, generated tbox bytes, coefficient openings, carry relations, and response bounds are verified before acceptance',
            zeroKnowledge:
                'LNP22 simulator accounting is accepted for centered 112-bit coefficient masks, opening-randomness masks, carry masks, verifier-bound no-wrap bounds, and transcript-bound tbox bytes; private coefficients, openings, and carries are not exposed in accepted public artifacts',
            qrom: 'DFM20/DFMS22 Fiat-Shamir reduction accounting is accepted through duplicate-free setup challenge domains and the setup proof theorem accounting object',
        },
    },
    {
        proofFamily: 'same-secret-consistency',
        claimScope:
            'same trustee secret across accepted VSS constant commitments',
        verifierClosedStatus:
            'relation-transcript-and-bound-checks-verifier-closed',
        verifierClosedChecks: [
            'statement hash binds setup proof record binding, trustee statement roots, accepted constant commitment roots, and tbox profile hash',
            'relation commitment hash and scalar challenge are recomputed from proof commitments and canonical transcript fields',
            'accepted same-secret tbox parameter profile is pinned, deterministic full-width commitment-prefix bytes are recomputed from statement and relation commitments, h coefficients at positions 0 and d/2 are enforced as zero, LaZer check_z34 seed material, challenge seed, challenge-tail hash, lower-protocol challenge hash, row-domain hash, full-width R/Rprime row-set hashes, signed z3/z4 check-window hashes, and measured z3/z4 norms are record-bound and enforced, generated z3/z4 check-window bounds are enforced, z1/z21 Gaussian L2 bounds and generated hint ranges are enforced, z34-bound lower-protocol challenge sampling is enforced, and generated lower-protocol tbox suffix bytes are decoded and enforced against the relation transcript',
            'ternary secret support is checked through Boolean negative-indicator and shifted-secret support equations',
            'all accepted Q_share constant commitments are checked against one shared secret response and opening randomness response',
            'secret, negative-indicator, and randomness responses are checked against fixed first-profile bounds',
        ],
        accountingStatus:
            'repo-owned-soundness-zero-knowledge-and-qrom-accounting-accepted',
        claimAccounting: {
            soundness:
                'LNP22 commit-and-prove extractor accounting is accepted for the same-secret relation because the verifier binds one shared secret response to every accepted constant commitment and support equation',
            zeroKnowledge:
                'LNP22 simulator accounting is accepted for centered 80-bit same-secret and support-response masks with witness-dependent support commitments treated as simulated first messages under the fixed relation and no-wrap response accounting',
            qrom: 'DFM20/DFMS22 Fiat-Shamir reduction accounting is accepted through duplicate-free setup challenge domains and the setup proof theorem accounting object',
        },
    },
    {
        proofFamily: 'public-key-share',
        claimScope:
            'public-key share relation bound to the accepted same-secret proof and public-key material roots',
        verifierClosedStatus:
            'relation-transcript-and-bound-checks-verifier-closed',
        verifierClosedChecks: [
            'statement hash binds public-key share roots, same-secret statement roots, public matrix roots, coefficient vector hashes, and setup proof record binding',
            'relation commitment hash and scalar challenge are recomputed from public-key, support, and commitment-response commitments',
            'accepted public-key-share tbox parameter profile is pinned, deterministic full-width commitment-prefix bytes are recomputed from statement and relation commitments, h coefficients at positions 0 and d/2 are enforced as zero, LaZer check_z34 seed material, challenge seed, challenge-tail hash, lower-protocol challenge hash, row-domain hash, full-width R/Rprime row-set hashes, signed z3/z4 check-window hashes, and measured z3/z4 norms are record-bound and enforced, generated z3/z4 check-window bounds are enforced, z1/z21 Gaussian L2 bounds and generated hint ranges are enforced, z34-bound lower-protocol challenge sampling is enforced, and generated lower-protocol tbox suffix bytes are decoded and enforced against the relation transcript',
            'same-secret opening response and ternary secret support are checked against accepted VSS constant commitments',
            'centered-binomial error support is checked for every accepted Q_share limb and coefficient',
            'lifted public-key equality PKShare_i,l - p*e_i,l + a_l*s_i + q_l*v_i,l = 0 is checked with explicit carry responses',
            'secret, negative-indicator, opening-randomness, and error responses are checked against fixed first-profile bounds',
        ],
        accountingStatus:
            'repo-owned-soundness-zero-knowledge-and-qrom-accounting-accepted',
        claimAccounting: {
            soundness:
                'LNP22 commit-and-prove extractor accounting is accepted for the public-key share relation because same-secret openings, ternary support, centered-binomial error support, lifted no-wrap public-key equality, and fixed response bounds are verifier-bound',
            zeroKnowledge:
                'LNP22 simulator accounting is accepted for centered 80-bit committed-secret masks, support commitments, error masks, opening masks, and carry masks with fixed-width signed relation commitments and no-wrap accounting',
            qrom: 'DFM20/DFMS22 Fiat-Shamir reduction accounting is accepted through duplicate-free setup challenge domains and the setup proof theorem accounting object',
        },
    },
    {
        proofFamily: 'trustee-evaluation-key',
        claimScope:
            'every scheduled relinearization and Galois key share of one trustee, proven by one batched succinct argument against the committed trustee secret and the recomputed round-one public aggregates',
        verifierClosedStatus:
            'statement-rebuild-and-argument-checks-verifier-closed',
        verifierClosedChecks: [
            'every statement is rebuilt by the verifier from the transported share records, the recomputed round-one public aggregate diagonals, the accepted same-secret constant commitments, and the ceremony context; no prover-supplied statement field is trusted',
            'key-switch component material is decoded against record-bound component vector roots and deterministic public sampler seeds shared by schedule entry',
            'per-limb trace commitments, masked column openings, batched row checks, the digit-and-key-batched linear sumcheck, DEEP out-of-domain bindings, and the batched low-degree proof are verified for every limb field',
            'arithmetic source relations are enforced inside the argument: round-one sources equal the committed secret, round-two sources equal the secret times the recomputed public aggregate, and Galois sources equal the automorphism image',
            'the same-secret linkage opens the accepted BDLOP constant commitments natively over the commitment-modulus fields against the shared key-relation secret',
            'cross-limb consistency claims are checked as masked centered integers inside the joint no-wrap window',
            'canonical proof bytes are decoded with trailing-byte refusal and rebound to the statement hash recorded in the package',
        ],
        accountingStatus:
            'succinct-trustee-evaluation-key-theorem-accounting-open',
        claimAccounting: {
            accountingObject: 'SuccinctEvaluationKeyProofAccounting',
            accountingHash: trusteeEvaluationKeyProofAccountingHash,
            openItems:
                'the proven low-degree bound, the cross-limb consistency lemma, the simulator argument, the smudging budget, and the multi-round Fiat-Shamir/QROM accounting carry explicit not-accepted status inside the bound accounting object',
            claimBoundary:
                'packages remain ClaimClosureMissing for active-malicious evaluation-key claims until every open accounting row is accepted',
        },
    },
];

const responseMaskRandomBound = (maskBits: number): bigint =>
    (1n << BigInt(maskBits)) - 1n;

const setupProofResponseMaskProfile = (
    responseKind: string,
    maskBits: number,
    witnessInfinityBound: bigint,
    maskOffset: bigint,
    encodingRole: string,
): JsonRecord => {
    const effectiveMaskBound = responseMaskRandomBound(maskBits) + maskOffset;
    const challengeWitnessTermBound =
        setupProofScalarChallengeMaximum * witnessInfinityBound;
    const responseBound = effectiveMaskBound + challengeWitnessTermBound;
    const challengeWitnessTermCeilBits = ceilLog2Bigint(
        challengeWitnessTermBound + 1n,
    );

    return {
        responseKind,
        encodingRole,
        maskRandomBits: maskBits,
        maskOffsetDecimal: maskOffset.toString(),
        effectiveMaskBoundDecimal: effectiveMaskBound.toString(),
        scalarChallengeBits: setupProofScalarChallengeBits,
        scalarChallengeMaximumDecimal:
            setupProofScalarChallengeMaximum.toString(),
        witnessInfinityBoundDecimal: witnessInfinityBound.toString(),
        challengeWitnessTermBoundDecimal: challengeWitnessTermBound.toString(),
        challengeWitnessTermCeilBits,
        responseBoundDecimal: responseBound.toString(),
        responseBoundCeilBits: ceilLog2Bigint(responseBound),
        maskingSlackBits: maskBits - challengeWitnessTermCeilBits,
    };
};

const setupProofResponseBound = (
    maskBits: number,
    witnessInfinityBound: bigint,
    maskOffset: bigint,
): bigint =>
    responseMaskRandomBound(maskBits) +
    maskOffset +
    setupProofScalarChallengeMaximum * witnessInfinityBound;

const liftedMessageNoWrapAccounting = (
    relationName: string,
    secretResponseBound: bigint,
    negativeIndicatorResponseBound: bigint,
    maxSourceMessageModulus: bigint,
    commitmentModulusProduct: bigint,
): JsonRecord => {
    const liftedMessageResponseBound =
        maxSourceMessageModulus * negativeIndicatorResponseBound +
        secretResponseBound;

    return {
        relationName,
        maxSourceMessageModulus: Number(maxSourceMessageModulus),
        secretResponseBoundDecimal: secretResponseBound.toString(),
        negativeIndicatorResponseBoundDecimal:
            negativeIndicatorResponseBound.toString(),
        liftedMessageResponseBoundDecimal:
            liftedMessageResponseBound.toString(),
        commitmentModulusProductDecimal: commitmentModulusProduct.toString(),
        noWrapSatisfied: liftedMessageResponseBound < commitmentModulusProduct,
    };
};

const setupProofResponseMaskingAccounting = (
    setupProfile: CollectiveBgvSetupProfileForCertificates,
): JsonRecord => {
    const qSharePrimes = setupProfile.qShare.primes;
    const maxSourceMessageModulus = BigInt(Math.max(...qSharePrimes));
    const commitmentModulusProduct =
        commitmentModulusProductForProfile(setupProfile);
    const privateVssCarryWitnessBound = scalarPowerSum(
        setupProfile.qDec,
        setupProfile.participantCount,
    );
    const publicKeyCarryWitnessBound = BigInt(setupProofRingDegree + 3);
    const sameSecretResponseBound = setupProofResponseBound(
        setupProofMessageMaskBits,
        setupProofSecretInfinityBound,
        0n,
    );
    const sameSecretNegativeResponseBound = setupProofResponseBound(
        setupProofMessageMaskBits,
        setupProofSecretInfinityBound,
        0n,
    );
    const publicKeySecretResponseBound = setupProofResponseBound(
        setupProofMessageMaskBits,
        setupProofSecretInfinityBound,
        0n,
    );
    const publicKeyNegativeResponseBound = setupProofResponseBound(
        setupProofMessageMaskBits,
        setupProofSecretInfinityBound,
        0n,
    );

    return {
        objectType: 'SetupProofResponseMaskingAccounting',
        objectVersion: 1,
        setupProofProfileId,
        accountingStatus:
            'response-mask-bounds-strengthened-verifier-bound-and-zk-accounting-accepted',
        encodingConstraints: {
            responseEncoding: 'signed-i128-little-endian',
            committedMessageEncoding:
                'u128-source-coefficients-and-centered-signed-response-coefficients-with-big-int-no-wrap-before-commitment-modulus-reduction',
            relationCommitmentEncoding:
                'public-key lifted relation commitments use fixed-width signed 32-byte little-endian big-integer coefficients; response vectors remain signed i128',
            commitmentModulusProductDecimal:
                commitmentModulusProduct.toString(),
            commitmentModulusProductCeilBits: ceilLog2Bigint(
                commitmentModulusProduct,
            ),
            maxSourceMessageModulus: Number(maxSourceMessageModulus),
            carryMaskWideningStatus:
                'carry masks remain 64 bits and scalar relation challenges are capped at 63 bits because carry responses and response vectors remain signed i128',
        },
        families: [
            {
                proofFamily: 'vss-opening-carry',
                responseProfiles: [
                    setupProofResponseMaskProfile(
                        'coefficient-message',
                        privateVssShareMessageMaskBits,
                        maxSourceMessageModulus - 1n,
                        0n,
                        'committed-message-response',
                    ),
                    setupProofResponseMaskProfile(
                        'opening-randomness',
                        setupProofWideMaskBits,
                        setupProofCommitmentRandomnessInfinityBound,
                        0n,
                        'signed-opening-response',
                    ),
                    setupProofResponseMaskProfile(
                        'lifted-carry',
                        setupProofCarryMaskBits,
                        privateVssCarryWitnessBound,
                        0n,
                        'signed-carry-response',
                    ),
                ],
                fullWidthCoefficientMaskingStatus:
                    'centered-signed-private-vss-message-response-masking-verifier-bound-and-simulator-accounting-accepted',
                commitmentNoWrapStatus:
                    'three-limb-big-int-no-wrap-bound-recorded',
            },
            {
                proofFamily: 'same-secret-consistency',
                responseProfiles: [
                    setupProofResponseMaskProfile(
                        'secret',
                        setupProofMessageMaskBits,
                        setupProofSecretInfinityBound,
                        0n,
                        'committed-message-response',
                    ),
                    setupProofResponseMaskProfile(
                        'negative-indicator',
                        setupProofMessageMaskBits,
                        setupProofSecretInfinityBound,
                        0n,
                        'committed-message-response',
                    ),
                    setupProofResponseMaskProfile(
                        'opening-randomness',
                        setupProofWideMaskBits,
                        setupProofCommitmentRandomnessInfinityBound,
                        0n,
                        'signed-opening-response',
                    ),
                ],
                liftedMessageNoWrap: liftedMessageNoWrapAccounting(
                    'secret-plus-rns-prime-times-negative-indicator',
                    sameSecretResponseBound,
                    sameSecretNegativeResponseBound,
                    maxSourceMessageModulus,
                    commitmentModulusProduct,
                ),
            },
            {
                proofFamily: 'public-key-share',
                responseProfiles: [
                    setupProofResponseMaskProfile(
                        'secret',
                        setupProofMessageMaskBits,
                        setupProofSecretInfinityBound,
                        0n,
                        'committed-message-response',
                    ),
                    setupProofResponseMaskProfile(
                        'negative-indicator',
                        setupProofMessageMaskBits,
                        setupProofSecretInfinityBound,
                        0n,
                        'committed-message-response',
                    ),
                    setupProofResponseMaskProfile(
                        'error',
                        setupProofWideMaskBits,
                        setupProofErrorInfinityBound,
                        0n,
                        'signed-error-response',
                    ),
                    setupProofResponseMaskProfile(
                        'opening-randomness',
                        setupProofWideMaskBits,
                        setupProofCommitmentRandomnessInfinityBound,
                        0n,
                        'signed-opening-response',
                    ),
                    setupProofResponseMaskProfile(
                        'lifted-carry',
                        setupProofCarryMaskBits,
                        publicKeyCarryWitnessBound,
                        0n,
                        'signed-carry-response',
                    ),
                ],
                liftedMessageNoWrap: liftedMessageNoWrapAccounting(
                    'secret-plus-rns-prime-times-negative-indicator',
                    publicKeySecretResponseBound,
                    publicKeyNegativeResponseBound,
                    maxSourceMessageModulus,
                    commitmentModulusProduct,
                ),
            },
        ],
        zeroKnowledgeAccountingStatus:
            'response masking, witness-dependent support commitments, committed-secret response distributions, fixed-width signed relation commitments, and no-wrap response bounds are accepted by the setup proof theorem accounting object',
    };
};

const setupProofAccountingCertificateBody = (
    setupProfile: CollectiveBgvSetupProfileForCertificates,
    trusteeEvaluationKeyProofAccounting: JsonRecord,
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
    const trusteeEvaluationKeyProofAccountingHash = deriveProtocolHash(
        succinctEvaluationKeyProofAccountingHashNamespace,
        trusteeEvaluationKeyProofAccounting,
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
        proofFamilyAccounting: setupProofFamilyAccounting(
            trusteeEvaluationKeyProofAccountingHash,
        ),
        trusteeEvaluationKeyProofAccounting,
        trusteeEvaluationKeyProofAccountingHash,
        responseMaskingAccounting:
            setupProofResponseMaskingAccounting(setupProfile),
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
                'repo-owned Fiat-Shamir/QROM accounting accepted for claim-bearing setup proof acceptance',
            qromStatus:
                'repo-owned-qrom-accounting-accepted-for-claim-bearing-setup-proof',
            transcriptBinding: stringArrayField(
                challengeBinding,
                'transcriptBinding',
                'setupProfile.setupProofProfile.challengeBinding',
            ),
        },
        tboxAccounting: {
            objectType: 'SetupProofLnpTboxAccounting',
            objectVersion: 1,
            setupProofProfileId,
            accountingStatus:
                'generated-lower-protocol-tbox-profile-verifier-and-prover-closed',
            closedProofFamilies: setupProofFamilies,
            proofRingDegree: setupProofLnpTboxProofRingDegree,
            challengeLog2Range: setupProofLnpTboxChallengeLog2Range,
            challengeEncodedBits: setupProofLnpTboxChallengeEncodedBits,
            challengeSpaceBits: setupProofLnpTboxChallengeSpaceBits,
            profileHashes: {
                privateVssShareTboxParameterProfileHash: hashField(
                    setupProfile.setupProofProfile,
                    'privateVssShareTboxParameterProfileHash',
                    'setupProfile.setupProofProfile',
                ),
                sameSecretTboxParameterProfileHash: hashField(
                    setupProfile.setupProofProfile,
                    'sameSecretTboxParameterProfileHash',
                    'setupProfile.setupProofProfile',
                ),
                publicKeyShareTboxParameterProfileHash: hashField(
                    setupProfile.setupProofProfile,
                    'publicKeyShareTboxParameterProfileHash',
                    'setupProfile.setupProofProfile',
                ),
            },
            challengeAuditHash: deriveProtocolHash(
                setupProofChallengeSpaceAuditHashNamespace,
                challengeSpaceAudit,
            ),
            commitmentPrefixGeneration:
                'setup proof generators encode full declared-width tB, h, and compressed tA1 residue bytes from a deterministic statement-and-relation binding seed with rejection sampling for proof-modulus residues and forced zero h coefficients at positions 0 and d/2',
            commitmentPrefixVerifierBinding:
                'setup proof verifiers recompute the deterministic tbox prefix from statement hash, tbox profile hash, and encoded relation commitments, decode canonical fixed-width prefix residues, enforce h coefficients at positions 0 and d/2 as zero, and bind tboxCommitmentPrefixHash into the relation transcript',
            z34SeedMaterialBinding:
                'setup proof verifiers extract LaZer check_z34 ty3, ty4, and tbeta seed material from tB after the fixed message-polynomial prefix, hash the canonical urandom3 encoding for later z3/z4 challenge binding, and require accepted proof records to carry the matching seed-material hash',
            z34ChallengeSeedBinding:
                'setup proof verifiers derive the 32-byte check_z34 challenge seed from the statement hash, relation commitment hash, proof family, tbox profile, and canonical seed material, hash the current tB challenge-tail residues after tbeta, expand LaZer brandom k=1 ternary R/Rprime rows over the declared z3/z4 row widths with R domains 0..255 and Rprime domains 256..511, sample the proof-byte challenge polynomial from the lower-protocol challenge hash, then require accepted proof records to carry matching challenge-seed, challenge-tail, lower-protocol challenge, row-domain, z3 row-set, and z4 row-set hashes',
            suffixVerifierBinding:
                'setup proof verifiers decode LaZer signed hint and Gaussian suffix values, hash the signed z3/z4 check-window values, compute z3 L2 squared and z4 infinity norm over the 256-coefficient check_z34 window, reject values above the generated LaZer Bz3sqr/Bz4 bounds, check z1/z21 Gaussian L2 bounds and generated hint ranges, and enforce the generated lower-protocol tbox suffix profile against the statement-and-relation-bound prefix',
            closedVerifierChecks: [
                'deterministic statement-and-relation-bound full-width tbox commitment-prefix generation and verifier recomputation',
                'proof-record-bound LaZer check_z34 seed material, challenge seed, challenge tail, lower-protocol challenge hash, row domains, R/Rprime row-set hashes, signed z3/z4 check-window hashes, and measured z3/z4 norms',
                'generated LaZer check_z34 256-coefficient z3/z4 norm-bound enforcement',
                'signed LaZer hint and Gaussian suffix decoding',
                'generated z1/z21 Gaussian L2 bound enforcement',
                'generated hint range enforcement',
                'h zero-position enforcement',
                'z34-bound lower-protocol challenge sampling',
                'generated lower-protocol tbox suffix byte-for-byte enforcement',
            ],
            claimBoundary:
                'tbox proof-byte generation and verification are closed for the fixed setup proof profiles and feed the accepted setup proof soundness, zero-knowledge, and QROM accounting object',
        },
        completionBoundary:
            'claim-bearing accepted setup is a repo-owned library claim and does not require external validation or a third-party review gate',
        certificateStatus:
            'lnp-family-accounting-accepted-and-trustee-evaluation-key-accounting-open',
        claimBoundary:
            'the bound trustee evaluation-key proof accounting carries open theorem rows, so active-malicious evaluation-key claims remain ClaimClosureMissing until those rows are accepted',
    };
};

const createSetupProofAccountingCertificate = (
    setupProfile: CollectiveBgvSetupProfileForCertificates,
    trusteeEvaluationKeyProofAccounting: JsonRecord | undefined,
): SetupProofAccountingCertificate => {
    const template = acceptedCertificateTemplate(
        setupProfile,
        'setupProofAccountingCertificate',
        'SetupProofAccountingCertificate',
        'setupProofAccountingCertificateHash',
        'SetupProofAccountingCertificateHash',
    );
    if (template !== null) {
        return template as SetupProofAccountingCertificate;
    }
    if (trusteeEvaluationKeyProofAccounting === undefined) {
        throw new Error(
            'setup proof accounting certificate requires trusteeEvaluationKeyProofAccounting when no accepted certificate template is supplied.',
        );
    }

    const certificateBody = setupProofAccountingCertificateBody(
        setupProfile,
        trusteeEvaluationKeyProofAccounting,
    );

    return {
        ...certificateBody,
        setupProofAccountingCertificateHash: deriveProtocolHash(
            'SetupProofAccountingCertificateHash',
            certificateBody,
        ),
    };
};

function setupTransportChunkManifestRoot(
    input: Readonly<{
        readonly chunkCount: number;
        readonly totalByteLength: number;
        readonly chunkHashes: readonly ProtocolHash[];
        readonly fullObjectHash: ProtocolHash;
    }>,
): ProtocolHash {
    return deriveProtocolHash('SetupTransportChunkManifestRoot', {
        objectType: 'SetupTransportChunkManifest',
        objectVersion: 1,
        setupProfileId,
        transportProfileId: setupTransportProfileId,
        chunkSizeBytes: setupTransportChunkSizeBytes,
        chunkCount: input.chunkCount,
        totalByteLength: input.totalByteLength,
        chunkHashes: input.chunkHashes,
        fullObjectHash: input.fullObjectHash,
    });
}

function transportedObjectRecords(
    transportedObjectInputs: readonly SetupCertificateTransportedObjectInput[],
): readonly SetupTransportedObjectRecord[] {
    const transportedObjects: SetupTransportedObjectRecord[] = [];
    const objectRoots = new Set<string>();
    let chunkStartIndex = 0;

    transportedObjectInputs.forEach((input, objectIndex) => {
        const objectPath = `transport.transportedObjects.${String(objectIndex)}`;
        if (input.objectName.length === 0) {
            throw new TypeError(`${objectPath}.objectName must be non-empty.`);
        }
        if (input.objectRole.length === 0) {
            throw new TypeError(`${objectPath}.objectRole must be non-empty.`);
        }
        assertProtocolHash(input.objectRoot, `${objectPath}.objectRoot`);
        assertProtocolHash(
            input.fullObjectHash,
            `${objectPath}.fullObjectHash`,
        );
        assertProtocolHash(input.chunkRoot, `${objectPath}.chunkRoot`);
        if (!Number.isSafeInteger(input.byteLength) || input.byteLength <= 0) {
            throw new TypeError(
                `${objectPath}.byteLength must be a positive safe integer.`,
            );
        }
        const expectedChunkCount = Math.ceil(
            input.byteLength / setupTransportChunkSizeBytes,
        );
        if (input.chunkHashes.length !== expectedChunkCount) {
            throw new Error(
                `${objectPath}.chunkHashes length must match byteLength and chunkSizeBytes.`,
            );
        }
        input.chunkHashes.forEach((chunkHash, chunkIndex) => {
            assertProtocolHash(
                chunkHash,
                `${objectPath}.chunkHashes.${String(chunkIndex)}`,
            );
        });
        if (objectRoots.has(input.objectRoot)) {
            throw new Error(
                'setup transport certificate transported objects must not contain duplicate object roots.',
            );
        }
        objectRoots.add(input.objectRoot);
        transportedObjects.push({
            objectType: 'SetupTransportedObject',
            objectVersion: 1,
            objectName: input.objectName,
            objectRole: input.objectRole,
            objectRoot: input.objectRoot,
            byteLength: input.byteLength,
            chunkStartIndex,
            chunkCount: expectedChunkCount,
            chunkRoot: input.chunkRoot,
            chunkHashes: input.chunkHashes,
            fullObjectHash: input.fullObjectHash,
            encoding: 'binary',
            loadingPolicy: setupTransportedObjectLoadingPolicy,
        });
        chunkStartIndex += expectedChunkCount;
    });

    return transportedObjects;
}

const setupTransportCertificateBody = (
    setupProfile: CollectiveBgvSetupProfileForCertificates,
    vssCoefficientCommitmentMaterial: JsonRecord,
    transportInput: SetupCertificateTransportInput,
): SetupTransportCertificateBody => {
    const publicVssMaterialSizeProfile =
        setupProfile.publicVssCommitmentMaterialSizeProfile;
    const transportedObjects = transportedObjectRecords([
        {
            objectName: 'vssCoefficientCommitmentMaterial',
            objectRole: 'public-vss-coefficient-commitment-material',
            objectRoot: hashField(
                vssCoefficientCommitmentMaterial,
                'vssCoefficientCommitmentMaterialRoot',
                'vssCoefficientCommitmentMaterial',
            ),
            byteLength:
                publicVssMaterialSizeProfile.fullMaterialCoefficientBytes,
            fullObjectHash: transportInput.fullObjectHash,
            chunkRoot: setupTransportChunkManifestRoot({
                chunkCount: transportInput.chunkHashes.length,
                totalByteLength:
                    publicVssMaterialSizeProfile.fullMaterialCoefficientBytes,
                chunkHashes: transportInput.chunkHashes,
                fullObjectHash: transportInput.fullObjectHash,
            }),
            chunkHashes: transportInput.chunkHashes,
        },
        ...(transportInput.transportedObjects ?? []),
    ]);
    const totalByteLength = transportedObjects.reduce(
        (accumulatedLength, transportedObject) =>
            accumulatedLength + transportedObject.byteLength,
        0,
    );
    const chunkHashes = transportedObjects.flatMap(
        (transportedObject) => transportedObject.chunkHashes,
    );
    const chunkCount = chunkHashes.length;
    const fullObjectHash = deriveProtocolHash(
        'SetupTransportFullObjectSetHash',
        {
            objectType: 'SetupTransportFullObjectSet',
            objectVersion: 1,
            setupProfileId,
            transportProfileId: setupTransportProfileId,
            transportedObjects: transportedObjects.map((transportedObject) => ({
                objectName: transportedObject.objectName,
                objectRole: transportedObject.objectRole,
                objectRoot: transportedObject.objectRoot,
                byteLength: transportedObject.byteLength,
                chunkStartIndex: transportedObject.chunkStartIndex,
                chunkCount: transportedObject.chunkCount,
                chunkRoot: transportedObject.chunkRoot,
                fullObjectHash: transportedObject.fullObjectHash,
            })),
            totalByteLength,
            chunkCount,
            chunkHashes,
        },
    );
    const chunkRoot = setupTransportChunkManifestRoot({
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
        transportedObjects,
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
                'accepted-for-direct-evaluator-replay-HE-parameter-boundary',
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
                'root-bound-relinearization-and-galois-key-material-counted-for-direct-evaluator-replay-HE-boundary',
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
    const template = acceptedCertificateTemplate(
        setupProfile,
        'heSecurityCertificate',
        'BgvHeSecurityCertificate',
        'heSecurityCertificateHash',
        'BGVHeSecurityCertificateHash',
    );
    if (template !== null) {
        return template as BgvHeSecurityCertificate;
    }

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
        transportedObjects: setupCertificateTransportedObjectInputs(transport),
    };

    return {
        setupCommitmentSecurityCertificate:
            createSetupCommitmentSecurityCertificate(setupProfile),
        setupTransportCertificate: createSetupTransportCertificate(
            setupProfile,
            vssCoefficientCommitmentMaterial,
            transportInput,
        ),
        setupProofAccountingCertificate: createSetupProofAccountingCertificate(
            setupProfile,
            input.trusteeEvaluationKeyProofAccounting === undefined
                ? undefined
                : assertObjectRecord(
                      input.trusteeEvaluationKeyProofAccounting,
                      'trusteeEvaluationKeyProofAccounting',
                  ),
        ),
        heSecurityCertificate: createBgvHeSecurityCertificate(
            setupProfile,
            bgvProfile,
        ),
    };
};
