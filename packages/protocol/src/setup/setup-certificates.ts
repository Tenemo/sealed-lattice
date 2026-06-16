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
    readonly sameSecretLinkageAnchorProofAccounting?: JsonRecord;
    readonly publicKeyShareProofAccounting?: JsonRecord;
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
const setupCommitmentProfileId = 'SealedLattice-BDLOP-Commitment-v1';
const setupProofProfileId = 'SealedLattice-SetupProof-v1';
const setupProofBytesDomain =
    'sealed-lattice/collective-bgv-setup/succinct-proof-bytes-v1';
const setupProofSerialization = 'binary';
const setupProofByteDecoder =
    'sealed-lattice-succinct-setup-proof-byte-decoder-v1';
const setupProofFamilies = ['vss-opening-carry'] as const;
const succinctSameSecretLinkageAnchorAccountingHashNamespace =
    'SuccinctSameSecretLinkageAnchorAccountingHash';
const succinctPrivateVssShareAccountingHashNamespace =
    'SuccinctPrivateVssShareAccountingHash';
const succinctPublicKeyShareAccountingHashNamespace =
    'SuccinctPublicKeyShareAccountingHash';
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
    // No-wrap bound: the homomorphic threshold-share aggregate (sum of message * trusteePoint^i over all trustees) must stay below the commitment modulus product, or the re-derived commitment opening becomes ambiguous and binding fails.
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
                    'accepted Module-SIS binding row under FPS25 commitment references and no-wrap threshold-opening bounds',
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
                    'accepted Module-LWE hiding row under FPS25/ACC18 references and recipient-hidden opening leakage boundary',
            },
        ],
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

    return {
        objectType: 'SetupProofRecordBinding',
        objectVersion: 1,
        setupProfileId,
        setupProofProfileId,
        setupProofProfileHash: setupProfile.setupProofProfileHash,
        proofBytesDomain: setupProofBytesDomain,
        proofSerialization: setupProofSerialization,
        proofByteDecoder: setupProofByteDecoder,
        privateVssShareProofAccountingHash: hashField(
            setupProofProfile,
            'privateVssShareProofAccountingHash',
            'setupProfile.setupProofProfile',
        ),
    };
};

const setupProofFamilyAccounting = (
    privateVssShareProofAccountingHash: ProtocolHash,
    sameSecretLinkageAnchorProofAccountingHash: ProtocolHash,
    publicKeyShareProofAccountingHash: ProtocolHash,
    trusteeEvaluationKeyProofAccountingHash: ProtocolHash,
): JsonRecord[] => [
    {
        proofFamily: 'vss-opening-carry',
        claimAccounting: {
            accountingHash: privateVssShareProofAccountingHash,
        },
    },
    {
        proofFamily: 'same-secret-linkage-anchor',
        claimAccounting: {
            accountingHash: sameSecretLinkageAnchorProofAccountingHash,
        },
    },
    {
        proofFamily: 'public-key-share',
        claimAccounting: {
            accountingHash: publicKeyShareProofAccountingHash,
        },
    },
    {
        proofFamily: 'trustee-evaluation-key',
        claimAccounting: {
            accountingHash: trusteeEvaluationKeyProofAccountingHash,
        },
    },
];

const setupProofSuccinctTransportAccounting = (): JsonRecord => ({
    objectType: 'SetupProofSuccinctTransportAccounting',
    objectVersion: 1,
    setupProofProfileId,
});

const setupProofSuccinctLeakageAccounting = (
    privateVssShareProofAccountingHash: ProtocolHash,
    sameSecretLinkageAnchorProofAccountingHash: ProtocolHash,
    publicKeyShareProofAccountingHash: ProtocolHash,
    trusteeEvaluationKeyProofAccountingHash: ProtocolHash,
): JsonRecord => ({
    objectType: 'SetupProofSuccinctLeakageAccounting',
    objectVersion: 1,
    setupProofProfileId,
    familyAccountingHashes: {
        sameSecretLinkageAnchor: sameSecretLinkageAnchorProofAccountingHash,
        publicKeyShare: publicKeyShareProofAccountingHash,
        privateVssShare: privateVssShareProofAccountingHash,
        trusteeEvaluationKey: trusteeEvaluationKeyProofAccountingHash,
    },
    zeroKnowledgeScope:
        'bounded-leakage succinct-family accounting only; the setup certificate does not claim 128-bit zero-knowledge for these families',
});

const setupProofFiatShamirTranscriptAccounting = (
    privateVssShareProofAccountingHash: ProtocolHash,
    sameSecretLinkageAnchorProofAccountingHash: ProtocolHash,
    publicKeyShareProofAccountingHash: ProtocolHash,
    trusteeEvaluationKeyProofAccountingHash: ProtocolHash,
): JsonRecord => ({
    objectType: 'SetupProofFiatShamirTranscriptAccounting',
    objectVersion: 1,
    setupProofProfileId,
    familyAccountingHashes: {
        sameSecretLinkageAnchor: sameSecretLinkageAnchorProofAccountingHash,
        publicKeyShare: publicKeyShareProofAccountingHash,
        privateVssShare: privateVssShareProofAccountingHash,
        trusteeEvaluationKey: trusteeEvaluationKeyProofAccountingHash,
    },
    challengeBinding:
        'each succinct proof statement hash, proof family label, binding roots, Merkle transcript, low-degree transcript, and challenge-extension sampling rule is recorded inside the bound family accounting object',
});

const setupProofTheoremAccounting = (
    privateVssShareProofAccounting: JsonRecord,
    sameSecretLinkageAnchorProofAccounting: JsonRecord,
    publicKeyShareProofAccounting: JsonRecord,
    trusteeEvaluationKeyProofAccounting: JsonRecord,
): JsonRecord => ({
    objectType: 'SetupProofTheoremAccounting',
    objectVersion: 1,
    setupProofProfileId,
    proofFamilies: [
        'same-secret-linkage-anchor',
        'public-key-share',
        'vss-opening-carry',
        'trustee-evaluation-key',
    ],
    familyAccounting: {
        sameSecretLinkageAnchor: sameSecretLinkageAnchorProofAccounting,
        publicKeyShare: publicKeyShareProofAccounting,
        privateVssShare: privateVssShareProofAccounting,
        trusteeEvaluationKey: trusteeEvaluationKeyProofAccounting,
    },
});

const setupProofAccountingCertificateBody = (
    setupProfile: CollectiveBgvSetupProfileForCertificates,
    sameSecretLinkageAnchorProofAccounting: JsonRecord,
    publicKeyShareProofAccounting: JsonRecord,
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
    const setupProofRecordBinding =
        setupProofRecordBindingForCertificate(setupProfile);
    const sameSecretLinkageAnchorProofAccountingHash = deriveProtocolHash(
        succinctSameSecretLinkageAnchorAccountingHashNamespace,
        sameSecretLinkageAnchorProofAccounting,
    );
    const privateVssShareProofAccounting = objectField(
        setupProofProfile,
        'privateVssShareProofAccounting',
        'setupProfile.setupProofProfile',
    );
    const privateVssShareProofAccountingHash = deriveProtocolHash(
        succinctPrivateVssShareAccountingHashNamespace,
        privateVssShareProofAccounting,
    );
    const expectedPrivateVssShareProofAccountingHash = hashField(
        setupProofProfile,
        'privateVssShareProofAccountingHash',
        'setupProfile.setupProofProfile',
    );
    if (
        privateVssShareProofAccountingHash !==
        expectedPrivateVssShareProofAccountingHash
    ) {
        throw new Error(
            'setupProfile.setupProofProfile.privateVssShareProofAccountingHash must match privateVssShareProofAccounting.',
        );
    }
    const publicKeyShareProofAccountingHash = deriveProtocolHash(
        succinctPublicKeyShareAccountingHashNamespace,
        publicKeyShareProofAccounting,
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
            privateVssShareProofAccountingHash,
            sameSecretLinkageAnchorProofAccountingHash,
            publicKeyShareProofAccountingHash,
            trusteeEvaluationKeyProofAccountingHash,
        ),
        sameSecretLinkageAnchorProofAccounting,
        sameSecretLinkageAnchorProofAccountingHash,
        publicKeyShareProofAccounting,
        publicKeyShareProofAccountingHash,
        trusteeEvaluationKeyProofAccounting,
        trusteeEvaluationKeyProofAccountingHash,
        succinctTransportAccounting: setupProofSuccinctTransportAccounting(),
        succinctLeakageAccounting: setupProofSuccinctLeakageAccounting(
            privateVssShareProofAccountingHash,
            sameSecretLinkageAnchorProofAccountingHash,
            publicKeyShareProofAccountingHash,
            trusteeEvaluationKeyProofAccountingHash,
        ),
        fiatShamirTranscriptAccounting:
            setupProofFiatShamirTranscriptAccounting(
                privateVssShareProofAccountingHash,
                sameSecretLinkageAnchorProofAccountingHash,
                publicKeyShareProofAccountingHash,
                trusteeEvaluationKeyProofAccountingHash,
            ),
        proofTheoremAccounting: setupProofTheoremAccounting(
            privateVssShareProofAccounting,
            sameSecretLinkageAnchorProofAccounting,
            publicKeyShareProofAccounting,
            trusteeEvaluationKeyProofAccounting,
        ),
    };
};

const createSetupProofAccountingCertificate = (
    setupProfile: CollectiveBgvSetupProfileForCertificates,
    sameSecretLinkageAnchorProofAccounting: JsonRecord | undefined,
    publicKeyShareProofAccounting: JsonRecord | undefined,
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
    if (sameSecretLinkageAnchorProofAccounting === undefined) {
        throw new Error(
            'setup proof accounting certificate requires sameSecretLinkageAnchorProofAccounting when no accepted certificate template is supplied.',
        );
    }
    if (trusteeEvaluationKeyProofAccounting === undefined) {
        throw new Error(
            'setup proof accounting certificate requires trusteeEvaluationKeyProofAccounting when no accepted certificate template is supplied.',
        );
    }
    if (publicKeyShareProofAccounting === undefined) {
        throw new Error(
            'setup proof accounting certificate requires publicKeyShareProofAccounting when no accepted certificate template is supplied.',
        );
    }

    const certificateBody = setupProofAccountingCertificateBody(
        setupProfile,
        sameSecretLinkageAnchorProofAccounting,
        publicKeyShareProofAccounting,
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
        parameterBoundary: {
            acceptedScope:
                'current Q_data/Q_share direct evaluator replay and accepted setup public key/evaluation-key exposure',
            excludedScope:
                'Q_target, target decryption, smudging, C1-C4, and downstream decryption-share proof material',
        },
        acceptedForDirectEvaluatorReplay,
        acceptedForTargetDecryption: false,
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
            input.sameSecretLinkageAnchorProofAccounting === undefined
                ? undefined
                : assertObjectRecord(
                      input.sameSecretLinkageAnchorProofAccounting,
                      'sameSecretLinkageAnchorProofAccounting',
                  ),
            input.publicKeyShareProofAccounting === undefined
                ? undefined
                : assertObjectRecord(
                      input.publicKeyShareProofAccounting,
                      'publicKeyShareProofAccounting',
                  ),
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
