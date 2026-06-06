import { deriveProtocolHash } from '@sealed-lattice/crypto';
import type { ProtocolHash } from '@sealed-lattice/types';

import {
    setupCommitmentProfileId,
    type VssCoefficientCommitmentRecord,
    type VssCoefficientCommitmentSet,
    type VssDealerCoefficientCommitmentRecord,
} from './vss-coefficient-commitments.js';
import type { CollectiveBgvSetupContext } from './vss-share-verification-records.js';

type JsonRecord = Record<string, unknown>;

export const setupProofProfileId = 'SealedLattice-LNP-SetupProof-v1';
export const sameSecretProofFamily = 'same-secret-consistency';
export const sameSecretProofVerificationStatus =
    'lnp-proof-verification-pending';
export const sameSecretRelation =
    'vss-constant-commitments-open-to-one-short-secret-across-q-share-limbs';
export const sameSecretBoundProofFamilies = [
    'vss-constant-relation',
    'public-key-share',
    'relinearization-key-share',
    'galois-key-share',
] as const;

export const sameSecretGenericKeySwitchBindingPolicy =
    'absent-unless-frozen-schedule-requires-proof-family';
export const sameSecretTargetDecryptionBindingPolicy =
    'later-target-share-must-bind-threshold-share-commitment';

export type SameSecretConstantCoefficientCommitmentRoot = Readonly<{
    readonly rnsLimbIndex: number;
    readonly rnsPrime: number;
    readonly shamirCoefficientIndex: 0;
    readonly commitmentRoot: ProtocolHash;
}>;

export type TrusteeSecretCommitmentRootReference = Readonly<{
    readonly trusteeIdentity: string;
    readonly trusteeRosterPosition: number;
    readonly trusteeSecretCommitmentRoot: ProtocolHash;
}>;

export type SameSecretConsistencyStatementRecord = Readonly<
    JsonRecord & {
        readonly objectType: 'SameSecretConsistencyStatement';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly commitmentProfileId: typeof setupCommitmentProfileId;
        readonly setupProofProfileId: typeof setupProofProfileId;
        readonly proofFamily: typeof sameSecretProofFamily;
        readonly proofVerificationStatus: typeof sameSecretProofVerificationStatus;
        readonly trusteeIdentity: string;
        readonly trusteeRosterPosition: number;
        readonly vssDealerCommitmentRoot: ProtocolHash;
        readonly constantCoefficientCommitmentRoots: readonly SameSecretConstantCoefficientCommitmentRoot[];
        readonly trusteeSecretCommitmentRoot: ProtocolHash;
        readonly boundSecretDependentProofFamilies: typeof sameSecretBoundProofFamilies;
        readonly genericKeySwitchBindingPolicy: typeof sameSecretGenericKeySwitchBindingPolicy;
        readonly targetDecryptionBindingPolicy: typeof sameSecretTargetDecryptionBindingPolicy;
        readonly sameSecretProofFamilyBindingRoot: ProtocolHash;
        readonly sameSecretRelation: typeof sameSecretRelation;
        readonly sameSecretStatementRoot: ProtocolHash;
    }
>;

export type SameSecretConsistencyStatementSet = Readonly<
    JsonRecord & {
        readonly objectType: 'SameSecretConsistencyStatementSet';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly commitmentProfileId: typeof setupCommitmentProfileId;
        readonly setupProofProfileId: typeof setupProofProfileId;
        readonly proofFamily: typeof sameSecretProofFamily;
        readonly proofVerificationStatus: typeof sameSecretProofVerificationStatus;
        readonly participantCount: number;
        readonly rnsLimbCount: number;
        readonly thresholdDegree: number;
        readonly vssCoefficientCommitmentRoot: ProtocolHash;
        readonly sameSecretProofFamilyBindingRoot: ProtocolHash;
        readonly trusteeSecretCommitmentRoots: readonly TrusteeSecretCommitmentRootReference[];
        readonly statementRecords: readonly SameSecretConsistencyStatementRecord[];
        readonly sameSecretConsistencyRoot: ProtocolHash;
    }
>;

export type SameSecretConsistencyStatementSetInput = {
    readonly setupContext: CollectiveBgvSetupContext;
    readonly qSharePrimes: readonly number[];
    readonly participantCount: number;
    readonly thresholdDegree: number;
    readonly vssCoefficientCommitments: VssCoefficientCommitmentSet;
};

const protocolHashPattern = /^[0-9a-f]{128}$/u;
const setupContextFieldNames = [
    'ceremonyId',
    'manifestHash',
    'rosterHash',
    'setupProfileHash',
    'qShareHash',
    'carryAwareVssShareRelationProfileHash',
    'commitmentProfileHash',
    'setupEpoch',
] as const;

const assertPositiveSafeInteger = (value: number, fieldName: string): void => {
    if (!Number.isSafeInteger(value) || value <= 0) {
        throw new TypeError(`${fieldName} must be a positive safe integer.`);
    }
};

const assertNonNegativeSafeInteger = (
    value: number,
    fieldName: string,
): void => {
    if (!Number.isSafeInteger(value) || value < 0) {
        throw new TypeError(
            `${fieldName} must be a non-negative safe integer.`,
        );
    }
};

const assertProtocolHash = (value: string, fieldName: string): void => {
    if (!protocolHashPattern.test(value)) {
        throw new TypeError(`${fieldName} must be a protocol hash.`);
    }
};

const assertNonEmptyString = (value: string, fieldName: string): void => {
    if (value.length === 0) {
        throw new TypeError(`${fieldName} must be non-empty.`);
    }
};

const contextFields = (
    setupContext: CollectiveBgvSetupContext,
): Pick<
    CollectiveBgvSetupContext,
    (typeof setupContextFieldNames)[number]
> => ({
    ceremonyId: setupContext.ceremonyId,
    manifestHash: setupContext.manifestHash,
    rosterHash: setupContext.rosterHash,
    setupProfileHash: setupContext.setupProfileHash,
    qShareHash: setupContext.qShareHash,
    carryAwareVssShareRelationProfileHash:
        setupContext.carryAwareVssShareRelationProfileHash,
    commitmentProfileHash: setupContext.commitmentProfileHash,
    setupEpoch: setupContext.setupEpoch,
});

const assertContextMatches = (
    setupContext: CollectiveBgvSetupContext,
    value: Readonly<Record<string, unknown>>,
    valueName: string,
): void => {
    for (const fieldName of setupContextFieldNames) {
        if (value[fieldName] !== setupContext[fieldName]) {
            throw new Error(
                `${valueName}.${fieldName} must match setupContext.`,
            );
        }
    }
};

const validateInput = (input: SameSecretConsistencyStatementSetInput): void => {
    assertPositiveSafeInteger(input.participantCount, 'participantCount');
    assertPositiveSafeInteger(input.thresholdDegree, 'thresholdDegree');
    input.qSharePrimes.forEach((qSharePrime, rnsLimbIndex) => {
        assertPositiveSafeInteger(
            qSharePrime,
            `qSharePrimes.${String(rnsLimbIndex)}`,
        );
    });
    assertContextMatches(
        input.setupContext,
        input.vssCoefficientCommitments,
        'vssCoefficientCommitments',
    );
    assertProtocolHash(
        input.vssCoefficientCommitments.vssCoefficientCommitmentRoot,
        'vssCoefficientCommitments.vssCoefficientCommitmentRoot',
    );
};

const sortedDealerRecords = (
    input: SameSecretConsistencyStatementSetInput,
): VssDealerCoefficientCommitmentRecord[] => {
    const dealerRecords = [
        ...input.vssCoefficientCommitments.dealerRecords,
    ].sort(
        (left, right) => left.dealerRosterPosition - right.dealerRosterPosition,
    );
    if (dealerRecords.length !== input.participantCount) {
        throw new Error(
            'vssCoefficientCommitments.dealerRecords must cover every participant.',
        );
    }
    dealerRecords.forEach((dealerRecord, expectedRosterPosition) => {
        assertNonEmptyString(dealerRecord.dealerIdentity, 'dealerIdentity');
        assertNonNegativeSafeInteger(
            dealerRecord.dealerRosterPosition,
            'dealerRosterPosition',
        );
        if (dealerRecord.dealerRosterPosition !== expectedRosterPosition) {
            throw new Error(
                'vssCoefficientCommitments.dealerRecords roster positions must be contiguous from zero.',
            );
        }
        assertContextMatches(input.setupContext, dealerRecord, 'dealerRecord');
        assertProtocolHash(
            dealerRecord.dealerCommitmentRoot,
            'dealerRecord.dealerCommitmentRoot',
        );
    });

    return dealerRecords;
};

const constantCoefficientCommitmentRoots = (
    dealerRecord: VssDealerCoefficientCommitmentRecord,
    qSharePrimes: readonly number[],
): SameSecretConstantCoefficientCommitmentRoot[] =>
    qSharePrimes.map((rnsPrime, rnsLimbIndex) => {
        const coefficientRecord = dealerRecord.coefficientCommitments.find(
            (candidateRecord: VssCoefficientCommitmentRecord) =>
                candidateRecord.rnsLimbIndex === rnsLimbIndex &&
                candidateRecord.rnsPrime === rnsPrime &&
                candidateRecord.shamirCoefficientIndex === 0,
        );
        if (coefficientRecord === undefined) {
            throw new Error(
                'dealerRecord.coefficientCommitments must include every constant coefficient commitment.',
            );
        }
        assertProtocolHash(
            coefficientRecord.commitmentRoot,
            'coefficientRecord.commitmentRoot',
        );

        return {
            rnsLimbIndex,
            rnsPrime,
            shamirCoefficientIndex: 0,
            commitmentRoot: coefficientRecord.commitmentRoot,
        };
    });

const trusteeSecretCommitmentPayload = (
    setupContext: CollectiveBgvSetupContext,
    dealerRecord: VssDealerCoefficientCommitmentRecord,
    constantRoots: readonly SameSecretConstantCoefficientCommitmentRoot[],
): JsonRecord => ({
    objectType: 'TrusteeSecretCommitment',
    objectVersion: 1,
    setupProfileId: 'CollectiveBgvSetup-v1',
    commitmentProfileId: setupCommitmentProfileId,
    setupProofProfileId,
    ...contextFields(setupContext),
    trusteeIdentity: dealerRecord.dealerIdentity,
    trusteeRosterPosition: dealerRecord.dealerRosterPosition,
    vssDealerCommitmentRoot: dealerRecord.dealerCommitmentRoot,
    secretCommitmentSource: 'vss-constant-coefficient-commitments',
    sameSecretRelation,
    constantCoefficientCommitmentRoots: constantRoots,
});

const sameSecretProofFamilyBindingPayload = (): JsonRecord => ({
    objectType: 'SameSecretProofFamilyBinding',
    objectVersion: 1,
    setupProfileId: 'CollectiveBgvSetup-v1',
    setupProofProfileId,
    proofFamily: sameSecretProofFamily,
    sameSecretRelation,
    boundSecretDependentProofFamilies: sameSecretBoundProofFamilies,
    genericKeySwitchBindingPolicy: sameSecretGenericKeySwitchBindingPolicy,
    targetDecryptionBindingPolicy: sameSecretTargetDecryptionBindingPolicy,
});

const sameSecretProofFamilyBindingRoot = (): ProtocolHash =>
    deriveProtocolHash(
        'SameSecretProofFamilyBindingRoot',
        sameSecretProofFamilyBindingPayload(),
    );

const createStatementRecord = (
    setupContext: CollectiveBgvSetupContext,
    dealerRecord: VssDealerCoefficientCommitmentRecord,
    constantRoots: readonly SameSecretConstantCoefficientCommitmentRoot[],
): {
    readonly statementRecord: SameSecretConsistencyStatementRecord;
    readonly trusteeSecretCommitmentRootReference: TrusteeSecretCommitmentRootReference;
} => {
    const trusteeSecretCommitmentRoot = deriveProtocolHash(
        'TrusteeSecretCommitmentRoot',
        trusteeSecretCommitmentPayload(
            setupContext,
            dealerRecord,
            constantRoots,
        ),
    );
    const proofFamilyBindingRoot = sameSecretProofFamilyBindingRoot();
    const statementRecordWithoutRoot = {
        objectType: 'SameSecretConsistencyStatement',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        commitmentProfileId: setupCommitmentProfileId,
        setupProofProfileId,
        proofFamily: sameSecretProofFamily,
        proofVerificationStatus: sameSecretProofVerificationStatus,
        ...contextFields(setupContext),
        trusteeIdentity: dealerRecord.dealerIdentity,
        trusteeRosterPosition: dealerRecord.dealerRosterPosition,
        vssDealerCommitmentRoot: dealerRecord.dealerCommitmentRoot,
        constantCoefficientCommitmentRoots: constantRoots,
        trusteeSecretCommitmentRoot,
        boundSecretDependentProofFamilies: sameSecretBoundProofFamilies,
        genericKeySwitchBindingPolicy: sameSecretGenericKeySwitchBindingPolicy,
        targetDecryptionBindingPolicy: sameSecretTargetDecryptionBindingPolicy,
        sameSecretProofFamilyBindingRoot: proofFamilyBindingRoot,
        sameSecretRelation,
    } as const satisfies Omit<
        SameSecretConsistencyStatementRecord,
        'sameSecretStatementRoot'
    >;
    const statementRecord = {
        ...statementRecordWithoutRoot,
        sameSecretStatementRoot: deriveProtocolHash(
            'SameSecretConsistencyRoot',
            statementRecordWithoutRoot,
        ),
    } satisfies SameSecretConsistencyStatementRecord;

    return {
        statementRecord,
        trusteeSecretCommitmentRootReference: {
            trusteeIdentity: dealerRecord.dealerIdentity,
            trusteeRosterPosition: dealerRecord.dealerRosterPosition,
            trusteeSecretCommitmentRoot,
        },
    };
};

export const createSameSecretConsistencyStatementSet = (
    input: SameSecretConsistencyStatementSetInput,
): SameSecretConsistencyStatementSet => {
    validateInput(input);
    const proofFamilyBindingRoot = sameSecretProofFamilyBindingRoot();
    const statementOutputs = sortedDealerRecords(input).map((dealerRecord) =>
        createStatementRecord(
            input.setupContext,
            dealerRecord,
            constantCoefficientCommitmentRoots(
                dealerRecord,
                input.qSharePrimes,
            ),
        ),
    );
    const statementSetWithoutRoot = {
        objectType: 'SameSecretConsistencyStatementSet',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        commitmentProfileId: setupCommitmentProfileId,
        setupProofProfileId,
        proofFamily: sameSecretProofFamily,
        proofVerificationStatus: sameSecretProofVerificationStatus,
        ...contextFields(input.setupContext),
        participantCount: input.participantCount,
        rnsLimbCount: input.qSharePrimes.length,
        thresholdDegree: input.thresholdDegree,
        vssCoefficientCommitmentRoot:
            input.vssCoefficientCommitments.vssCoefficientCommitmentRoot,
        sameSecretProofFamilyBindingRoot: proofFamilyBindingRoot,
        trusteeSecretCommitmentRoots: statementOutputs.map(
            (output) => output.trusteeSecretCommitmentRootReference,
        ),
        statementRecords: statementOutputs.map(
            (output) => output.statementRecord,
        ),
    } as const satisfies Omit<
        SameSecretConsistencyStatementSet,
        'sameSecretConsistencyRoot'
    >;

    return {
        ...statementSetWithoutRoot,
        sameSecretConsistencyRoot: deriveProtocolHash(
            'SameSecretConsistencyRoot',
            statementSetWithoutRoot,
        ),
    } satisfies SameSecretConsistencyStatementSet;
};
