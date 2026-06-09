import { deriveProtocolHash } from '@sealed-lattice/crypto';
import type { ProtocolHash } from '@sealed-lattice/types';

import type { CollectiveBgvSetupContext } from './vss-share-verification-records.js';

type JsonRecord = Record<string, unknown>;

type CommonRandomnessContextFields = Readonly<{
    readonly ceremonyId: string;
    readonly manifestHash: ProtocolHash;
    readonly rosterHash: ProtocolHash;
    readonly setupProfileHash: ProtocolHash;
    readonly setupEpoch: string;
}>;

export type CommonRandomnessParticipantInput = Readonly<{
    readonly setupContext: CollectiveBgvSetupContext;
    readonly trusteeIdentity: string;
    readonly rosterPosition: number;
    readonly recoveryEpoch: number;
    readonly deviceEpoch: number;
    readonly signatureEnvelopeHash: ProtocolHash;
}>;

export type CommonRandomnessRevealInput = CommonRandomnessParticipantInput &
    Readonly<{
        readonly revealHex: string;
    }>;

export type CommonRandomnessReveal = Readonly<
    JsonRecord &
        CommonRandomnessContextFields & {
            readonly objectType: 'CommonRandomnessReveal';
            readonly objectVersion: 1;
            readonly signerRole: 'Trustee';
            readonly trusteeIdentity: string;
            readonly rosterPosition: number;
            readonly recoveryEpoch: number;
            readonly deviceEpoch: number;
            readonly revealHex: string;
            readonly signatureEnvelopeHash: ProtocolHash;
            readonly revealHash: ProtocolHash;
        }
>;

export type CommonRandomnessCommitInput = CommonRandomnessParticipantInput &
    Readonly<{
        readonly revealHash: ProtocolHash;
    }>;

export type CommonRandomnessCommit = Readonly<
    JsonRecord &
        CommonRandomnessContextFields & {
            readonly objectType: 'CommonRandomnessCommit';
            readonly objectVersion: 1;
            readonly signerRole: 'Trustee';
            readonly trusteeIdentity: string;
            readonly rosterPosition: number;
            readonly recoveryEpoch: number;
            readonly deviceEpoch: number;
            readonly revealHash: ProtocolHash;
            readonly signatureEnvelopeHash: ProtocolHash;
            readonly commitHash: ProtocolHash;
        }
>;

export type SetupCommonRandomnessPublicDerivations = Readonly<
    JsonRecord & {
        readonly objectType: 'SetupPublicDerivations';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly bgvPublicA: Readonly<
            JsonRecord & {
                readonly objectType: 'BgvPublicAPolynomial';
                readonly objectVersion: 1;
                readonly setupProfileId: 'CollectiveBgvSetup-v1';
                readonly publicMatrixSeedHash: ProtocolHash;
                readonly publicPolynomialRoot: ProtocolHash;
            }
        >;
        readonly publicMatrices: Readonly<
            JsonRecord & {
                readonly objectType: 'SetupPublicMatrixMaterial';
                readonly objectVersion: 1;
                readonly setupProfileId: 'CollectiveBgvSetup-v1';
                readonly publicMatrixSeedHash: ProtocolHash;
                readonly publicMatricesRoot: ProtocolHash;
            }
        >;
        readonly crpRoots: Readonly<{
            readonly publicKeyCrpRoot: ProtocolHash;
            readonly relinearizationCrpRoot: ProtocolHash;
            readonly galoisKeyCrpRoot: ProtocolHash;
            readonly commitmentMatrixCrpRoot: ProtocolHash;
            readonly proofMatrixCrpRoot: ProtocolHash;
        }>;
        readonly status: 'deterministic-public-derivations-bound';
        readonly publicDerivationRoot: ProtocolHash;
    }
>;

export type SetupCommonRandomnessInput = Readonly<{
    readonly setupContext: CollectiveBgvSetupContext;
    readonly participantCount: number;
    readonly commitRecords: readonly CommonRandomnessCommit[];
    readonly revealRecords: readonly CommonRandomnessReveal[];
    readonly derivePublicDerivations: (
        publicMatrixSeedHash: ProtocolHash,
    ) => SetupCommonRandomnessPublicDerivations;
}>;

export type SetupCommonRandomness = Readonly<
    JsonRecord &
        CommonRandomnessContextFields & {
            readonly objectType: 'SetupCommonRandomness';
            readonly objectVersion: 1;
            readonly commitRecords: readonly CommonRandomnessCommit[];
            readonly revealRecords: readonly CommonRandomnessReveal[];
            readonly publicMatrixSeedHash: ProtocolHash;
            readonly publicDerivations: SetupCommonRandomnessPublicDerivations;
            readonly commonRandomnessRoot: ProtocolHash;
        }
>;

const protocolHashPattern = /^[0-9a-f]{128}$/u;
const revealHexPattern = /^[0-9a-f]{64}$/u;

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

const assertPositiveSafeInteger = (value: number, fieldName: string): void => {
    if (!Number.isSafeInteger(value) || value <= 0) {
        throw new TypeError(`${fieldName} must be a positive safe integer.`);
    }
};

const assertJsonRecord = (value: unknown, fieldName: string): JsonRecord => {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
        throw new TypeError(`${fieldName} must be an object.`);
    }

    return value as JsonRecord;
};

const assertRevealHex = (value: string, fieldName: string): void => {
    if (!revealHexPattern.test(value)) {
        throw new TypeError(
            `${fieldName} must contain 64 lowercase hex characters.`,
        );
    }
};

const commonRandomnessContextFields = (
    setupContext: CollectiveBgvSetupContext,
): CommonRandomnessContextFields => ({
    ceremonyId: setupContext.ceremonyId,
    manifestHash: setupContext.manifestHash,
    rosterHash: setupContext.rosterHash,
    setupProfileHash: setupContext.setupProfileHash,
    setupEpoch: setupContext.setupEpoch,
});

const assertInputContext = (setupContext: CollectiveBgvSetupContext): void => {
    for (const fieldName of [
        'ceremonyId',
        'manifestHash',
        'rosterHash',
        'setupProfileHash',
        'setupEpoch',
    ] as const) {
        assertNonEmptyString(
            setupContext[fieldName],
            `setupContext.${fieldName}`,
        );
    }
};

const assertParticipantInput = (
    input: CommonRandomnessParticipantInput,
): void => {
    assertInputContext(input.setupContext);
    assertNonEmptyString(input.trusteeIdentity, 'trusteeIdentity');
    assertNonNegativeSafeInteger(input.rosterPosition, 'rosterPosition');
    assertNonNegativeSafeInteger(input.recoveryEpoch, 'recoveryEpoch');
    assertNonNegativeSafeInteger(input.deviceEpoch, 'deviceEpoch');
    assertProtocolHash(input.signatureEnvelopeHash, 'signatureEnvelopeHash');
};

const commonRandomnessParticipantFields = (
    input: CommonRandomnessParticipantInput,
) =>
    ({
        ...commonRandomnessContextFields(input.setupContext),
        signerRole: 'Trustee',
        trusteeIdentity: input.trusteeIdentity,
        rosterPosition: input.rosterPosition,
        recoveryEpoch: input.recoveryEpoch,
        deviceEpoch: input.deviceEpoch,
        signatureEnvelopeHash: input.signatureEnvelopeHash,
    }) as const;

const withoutHashField = <RecordType extends JsonRecord>(
    record: RecordType,
    hashFieldName: keyof RecordType,
): JsonRecord => {
    const { [hashFieldName]: removedHash, ...hashInput } = record;
    void removedHash;

    return hashInput;
};

const assertRecordContextMatches = (
    setupContext: CollectiveBgvSetupContext,
    record: CommonRandomnessCommit | CommonRandomnessReveal,
    objectPath: string,
): void => {
    const expectedContext = commonRandomnessContextFields(setupContext);
    for (const fieldName of Object.keys(
        expectedContext,
    ) as readonly (keyof CommonRandomnessContextFields)[]) {
        if (record[fieldName] !== expectedContext[fieldName]) {
            throw new Error(
                `${objectPath}.${fieldName} must match setupContext.${fieldName}.`,
            );
        }
    }
};

const assertRecordShape = (
    record: CommonRandomnessCommit | CommonRandomnessReveal,
    expectedObjectType: 'CommonRandomnessCommit' | 'CommonRandomnessReveal',
    objectPath: string,
): void => {
    if (record.objectType !== expectedObjectType) {
        throw new Error(
            `${objectPath}.objectType must be ${expectedObjectType}.`,
        );
    }
    if (record.objectVersion !== 1) {
        throw new Error(`${objectPath}.objectVersion must be 1.`);
    }
    if (record.signerRole !== 'Trustee') {
        throw new Error(`${objectPath}.signerRole must be Trustee.`);
    }
    assertNonEmptyString(
        record.trusteeIdentity,
        `${objectPath}.trusteeIdentity`,
    );
    assertNonNegativeSafeInteger(
        record.rosterPosition,
        `${objectPath}.rosterPosition`,
    );
    assertNonNegativeSafeInteger(
        record.recoveryEpoch,
        `${objectPath}.recoveryEpoch`,
    );
    assertNonNegativeSafeInteger(
        record.deviceEpoch,
        `${objectPath}.deviceEpoch`,
    );
    assertProtocolHash(
        record.signatureEnvelopeHash,
        `${objectPath}.signatureEnvelopeHash`,
    );
};

const assertRecordHashMatches = (
    record: CommonRandomnessCommit | CommonRandomnessReveal,
    objectPath: string,
): void => {
    if (record.objectType === 'CommonRandomnessCommit') {
        const expectedCommitHash = deriveProtocolHash(
            'CommonRandomnessCommitHash',
            withoutHashField(record, 'commitHash'),
        );
        if (record.commitHash !== expectedCommitHash) {
            throw new Error(
                `${objectPath}.commitHash does not match the canonical payload.`,
            );
        }

        return;
    }

    const expectedRevealHash = deriveProtocolHash(
        'CommonRandomnessRevealHash',
        withoutHashField(record, 'revealHash'),
    );
    if (record.revealHash !== expectedRevealHash) {
        throw new Error(
            `${objectPath}.revealHash does not match the canonical payload.`,
        );
    }
};

const sortedByRosterPosition = <
    RecordType extends CommonRandomnessCommit | CommonRandomnessReveal,
>(
    records: readonly RecordType[],
): RecordType[] =>
    [...records].sort(
        (left, right) => left.rosterPosition - right.rosterPosition,
    );

const validateFullRosterRecords = <
    RecordType extends CommonRandomnessCommit | CommonRandomnessReveal,
>(
    records: readonly RecordType[],
    participantCount: number,
    objectPath: string,
): RecordType[] => {
    if (records.length !== participantCount) {
        throw new Error(
            `${objectPath} must contain one record per participant.`,
        );
    }

    const sortedRecords = sortedByRosterPosition(records);
    sortedRecords.forEach((record, recordIndex) => {
        if (record.rosterPosition !== recordIndex) {
            throw new Error(
                `${objectPath} must cover roster positions 0 through ${String(participantCount - 1)} exactly once.`,
            );
        }
    });

    return sortedRecords;
};

const assertPublicDerivationsMatchKernelShape = (
    publicDerivations: SetupCommonRandomnessPublicDerivations,
    publicMatrixSeedHash: ProtocolHash,
): void => {
    if (publicDerivations.objectType !== 'SetupPublicDerivations') {
        throw new Error(
            'publicDerivations.objectType must be SetupPublicDerivations.',
        );
    }
    if (publicDerivations.objectVersion !== 1) {
        throw new Error('publicDerivations.objectVersion must be 1.');
    }
    if (publicDerivations.setupProfileId !== 'CollectiveBgvSetup-v1') {
        throw new Error(
            'publicDerivations.setupProfileId must be CollectiveBgvSetup-v1.',
        );
    }
    if (publicDerivations.publicMatrixSeedHash !== publicMatrixSeedHash) {
        throw new Error(
            'publicDerivations.publicMatrixSeedHash must match the derived public matrix seed hash.',
        );
    }
    if (publicDerivations.status !== 'deterministic-public-derivations-bound') {
        throw new Error(
            'publicDerivations.status must be deterministic-public-derivations-bound.',
        );
    }

    const bgvPublicA = assertJsonRecord(
        publicDerivations.bgvPublicA,
        'publicDerivations.bgvPublicA',
    );
    if (
        bgvPublicA.objectType !== 'BgvPublicAPolynomial' ||
        bgvPublicA.objectVersion !== 1 ||
        bgvPublicA.setupProfileId !== 'CollectiveBgvSetup-v1' ||
        bgvPublicA.publicMatrixSeedHash !== publicMatrixSeedHash
    ) {
        throw new Error(
            'publicDerivations.bgvPublicA must match the accepted public-a derivation profile.',
        );
    }
    assertProtocolHash(
        bgvPublicA.publicPolynomialRoot as string,
        'publicDerivations.bgvPublicA.publicPolynomialRoot',
    );

    const publicMatrices = assertJsonRecord(
        publicDerivations.publicMatrices,
        'publicDerivations.publicMatrices',
    );
    if (
        publicMatrices.objectType !== 'SetupPublicMatrixMaterial' ||
        publicMatrices.objectVersion !== 1 ||
        publicMatrices.setupProfileId !== 'CollectiveBgvSetup-v1' ||
        publicMatrices.publicMatrixSeedHash !== publicMatrixSeedHash ||
        publicMatrices.materializationStatus !==
            'deterministic-entry-streams-bound'
    ) {
        throw new Error(
            'publicDerivations.publicMatrices must match the accepted setup public matrix profile.',
        );
    }
    assertProtocolHash(
        publicMatrices.publicMatricesRoot as string,
        'publicDerivations.publicMatrices.publicMatricesRoot',
    );

    const crpRoots = assertJsonRecord(
        publicDerivations.crpRoots,
        'publicDerivations.crpRoots',
    );
    for (const fieldName of [
        'publicKeyCrpRoot',
        'relinearizationCrpRoot',
        'galoisKeyCrpRoot',
        'commitmentMatrixCrpRoot',
        'proofMatrixCrpRoot',
    ] as const) {
        assertProtocolHash(
            crpRoots[fieldName] as string,
            `publicDerivations.crpRoots.${fieldName}`,
        );
    }

    assertProtocolHash(
        publicDerivations.publicDerivationRoot,
        'publicDerivations.publicDerivationRoot',
    );
    const expectedPublicDerivationRoot = deriveProtocolHash(
        'SetupPublicDerivationRoot',
        withoutHashField(publicDerivations, 'publicDerivationRoot'),
    );
    if (
        publicDerivations.publicDerivationRoot !== expectedPublicDerivationRoot
    ) {
        throw new Error(
            'publicDerivations.publicDerivationRoot does not match the canonical payload.',
        );
    }
};

export const createCommonRandomnessReveal = (
    input: CommonRandomnessRevealInput,
): CommonRandomnessReveal => {
    assertParticipantInput(input);
    assertRevealHex(input.revealHex, 'revealHex');

    const revealWithoutHash = {
        objectType: 'CommonRandomnessReveal',
        objectVersion: 1,
        ...commonRandomnessParticipantFields(input),
        revealHex: input.revealHex,
    } as const satisfies Omit<CommonRandomnessReveal, 'revealHash'>;

    return {
        ...revealWithoutHash,
        revealHash: deriveProtocolHash(
            'CommonRandomnessRevealHash',
            revealWithoutHash,
        ),
    } satisfies CommonRandomnessReveal;
};

export const createCommonRandomnessCommit = (
    input: CommonRandomnessCommitInput,
): CommonRandomnessCommit => {
    assertParticipantInput(input);
    assertProtocolHash(input.revealHash, 'revealHash');

    const commitWithoutHash = {
        objectType: 'CommonRandomnessCommit',
        objectVersion: 1,
        ...commonRandomnessParticipantFields(input),
        revealHash: input.revealHash,
    } as const satisfies Omit<CommonRandomnessCommit, 'commitHash'>;

    return {
        ...commitWithoutHash,
        commitHash: deriveProtocolHash(
            'CommonRandomnessCommitHash',
            commitWithoutHash,
        ),
    } satisfies CommonRandomnessCommit;
};

export const createSetupCommonRandomness = (
    input: SetupCommonRandomnessInput,
): SetupCommonRandomness => {
    assertInputContext(input.setupContext);
    assertPositiveSafeInteger(input.participantCount, 'participantCount');

    const commitRecords = validateFullRosterRecords(
        input.commitRecords,
        input.participantCount,
        'commitRecords',
    );
    const revealRecords = validateFullRosterRecords(
        input.revealRecords,
        input.participantCount,
        'revealRecords',
    );
    const revealHashesByRosterPosition = new Map<number, ProtocolHash>();
    revealRecords.forEach((revealRecord, revealRecordIndex) => {
        const objectPath = `revealRecords.${String(revealRecordIndex)}`;
        assertRecordShape(revealRecord, 'CommonRandomnessReveal', objectPath);
        assertRecordContextMatches(
            input.setupContext,
            revealRecord,
            objectPath,
        );
        assertRevealHex(revealRecord.revealHex, `${objectPath}.revealHex`);
        assertRecordHashMatches(revealRecord, objectPath);
        revealHashesByRosterPosition.set(
            revealRecord.rosterPosition,
            revealRecord.revealHash,
        );
    });

    commitRecords.forEach((commitRecord, commitRecordIndex) => {
        const objectPath = `commitRecords.${String(commitRecordIndex)}`;
        assertRecordShape(commitRecord, 'CommonRandomnessCommit', objectPath);
        assertRecordContextMatches(
            input.setupContext,
            commitRecord,
            objectPath,
        );
        assertRecordHashMatches(commitRecord, objectPath);
        if (
            revealHashesByRosterPosition.get(commitRecord.rosterPosition) !==
            commitRecord.revealHash
        ) {
            throw new Error(
                `${objectPath}.revealHash must match the reveal record for the same roster position.`,
            );
        }
    });

    const orderedRevealHashes = revealRecords.map(
        (revealRecord) => revealRecord.revealHash,
    );
    const publicMatrixSeedHash = deriveProtocolHash(
        'SetupPublicMatrixSeedHash',
        {
            setupProfileId: 'CollectiveBgvSetup-v1',
            ceremonyId: input.setupContext.ceremonyId,
            manifestHash: input.setupContext.manifestHash,
            rosterHash: input.setupContext.rosterHash,
            setupProfileHash: input.setupContext.setupProfileHash,
            setupEpoch: input.setupContext.setupEpoch,
            orderedRevealHashes,
        },
    );
    const publicDerivations =
        input.derivePublicDerivations(publicMatrixSeedHash);
    assertPublicDerivationsMatchKernelShape(
        publicDerivations,
        publicMatrixSeedHash,
    );

    const commonRandomnessWithoutRoot = {
        objectType: 'SetupCommonRandomness',
        objectVersion: 1,
        ...commonRandomnessContextFields(input.setupContext),
        commitRecords,
        revealRecords,
        publicMatrixSeedHash,
        publicDerivations,
    } as const satisfies Omit<SetupCommonRandomness, 'commonRandomnessRoot'>;

    return {
        ...commonRandomnessWithoutRoot,
        commonRandomnessRoot: deriveProtocolHash(
            'SetupCommonRandomnessRoot',
            commonRandomnessWithoutRoot,
        ),
    } satisfies SetupCommonRandomness;
};
