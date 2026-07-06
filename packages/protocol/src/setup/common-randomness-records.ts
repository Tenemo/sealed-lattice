import {
    canonicalJson,
    deriveCanonicalObjectHash,
    verifySignedObjectSignature,
} from '@sealed-lattice/crypto';
import type {
    CanonicalSignedRootObject,
    ProtocolHash,
    ProtocolSignatureEnvelope,
} from '@sealed-lattice/types';

import {
    assertJsonRecord,
    assertNonEmptyString,
    assertNonNegativeSafeInteger,
    assertPositiveSafeInteger,
    assertProtocolHash,
    type JsonRecord,
} from './common-fields.js';
import type {
    CollectiveBgvSetupContext,
    ProtocolRootSigner,
} from './vss-share-verification-records.js';

type CommonRandomnessContextFields = Readonly<{
    readonly ceremonyId: string;
    readonly manifestHash: ProtocolHash;
    readonly rosterHash: ProtocolHash;
    readonly setupParametersHash: ProtocolHash;
    readonly setupEpoch: string;
}>;

export type CommonRandomnessParticipantInput = Readonly<{
    readonly setupContext: CollectiveBgvSetupContext;
    readonly trusteeIdentity: string;
    readonly rosterPosition: number;
    readonly recoveryEpoch: number;
    readonly deviceEpoch: number;
    readonly signingPublicKeyHash: ProtocolHash;
    readonly signRoot: ProtocolRootSigner;
}>;

export type CommonRandomnessRevealInput = CommonRandomnessParticipantInput &
    Readonly<{
        readonly revealHex: string;
    }>;

export type CommonRandomnessReveal = Readonly<
    JsonRecord &
        CommonRandomnessContextFields & {
            readonly objectType: 'CommonRandomnessReveal';
            readonly signerRole: 'Trustee';
            readonly trusteeIdentity: string;
            readonly rosterPosition: number;
            readonly recoveryEpoch: number;
            readonly deviceEpoch: number;
            readonly revealHex: string;
            readonly signatureEnvelopeHash: ProtocolHash;
            readonly signatureEnvelope: ProtocolSignatureEnvelope;
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
            readonly signerRole: 'Trustee';
            readonly trusteeIdentity: string;
            readonly rosterPosition: number;
            readonly recoveryEpoch: number;
            readonly deviceEpoch: number;
            readonly revealHash: ProtocolHash;
            readonly signatureEnvelopeHash: ProtocolHash;
            readonly signatureEnvelope: ProtocolSignatureEnvelope;
            readonly commitHash: ProtocolHash;
        }
>;

export type SetupCommonRandomnessPublicDerivations = Readonly<
    JsonRecord & {
        readonly objectType: 'SetupPublicDerivations';
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly bgvPublicA: Readonly<
            JsonRecord & {
                readonly objectType: 'BgvPublicAPolynomial';
                readonly publicMatrixSeedHash: ProtocolHash;
                readonly publicPolynomialRoot: ProtocolHash;
            }
        >;
        readonly publicMatrices: Readonly<
            JsonRecord & {
                readonly objectType: 'SetupPublicMatrixMaterial';
                readonly publicMatrixSeedHash: ProtocolHash;
                readonly publicMatricesRoot: ProtocolHash;
            }
        >;
        readonly crpRoots: Readonly<{
            readonly publicKeyCrpRoot: ProtocolHash;
            readonly relinearizationCrpRoot: ProtocolHash;
            readonly galoisKeyCrpRoot: ProtocolHash;
            readonly commitmentMatrixCrpRoot: ProtocolHash;
        }>;
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
            readonly commitRecords: readonly CommonRandomnessCommit[];
            readonly revealRecords: readonly CommonRandomnessReveal[];
            readonly publicMatrixSeedHash: ProtocolHash;
            readonly publicDerivations: SetupCommonRandomnessPublicDerivations;
            readonly commonRandomnessRoot: ProtocolHash;
        }
>;

// Each reveal contributes exactly 32 bytes (256 bits) of entropy to the joint public matrix seed.
const revealHexPattern = /^[0-9a-f]{64}$/u;
const textEncoder = new TextEncoder();

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
    setupParametersHash: setupContext.setupParametersHash,
    setupEpoch: setupContext.setupEpoch,
});

const assertInputContext = (setupContext: CollectiveBgvSetupContext): void => {
    for (const fieldName of [
        'ceremonyId',
        'manifestHash',
        'rosterHash',
        'setupParametersHash',
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
    assertProtocolHash(input.signingPublicKeyHash, 'signingPublicKeyHash');
};

const canonicalByteLength = (value: unknown): number =>
    textEncoder.encode(canonicalJson(value)).byteLength;

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
    assertJsonRecord(
        record.signatureEnvelope,
        `${objectPath}.signatureEnvelope`,
    );
};

const assertRecordHashMatches = (
    record: CommonRandomnessCommit | CommonRandomnessReveal,
    objectPath: string,
): void => {
    if (record.objectType === 'CommonRandomnessCommit') {
        const {
            commitHash: removedCommitHash,
            signatureEnvelopeHash: removedSignatureEnvelopeHash,
            signatureEnvelope: removedSignatureEnvelope,
            ...hashInput
        } = record;
        void removedCommitHash;
        void removedSignatureEnvelopeHash;
        void removedSignatureEnvelope;
        const expectedCommitHash = deriveCanonicalObjectHash(hashInput);
        if (record.commitHash !== expectedCommitHash) {
            throw new Error(
                `${objectPath}.commitHash does not match the canonical payload.`,
            );
        }

        return;
    }

    const {
        revealHash: removedRevealHash,
        signatureEnvelopeHash: removedSignatureEnvelopeHash,
        signatureEnvelope: removedSignatureEnvelope,
        ...hashInput
    } = record;
    void removedRevealHash;
    void removedSignatureEnvelopeHash;
    void removedSignatureEnvelope;
    const expectedRevealHash = deriveCanonicalObjectHash(hashInput);
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
    if (publicDerivations.publicMatrixSeedHash !== publicMatrixSeedHash) {
        throw new Error(
            'publicDerivations.publicMatrixSeedHash must match the derived public matrix seed hash.',
        );
    }

    const bgvPublicA = assertJsonRecord(
        publicDerivations.bgvPublicA,
        'publicDerivations.bgvPublicA',
    );
    if (
        bgvPublicA.objectType !== 'BgvPublicAPolynomial' ||
        bgvPublicA.publicMatrixSeedHash !== publicMatrixSeedHash
    ) {
        throw new Error(
            'publicDerivations.bgvPublicA must match the accepted public-a derivation parameters.',
        );
    }
    assertProtocolHash(
        bgvPublicA.publicPolynomialRoot,
        'publicDerivations.bgvPublicA.publicPolynomialRoot',
    );

    const publicMatrices = assertJsonRecord(
        publicDerivations.publicMatrices,
        'publicDerivations.publicMatrices',
    );
    if (
        publicMatrices.objectType !== 'SetupPublicMatrixMaterial' ||
        publicMatrices.publicMatrixSeedHash !== publicMatrixSeedHash
    ) {
        throw new Error(
            'publicDerivations.publicMatrices must match the accepted setup public matrix parameters.',
        );
    }
    assertProtocolHash(
        publicMatrices.publicMatricesRoot,
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
    ] as const) {
        assertProtocolHash(
            crpRoots[fieldName],
            `publicDerivations.crpRoots.${fieldName}`,
        );
    }

    assertProtocolHash(
        publicDerivations.publicDerivationRoot,
        'publicDerivations.publicDerivationRoot',
    );
    const expectedPublicDerivationRoot = deriveCanonicalObjectHash(
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

const commonRandomnessSignatureContextHash = (
    objectType: 'CommonRandomnessCommit' | 'CommonRandomnessReveal',
    purpose:
        | 'common-randomness-commit-signature-context'
        | 'common-randomness-reveal-signature-context',
    payload: JsonRecord,
    objectRoot: ProtocolHash,
): ProtocolHash =>
    deriveCanonicalObjectHash({
        objectType: `${objectType}SignatureContext`,
        purpose,
        ceremonyId: payload.ceremonyId,
        manifestHash: payload.manifestHash,
        rosterHash: payload.rosterHash,
        setupParametersHash: payload.setupParametersHash,
        setupEpoch: payload.setupEpoch,
        trusteeIdentity: payload.trusteeIdentity,
        rosterPosition: payload.rosterPosition,
        objectRoot,
    });

const verifyGeneratedSignatureEnvelope = (
    recordLabel: string,
    signatureEnvelope: ProtocolSignatureEnvelope,
    signedRoot: CanonicalSignedRootObject,
    signingPublicKeyHash: ProtocolHash,
): void => {
    const result = verifySignedObjectSignature(signatureEnvelope, {
        objectType: signedRoot.objectType,
        signerRole: signedRoot.signerRole,
        signerIdentity: signedRoot.signerIdentity,
        ceremonyId: signedRoot.ceremonyId,
        publicKeyHash: signingPublicKeyHash,
        manifestHash: signedRoot.manifestHash,
        objectRoot: signedRoot.objectRoot,
        chunkMerkleRoot: signedRoot.chunkMerkleRoot,
        boardHeadHash: signedRoot.boardHeadHash,
        contextHash: signedRoot.contextHash,
        byteLength: signedRoot.byteLength,
        recoveryEpoch: signedRoot.recoveryEpoch,
        deviceEpoch: signedRoot.deviceEpoch,
    });
    if (!result.isValid) {
        const refusedObject = result.refusedObjects[0];
        throw new Error(
            refusedObject === undefined
                ? `${recordLabel} signature envelope failed verification.`
                : `${recordLabel} signature envelope failed verification: ${refusedObject.code}: ${refusedObject.message}`,
        );
    }
    if (signatureEnvelope.signatureHash !== result.acceptedHashes[0]) {
        throw new Error(
            `${recordLabel} signature envelope hash does not match the verified signature hash.`,
        );
    }
};

export const createCommonRandomnessReveal = async (
    input: CommonRandomnessRevealInput,
): Promise<CommonRandomnessReveal> => {
    assertParticipantInput(input);
    assertRevealHex(input.revealHex, 'revealHex');

    const revealWithoutHash = {
        objectType: 'CommonRandomnessReveal',
        ...commonRandomnessParticipantFields(input),
        revealHex: input.revealHex,
    } as const satisfies JsonRecord;
    const revealHash = deriveCanonicalObjectHash(revealWithoutHash);
    const revealContextHash = commonRandomnessSignatureContextHash(
        'CommonRandomnessReveal',
        'common-randomness-reveal-signature-context',
        revealWithoutHash,
        revealHash,
    );
    const signedRoot = {
        objectType: 'CommonRandomnessReveal',
        ceremonyId: input.setupContext.ceremonyId,
        manifestHash: input.setupContext.manifestHash,
        boardHeadHash: null,
        objectRoot: revealHash,
        chunkMerkleRoot: null,
        byteLength: canonicalByteLength(revealWithoutHash),
        signerRole: 'Trustee',
        signerIdentity: input.trusteeIdentity,
        recoveryEpoch: input.recoveryEpoch,
        deviceEpoch: input.deviceEpoch,
        contextHash: revealContextHash,
    } as const satisfies CanonicalSignedRootObject;
    const signatureEnvelope = await input.signRoot(signedRoot);
    verifyGeneratedSignatureEnvelope(
        'Common-randomness reveal',
        signatureEnvelope,
        signedRoot,
        input.signingPublicKeyHash,
    );

    return {
        ...revealWithoutHash,
        signatureEnvelopeHash: signatureEnvelope.signatureHash,
        signatureEnvelope,
        revealHash,
    } satisfies CommonRandomnessReveal;
};

export const createCommonRandomnessCommit = async (
    input: CommonRandomnessCommitInput,
): Promise<CommonRandomnessCommit> => {
    assertParticipantInput(input);
    assertProtocolHash(input.revealHash, 'revealHash');

    const commitWithoutHash = {
        objectType: 'CommonRandomnessCommit',
        ...commonRandomnessParticipantFields(input),
        revealHash: input.revealHash,
    } as const satisfies JsonRecord;
    const commitHash = deriveCanonicalObjectHash(commitWithoutHash);
    const commitContextHash = commonRandomnessSignatureContextHash(
        'CommonRandomnessCommit',
        'common-randomness-commit-signature-context',
        commitWithoutHash,
        commitHash,
    );
    const signedRoot = {
        objectType: 'CommonRandomnessCommit',
        ceremonyId: input.setupContext.ceremonyId,
        manifestHash: input.setupContext.manifestHash,
        boardHeadHash: null,
        objectRoot: commitHash,
        chunkMerkleRoot: null,
        byteLength: canonicalByteLength(commitWithoutHash),
        signerRole: 'Trustee',
        signerIdentity: input.trusteeIdentity,
        recoveryEpoch: input.recoveryEpoch,
        deviceEpoch: input.deviceEpoch,
        contextHash: commitContextHash,
    } as const satisfies CanonicalSignedRootObject;
    const signatureEnvelope = await input.signRoot(signedRoot);
    verifyGeneratedSignatureEnvelope(
        'Common-randomness commit',
        signatureEnvelope,
        signedRoot,
        input.signingPublicKeyHash,
    );

    return {
        ...commitWithoutHash,
        signatureEnvelopeHash: signatureEnvelope.signatureHash,
        signatureEnvelope,
        commitHash,
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
    // Commit-then-reveal coin flip: the public matrix seed is the joint digest of all reveal hashes in roster order, so no single trustee can bias the derived CRS after seeing others' reveals.
    const publicMatrixSeedHash = deriveCanonicalObjectHash({
        objectType: 'SetupPublicMatrixSeed',
        ceremonyId: input.setupContext.ceremonyId,
        manifestHash: input.setupContext.manifestHash,
        rosterHash: input.setupContext.rosterHash,
        setupParametersHash: input.setupContext.setupParametersHash,
        setupEpoch: input.setupContext.setupEpoch,
        orderedRevealHashes,
    });
    const publicDerivations =
        input.derivePublicDerivations(publicMatrixSeedHash);
    assertPublicDerivationsMatchKernelShape(
        publicDerivations,
        publicMatrixSeedHash,
    );

    const commonRandomnessWithoutRoot = {
        objectType: 'SetupCommonRandomness',
        ...commonRandomnessContextFields(input.setupContext),
        commitRecords,
        revealRecords,
        publicMatrixSeedHash,
        publicDerivations,
    } as const satisfies Omit<SetupCommonRandomness, 'commonRandomnessRoot'>;

    return {
        ...commonRandomnessWithoutRoot,
        commonRandomnessRoot: deriveCanonicalObjectHash(
            commonRandomnessWithoutRoot,
        ),
    } satisfies SetupCommonRandomness;
};
