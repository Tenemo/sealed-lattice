import {
    encryptPrivateVssMailboxEnvelope,
    privateVssMailboxEncryptionProfileId,
    type PrivateVssEncryptedEnvelope,
} from '@sealed-lattice/crypto';
import type { ProtocolHash } from '@sealed-lattice/types';

type JsonRecord = Record<string, unknown>;

type PrivateVssSetupContext = Readonly<
    Record<string, unknown> & {
        readonly ceremonyId: string;
        readonly manifestHash: ProtocolHash;
        readonly rosterHash: ProtocolHash;
        readonly setupProfileHash: ProtocolHash;
        readonly qShareHash: ProtocolHash;
        readonly carryAwareVssShareRelationProfileHash: ProtocolHash;
        readonly commitmentProfileHash: ProtocolHash;
        readonly setupEpoch: string;
    }
>;

export type PrivateVssCoefficientOpeningState = {
    readonly rnsLimbIndex: number;
    readonly rnsPrime: number;
    readonly shamirCoefficientIndex: number;
    readonly commitmentRoot: ProtocolHash;
    readonly coefficientMessage: readonly number[];
    readonly randomnessByColumn: readonly (readonly number[])[];
};

export type PrivateVssDealerContributionState = {
    readonly dealerIdentity: string;
    readonly dealerRosterPosition: number;
    readonly dealerCommitmentRoot: ProtocolHash;
    readonly dealerCoefficientCommitmentRecord: unknown;
    readonly dealerCoefficientCommitmentMaterialRecords: readonly unknown[];
    readonly coefficientOpenings: readonly PrivateVssCoefficientOpeningState[];
};

export type PrivateVssMailboxRecipient = {
    readonly recipientIdentity: string;
    readonly recipientRosterPosition: number;
    readonly mailboxPublicKeyBytesHex: string;
};

export type PrivateVssShareProofFactoryInput = {
    readonly setupContext: PrivateVssSetupContext;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly dealerContributionState: PrivateVssDealerContributionState;
    readonly recipient: PrivateVssMailboxRecipient;
    readonly rnsLimbIndex: number;
    readonly rnsPrime: number;
    readonly ringDegree: number;
    readonly shareValues: readonly number[];
    readonly coefficientCommitmentRoots: readonly ProtocolHash[];
};

export type PrivateVssShareProofFactory = (
    input: PrivateVssShareProofFactoryInput,
) => JsonRecord;

export type PrivateVssMailboxDeliveryKernel = {
    readonly deriveProtocolHash: (input: {
        readonly namespace: string;
        readonly value: unknown;
    }) => ProtocolHash;
    readonly verifyPrivateVssShareEnvelope: (input: {
        readonly setupContext: unknown;
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly dealerCoefficientCommitmentRecord: unknown;
        readonly dealerCoefficientCommitmentMaterialRecords: readonly unknown[];
        readonly privateEnvelope: unknown;
        readonly expectedPrivateEnvelopeHash?: ProtocolHash;
        readonly expectedLocalVerificationRoot?: ProtocolHash;
    }) => {
        readonly ok: boolean;
        readonly privateEnvelopeHash: ProtocolHash | null;
        readonly localVerificationRoot: ProtocolHash | null;
        readonly refusedObjects: readonly {
            readonly reasonCode: string;
            readonly message: string;
            readonly objectPath?: string;
        }[];
    };
};

export type PrivateVssMailboxDeliverySetInput = {
    readonly kernel: PrivateVssMailboxDeliveryKernel;
    readonly setupContext: PrivateVssSetupContext;
    readonly phaseOrderHash: ProtocolHash;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly vssCoefficientCommitmentRoot: ProtocolHash;
    readonly qSharePrimes: readonly number[];
    readonly ringDegree: number;
    readonly participantCount: number;
    readonly deliveryPhaseNumber: number;
    readonly verificationPhaseNumber: number;
    readonly privateVssShareProofFactory?: PrivateVssShareProofFactory;
    readonly dealerContributionStates: readonly PrivateVssDealerContributionState[];
    readonly recipients: readonly PrivateVssMailboxRecipient[];
};

export type PrivateVssMailboxDealerDeliveryInput = Omit<
    PrivateVssMailboxDeliverySetInput,
    'dealerContributionStates'
> & {
    readonly dealerContributionState: PrivateVssDealerContributionState;
};

type PrivateVssMailboxDeliveryContext = Omit<
    PrivateVssMailboxDeliverySetInput,
    'dealerContributionStates' | 'recipients'
>;

export type PrivateVssMailboxDeliverySet = Readonly<
    JsonRecord & {
        readonly objectType: 'PrivateVssEnvelopeCommitmentSet';
        readonly objectVersion: 1;
        readonly mailboxEncryptionProfileId: typeof privateVssMailboxEncryptionProfileId;
        readonly privateVssEnvelopeCommitmentRoot: ProtocolHash;
        readonly envelopeReferences: readonly PrivateVssEnvelopeCommitment[];
    }
>;

export type PrivateVssEnvelopeCommitment = Readonly<
    JsonRecord & {
        readonly objectType: 'PrivateVssEnvelopeCommitment';
        readonly objectVersion: 1;
        readonly privateEnvelopeHash: ProtocolHash;
        readonly encryptedEnvelopeHash: ProtocolHash;
        readonly privateEnvelopeAad: JsonRecord;
        readonly privateEnvelopeAadHash: ProtocolHash;
        readonly encryptedEnvelope: PrivateVssEncryptedEnvelope;
        readonly recipientMailboxPublicKeyHash: ProtocolHash;
        readonly localVerificationRoot: ProtocolHash;
        readonly privateEnvelopeCommitmentRoot: ProtocolHash;
    }
>;

const privateEnvelopeDeliveryContentType = 'private-vss-share-envelope';
const privateEnvelopeObjectType = 'PrivateVssShareEnvelope';
const privateEnvelopeAadObjectType = 'PrivateVssEnvelopeAad';
const localOpeningAcceptedStatus = 'accepted-local-private-vss-opening';
const recipientVerificationRequirement =
    'recipient-verifies-private-vss-opening-before-acceptance';

const validatePositiveSafeInteger = (
    value: number,
    fieldName: string,
): void => {
    if (!Number.isSafeInteger(value) || value <= 0) {
        throw new TypeError(`${fieldName} must be a positive safe integer.`);
    }
};

const validateSafeRosterPosition = (value: number, fieldName: string): void => {
    if (!Number.isSafeInteger(value) || value < 0) {
        throw new TypeError(
            `${fieldName} must be a non-negative safe integer.`,
        );
    }
};

const sortedByRosterPosition = <Entry>(
    entries: readonly Entry[],
    rosterPosition: (entry: Entry) => number,
    entryLabel: string,
): Entry[] => {
    const sortedEntries = [...entries].sort(
        (left, right) => rosterPosition(left) - rosterPosition(right),
    );
    const seenRosterPositions = new Set<number>();
    for (const entry of sortedEntries) {
        const position = rosterPosition(entry);
        validateSafeRosterPosition(position, `${entryLabel} roster position`);
        if (seenRosterPositions.has(position)) {
            throw new Error(`${entryLabel} roster positions must be distinct.`);
        }
        seenRosterPositions.add(position);
    }

    return sortedEntries;
};

const assertFullRosterPositions = (
    positions: readonly number[],
    participantCount: number,
    entryLabel: string,
): void => {
    if (positions.length !== participantCount) {
        throw new Error(
            `${entryLabel} count must match the accepted participant count.`,
        );
    }
    positions.forEach((position, expectedPosition) => {
        if (position !== expectedPosition) {
            throw new Error(
                `${entryLabel} roster positions must be contiguous from zero.`,
            );
        }
    });
};

const shareValuesForRecipient = (
    coefficientMessagesByShamirIndex: readonly (readonly number[])[],
    recipientRosterPosition: number,
    rnsPrime: number,
    ringDegree: number,
): readonly number[] => {
    const trusteePoint = BigInt(recipientRosterPosition + 1);
    const trusteePointPowers: bigint[] = [];
    let trusteePointPower = 1n;
    for (const _coefficientMessages of coefficientMessagesByShamirIndex) {
        trusteePointPowers.push(trusteePointPower);
        trusteePointPower *= trusteePoint;
    }
    const rnsPrimeWide = BigInt(rnsPrime);
    const shareValues: number[] = [];
    for (
        let coefficientPosition = 0;
        coefficientPosition < ringDegree;
        coefficientPosition += 1
    ) {
        const unreducedValue = coefficientMessagesByShamirIndex.reduce(
            (accumulatedValue, coefficientMessages, shamirCoefficientIndex) => {
                const coefficientMessage =
                    coefficientMessages[coefficientPosition];
                if (coefficientMessage === undefined) {
                    throw new Error(
                        'VSS coefficient message length must match ringDegree.',
                    );
                }

                return (
                    accumulatedValue +
                    BigInt(coefficientMessage) *
                        trusteePointPowers[shamirCoefficientIndex]
                );
            },
            0n,
        );
        shareValues.push(Number(unreducedValue % rnsPrimeWide));
    }

    return shareValues;
};

const privateEnvelopeAad = (
    input: PrivateVssMailboxDeliveryContext,
    dealerState: PrivateVssDealerContributionState,
    recipient: PrivateVssMailboxRecipient,
    envelopeSequenceNumber: number,
): JsonRecord => ({
    objectType: privateEnvelopeAadObjectType,
    objectVersion: 1,
    setupProfileId: 'CollectiveBgvSetup-v1',
    mailboxEncryptionProfileId: privateVssMailboxEncryptionProfileId,
    privateEnvelopeObjectType,
    ciphertextContentType: privateEnvelopeDeliveryContentType,
    ceremonyId: input.setupContext.ceremonyId,
    manifestHash: input.setupContext.manifestHash,
    rosterHash: input.setupContext.rosterHash,
    setupProfileHash: input.setupContext.setupProfileHash,
    qShareHash: input.setupContext.qShareHash,
    carryAwareVssShareRelationProfileHash:
        input.setupContext.carryAwareVssShareRelationProfileHash,
    commitmentProfileHash: input.setupContext.commitmentProfileHash,
    setupEpoch: input.setupContext.setupEpoch,
    phaseOrderHash: input.phaseOrderHash,
    publicMatrixSeedHash: input.publicMatrixSeedHash,
    vssCoefficientCommitmentRoot: input.vssCoefficientCommitmentRoot,
    dealerIdentity: dealerState.dealerIdentity,
    dealerRosterPosition: dealerState.dealerRosterPosition,
    recipientIdentity: recipient.recipientIdentity,
    recipientRosterPosition: recipient.recipientRosterPosition,
    dealerCommitmentRoot: dealerState.dealerCommitmentRoot,
    envelopeSequenceNumber,
    deliveryPhaseNumber: input.deliveryPhaseNumber,
    verificationPhaseNumber: input.verificationPhaseNumber,
    recipientVerificationRequirement,
});

const privateEnvelope = (
    input: PrivateVssMailboxDeliveryContext,
    dealerState: PrivateVssDealerContributionState,
    recipient: PrivateVssMailboxRecipient,
    privateEnvelopeAadHash: ProtocolHash,
): JsonRecord => {
    const rnsShareOpenings = input.qSharePrimes.map(
        (rnsPrime, rnsLimbIndex) => {
            const coefficientOpenings = dealerState.coefficientOpenings
                .filter(
                    (opening) =>
                        opening.rnsLimbIndex === rnsLimbIndex &&
                        opening.rnsPrime === rnsPrime,
                )
                .sort(
                    (left, right) =>
                        left.shamirCoefficientIndex -
                        right.shamirCoefficientIndex,
                );
            if (coefficientOpenings.length === 0) {
                throw new Error(
                    'Dealer local VSS state must contain every Q_share limb.',
                );
            }
            const coefficientMessagesByShamirIndex = coefficientOpenings.map(
                (opening) => {
                    if (
                        opening.coefficientMessage.length !== input.ringDegree
                    ) {
                        throw new Error(
                            'VSS coefficient message length must match ringDegree.',
                        );
                    }

                    return opening.coefficientMessage;
                },
            );
            const shareValues = shareValuesForRecipient(
                coefficientMessagesByShamirIndex,
                recipient.recipientRosterPosition,
                rnsPrime,
                input.ringDegree,
            );
            const coefficientCommitmentRoots = coefficientOpenings.map(
                (opening) => opening.commitmentRoot,
            );
            if (input.privateVssShareProofFactory === undefined) {
                throw new Error(
                    'Private VSS mailbox delivery requires recipient-local zero-knowledge privateVssShareProof generation; plaintext aggregate openings and carry witnesses are refused.',
                );
            }
            const privateVssShareProof = input.privateVssShareProofFactory({
                setupContext: input.setupContext,
                publicMatrixSeedHash: input.publicMatrixSeedHash,
                dealerContributionState: dealerState,
                recipient,
                rnsLimbIndex,
                rnsPrime,
                ringDegree: input.ringDegree,
                shareValues,
                coefficientCommitmentRoots,
            });

            return {
                objectType: 'PrivateVssShareLimbOpening',
                objectVersion: 1,
                rnsLimbIndex,
                rnsPrime,
                shareValues,
                coefficientCommitmentRoots,
                privateVssShareProof,
            };
        },
    );

    return {
        objectType: privateEnvelopeObjectType,
        objectVersion: 1,
        ceremonyId: input.setupContext.ceremonyId,
        manifestHash: input.setupContext.manifestHash,
        rosterHash: input.setupContext.rosterHash,
        setupProfileHash: input.setupContext.setupProfileHash,
        qShareHash: input.setupContext.qShareHash,
        carryAwareVssShareRelationProfileHash:
            input.setupContext.carryAwareVssShareRelationProfileHash,
        commitmentProfileHash: input.setupContext.commitmentProfileHash,
        setupEpoch: input.setupContext.setupEpoch,
        publicMatrixSeedHash: input.publicMatrixSeedHash,
        privateEnvelopeAadHash,
        dealerIdentity: dealerState.dealerIdentity,
        dealerRosterPosition: dealerState.dealerRosterPosition,
        recipientIdentity: recipient.recipientIdentity,
        recipientRosterPosition: recipient.recipientRosterPosition,
        dealerCommitmentRoot: dealerState.dealerCommitmentRoot,
        rnsShareOpenings,
    };
};

const createEnvelopeCommitment = async (
    input: PrivateVssMailboxDeliveryContext,
    dealerState: PrivateVssDealerContributionState,
    recipient: PrivateVssMailboxRecipient,
): Promise<PrivateVssEnvelopeCommitment> => {
    const envelopeSequenceNumber =
        dealerState.dealerRosterPosition * input.participantCount +
        recipient.recipientRosterPosition;
    const associatedData = privateEnvelopeAad(
        input,
        dealerState,
        recipient,
        envelopeSequenceNumber,
    );
    const associatedDataHash = input.kernel.deriveProtocolHash({
        namespace: 'PrivateVssEnvelopeAadHash',
        value: associatedData,
    });
    const privateShareEnvelope = privateEnvelope(
        input,
        dealerState,
        recipient,
        associatedDataHash,
    );
    const localVerification = input.kernel.verifyPrivateVssShareEnvelope({
        setupContext: input.setupContext,
        publicMatrixSeedHash: input.publicMatrixSeedHash,
        dealerCoefficientCommitmentRecord:
            dealerState.dealerCoefficientCommitmentRecord,
        dealerCoefficientCommitmentMaterialRecords:
            dealerState.dealerCoefficientCommitmentMaterialRecords,
        privateEnvelope: privateShareEnvelope,
    });
    if (
        !localVerification.ok ||
        localVerification.privateEnvelopeHash === null ||
        localVerification.localVerificationRoot === null
    ) {
        const refusal = localVerification.refusedObjects[0];
        throw new Error(
            refusal === undefined
                ? 'Private VSS envelope failed local verification.'
                : `Private VSS envelope failed local verification: ${refusal.reasonCode}: ${refusal.message}`,
        );
    }
    const encryptedDelivery = await encryptPrivateVssMailboxEnvelope({
        privateEnvelope: privateShareEnvelope,
        privateEnvelopeAad: associatedData,
        recipientMailboxPublicKeyBytesHex: recipient.mailboxPublicKeyBytesHex,
    });
    if (
        encryptedDelivery.privateEnvelopeHash !==
            localVerification.privateEnvelopeHash ||
        encryptedDelivery.privateEnvelopeAadHash !== associatedDataHash
    ) {
        throw new Error(
            'Private VSS mailbox encryption did not preserve the verified envelope binding.',
        );
    }

    const commitmentWithoutRoot = {
        objectType: 'PrivateVssEnvelopeCommitment',
        objectVersion: 1,
        mailboxEncryptionProfileId: privateVssMailboxEncryptionProfileId,
        ceremonyId: input.setupContext.ceremonyId,
        manifestHash: input.setupContext.manifestHash,
        rosterHash: input.setupContext.rosterHash,
        setupProfileHash: input.setupContext.setupProfileHash,
        qShareHash: input.setupContext.qShareHash,
        carryAwareVssShareRelationProfileHash:
            input.setupContext.carryAwareVssShareRelationProfileHash,
        commitmentProfileHash: input.setupContext.commitmentProfileHash,
        setupEpoch: input.setupContext.setupEpoch,
        publicMatrixSeedHash: input.publicMatrixSeedHash,
        vssCoefficientCommitmentRoot: input.vssCoefficientCommitmentRoot,
        dealerIdentity: dealerState.dealerIdentity,
        dealerRosterPosition: dealerState.dealerRosterPosition,
        recipientIdentity: recipient.recipientIdentity,
        recipientRosterPosition: recipient.recipientRosterPosition,
        dealerCommitmentRoot: dealerState.dealerCommitmentRoot,
        envelopeSequenceNumber,
        deliveryPhaseNumber: input.deliveryPhaseNumber,
        verificationPhaseNumber: input.verificationPhaseNumber,
        privateEnvelopeHash: localVerification.privateEnvelopeHash,
        encryptedEnvelopeHash:
            encryptedDelivery.encryptedEnvelope.encryptedEnvelopeHash,
        privateEnvelopeAad: associatedData,
        privateEnvelopeAadHash: associatedDataHash,
        encryptedEnvelope: encryptedDelivery.encryptedEnvelope,
        recipientMailboxPublicKeyHash:
            encryptedDelivery.encryptedEnvelope.recipientMailboxPublicKeyHash,
        localVerificationRoot: localVerification.localVerificationRoot,
        openingVerificationStatus: localOpeningAcceptedStatus,
    } as const satisfies JsonRecord;

    return {
        ...commitmentWithoutRoot,
        privateEnvelopeCommitmentRoot: input.kernel.deriveProtocolHash({
            namespace: 'PrivateVssEnvelopeCommitmentRoot',
            value: commitmentWithoutRoot,
        }),
    } satisfies PrivateVssEnvelopeCommitment;
};

export const createPrivateVssMailboxDealerDeliveryReferences = async (
    input: PrivateVssMailboxDealerDeliveryInput,
): Promise<readonly PrivateVssEnvelopeCommitment[]> => {
    validatePositiveSafeInteger(input.participantCount, 'participantCount');
    validatePositiveSafeInteger(input.ringDegree, 'ringDegree');
    validateSafeRosterPosition(
        input.dealerContributionState.dealerRosterPosition,
        'dealer contribution state roster position',
    );
    if (
        input.dealerContributionState.dealerRosterPosition >=
        input.participantCount
    ) {
        throw new Error(
            'dealer contribution state roster position must be inside the accepted participant count.',
        );
    }
    const recipients = sortedByRosterPosition(
        input.recipients,
        (recipient) => recipient.recipientRosterPosition,
        'mailbox recipient',
    );
    assertFullRosterPositions(
        recipients.map((recipient) => recipient.recipientRosterPosition),
        input.participantCount,
        'mailbox recipient',
    );

    return Promise.all(
        recipients.map((recipient) =>
            createEnvelopeCommitment(
                input,
                input.dealerContributionState,
                recipient,
            ),
        ),
    );
};

export const createPrivateVssMailboxDeliverySet = async (
    input: PrivateVssMailboxDeliverySetInput,
): Promise<PrivateVssMailboxDeliverySet> => {
    validatePositiveSafeInteger(input.participantCount, 'participantCount');
    validatePositiveSafeInteger(input.ringDegree, 'ringDegree');
    const dealerStates = sortedByRosterPosition(
        input.dealerContributionStates,
        (dealerState) => dealerState.dealerRosterPosition,
        'dealer contribution state',
    );
    const recipients = sortedByRosterPosition(
        input.recipients,
        (recipient) => recipient.recipientRosterPosition,
        'mailbox recipient',
    );
    assertFullRosterPositions(
        dealerStates.map((dealerState) => dealerState.dealerRosterPosition),
        input.participantCount,
        'dealer contribution state',
    );
    assertFullRosterPositions(
        recipients.map((recipient) => recipient.recipientRosterPosition),
        input.participantCount,
        'mailbox recipient',
    );

    const envelopeReferences = (
        await Promise.all(
            dealerStates.map((dealerContributionState) =>
                createPrivateVssMailboxDealerDeliveryReferences({
                    ...input,
                    dealerContributionState,
                    recipients,
                }),
            ),
        )
    ).flat();

    const commitmentSetWithoutRoot = {
        objectType: 'PrivateVssEnvelopeCommitmentSet',
        objectVersion: 1,
        mailboxEncryptionProfileId: privateVssMailboxEncryptionProfileId,
        ceremonyId: input.setupContext.ceremonyId,
        manifestHash: input.setupContext.manifestHash,
        rosterHash: input.setupContext.rosterHash,
        setupProfileHash: input.setupContext.setupProfileHash,
        qShareHash: input.setupContext.qShareHash,
        carryAwareVssShareRelationProfileHash:
            input.setupContext.carryAwareVssShareRelationProfileHash,
        commitmentProfileHash: input.setupContext.commitmentProfileHash,
        setupEpoch: input.setupContext.setupEpoch,
        publicMatrixSeedHash: input.publicMatrixSeedHash,
        vssCoefficientCommitmentRoot: input.vssCoefficientCommitmentRoot,
        participantCount: input.participantCount,
        envelopeCount: input.participantCount * input.participantCount,
        deliveryPhaseNumber: input.deliveryPhaseNumber,
        verificationPhaseNumber: input.verificationPhaseNumber,
        envelopeReferences,
    } as const satisfies JsonRecord;

    return {
        ...commitmentSetWithoutRoot,
        privateVssEnvelopeCommitmentRoot: input.kernel.deriveProtocolHash({
            namespace: 'PrivateVssEnvelopeCommitmentRoot',
            value: commitmentSetWithoutRoot,
        }),
    } satisfies PrivateVssMailboxDeliverySet;
};
