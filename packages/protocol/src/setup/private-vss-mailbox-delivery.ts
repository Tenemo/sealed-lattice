import {
    encryptPrivateVssMailboxEnvelope,
    type PrivateVssEncryptedEnvelope,
} from '@sealed-lattice/crypto';
import type { ProtocolHash } from '@sealed-lattice/types';

import {
    assertNonNegativeSafeInteger,
    assertPositiveSafeInteger,
    assertProtocolHash,
    bytesToHex,
} from './common-fields.js';
import {
    setupProofMaterialReferenceSetForVerificationInput,
    type CanonicalGeneratedSetupProofMaterial,
} from './setup-proof-material-transport.js';
import { copyCanonicalStreamDescriptor } from './canonical-stream-descriptor.js';

type JsonRecord = Record<string, unknown>;

type PrivateVssSetupContext = Readonly<
    Record<string, unknown> & {
        readonly ceremonyId: string;
        readonly manifestHash: ProtocolHash;
        readonly rosterHash: ProtocolHash;
        readonly setupParametersHash: ProtocolHash;
        readonly setupEpoch: string;
    }
>;

type PrivateVssCoefficientOpeningState = {
    readonly rnsLimbIndex: number;
    readonly rnsPrime: number;
    readonly shamirCoefficientIndex: number;
    readonly commitmentRoot: ProtocolHash;
    readonly coefficientMessage: readonly number[];
    readonly randomnessByColumn: readonly (readonly number[])[];
};

type PrivateVssSourceTrusteeContributionState = {
    readonly sourceTrusteeIdentity: string;
    readonly sourceTrusteeRosterPosition: number;
    readonly sourceTrusteeCommitmentRoot: ProtocolHash;
    readonly sourceTrusteeCoefficientCommitmentRecord: unknown;
    readonly sourceTrusteeCoefficientCommitmentMaterialRecords: readonly unknown[];
    readonly coefficientOpenings: readonly PrivateVssCoefficientOpeningState[];
};

type PrivateVssMailboxRecipient = {
    readonly recipientIdentity: string;
    readonly recipientRosterPosition: number;
    readonly mailboxPublicKeyBytesHex: string;
};

type PrivateVssMailboxDeliveryKernel = {
    readonly deriveCanonicalObjectHash: (input: {
        readonly value: unknown;
    }) => ProtocolHash;
    readonly generatePrivateVssShareProof: (input: {
        readonly setupContext: unknown;
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly privateEnvelopeAadHash: ProtocolHash;
        readonly sourceTrusteeCoefficientCommitmentRecord: unknown;
        readonly sourceTrusteeCoefficientCommitmentMaterialRecords: readonly unknown[];
        readonly recipientIdentity: string;
        readonly recipientRosterPosition: number;
        readonly rnsLimbIndex: number;
        readonly rnsPrime: number;
        readonly ringDegree: number;
        readonly shareValues: readonly number[];
        readonly coefficientCommitmentRoots: readonly ProtocolHash[];
        readonly coefficientMessagesByShamirIndex: readonly (readonly number[])[];
        readonly openingRandomnessByShamirIndex: readonly (readonly (readonly number[])[])[];
        readonly proofRandomnessSeedHex: string;
        readonly proofRandomnessNonceHex: string;
    }) => {
        readonly privateVssShareProof: JsonRecord;
    };
    readonly exportCanonicalProofMaterial: (input: {
        readonly proofFamily: typeof privateVssShareProofFamily;
        readonly proofMaterialRoot: ProtocolHash;
    }) => Promise<CanonicalGeneratedSetupProofMaterial>;
    readonly verifyPrivateVssShareEnvelope: (input: {
        readonly setupContext: unknown;
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly sourceTrusteeCoefficientCommitmentRecord: unknown;
        readonly sourceTrusteeCoefficientCommitmentMaterialRecords: readonly unknown[];
        readonly privateEnvelope: unknown;
        readonly transportedPrivateVssShareProofMaterial?: unknown;
        readonly expectedPrivateEnvelopeHash?: ProtocolHash;
        readonly expectedLocalVerificationRoot?: ProtocolHash;
    }) => {
        readonly isValid: boolean;
        readonly privateEnvelopeHash: ProtocolHash | null;
        readonly localVerificationRoot: ProtocolHash | null;
        readonly refusedObjects: readonly {
            readonly reasonCode: string;
            readonly message: string;
            readonly objectPath?: string;
        }[];
    };
};

type PrivateVssMailboxDeliverySetInput = {
    readonly kernel: PrivateVssMailboxDeliveryKernel;
    readonly setupContext: PrivateVssSetupContext;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly vssCoefficientCommitmentRoot: ProtocolHash;
    readonly qSharePrimes: readonly number[];
    readonly ringDegree: number;
    readonly participantCount: number;
    readonly sourceTrusteeContributionStates: readonly PrivateVssSourceTrusteeContributionState[];
    readonly recipients: readonly PrivateVssMailboxRecipient[];
};

type PrivateVssMailboxSourceTrusteeDeliveryInput = Omit<
    PrivateVssMailboxDeliverySetInput,
    'sourceTrusteeContributionStates'
> & {
    readonly sourceTrusteeContributionState: PrivateVssSourceTrusteeContributionState;
};

type PrivateVssMailboxDeliveryContext = Omit<
    PrivateVssMailboxDeliverySetInput,
    'sourceTrusteeContributionStates' | 'recipients'
>;

const privateVssEnvelopeCommitmentRootInput = (
    envelopeReference: JsonRecord,
): JsonRecord => {
    const {
        encryptedEnvelope: encryptedEnvelopeForRecipientTransport,
        transportedPrivateVssShareProofMaterial:
            transportedPrivateVssShareProofMaterialForRecipientTransport,
        ...rootInput
    } = envelopeReference;
    void encryptedEnvelopeForRecipientTransport;
    void transportedPrivateVssShareProofMaterialForRecipientTransport;

    return rootInput;
};

const privateVssEnvelopeCommitmentSetRootInput = (
    commitmentSet: JsonRecord,
): JsonRecord => ({
    ...commitmentSet,
    envelopeReferences: (commitmentSet.envelopeReferences as JsonRecord[]).map(
        privateVssEnvelopeCommitmentRootInput,
    ),
});

type PrivateVssMailboxDeliverySet = Readonly<
    JsonRecord & {
        readonly objectType: 'PrivateVssEnvelopeCommitmentSet';
        readonly privateVssEnvelopeCommitmentRoot: ProtocolHash;
        readonly envelopeReferences: readonly PrivateVssEnvelopeCommitment[];
    }
>;

export type PrivateVssEnvelopeCommitment = Readonly<
    JsonRecord & {
        readonly objectType: 'PrivateVssEnvelopeCommitment';
        readonly sourceTrusteeIdentity: string;
        readonly sourceTrusteeRosterPosition: number;
        readonly recipientIdentity: string;
        readonly recipientRosterPosition: number;
        readonly privateEnvelopeHash: ProtocolHash;
        readonly encryptedEnvelopeHash: ProtocolHash;
        readonly encryptedEnvelope?: PrivateVssEncryptedEnvelope;
        readonly localVerificationRoot: ProtocolHash;
        readonly transportedPrivateVssShareProofMaterial?: TransportedPrivateVssShareProofMaterialSet;
        readonly privateEnvelopeCommitmentRoot: ProtocolHash;
    }
>;

type PrivateVssMailboxDeliverySetFromReferencesInput = Pick<
    PrivateVssMailboxDeliverySetInput,
    | 'kernel'
    | 'setupContext'
    | 'publicMatrixSeedHash'
    | 'vssCoefficientCommitmentRoot'
    | 'participantCount'
> & {
    readonly envelopeReferences: readonly PrivateVssEnvelopeCommitment[];
};

type TransportedPrivateVssShareProofMaterial = Readonly<
    JsonRecord & {
        readonly objectType: 'SetupTransportedPrivateVssShareProofMaterial';
        readonly proofMaterialRoot: ProtocolHash;
        readonly descriptorBytes: Uint8Array;
    }
>;

type TransportedPrivateVssShareProofMaterialSet = Readonly<
    JsonRecord & {
        readonly objectType: 'SetupTransportedPrivateVssShareProofMaterialSet';
        readonly proofMaterials: readonly TransportedPrivateVssShareProofMaterial[];
    }
>;

const privateEnvelopeAadObjectType = 'PrivateVssEnvelopeAad';
const privateVssShareProofFamily = 'vss-opening-carry';
const proofRandomnessByteLength = 64;

const defaultProofRandomBytes = (byteLength: number): Uint8Array => {
    const cryptoProvider = globalThis.crypto;
    if (cryptoProvider === undefined) {
        throw new Error(
            'Private VSS share proof generation requires Web Crypto getRandomValues.',
        );
    }
    const bytes = new Uint8Array(byteLength);
    cryptoProvider.getRandomValues(bytes);

    return bytes;
};

const freshProofRandomnessHex = (): string => {
    const bytes = defaultProofRandomBytes(proofRandomnessByteLength);
    if (bytes.byteLength !== proofRandomnessByteLength) {
        throw new Error(
            'proof randomness byte source must return exactly 64 bytes.',
        );
    }

    return bytesToHex(bytes);
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
        assertNonNegativeSafeInteger(
            position,
            `${entryLabel} roster position`,
        );
        if (seenRosterPositions.has(position)) {
            throw new Error(`${entryLabel} roster positions must be distinct.`);
        }
        seenRosterPositions.add(position);
    }

    return sortedEntries;
};

const sortedBySourceTrusteeThenRecipient = (
    envelopeReferences: readonly PrivateVssEnvelopeCommitment[],
): PrivateVssEnvelopeCommitment[] =>
    [...envelopeReferences].sort((left, right) => {
        const sourceOrder =
            assertNonNegativeSafeInteger(
                left.sourceTrusteeRosterPosition,
                'private VSS envelope reference source trustee roster position',
            ) -
            assertNonNegativeSafeInteger(
                right.sourceTrusteeRosterPosition,
                'private VSS envelope reference source trustee roster position',
            );

        return sourceOrder === 0
            ? assertNonNegativeSafeInteger(
                  left.recipientRosterPosition,
                  'private VSS envelope reference recipient roster position',
              ) -
                  assertNonNegativeSafeInteger(
                      right.recipientRosterPosition,
                      'private VSS envelope reference recipient roster position',
                  )
            : sourceOrder;
    });

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

const assertFullEnvelopeReferenceCoverage = (
    envelopeReferences: readonly PrivateVssEnvelopeCommitment[],
    participantCount: number,
): void => {
    if (envelopeReferences.length !== participantCount * participantCount) {
        throw new Error(
            'private VSS envelope reference count must match the accepted participant square.',
        );
    }
    const observedPairs = new Set<string>();
    envelopeReferences.forEach((envelopeReference, envelopeReferenceIndex) => {
        const sourceTrusteeRosterPosition = assertNonNegativeSafeInteger(
            envelopeReference.sourceTrusteeRosterPosition,
            `private VSS envelope reference ${String(envelopeReferenceIndex)} source trustee roster position`,
        );
        const recipientRosterPosition = assertNonNegativeSafeInteger(
            envelopeReference.recipientRosterPosition,
            `private VSS envelope reference ${String(envelopeReferenceIndex)} recipient roster position`,
        );
        assertNonNegativeSafeInteger(
            sourceTrusteeRosterPosition,
            `private VSS envelope reference ${String(envelopeReferenceIndex)} source trustee roster position`,
        );
        assertNonNegativeSafeInteger(
            recipientRosterPosition,
            `private VSS envelope reference ${String(envelopeReferenceIndex)} recipient roster position`,
        );
        if (
            sourceTrusteeRosterPosition >= participantCount ||
            recipientRosterPosition >= participantCount
        ) {
            throw new Error(
                'private VSS envelope reference roster positions must be inside the accepted participant count.',
            );
        }
        const pairKey = `${String(sourceTrusteeRosterPosition)}:${String(
            recipientRosterPosition,
        )}`;
        if (observedPairs.has(pairKey)) {
            throw new Error(
                'private VSS envelope references must have distinct source-recipient pairs.',
            );
        }
        observedPairs.add(pairKey);
    });

    for (
        let sourceTrusteeRosterPosition = 0;
        sourceTrusteeRosterPosition < participantCount;
        sourceTrusteeRosterPosition += 1
    ) {
        for (
            let recipientRosterPosition = 0;
            recipientRosterPosition < participantCount;
            recipientRosterPosition += 1
        ) {
            if (
                !observedPairs.has(
                    `${String(sourceTrusteeRosterPosition)}:${String(
                        recipientRosterPosition,
                    )}`,
                )
            ) {
                throw new Error(
                    'private VSS envelope references must cover every source-recipient pair.',
                );
            }
        }
    }
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
    sourceTrusteeState: PrivateVssSourceTrusteeContributionState,
    recipient: PrivateVssMailboxRecipient,
): JsonRecord => ({
    objectType: privateEnvelopeAadObjectType,
    ceremonyId: input.setupContext.ceremonyId,
    manifestHash: input.setupContext.manifestHash,
    rosterHash: input.setupContext.rosterHash,
    setupParametersHash: input.setupContext.setupParametersHash,
    setupEpoch: input.setupContext.setupEpoch,
    publicMatrixSeedHash: input.publicMatrixSeedHash,
    vssCoefficientCommitmentRoot: input.vssCoefficientCommitmentRoot,
    sourceTrusteeIdentity: sourceTrusteeState.sourceTrusteeIdentity,
    sourceTrusteeRosterPosition: sourceTrusteeState.sourceTrusteeRosterPosition,
    recipientIdentity: recipient.recipientIdentity,
    recipientRosterPosition: recipient.recipientRosterPosition,
    sourceTrusteeCommitmentRoot: sourceTrusteeState.sourceTrusteeCommitmentRoot,
});

const transportPrivateVssShareProofMaterial = (
    kernel: PrivateVssMailboxDeliveryKernel,
    proofRecord: JsonRecord,
    canonicalMaterial: CanonicalGeneratedSetupProofMaterial,
): {
    readonly proofRecord: JsonRecord;
    readonly proofMaterial: TransportedPrivateVssShareProofMaterial;
} => {
    const proofBytesHash = assertProtocolHash(
        proofRecord.proofBytesHash,
        'privateVssShareProof.proofBytesHash',
    );
    const statementHash = assertProtocolHash(
        proofRecord.statementHash,
        'privateVssShareProof.statementHash',
    );
    const expectedProofMaterialRoot = kernel.deriveCanonicalObjectHash({
        value: {
            objectType: 'PrivateVssShareTransportedSuccinctProofMaterial',
            statementHash,
            proofBytesHash,
        },
    });
    const proofMaterialRoot = assertProtocolHash(
        proofRecord.proofMaterialRoot,
        'privateVssShareProof.proofMaterialRoot',
    );
    if (proofMaterialRoot !== expectedProofMaterialRoot) {
        throw new Error(
            'privateVssShareProof.proofMaterialRoot must match its semantic proof reference.',
        );
    }
    const transportedProofRecord = {
        ...proofRecord,
        proofMaterialRoot,
    };

    return {
        proofRecord: transportedProofRecord,
        proofMaterial: {
            objectType: 'SetupTransportedPrivateVssShareProofMaterial',
            proofMaterialRoot,
            descriptorBytes: copyCanonicalStreamDescriptor(
                canonicalMaterial.descriptorBytes,
                'canonical generated proof material descriptorBytes',
            ),
        },
    };
};

type PrivateVssShareEnvelopeBuild = Readonly<{
    readonly privateEnvelope: JsonRecord;
    readonly transportedPrivateVssShareProofMaterial?: TransportedPrivateVssShareProofMaterialSet;
}>;

const privateEnvelope = async (
    input: PrivateVssMailboxDeliveryContext,
    sourceTrusteeState: PrivateVssSourceTrusteeContributionState,
    recipient: PrivateVssMailboxRecipient,
    privateEnvelopeAadHash: ProtocolHash,
): Promise<PrivateVssShareEnvelopeBuild> => {
    const transportedProofMaterials: TransportedPrivateVssShareProofMaterial[] =
        [];
    const rnsShareOpenings: JsonRecord[] = [];
    for (
        let rnsLimbIndex = 0;
        rnsLimbIndex < input.qSharePrimes.length;
        rnsLimbIndex += 1
    ) {
        const rnsPrime = input.qSharePrimes[rnsLimbIndex];
        if (rnsPrime === undefined) {
            throw new Error('Q_share prime schedule is incomplete.');
        }
        const coefficientOpenings = sourceTrusteeState.coefficientOpenings
            .filter(
                (opening) =>
                    opening.rnsLimbIndex === rnsLimbIndex &&
                    opening.rnsPrime === rnsPrime,
            )
            .sort(
                (left, right) =>
                    left.shamirCoefficientIndex - right.shamirCoefficientIndex,
            );
        if (coefficientOpenings.length === 0) {
            throw new Error(
                'Source trustee local VSS state must contain every Q_share limb.',
            );
        }
        const coefficientMessagesByShamirIndex = coefficientOpenings.map(
            (opening) => {
                if (opening.coefficientMessage.length !== input.ringDegree) {
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
        const generatedProof = input.kernel.generatePrivateVssShareProof({
            setupContext: input.setupContext,
            publicMatrixSeedHash: input.publicMatrixSeedHash,
            privateEnvelopeAadHash,
            sourceTrusteeCoefficientCommitmentRecord:
                sourceTrusteeState.sourceTrusteeCoefficientCommitmentRecord,
            sourceTrusteeCoefficientCommitmentMaterialRecords:
                sourceTrusteeState.sourceTrusteeCoefficientCommitmentMaterialRecords,
            recipientIdentity: recipient.recipientIdentity,
            recipientRosterPosition: recipient.recipientRosterPosition,
            rnsLimbIndex,
            rnsPrime,
            ringDegree: input.ringDegree,
            shareValues,
            coefficientCommitmentRoots,
            coefficientMessagesByShamirIndex,
            openingRandomnessByShamirIndex: coefficientOpenings.map(
                (opening) => opening.randomnessByColumn,
            ),
            proofRandomnessSeedHex: freshProofRandomnessHex(),
            proofRandomnessNonceHex: freshProofRandomnessHex(),
        });
        const proofRecord = generatedProof.privateVssShareProof;
        const proofMaterialRoot = assertProtocolHash(
            proofRecord.proofMaterialRoot,
            'privateVssShareProof.proofMaterialRoot',
        );
        const canonicalMaterial =
            await input.kernel.exportCanonicalProofMaterial({
                proofFamily: privateVssShareProofFamily,
                proofMaterialRoot,
            });
        const transportedProof = transportPrivateVssShareProofMaterial(
            input.kernel,
            proofRecord,
            canonicalMaterial,
        );
        transportedProofMaterials.push(transportedProof.proofMaterial);
        const privateVssShareProof = transportedProof.proofRecord;

        rnsShareOpenings.push({
            objectType: 'PrivateVssShareLimbOpening',
            rnsLimbIndex,
            rnsPrime,
            shareValues,
            coefficientCommitmentRoots,
            privateVssShareProof,
        });
    }

    const privateShareEnvelope = {
        objectType: 'PrivateVssShareEnvelope',
        ceremonyId: input.setupContext.ceremonyId,
        manifestHash: input.setupContext.manifestHash,
        rosterHash: input.setupContext.rosterHash,
        setupParametersHash: input.setupContext.setupParametersHash,
        setupEpoch: input.setupContext.setupEpoch,
        publicMatrixSeedHash: input.publicMatrixSeedHash,
        privateEnvelopeAadHash,
        sourceTrusteeIdentity: sourceTrusteeState.sourceTrusteeIdentity,
        sourceTrusteeRosterPosition:
            sourceTrusteeState.sourceTrusteeRosterPosition,
        recipientIdentity: recipient.recipientIdentity,
        recipientRosterPosition: recipient.recipientRosterPosition,
        sourceTrusteeCommitmentRoot:
            sourceTrusteeState.sourceTrusteeCommitmentRoot,
        rnsShareOpenings,
    };

    if (transportedProofMaterials.length === 0) {
        return { privateEnvelope: privateShareEnvelope };
    }

    return {
        privateEnvelope: privateShareEnvelope,
        transportedPrivateVssShareProofMaterial: {
            objectType: 'SetupTransportedPrivateVssShareProofMaterialSet',
            proofMaterials: transportedProofMaterials,
        },
    };
};

const createEnvelopeCommitment = async (
    input: PrivateVssMailboxDeliveryContext,
    sourceTrusteeState: PrivateVssSourceTrusteeContributionState,
    recipient: PrivateVssMailboxRecipient,
): Promise<PrivateVssEnvelopeCommitment> => {
    const associatedData = privateEnvelopeAad(
        input,
        sourceTrusteeState,
        recipient,
    );
    const associatedDataHash = input.kernel.deriveCanonicalObjectHash({
        value: associatedData,
    });
    const privateShareEnvelopeBuild = await privateEnvelope(
        input,
        sourceTrusteeState,
        recipient,
        associatedDataHash,
    );
    const localVerification = input.kernel.verifyPrivateVssShareEnvelope({
        setupContext: input.setupContext,
        publicMatrixSeedHash: input.publicMatrixSeedHash,
        sourceTrusteeCoefficientCommitmentRecord:
            sourceTrusteeState.sourceTrusteeCoefficientCommitmentRecord,
        sourceTrusteeCoefficientCommitmentMaterialRecords:
            sourceTrusteeState.sourceTrusteeCoefficientCommitmentMaterialRecords,
        privateEnvelope: privateShareEnvelopeBuild.privateEnvelope,
        ...(privateShareEnvelopeBuild.transportedPrivateVssShareProofMaterial ===
        undefined
            ? {}
            : {
                  transportedPrivateVssShareProofMaterial:
                      setupProofMaterialReferenceSetForVerificationInput(
                          privateShareEnvelopeBuild.transportedPrivateVssShareProofMaterial,
                      ),
              }),
    });
    if (
        !localVerification.isValid ||
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
        privateEnvelope: privateShareEnvelopeBuild.privateEnvelope,
        privateEnvelopeAad: associatedData,
        recipientMailboxPublicKeyBytesHex: recipient.mailboxPublicKeyBytesHex,
    });
    const commitmentWithoutRoot = {
        objectType: 'PrivateVssEnvelopeCommitment',
        sourceTrusteeIdentity: sourceTrusteeState.sourceTrusteeIdentity,
        sourceTrusteeRosterPosition:
            sourceTrusteeState.sourceTrusteeRosterPosition,
        recipientIdentity: recipient.recipientIdentity,
        recipientRosterPosition: recipient.recipientRosterPosition,
        privateEnvelopeHash: localVerification.privateEnvelopeHash,
        encryptedEnvelopeHash: encryptedDelivery.encryptedEnvelopeHash,
        encryptedEnvelope: encryptedDelivery.encryptedEnvelope,
        localVerificationRoot: localVerification.localVerificationRoot,
        ...(privateShareEnvelopeBuild.transportedPrivateVssShareProofMaterial ===
        undefined
            ? {}
            : {
                  transportedPrivateVssShareProofMaterial:
                      privateShareEnvelopeBuild.transportedPrivateVssShareProofMaterial,
              }),
    } as const satisfies JsonRecord;

    return {
        ...commitmentWithoutRoot,
        privateEnvelopeCommitmentRoot: input.kernel.deriveCanonicalObjectHash({
            value: privateVssEnvelopeCommitmentRootInput(commitmentWithoutRoot),
        }),
    } satisfies PrivateVssEnvelopeCommitment;
};

const createPrivateVssMailboxSourceTrusteeDeliveryReferences = async (
    input: PrivateVssMailboxSourceTrusteeDeliveryInput,
): Promise<readonly PrivateVssEnvelopeCommitment[]> => {
    assertPositiveSafeInteger(input.participantCount, 'participantCount');
    assertPositiveSafeInteger(input.ringDegree, 'ringDegree');
    assertNonNegativeSafeInteger(
        input.sourceTrusteeContributionState.sourceTrusteeRosterPosition,
        'source trustee contribution state roster position',
    );
    if (
        input.sourceTrusteeContributionState.sourceTrusteeRosterPosition >=
        input.participantCount
    ) {
        throw new Error(
            'source trustee contribution state roster position must be inside the accepted participant count.',
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

    const envelopeReferences: PrivateVssEnvelopeCommitment[] = [];
    for (const recipient of recipients) {
        envelopeReferences.push(
            await createEnvelopeCommitment(
                input,
                input.sourceTrusteeContributionState,
                recipient,
            ),
        );
    }

    return envelopeReferences;
};

const createPrivateVssMailboxDeliverySetFromReferences = (
    input: PrivateVssMailboxDeliverySetFromReferencesInput,
): PrivateVssMailboxDeliverySet => {
    assertPositiveSafeInteger(input.participantCount, 'participantCount');
    const envelopeReferences = sortedBySourceTrusteeThenRecipient(
        input.envelopeReferences,
    );
    assertFullEnvelopeReferenceCoverage(
        envelopeReferences,
        input.participantCount,
    );

    const commitmentSetWithoutRoot = {
        objectType: 'PrivateVssEnvelopeCommitmentSet',
        ceremonyId: input.setupContext.ceremonyId,
        manifestHash: input.setupContext.manifestHash,
        rosterHash: input.setupContext.rosterHash,
        setupParametersHash: input.setupContext.setupParametersHash,
        setupEpoch: input.setupContext.setupEpoch,
        publicMatrixSeedHash: input.publicMatrixSeedHash,
        vssCoefficientCommitmentRoot: input.vssCoefficientCommitmentRoot,
        envelopeReferences,
    } as const satisfies JsonRecord;

    return {
        ...commitmentSetWithoutRoot,
        privateVssEnvelopeCommitmentRoot:
            input.kernel.deriveCanonicalObjectHash({
                value: privateVssEnvelopeCommitmentSetRootInput(
                    commitmentSetWithoutRoot,
                ),
            }),
    } satisfies PrivateVssMailboxDeliverySet;
};

export const createPrivateVssMailboxDeliverySet = async (
    input: PrivateVssMailboxDeliverySetInput,
): Promise<PrivateVssMailboxDeliverySet> => {
    assertPositiveSafeInteger(input.participantCount, 'participantCount');
    assertPositiveSafeInteger(input.ringDegree, 'ringDegree');
    const sourceTrusteeStates = sortedByRosterPosition(
        input.sourceTrusteeContributionStates,
        (sourceTrusteeState) => sourceTrusteeState.sourceTrusteeRosterPosition,
        'source trustee contribution state',
    );
    const recipients = sortedByRosterPosition(
        input.recipients,
        (recipient) => recipient.recipientRosterPosition,
        'mailbox recipient',
    );
    assertFullRosterPositions(
        sourceTrusteeStates.map(
            (sourceTrusteeState) =>
                sourceTrusteeState.sourceTrusteeRosterPosition,
        ),
        input.participantCount,
        'source trustee contribution state',
    );
    assertFullRosterPositions(
        recipients.map((recipient) => recipient.recipientRosterPosition),
        input.participantCount,
        'mailbox recipient',
    );

    const envelopeReferences: PrivateVssEnvelopeCommitment[] = [];
    for (const sourceTrusteeContributionState of sourceTrusteeStates) {
        envelopeReferences.push(
            ...(await createPrivateVssMailboxSourceTrusteeDeliveryReferences({
                ...input,
                sourceTrusteeContributionState,
                recipients,
            })),
        );
    }

    return createPrivateVssMailboxDeliverySetFromReferences({
        kernel: input.kernel,
        setupContext: input.setupContext,
        publicMatrixSeedHash: input.publicMatrixSeedHash,
        vssCoefficientCommitmentRoot: input.vssCoefficientCommitmentRoot,
        participantCount: input.participantCount,
        envelopeReferences,
    });
};
