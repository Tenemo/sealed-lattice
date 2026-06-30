import {
    aggregateCompactVssThresholdShareCommitments,
    createCompactVssCoefficientCommitmentSet,
    createCompactVssRecipientShareCommitmentBundle,
    createCompactVssShareLinkageProofMaterialSet,
    createCompactVssShareLinkageStatement,
    type CompactVssAggregateThresholdCommitmentSet,
    type CompactVssCoefficientCommitmentSet,
    type CompactVssRecipientShareCommitmentSet,
    type CompactVssShareLinkageProofMaterialSet,
    type CompactVssShareLinkageProofStatement,
    type CompactVssShareLinkageProofStatementItem,
    type CompactVssShareLinkageStatement,
} from "#packages/protocol/src/setup/compact-vss-commitments";
import {
    createCompactVssSameSecretBridgeProofMaterialSet,
    createCompactVssSameSecretBridgeStatementSet,
    type CompactVssSameSecretBridgeProofMaterialSet,
    type CompactVssSameSecretBridgeStatementSet,
    type SameSecretConsistencyStatementSet,
    type SameSecretProofSet,
} from "#packages/protocol/src/setup/same-secret-consistency-records";
import {
    acceptedBgvProfileRingDegree,
    type VssCoefficientCommitmentBundle,
    type VssCoefficientOpeningInput,
    type VssSourceTrusteeCoefficientOpeningState,
} from "#packages/protocol/src/setup/vss-coefficient-commitments";
import type { CollectiveBgvSetupContext } from "#packages/protocol/src/setup/vss-share-verification-records";
import type {
    BgvCollectiveSetupProfileDescription,
    BgvCompactSameSecretBridgeProofStatement,
    TranscriptCoreKernel,
} from "#packages/wasm/src/index";
import { hash512Hex } from "#packages/crypto/src/index";

import {
    deterministicRandomBytes,
    firstProfileDecryptionThreshold,
    firstProfileParticipantCount,
    minimumSuccinctProofFixtureRingDegree,
    textEncoder,
    type JsonRecord,
} from "../setup-fixture-primitives.js";

export type AcceptedCompactVssMaterial = Readonly<{
    readonly compactVssCoefficientCommitmentSet: CompactVssCoefficientCommitmentSet;
    readonly compactVssRecipientShareCommitmentSet: CompactVssRecipientShareCommitmentSet;
    readonly compactVssAggregateThresholdCommitmentSet: CompactVssAggregateThresholdCommitmentSet;
    readonly compactVssShareLinkageStatement: CompactVssShareLinkageStatement;
    readonly compactVssShareLinkageProofMaterialSet: CompactVssShareLinkageProofMaterialSet;
    readonly compactSameSecretBridgeStatementSet: CompactVssSameSecretBridgeStatementSet;
    readonly compactSameSecretBridgeProofMaterialSet: CompactVssSameSecretBridgeProofMaterialSet;
}>;

type CompactCoefficientRandomnessInput = Readonly<{
    readonly trusteeIdentity: string;
    readonly trusteeRosterPosition: number;
    readonly rnsLimbIndex: number;
    readonly rnsPrime: number;
    readonly shamirCoefficientIndex: number;
    readonly ringDegree: number;
}>;

const requiredArrayValue = <ValueType>(
    values: readonly ValueType[],
    index: number,
    message: string,
): ValueType => {
    const value = values[index];
    if (value === undefined) {
        throw new Error(message);
    }

    return value;
};

const compactCoefficientOpeningRandomness = (
    input: CompactCoefficientRandomnessInput,
): readonly (readonly number[])[] => {
    const randomBytes = deterministicRandomBytes(
        [
            "compact-vss-coefficient",
            input.trusteeIdentity,
            String(input.trusteeRosterPosition),
            String(input.rnsLimbIndex),
            String(input.rnsPrime),
            String(input.shamirCoefficientIndex),
        ].join(":"),
    );

    return Array.from({ length: 2 }, () =>
        Array.from(
            { length: input.ringDegree },
            () => ((randomBytes(1)[0] ?? 0) % 3) - 1,
        ),
    );
};

const compactProofHash = (domain: string, value: string): string =>
    hash512Hex(domain, [textEncoder.encode(value)]);

const sourceTrusteeOpeningStatesFromBundle = (
    vssCoefficientCommitmentBundle: VssCoefficientCommitmentBundle,
): readonly VssSourceTrusteeCoefficientOpeningState[] =>
    vssCoefficientCommitmentBundle.privateOpeningMaterialBySourceTrustee.map(
        (sourceOpeningMaterial) => ({
            sourceTrusteeIdentity: sourceOpeningMaterial.sourceTrusteeIdentity,
            sourceTrusteeRosterPosition:
                sourceOpeningMaterial.sourceTrusteeRosterPosition,
            coefficientOpenings: sourceOpeningMaterial.coefficientOpenings.map(
                (coefficientOpening) => ({
                    rnsLimbIndex: coefficientOpening.rnsLimbIndex,
                    rnsPrime: coefficientOpening.rnsPrime,
                    shamirCoefficientIndex:
                        coefficientOpening.shamirCoefficientIndex,
                    coefficientMessage: coefficientOpening.coefficientMessage,
                    randomnessByColumn: coefficientOpening.randomnessByColumn,
                }),
            ),
        }),
    );

const coefficientOpeningByCoordinate = (
    sourceTrusteeOpeningState: VssSourceTrusteeCoefficientOpeningState,
): ReadonlyMap<string, VssCoefficientOpeningInput> =>
    new Map(
        sourceTrusteeOpeningState.coefficientOpenings.map(
            (coefficientOpening) => [
                [
                    coefficientOpening.rnsLimbIndex,
                    coefficientOpening.shamirCoefficientIndex,
                ].join(":"),
                coefficientOpening,
            ],
        ),
    );

const requiredCoefficientOpening = (
    openingsByCoordinate: ReadonlyMap<string, VssCoefficientOpeningInput>,
    rnsLimbIndex: number,
    shamirCoefficientIndex: number,
): VssCoefficientOpeningInput => {
    const coefficientOpening = openingsByCoordinate.get(
        [rnsLimbIndex, shamirCoefficientIndex].join(":"),
    );
    if (coefficientOpening === undefined) {
        throw new Error(
            "compact VSS fixture is missing a coefficient opening.",
        );
    }

    return coefficientOpening;
};

const targetRnsPrimesFromProfile = (
    profile: BgvCollectiveSetupProfileDescription,
): readonly number[] => {
    const targetPrimes = profile.canonicalTargetBasis.targetPrimes;
    if (targetPrimes.length === 0) {
        throw new Error("canonical target basis must contain target primes.");
    }

    return targetPrimes.map((targetPrime, targetPrimeIndex) => {
        if (!Number.isSafeInteger(targetPrime) || targetPrime <= 0) {
            throw new Error(
                `canonicalTargetBasis.targetPrimes.${String(targetPrimeIndex)} must be a positive safe integer.`,
            );
        }

        return targetPrime;
    });
};

const acceptedSetupTrusteeReferences = (): readonly {
    readonly trusteeIdentity: string;
    readonly trusteeRosterPosition: number;
}[] =>
    Array.from(
        { length: firstProfileParticipantCount },
        (_unusedTrustee, trusteeRosterPosition) => ({
            trusteeIdentity: `trustee-${String(trusteeRosterPosition)}`,
            trusteeRosterPosition,
        }),
    );

const centeredTernaryFromResidue = (
    residue: number,
    rnsPrime: number,
): number => {
    const centeredValue =
        residue > Math.floor(rnsPrime / 2) ? residue - rnsPrime : residue;
    if (centeredValue !== -1 && centeredValue !== 0 && centeredValue !== 1) {
        throw new Error(
            "same-secret compact bridge witness must be centered ternary.",
        );
    }

    return centeredValue;
};

const shareLinkageItem = (input: {
    readonly coefficientCommitmentSet: CompactVssCoefficientCommitmentSet;
    readonly recipientShareCommitmentSet: CompactVssRecipientShareCommitmentSet;
    readonly recipientShareOpeningCredentialsByCoordinate: ReadonlyMap<
        string,
        {
            readonly shareValues: readonly number[];
            readonly shareCommitmentMessageCarryValues: readonly number[];
            readonly randomnessByColumn: readonly (readonly number[])[];
            readonly shareCommitmentRoot: string;
            readonly shareOpeningRoot: string;
        }
    >;
    readonly sourceTrusteeRosterPosition: number;
    readonly recipientRosterPosition: number;
    readonly rnsLimbIndex: number;
}): {
    readonly item: CompactVssShareLinkageProofStatementItem;
    readonly recipientShareMessages: readonly number[];
    readonly recipientShareOpeningRandomness: readonly (readonly number[])[];
    readonly carryWitnesses: readonly number[];
} => {
    const coefficientSourceRecord = requiredArrayValue(
        input.coefficientCommitmentSet.sourceTrusteeRecords,
        input.sourceTrusteeRosterPosition,
        "compact VSS coefficient source record is missing.",
    );
    const recipientSourceRecord = requiredArrayValue(
        input.recipientShareCommitmentSet.sourceTrusteeRecords,
        input.sourceTrusteeRosterPosition,
        "compact VSS recipient source record is missing.",
    );
    const recipientRecordIndex =
        input.recipientRosterPosition *
            input.recipientShareCommitmentSet.rnsLimbCount +
        input.rnsLimbIndex;
    const recipientShareRecord = requiredArrayValue(
        recipientSourceRecord.recipientShareCommitments,
        recipientRecordIndex,
        "compact VSS recipient share record is missing.",
    );
    const coefficientCommitmentOffset =
        input.rnsLimbIndex * input.coefficientCommitmentSet.thresholdDegree;
    const coefficientCommitmentRecords = Array.from(
        { length: input.coefficientCommitmentSet.thresholdDegree },
        (_unusedCoefficient, shamirCoefficientIndex) =>
            requiredArrayValue(
                coefficientSourceRecord.coefficientCommitments,
                coefficientCommitmentOffset + shamirCoefficientIndex,
                "compact VSS coefficient commitment record is missing.",
            ),
    );
    const credential = input.recipientShareOpeningCredentialsByCoordinate.get(
        [
            input.sourceTrusteeRosterPosition,
            input.recipientRosterPosition,
            input.rnsLimbIndex,
        ].join(":"),
    );
    if (credential === undefined) {
        throw new Error(
            "compact VSS recipient share opening credential is missing.",
        );
    }

    return {
        item: {
            sourceTrusteeIdentity:
                coefficientSourceRecord.sourceTrusteeIdentity,
            sourceTrusteeRosterPosition:
                coefficientSourceRecord.sourceTrusteeRosterPosition,
            sourceCoefficientCommitmentRoot:
                coefficientSourceRecord.sourceCoefficientCommitmentRoot,
            sourceRecipientShareCommitmentRoot:
                recipientSourceRecord.sourceRecipientShareCommitmentRoot,
            recipientIdentity: recipientShareRecord.recipientIdentity,
            recipientRosterPosition:
                recipientShareRecord.recipientRosterPosition,
            sourceRnsLimbIndex: input.rnsLimbIndex,
            sourceMessageModulus: recipientShareRecord.rnsPrime,
            coefficientCommitmentRoots: coefficientCommitmentRecords.map(
                (coefficientCommitment) =>
                    coefficientCommitment.coefficientCommitmentRoot,
            ),
            coefficientOpeningRoots: coefficientCommitmentRecords.map(
                (coefficientCommitment) =>
                    coefficientCommitment.coefficientOpeningRoot,
            ),
            coefficientCommitments: coefficientCommitmentRecords.map(
                (coefficientCommitment) => coefficientCommitment.commitment,
            ),
            recipientShareCommitmentRoot:
                recipientShareRecord.shareCommitmentRoot,
            recipientShareOpeningRoot: recipientShareRecord.shareOpeningRoot,
            recipientShareCommitment: recipientShareRecord.commitment,
        },
        recipientShareMessages: credential.shareValues,
        recipientShareOpeningRandomness: credential.randomnessByColumn,
        carryWitnesses: credential.shareCommitmentMessageCarryValues,
    };
};

const shareLinkageProofRecordInputs = (input: {
    readonly kernel: TranscriptCoreKernel;
    readonly setupContext: CollectiveBgvSetupContext;
    readonly statement: CompactVssShareLinkageStatement;
    readonly coefficientCommitmentSet: CompactVssCoefficientCommitmentSet;
    readonly recipientShareCommitmentSet: CompactVssRecipientShareCommitmentSet;
    readonly recipientShareOpeningCredentialsByCoordinate: ReadonlyMap<
        string,
        {
            readonly shareValues: readonly number[];
            readonly shareCommitmentMessageCarryValues: readonly number[];
            readonly randomnessByColumn: readonly (readonly number[])[];
            readonly shareCommitmentRoot: string;
            readonly shareOpeningRoot: string;
        }
    >;
    readonly sourceTrusteeOpeningStates: readonly VssSourceTrusteeCoefficientOpeningState[];
}): readonly {
    readonly compactVssShareLinkage: CompactVssShareLinkageProofStatement;
    readonly proofBytesHex: string;
}[] => {
    const sourceTrusteeOpeningStates = [
        ...input.sourceTrusteeOpeningStates,
    ].sort(
        (leftState, rightState) =>
            leftState.sourceTrusteeRosterPosition -
            rightState.sourceTrusteeRosterPosition,
    );
    const sourceTrusteeOpeningStateByPosition = new Map(
        sourceTrusteeOpeningStates.map((sourceTrusteeOpeningState) => [
            sourceTrusteeOpeningState.sourceTrusteeRosterPosition,
            sourceTrusteeOpeningState,
        ]),
    );
    const coefficientOpeningsByPosition = new Map(
        sourceTrusteeOpeningStates.map((sourceTrusteeOpeningState) => [
            sourceTrusteeOpeningState.sourceTrusteeRosterPosition,
            coefficientOpeningByCoordinate(sourceTrusteeOpeningState),
        ]),
    );
    const linkageItems = sourceTrusteeOpeningStates
        .map((sourceTrusteeOpeningState) =>
            Array.from(
                { length: firstProfileParticipantCount },
                (_unusedRecipient, recipientRosterPosition) =>
                    Array.from(
                        { length: input.statement.targetRnsLimbCount },
                        (_unusedLimb, rnsLimbIndex) =>
                            shareLinkageItem({
                                coefficientCommitmentSet:
                                    input.coefficientCommitmentSet,
                                recipientShareCommitmentSet:
                                    input.recipientShareCommitmentSet,
                                recipientShareOpeningCredentialsByCoordinate:
                                    input.recipientShareOpeningCredentialsByCoordinate,
                                sourceTrusteeRosterPosition:
                                    sourceTrusteeOpeningState.sourceTrusteeRosterPosition,
                                recipientRosterPosition,
                                rnsLimbIndex,
                            }),
                    ),
            ),
        )
        .flat(2);
    const maximumMixedBatchItemsPerProof = Math.max(
        1,
        Math.floor(
            acceptedBgvProfileRingDegree /
                minimumSuccinctProofFixtureRingDegree,
        ),
    );
    const proofRecordInputs: {
        readonly compactVssShareLinkage: CompactVssShareLinkageProofStatement;
        readonly proofBytesHex: string;
    }[] = [];
    for (
        let batchOffset = 0;
        batchOffset < linkageItems.length;
        batchOffset += maximumMixedBatchItemsPerProof
    ) {
        const batchLinkageItems = linkageItems.slice(
            batchOffset,
            batchOffset + maximumMixedBatchItemsPerProof,
        );
        const firstLinkageItem = requiredArrayValue(
            batchLinkageItems,
            0,
            "compact VSS share-linkage proof requires at least one item.",
        );
        const compactVssShareLinkage: CompactVssShareLinkageProofStatement = {
            ...firstLinkageItem.item,
            publicMatrixSeedHash: input.statement.publicMatrixSeedHash,
            shareLinkageStatementRoot: input.statement.statementRoot,
            additionalLinkageItems: batchLinkageItems
                .slice(1)
                .map((linkageItem) => linkageItem.item),
        };
        const coefficientMessagesByShamirIndex: number[][] = [];
        const coefficientOpeningRandomnessByShamirIndex: number[][][] = [];
        const seenCoefficientOpenings = new Set<string>();
        batchLinkageItems.forEach((linkageItem) => {
            linkageItem.item.coefficientOpeningRoots.forEach(
                (coefficientOpeningRoot, shamirCoefficientIndex) => {
                    const sourceTrusteeRosterPosition =
                        linkageItem.item.sourceTrusteeRosterPosition;
                    const key = [
                        sourceTrusteeRosterPosition,
                        linkageItem.item.sourceRnsLimbIndex,
                        shamirCoefficientIndex,
                        coefficientOpeningRoot,
                    ].join(":");
                    if (seenCoefficientOpenings.has(key)) {
                        return;
                    }
                    seenCoefficientOpenings.add(key);
                    const sourceTrusteeOpeningState =
                        sourceTrusteeOpeningStateByPosition.get(
                            sourceTrusteeRosterPosition,
                        );
                    const openingsByCoordinate =
                        coefficientOpeningsByPosition.get(
                            sourceTrusteeRosterPosition,
                        );
                    if (
                        sourceTrusteeOpeningState === undefined ||
                        openingsByCoordinate === undefined
                    ) {
                        throw new Error(
                            "compact VSS share-linkage proof is missing source opening state.",
                        );
                    }
                    const coefficientOpening = requiredCoefficientOpening(
                        openingsByCoordinate,
                        linkageItem.item.sourceRnsLimbIndex,
                        shamirCoefficientIndex,
                    );
                    coefficientMessagesByShamirIndex.push([
                        ...coefficientOpening.coefficientMessage,
                    ]);
                    coefficientOpeningRandomnessByShamirIndex.push(
                        compactCoefficientOpeningRandomness({
                            trusteeIdentity:
                                sourceTrusteeOpeningState.sourceTrusteeIdentity,
                            trusteeRosterPosition:
                                sourceTrusteeOpeningState.sourceTrusteeRosterPosition,
                            rnsLimbIndex: linkageItem.item.sourceRnsLimbIndex,
                            rnsPrime: coefficientOpening.rnsPrime,
                            shamirCoefficientIndex,
                            ringDegree: input.statement.ringDegree,
                        }).map((column) => [...column]),
                    );
                },
            );
        });
        const generation = input.kernel.generateCompactVssShareLinkageProof({
            context: {
                ceremonyId: input.setupContext.ceremonyId,
                manifestHash: input.setupContext.manifestHash,
                rosterHash: input.setupContext.rosterHash,
                trusteeIdentity: "compact-vss-share-linkage",
                trusteeRosterPosition: 0,
                setupEpoch: input.setupContext.setupEpoch,
                shareLinkageStatementRoot: input.statement.statementRoot,
            },
            ringDegree: input.statement.ringDegree,
            compactVssShareLinkage,
            coefficientMessagesByShamirIndex,
            recipientShareMessages: [
                ...firstLinkageItem.recipientShareMessages,
            ],
            coefficientOpeningRandomnessByShamirIndex,
            recipientShareOpeningRandomness:
                firstLinkageItem.recipientShareOpeningRandomness.map(
                    (column) => [...column],
                ),
            carryWitnesses: [...firstLinkageItem.carryWitnesses],
            recipientShareMessagesByItem: batchLinkageItems.map(
                (linkageItem) => [...linkageItem.recipientShareMessages],
            ),
            recipientShareOpeningRandomnessByItem: batchLinkageItems.map(
                (linkageItem) =>
                    linkageItem.recipientShareOpeningRandomness.map(
                        (column) => [...column],
                    ),
            ),
            carryWitnessesByItem: batchLinkageItems.map((linkageItem) => [
                ...linkageItem.carryWitnesses,
            ]),
            proofRandomnessSeedHex: compactProofHash(
                "sealed-lattice-test/compact-vss-share-linkage-proof-seed-v1",
                String(batchOffset),
            ),
            proofRandomnessNonceHex: compactProofHash(
                "sealed-lattice-test/compact-vss-share-linkage-proof-nonce-v1",
                String(batchOffset),
            ),
        });

        proofRecordInputs.push({
            compactVssShareLinkage,
            proofBytesHex: generation.proofBytesHex,
        });
    }

    return proofRecordInputs;
};

const recipientShareOpeningCredentialsByCoordinate = (
    recipientShareOpeningCredentials: readonly {
        readonly sourceTrusteeRosterPosition: number;
        readonly recipientRosterPosition: number;
        readonly rnsLimbIndex: number;
        readonly shareValues: readonly number[];
        readonly shareCommitmentMessageCarryValues: readonly number[];
        readonly randomnessByColumn: readonly (readonly number[])[];
        readonly shareCommitmentRoot: string;
        readonly shareOpeningRoot: string;
    }[],
): ReadonlyMap<
    string,
    {
        readonly shareValues: readonly number[];
        readonly shareCommitmentMessageCarryValues: readonly number[];
        readonly randomnessByColumn: readonly (readonly number[])[];
        readonly shareCommitmentRoot: string;
        readonly shareOpeningRoot: string;
    }
> =>
    new Map(
        recipientShareOpeningCredentials.map((credential) => [
            [
                credential.sourceTrusteeRosterPosition,
                credential.recipientRosterPosition,
                credential.rnsLimbIndex,
            ].join(":"),
            credential,
        ]),
    );

const compactSameSecretBridgeStatement = (
    statementRecord: CompactVssSameSecretBridgeStatementSet["statementRecords"][number],
): BgvCompactSameSecretBridgeProofStatement => ({
    compactSameSecretBridgeStatementRoot:
        statementRecord.compactSameSecretBridgeStatementRoot,
    sameSecretStatementRoot: statementRecord.sameSecretStatementRoot,
    sameSecretProofRoot: statementRecord.sameSecretProofRoot,
    sameSecretProofFamilyBindingRoot:
        statementRecord.sameSecretProofFamilyBindingRoot,
    publicMatrixSeedHash: statementRecord.publicMatrixSeedHash,
    sourceTrusteeIdentity: statementRecord.trusteeIdentity,
    sourceTrusteeRosterPosition: statementRecord.trusteeRosterPosition,
    targetBasisHash: statementRecord.targetBasisHash,
    targetRnsPrimes: statementRecord.targetConstantCoefficientCommitments.map(
        (targetCommitment) => targetCommitment.rnsPrime,
    ),
    targetConstantCommitmentRoots:
        statementRecord.targetConstantCoefficientCommitmentRoots.map(
            (targetRoot) => targetRoot.coefficientCommitmentRoot,
        ),
    targetConstantCommitments:
        statementRecord.targetConstantCoefficientCommitments.map(
            (targetCommitment) => targetCommitment.commitment,
        ),
});

const sameSecretBridgeProofRecordInputs = (input: {
    readonly kernel: TranscriptCoreKernel;
    readonly setupContext: CollectiveBgvSetupContext;
    readonly statementSet: CompactVssSameSecretBridgeStatementSet;
    readonly sourceTrusteeOpeningStates: readonly VssSourceTrusteeCoefficientOpeningState[];
}): readonly {
    readonly compactSameSecretBridgeStatementRoot: string;
    readonly proofBytesHex: string;
}[] =>
    input.statementSet.statementRecords.map((statementRecord) => {
        const sourceTrusteeOpeningState = requiredArrayValue(
            input.sourceTrusteeOpeningStates,
            statementRecord.trusteeRosterPosition,
            "compact same-secret bridge source opening state is missing.",
        );
        const openingsByCoordinate = coefficientOpeningByCoordinate(
            sourceTrusteeOpeningState,
        );
        const firstLimbSecretOpening = requiredCoefficientOpening(
            openingsByCoordinate,
            0,
            0,
        );
        const secretCoefficients =
            firstLimbSecretOpening.coefficientMessage.map((residue) =>
                centeredTernaryFromResidue(
                    residue,
                    firstLimbSecretOpening.rnsPrime,
                ),
            );
        const compactSameSecretBridge =
            compactSameSecretBridgeStatement(statementRecord);
        const generation = input.kernel.generateCompactSameSecretBridgeProof({
            context: {
                ceremonyId: input.setupContext.ceremonyId,
                manifestHash: input.setupContext.manifestHash,
                rosterHash: input.setupContext.rosterHash,
                trusteeIdentity:
                    sourceTrusteeOpeningState.sourceTrusteeIdentity,
                trusteeRosterPosition:
                    sourceTrusteeOpeningState.sourceTrusteeRosterPosition,
                setupEpoch: input.setupContext.setupEpoch,
                compactSameSecretBridgeStatementRoot:
                    statementRecord.compactSameSecretBridgeStatementRoot,
                sameSecretStatementRoot:
                    statementRecord.sameSecretStatementRoot,
                sameSecretProofRoot: statementRecord.sameSecretProofRoot,
                sameSecretProofFamilyBindingRoot:
                    statementRecord.sameSecretProofFamilyBindingRoot,
            },
            ringDegree: input.statementSet.ringDegree,
            compactSameSecretBridge,
            secretCoefficients,
            negativeIndicatorCoefficients: secretCoefficients.map(
                (coefficient) => (coefficient < 0 ? 1 : 0),
            ),
            openingRandomnessByLimb:
                statementRecord.targetConstantCoefficientCommitments.map(
                    (targetCommitment) =>
                        compactCoefficientOpeningRandomness({
                            trusteeIdentity:
                                sourceTrusteeOpeningState.sourceTrusteeIdentity,
                            trusteeRosterPosition:
                                sourceTrusteeOpeningState.sourceTrusteeRosterPosition,
                            rnsLimbIndex: targetCommitment.rnsLimbIndex,
                            rnsPrime: targetCommitment.rnsPrime,
                            shamirCoefficientIndex: 0,
                            ringDegree: input.statementSet.ringDegree,
                        }),
                ),
            proofRandomnessSeedHex: compactProofHash(
                "sealed-lattice-test/compact-same-secret-bridge-proof-seed-v1",
                String(statementRecord.trusteeRosterPosition),
            ),
            proofRandomnessNonceHex: compactProofHash(
                "sealed-lattice-test/compact-same-secret-bridge-proof-nonce-v1",
                String(statementRecord.trusteeRosterPosition),
            ),
        });

        return {
            compactSameSecretBridgeStatementRoot:
                statementRecord.compactSameSecretBridgeStatementRoot,
            proofBytesHex: generation.proofBytesHex,
        };
    });

export const acceptedCompactVssMaterial = (input: {
    readonly kernel: TranscriptCoreKernel;
    readonly profile: BgvCollectiveSetupProfileDescription;
    readonly setupPackage: JsonRecord;
    readonly vssCoefficientCommitmentBundle: VssCoefficientCommitmentBundle;
}): AcceptedCompactVssMaterial => {
    const setupContext = input.setupPackage
        .setupContext as CollectiveBgvSetupContext;
    const commonRandomness = input.setupPackage.commonRandomness as JsonRecord;
    const publicMatrixSeedHash = String(commonRandomness.publicMatrixSeedHash);
    const targetRnsPrimes = targetRnsPrimesFromProfile(input.profile);
    const sourceTrusteeOpeningStates = sourceTrusteeOpeningStatesFromBundle(
        input.vssCoefficientCommitmentBundle,
    );
    const recipientTrustees = acceptedSetupTrusteeReferences();
    const compactVssCoefficientCommitmentSet =
        createCompactVssCoefficientCommitmentSet({
            setupContext,
            publicMatrixSeedHash,
            participantCount: firstProfileParticipantCount,
            qSharePrimes: targetRnsPrimes,
            ringDegree: minimumSuccinctProofFixtureRingDegree,
            thresholdDegree: firstProfileDecryptionThreshold,
            sourceTrusteeOpeningStates,
            coefficientOpeningRandomness: compactCoefficientOpeningRandomness,
        });
    const compactRecipientShareCommitmentBundle =
        createCompactVssRecipientShareCommitmentBundle({
            setupContext,
            publicMatrixSeedHash,
            participantCount: firstProfileParticipantCount,
            qSharePrimes: targetRnsPrimes,
            ringDegree: minimumSuccinctProofFixtureRingDegree,
            thresholdDegree: firstProfileDecryptionThreshold,
            coefficientCommitmentSet: compactVssCoefficientCommitmentSet,
            sourceTrusteeOpeningStates,
            recipientTrustees,
            coefficientOpeningRandomness: compactCoefficientOpeningRandomness,
        });
    const compactVssRecipientShareCommitmentSet =
        compactRecipientShareCommitmentBundle.recipientShareCommitmentSet;
    const compactVssAggregateThresholdCommitmentSet =
        aggregateCompactVssThresholdShareCommitments({
            setupContext,
            publicMatrixSeedHash,
            participantCount: firstProfileParticipantCount,
            qSharePrimes: targetRnsPrimes,
            ringDegree: minimumSuccinctProofFixtureRingDegree,
            recipientTrustees,
            recipientShareOpeningCredentials:
                compactRecipientShareCommitmentBundle.recipientShareOpeningCredentials,
        }).aggregateThresholdCommitmentSet;
    const compactVssShareLinkageStatement =
        createCompactVssShareLinkageStatement({
            setupContext,
            publicMatrixSeedHash,
            targetBasisHash: input.profile.canonicalTargetBasisHash,
            coefficientCommitmentSet: compactVssCoefficientCommitmentSet,
            recipientShareCommitmentSet: compactVssRecipientShareCommitmentSet,
            aggregateThresholdCommitmentSet:
                compactVssAggregateThresholdCommitmentSet,
        });
    const compactVssShareLinkageProofMaterialSet =
        createCompactVssShareLinkageProofMaterialSet({
            statement: compactVssShareLinkageStatement,
            coefficientCommitmentSet: compactVssCoefficientCommitmentSet,
            recipientShareCommitmentSet: compactVssRecipientShareCommitmentSet,
            aggregateThresholdCommitmentSet:
                compactVssAggregateThresholdCommitmentSet,
            ringDegree: minimumSuccinctProofFixtureRingDegree,
            proofRecordInputs: shareLinkageProofRecordInputs({
                kernel: input.kernel,
                setupContext,
                statement: compactVssShareLinkageStatement,
                coefficientCommitmentSet: compactVssCoefficientCommitmentSet,
                recipientShareCommitmentSet:
                    compactVssRecipientShareCommitmentSet,
                recipientShareOpeningCredentialsByCoordinate:
                    recipientShareOpeningCredentialsByCoordinate(
                        compactRecipientShareCommitmentBundle.recipientShareOpeningCredentials,
                    ),
                sourceTrusteeOpeningStates,
            }),
        });
    const sameSecretConsistency = input.setupPackage
        .sameSecretConsistency as SameSecretConsistencyStatementSet;
    const sameSecretProofs = input.setupPackage
        .sameSecretProofs as SameSecretProofSet;
    const compactSameSecretBridgeStatementSet =
        createCompactVssSameSecretBridgeStatementSet({
            setupContext,
            targetBasisHash: input.profile.canonicalTargetBasisHash,
            publicMatrixSeedHash,
            compactCoefficientCommitmentSet: compactVssCoefficientCommitmentSet,
            sameSecretConsistency,
            sameSecretProofs,
        });
    const compactSameSecretBridgeProofMaterialSet =
        createCompactVssSameSecretBridgeProofMaterialSet({
            statementSet: compactSameSecretBridgeStatementSet,
            sameSecretConsistency,
            sameSecretProofs,
            proofRecordInputs: sameSecretBridgeProofRecordInputs({
                kernel: input.kernel,
                setupContext,
                statementSet: compactSameSecretBridgeStatementSet,
                sourceTrusteeOpeningStates,
            }),
        });

    return {
        compactVssCoefficientCommitmentSet,
        compactVssRecipientShareCommitmentSet,
        compactVssAggregateThresholdCommitmentSet,
        compactVssShareLinkageStatement,
        compactVssShareLinkageProofMaterialSet,
        compactSameSecretBridgeStatementSet,
        compactSameSecretBridgeProofMaterialSet,
    };
};
