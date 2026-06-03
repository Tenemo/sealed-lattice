import {
    lowerHexHash,
    measure,
    type ContributionBuild,
    type TranscriptCoreKernel,
    type Variant,
} from './shared.js';

import {
    canonicalJson,
    createMlDsaKeyPairFixture,
    createMlDsaSignatureProfileFixture,
    createProtocolSignatureFixture,
    deriveProtocolHash,
} from '#packages/crypto/src/index';
import {
    createPendingBridgeProofRecordFromBridgeEvidence,
    type PendingBridgeProofRecordFromEvidenceInput,
} from '#packages/protocol/src/ballot-privacy/aggregate-bridge/structure-verification.js';
import {
    deriveAggregateCommitmentBodyHash,
    deriveAggregateDerivationBallotSetHash,
    deriveAggregateDerivationStatementHash,
    deriveAggregateShareCommitmentHash,
} from '#packages/protocol/src/ballot-privacy/aggregate-derivation/hashes';
import {
    aggregateWitnessFromReceiverPlaintext,
    buildAggregateDerivationProofInput,
    createAggregateContributionFromBridgeProofRecord,
    createAggregateDerivationComponent,
    createShareCommitmentMessageBoundCert,
    verifyAggregateContributionStructure,
    type AggregateDerivationWitnessInput,
} from '#packages/protocol/src/ballot-privacy/index';
import { createVariantBallotProofRecordGenerationFixture } from '#packages/protocol/tests/node/ballot-privacy-proof-record-generation-fixtures/fixture-assembly.js';
import {
    aggregateDerivationProofEncodingProfileId,
    aggregateDerivationProofParameterProfileId,
    aggregateDerivationProofProfileId,
    type ActionContext,
    type AggregateContribution,
    type AggregateDerivationComponent,
    type AggregateDerivationPackageReference,
    type AggregateDerivationStatement,
    type AggregateShareCommitment,
    type ClaimBearingBallotPackage,
    type ProtocolHash,
    type ProtocolSignatureEnvelope,
    type RecoveryEpochMapEntry,
    type ShareCommitment,
} from '#packages/types/src/index';

const actionContextForContributor = (input: {
    readonly contributorIdentity: string;
    readonly contributorRosterExternalAcceptanceHash: ProtocolHash;
    readonly postVotingClosedContextHash: ProtocolHash;
    readonly statement: ClaimBearingBallotPackage['ballotProofStatement'];
}): ActionContext => {
    const contributorRosterPosition = Number(
        input.contributorIdentity.replace('receiver-', ''),
    );
    const actionContextPayload = {
        acceptedRecoveryEpochUpdateHash: null,
        actionSequence: contributorRosterPosition,
        boardHeadHash: lowerHexHash('closed-board-head'),
        boardSequence: 7,
        ceremonyId: input.statement.ceremonyId,
        contextHash: input.postVotingClosedContextHash,
        deviceEpoch: 0,
        electionManifestHash: input.statement.manifestHash,
        recoveryEpoch: 0,
        recoveryPolicyHash: lowerHexHash('recovery-policy'),
        rosterExternalAcceptanceHash:
            input.contributorRosterExternalAcceptanceHash,
        signerIdentity: input.contributorIdentity,
    };

    return {
        ...actionContextPayload,
        actionContextHash: deriveProtocolHash(
            'ActionContextHash',
            actionContextPayload,
        ),
    };
};

type ContributionMode = 'checked-accepted-counted-package' | 'relation-only';

const signatureForContributor = (input: {
    readonly actionContext: ActionContext;
    readonly objectRoot: ProtocolHash;
    readonly statement: ClaimBearingBallotPackage['ballotProofStatement'];
}): ProtocolSignatureEnvelope => {
    const keyFixture = createMlDsaKeyPairFixture(
        `aggregate-bridge-matrix-${input.actionContext.signerIdentity}`,
    );

    return createProtocolSignatureFixture({
        profile: createMlDsaSignatureProfileFixture(),
        publicKeyBytesHex: keyFixture.publicKeyBytesHex,
        publicKeyHash: keyFixture.publicKeyHash,
        secretKeyBytesHex: keyFixture.secretKeyBytesHex,
        signedRoot: {
            boardHeadHash: input.actionContext.boardHeadHash,
            byteLength: 64,
            ceremonyId: input.statement.ceremonyId,
            chunkMerkleRoot: null,
            contextHash: input.actionContext.contextHash,
            deviceEpoch: input.actionContext.deviceEpoch,
            manifestHash: input.statement.manifestHash,
            objectRoot: input.objectRoot,
            objectType: 'AggregateContribution',
            objectVersion: 1,
            recoveryEpoch: input.actionContext.recoveryEpoch,
            signerIdentity: input.actionContext.signerIdentity,
            signerRole: 'Trustee',
        },
    });
};

export const createSyntheticBallotPackageShell = (input: {
    readonly fixture: ReturnType<
        typeof createVariantBallotProofRecordGenerationFixture
    >;
}): ClaimBearingBallotPackage =>
    ({
        ballotPackageHash: input.fixture.statement.ballotPackageHash,
        ballotProof: {
            ballotProofRecordHash: lowerHexHash(
                `ballot-proof-record-${input.fixture.statement.ballotProofStatementHash}`,
            ),
            ballotProofStatementHash:
                input.fixture.statement.ballotProofStatementHash,
            objectType: 'BallotProofRecord',
            objectVersion: 1,
            proofBackend: 'LocalLinearLatticeRelation',
            proofBytesHash: lowerHexHash('ballot-proof-bytes'),
            proofRoot: lowerHexHash('ballot-proof-root'),
            proofSizeBytes: 1,
            relationStatementHash: lowerHexHash('ballot-relation-statement'),
        },
        ballotProofStatement: input.fixture.statement,
        componentBundleStatement:
            input.fixture.request.componentBundleStatement,
        componentProofBundle: {
            backendStatementHash: lowerHexHash('component-backend'),
            ballotProofStatementHash:
                input.fixture.statement.ballotProofStatementHash,
            bundleCoverage: 'full-encoded-score-ballot-relation',
            componentBundleStatementHash: lowerHexHash(
                'component-bundle-statement',
            ),
            componentProofBundleHash: lowerHexHash('component-proof-bundle'),
            componentProofs: [],
            objectType: 'BallotProofComponentProofBundle',
            objectVersion: 1,
            relationStatementHash: lowerHexHash('component-relation'),
            requiredComponentIds: [],
        },
        componentProofInputs: input.fixture.request.componentProofInputs,
        linearStatement: input.fixture.request.linearStatement,
        objectType: 'ClaimBearingBallotPackage',
        objectVersion: 1,
        parameterSet: input.fixture.request.parameterSet,
        proofBytesHex: '00',
        proofEncoding: input.fixture.request.proofEncoding,
        publicRandomnessHex: input.fixture.request.publicRandomnessHex,
        receiverKeyProofRootEvidence:
            input.fixture.receiverKeyProofRootEvidence,
        receiverPayloads: input.fixture.claimBearingReceiverPayloads,
        shareCommitments: input.fixture.claimBearingShareCommitments,
    }) as unknown as ClaimBearingBallotPackage;

const shareCommitmentForContributor = (input: {
    readonly ballotPackage: ClaimBearingBallotPackage;
    readonly contributorIdentity: string;
    readonly contributorRosterPosition: number;
}): ShareCommitment & {
    readonly commitmentPolynomialVector: AggregateShareCommitment['commitmentPolynomialVector'];
} => {
    const shareCommitment = input.ballotPackage.shareCommitments.find(
        (candidate) =>
            candidate.receiverIdentity === input.contributorIdentity &&
            candidate.receiverRosterPosition ===
                input.contributorRosterPosition,
    );
    if (shareCommitment?.commitmentPolynomialVector === undefined) {
        throw new Error('Contributor share commitment is missing.');
    }

    return shareCommitment as ShareCommitment & {
        readonly commitmentPolynomialVector: AggregateShareCommitment['commitmentPolynomialVector'];
    };
};

const packageReferenceForContributor = (input: {
    readonly ballotPackage: ClaimBearingBallotPackage;
    readonly contributorIdentity: string;
    readonly contributorRosterPosition: number;
}): AggregateDerivationPackageReference => {
    const payloadReference =
        input.ballotPackage.ballotProofStatement.receiverPayloads.find(
            (candidate) =>
                candidate.receiverIdentity === input.contributorIdentity &&
                candidate.receiverRosterPosition ===
                    input.contributorRosterPosition,
        );
    const commitmentReference =
        input.ballotPackage.ballotProofStatement.shareCommitments.find(
            (candidate) =>
                candidate.receiverIdentity === input.contributorIdentity &&
                candidate.receiverRosterPosition ===
                    input.contributorRosterPosition,
        );
    if (payloadReference === undefined || commitmentReference === undefined) {
        throw new Error('Contributor package reference is missing.');
    }

    return {
        ballotPackageHash: input.ballotPackage.ballotPackageHash,
        ballotProofStatementHash:
            input.ballotPackage.ballotProofStatement.ballotProofStatementHash,
        receiverPayloadCiphertextRoot:
            payloadReference.receiverPayloadCiphertextRoot,
        receiverPayloadHash: payloadReference.receiverPayloadHash,
        shareCommitmentHash: commitmentReference.shareCommitmentHash,
    };
};

const aggregateWitnessForContributor = (input: {
    readonly contributorRosterPosition: number;
    readonly fixture: ReturnType<
        typeof createVariantBallotProofRecordGenerationFixture
    >;
}): AggregateDerivationWitnessInput => {
    const receiverPayloadPlaintext =
        input.fixture.projectionWitness.receiverPayloadPlaintexts?.find(
            (candidate) =>
                candidate.receiverRosterPosition ===
                input.contributorRosterPosition,
        );
    const shareCommitmentOpening =
        input.fixture.projectionWitness.shareCommitmentOpenings.find(
            (candidate) =>
                candidate.receiverRosterPosition ===
                input.contributorRosterPosition,
        );
    if (
        receiverPayloadPlaintext === undefined ||
        shareCommitmentOpening === undefined
    ) {
        throw new Error('Contributor aggregate witness is missing.');
    }

    return aggregateWitnessFromReceiverPlaintext({
        openingRandomness: shareCommitmentOpening.openingRandomness,
        receiverShareVector: receiverPayloadPlaintext.receiverShareVector,
    });
};

const createAggregateComponentForContributor = (input: {
    readonly ballotPackage: ClaimBearingBallotPackage;
    readonly certificate: ReturnType<
        typeof createShareCommitmentMessageBoundCert
    >;
    readonly closeRecordHash: ProtocolHash;
    readonly contributorActionContextHash: ProtocolHash;
    readonly contributorIdentity: string;
    readonly contributorRosterExternalAcceptanceHash: ProtocolHash;
    readonly contributorRosterPosition: number;
    readonly kernel: TranscriptCoreKernel;
    readonly postVotingClosedContextHash: ProtocolHash;
    readonly proverRandomnessHex: string;
    readonly casualMicroRosterAcknowledged: boolean;
    readonly votingClosedBoardHeadHash: ProtocolHash;
    readonly witness: AggregateDerivationWitnessInput;
}): AggregateDerivationComponent => {
    const statement = input.ballotPackage.ballotProofStatement;
    const shareCommitment = shareCommitmentForContributor({
        ballotPackage: input.ballotPackage,
        contributorIdentity: input.contributorIdentity,
        contributorRosterPosition: input.contributorRosterPosition,
    });
    const ballotSetHash = deriveAggregateDerivationBallotSetHash({
        ballotPackageHashes: [input.ballotPackage.ballotPackageHash],
        closeRecordHash: input.closeRecordHash,
        manifestHash: statement.manifestHash,
        pollSpecHash: statement.pollSpecHash,
        postVotingClosedContextHash: input.postVotingClosedContextHash,
        rosterHash: statement.rosterHash,
        thresholdProfileHash: statement.thresholdProfileHash,
        votingClosedBoardHeadHash: input.votingClosedBoardHeadHash,
    });
    const commitmentBodyHash = deriveAggregateCommitmentBodyHash({
        commitmentPolynomialVector: shareCommitment.commitmentPolynomialVector,
        shareCommitmentProfileHash: statement.shareCommitmentProfileHash,
    });
    const commitmentPayload: Omit<
        AggregateShareCommitment,
        'aggregateShareCommitmentHash'
    > = {
        ballotSetHash,
        ceremonyId: statement.ceremonyId,
        commitmentBodyHash,
        commitmentPolynomialVector: shareCommitment.commitmentPolynomialVector,
        contributorIdentity: input.contributorIdentity,
        contributorRosterPosition: input.contributorRosterPosition,
        manifestHash: statement.manifestHash,
        objectType: 'AggregateShareCommitment',
        objectVersion: 1,
        pollSpecHash: statement.pollSpecHash,
        rosterHash: statement.rosterHash,
        shareCommitmentProfileHash: statement.shareCommitmentProfileHash,
        shareVectorWidth: statement.shareVectorWidth,
    };
    const aggregateCommitment: AggregateShareCommitment = {
        ...commitmentPayload,
        aggregateShareCommitmentHash:
            deriveAggregateShareCommitmentHash(commitmentPayload),
    };
    const challengeDomainHash = deriveProtocolHash('ChallengeDomainHash', {
        aggregateDerivationProofEncodingProfileId,
        aggregateDerivationProofParameterProfileId,
        aggregateDerivationProofProfileId,
        aggregateShareCommitmentHash:
            aggregateCommitment.aggregateShareCommitmentHash,
        ballotSetHash,
        purpose: 'aggregate-derivation-proof-challenge-v1',
        shareCommitmentMessageBoundCertHash:
            input.certificate.shareCommitmentMessageBoundCertHash,
    });
    const statementPayload: Omit<
        AggregateDerivationStatement,
        'aggregateDerivationStatementHash'
    > = {
        aggregateCommitmentHash:
            aggregateCommitment.aggregateShareCommitmentHash,
        aggregateInputEncodingProfileHash:
            statement.aggregateInputEncodingProfileHash,
        aggregateShareCommitmentHash:
            aggregateCommitment.aggregateShareCommitmentHash,
        ballotScoreEncodingProfileHash:
            statement.ballotScoreEncodingProfileHash,
        ballotSetHash,
        ballotShareLayoutProfileHash: statement.ballotShareLayoutProfileHash,
        canonicalTurnout: 1,
        ceremonyId: statement.ceremonyId,
        challengeDomainHash,
        closeRecordHash: input.closeRecordHash,
        contributorActionContextHash: input.contributorActionContextHash,
        contributorIdentity: input.contributorIdentity,
        contributorRosterExternalAcceptanceHash:
            input.contributorRosterExternalAcceptanceHash,
        contributorRosterPosition: input.contributorRosterPosition,
        encodedAggregateLayoutHash: statement.encodedAggregateLayoutHash,
        encodedShareVectorLayoutHash: statement.encodedShareVectorLayoutHash,
        manifestHash: statement.manifestHash,
        objectType: 'AggregateDerivationStatement',
        objectVersion: 1,
        optionCount: statement.optionCount,
        packageReferences: [
            packageReferenceForContributor({
                ballotPackage: input.ballotPackage,
                contributorIdentity: input.contributorIdentity,
                contributorRosterPosition: input.contributorRosterPosition,
            }),
        ],
        participantCount: statement.receiverPublicKeys.length,
        pollSpecHash: statement.pollSpecHash,
        postVotingClosedContextHash: input.postVotingClosedContextHash,
        proofEncodingProfileId: aggregateDerivationProofEncodingProfileId,
        proofParameterProfileId: aggregateDerivationProofParameterProfileId,
        proofProfileId: aggregateDerivationProofProfileId,
        receiverEncryptionProfileHash: statement.receiverEncryptionProfileHash,
        rosterHash: statement.rosterHash,
        shareCommitmentMessageBoundCertHash:
            input.certificate.shareCommitmentMessageBoundCertHash,
        shareCommitmentProfileHash: statement.shareCommitmentProfileHash,
        shareVectorWidth: statement.shareVectorWidth,
        thresholdProfileHash: statement.thresholdProfileHash,
        ...(input.casualMicroRosterAcknowledged
            ? { casualMicroRosterAcknowledged: true as const }
            : {}),
        votingClosedBoardHeadHash: input.votingClosedBoardHeadHash,
    };
    const aggregateStatement = {
        ...statementPayload,
        aggregateDerivationStatementHash:
            deriveAggregateDerivationStatementHash(statementPayload),
    };
    const proofBuild = buildAggregateDerivationProofInput({
        aggregateCommitment,
        statement: aggregateStatement,
        witness: input.witness,
    });
    const generatedProof = input.kernel.generateAggregateDerivationProof({
        proofInput: proofBuild.proofInput,
        proverRandomnessHex: input.proverRandomnessHex,
        secretState: proofBuild.secretState,
    }) as Record<string, unknown>;
    if (generatedProof.ok !== true) {
        throw new Error(
            `Aggregate derivation proof generation failed: ${canonicalJson(generatedProof)}`,
        );
    }

    return createAggregateDerivationComponent({
        aggregateCommitment,
        proofBytesHex: String(generatedProof.proofBytesHex),
        proofInput: proofBuild.proofInput,
        shareCommitmentMessageBoundCert: input.certificate,
        statement: aggregateStatement,
    });
};

export const setupParticipants = (
    rosterSize: number,
): readonly {
    readonly boardPosition: number;
    readonly rosterPosition: number;
    readonly trusteeIdentity: string;
}[] =>
    Array.from({ length: rosterSize }, (_unusedValue, participantIndex) => ({
        boardPosition: participantIndex + 1,
        rosterPosition: participantIndex,
        trusteeIdentity: `receiver-${participantIndex + 1}`,
    }));

export const createContribution = (input: {
    readonly aggregateSelectionPolicyHash: ProtocolHash;
    readonly ballotPackage: ClaimBearingBallotPackage;
    readonly bridgeWitnessPrivacyProfileHash: ProtocolHash;
    readonly certificate: ReturnType<
        typeof createShareCommitmentMessageBoundCert
    >;
    readonly contributorRosterPosition: number;
    readonly fixture: ReturnType<
        typeof createVariantBallotProofRecordGenerationFixture
    >;
    readonly heParamHash: ProtocolHash;
    readonly kernel: TranscriptCoreKernel;
    readonly setupPackage: Record<string, unknown>;
    readonly casualMicroRosterAcknowledged: boolean;
    readonly contributionMode: ContributionMode;
    readonly variant: Variant;
}): ContributionBuild => {
    const statement = input.ballotPackage.ballotProofStatement;
    const contributorIdentity = `receiver-${input.contributorRosterPosition}`;
    const contributorRosterExternalAcceptanceHash =
        statement.rosterExternalAcceptanceHash;
    const votingClosedBoardHeadHash = lowerHexHash('closed-board-head');
    const closeRecordPayload = {
        boardPosition: 0,
        boardSequence: 7,
        ceremonyId: statement.ceremonyId,
        closeKind: 'VotingClosed',
        closedBoardHeadHash: votingClosedBoardHeadHash,
        electionManifestHash: statement.manifestHash,
        objectType: 'CloseRecord',
        objectVersion: 1,
        organizerIdentity: 'organizer-1',
    };
    const closeRecordHash = deriveProtocolHash(
        'CloseRecordHash',
        closeRecordPayload,
    );
    const postVotingClosedContextHash = deriveProtocolHash(
        'PostVotingClosedContextHash',
        {
            ceremonyId: statement.ceremonyId,
            closeRecordHash,
            electionManifestHash: statement.manifestHash,
            votingClosedBoardHeadHash,
        },
    );
    const closeRecord = {
        ...closeRecordPayload,
        closeRecordHash,
        postVotingClosedContextHash,
    };
    const actionContext = actionContextForContributor({
        contributorIdentity,
        contributorRosterExternalAcceptanceHash,
        postVotingClosedContextHash,
        statement,
    });
    const aggregateWitness = aggregateWitnessForContributor({
        contributorRosterPosition: input.contributorRosterPosition,
        fixture: input.fixture,
    });
    const aggregateDerivationComponent = createAggregateComponentForContributor(
        {
            ballotPackage: input.ballotPackage,
            certificate: input.certificate,
            closeRecordHash,
            contributorActionContextHash: actionContext.actionContextHash,
            contributorIdentity,
            contributorRosterExternalAcceptanceHash,
            contributorRosterPosition: input.contributorRosterPosition,
            kernel: input.kernel,
            postVotingClosedContextHash,
            proverRandomnessHex: '66'.repeat(32),
            casualMicroRosterAcknowledged: input.casualMicroRosterAcknowledged,
            votingClosedBoardHeadHash,
            witness: aggregateWitness,
        },
    );
    const aggregateDerivationVerificationContext =
        input.contributionMode === 'checked-accepted-counted-package'
            ? {
                  closeRecord,
                  contributorActionContext: actionContext,
                  countedBallotPackages: [input.ballotPackage],
              }
            : {};
    const bridgeGeneration = measure(() =>
        input.kernel.generateAggregateBridgeEncryption({
            aggregateDerivationComponent,
            aggregateSelectionPolicyHash: input.aggregateSelectionPolicyHash,
            aggregateWitness,
            bridgeWitnessPrivacyProfileHash:
                input.bridgeWitnessPrivacyProfileHash,
            ...aggregateDerivationVerificationContext,
            heParamHash: input.heParamHash,
            includeCanonicalBytesHex: true,
            proverRandomnessHex: '77'.repeat(32),
            encryptionRandomnessSeedHex: '88'.repeat(32),
            developmentRandomnessOverrideAcknowledged: true,
            setupPackage: input.setupPackage,
        }),
    );
    const bridgeEncryption = bridgeGeneration.result as Record<string, unknown>;
    if (bridgeEncryption.ok !== true) {
        throw new Error(
            `Bridge proof generation failed: ${canonicalJson(bridgeEncryption)}`,
        );
    }
    const bridgeVerification = measure(() =>
        input.kernel.verifyAggregateBridgeEncryption({
            aggregateDerivationComponent,
            aggregateSelectionPolicyHash: input.aggregateSelectionPolicyHash,
            bridgeEncryption,
            bridgeWitnessPrivacyProfileHash:
                input.bridgeWitnessPrivacyProfileHash,
            ...aggregateDerivationVerificationContext,
            heParamHash: input.heParamHash,
            setupPackage: input.setupPackage,
        }),
    );
    const bridgeVerificationResult = bridgeVerification.result as Record<
        string,
        unknown
    >;
    if (bridgeVerificationResult.ok !== true) {
        throw new Error(
            `Bridge proof verification failed: ${canonicalJson(bridgeVerificationResult)}`,
        );
    }
    const aggregateContribution =
        input.contributionMode === 'checked-accepted-counted-package'
            ? createAggregateContributionFromBridgeProofRecord({
                  actionContext,
                  boardPosition: input.contributorRosterPosition,
                  bridgeProofRecord:
                      createPendingBridgeProofRecordFromBridgeEvidence({
                          aggregateDerivationComponent,
                          aggregateSelectionPolicyHash:
                              input.aggregateSelectionPolicyHash,
                          bridgeEncryptionEvidence:
                              bridgeEncryption as PendingBridgeProofRecordFromEvidenceInput['bridgeEncryptionEvidence'],
                          bridgeEvidenceVerification:
                              bridgeVerificationResult as PendingBridgeProofRecordFromEvidenceInput['bridgeEvidenceVerification'],
                          bridgeWitnessPrivacyProfileHash:
                              input.bridgeWitnessPrivacyProfileHash,
                          heParamHash: input.heParamHash,
                          setupPackage:
                              input.setupPackage as PendingBridgeProofRecordFromEvidenceInput['setupPackage'],
                      }),
                  closeRecordHash,
                  signature: ({ aggregateContributionHash }) =>
                      signatureForContributor({
                          actionContext,
                          objectRoot: aggregateContributionHash,
                          statement,
                      }),
              })
            : null;
    if (aggregateContribution !== null) {
        const contributionVerification = verifyAggregateContributionStructure(
            aggregateContribution,
        );
        if (!contributionVerification.ok) {
            throw new Error('Aggregate contribution structure did not verify.');
        }
    }

    return {
        aggregateContribution,
        aggregateDerivationComponent,
        aggregateWitness,
        bridgeEncryption,
        bridgeVerification: bridgeVerificationResult,
        proofByteLength:
            String(bridgeEncryption.bridgeProofBytesHex).length / 2,
        proverTime: bridgeGeneration.elapsedMilliseconds,
        verifierTime: bridgeVerification.elapsedMilliseconds,
    };
};

export const currentRecoveryEpochMap = (
    contributions: readonly AggregateContribution[],
): Record<string, RecoveryEpochMapEntry> =>
    Object.fromEntries(
        contributions.map((contribution) => [
            contribution.contributorIdentity,
            {
                currentDeviceEpoch: contribution.deviceEpoch,
                currentRecoveryEpoch: contribution.recoveryEpoch,
                signerIdentity: contribution.contributorIdentity,
            },
        ]),
    );
