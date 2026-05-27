import {
    lowerHexDigest,
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
    deriveProtocolDigest,
} from '#packages/crypto/src/index';
import {
    createPendingBridgeProofRecordFromBridgeEvidence,
    type PendingBridgeProofRecordFromEvidenceInput,
} from '#packages/protocol/src/ballot-privacy/aggregate-bridge/structure-verification.js';
import {
    deriveAggregateCommitmentBodyDigest,
    deriveAggregateDerivationBallotSetDigest,
    deriveAggregateDerivationStatementDigest,
    deriveAggregateShareCommitmentDigest,
} from '#packages/protocol/src/ballot-privacy/aggregate-derivation/digests';
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
    type ProtocolDigest,
    type ProtocolSignatureEnvelope,
    type RecoveryEpochMapEntry,
    type ShareCommitment,
} from '#packages/types/src/index';

const actionContextForContributor = (input: {
    readonly contributorIdentity: string;
    readonly contributorRosterExternalAcceptanceDigest: ProtocolDigest;
    readonly postVotingClosedContextDigest: ProtocolDigest;
    readonly statement: ClaimBearingBallotPackage['ballotProofStatement'];
}): ActionContext => {
    const contributorRosterPosition = Number(
        input.contributorIdentity.replace('receiver-', ''),
    );
    const actionContextPayload = {
        acceptedRecoveryEpochUpdateDigest: null,
        actionSequence: contributorRosterPosition,
        boardHeadDigest: lowerHexDigest('closed-board-head'),
        boardSequence: 7,
        ceremonyId: input.statement.ceremonyId,
        contextDigest: input.postVotingClosedContextDigest,
        deviceEpoch: 0,
        electionManifestDigest: input.statement.manifestDigest,
        recoveryEpoch: 0,
        recoveryPolicyDigest: lowerHexDigest('recovery-policy'),
        rosterExternalAcceptanceDigest:
            input.contributorRosterExternalAcceptanceDigest,
        signerIdentity: input.contributorIdentity,
    };

    return {
        ...actionContextPayload,
        actionContextDigest: deriveProtocolDigest(
            'ActionContextDigest',
            actionContextPayload,
        ),
    };
};

const signatureForContributor = (input: {
    readonly actionContext: ActionContext;
    readonly objectRoot: ProtocolDigest;
    readonly statement: ClaimBearingBallotPackage['ballotProofStatement'];
}): ProtocolSignatureEnvelope => {
    const keyFixture = createMlDsaKeyPairFixture(
        `aggregate-bridge-matrix-${input.actionContext.signerIdentity}`,
    );

    return createProtocolSignatureFixture({
        profile: createMlDsaSignatureProfileFixture(),
        publicKeyBytesHex: keyFixture.publicKeyBytesHex,
        publicKeyDigest: keyFixture.publicKeyDigest,
        secretKeyBytesHex: keyFixture.secretKeyBytesHex,
        signedRoot: {
            boardHeadDigest: input.actionContext.boardHeadDigest,
            byteLength: 64,
            ceremonyId: input.statement.ceremonyId,
            chunkMerkleRoot: null,
            contextDigest: input.actionContext.contextDigest,
            deviceEpoch: input.actionContext.deviceEpoch,
            manifestDigest: input.statement.manifestDigest,
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
        ballotPackageDigest: input.fixture.statement.ballotPackageDigest,
        ballotProof: {
            ballotProofRecordDigest: lowerHexDigest(
                `ballot-proof-record-${input.fixture.statement.ballotProofStatementDigest}`,
            ),
            ballotProofStatementDigest:
                input.fixture.statement.ballotProofStatementDigest,
            objectType: 'BallotProofRecord',
            objectVersion: 1,
            proofBackend: 'LocalLinearLatticeRelation',
            proofBytesDigest: lowerHexDigest('ballot-proof-bytes'),
            proofRoot: lowerHexDigest('ballot-proof-root'),
            proofSizeBytes: 1,
            relationStatementDigest: lowerHexDigest(
                'ballot-relation-statement',
            ),
        },
        ballotProofStatement: input.fixture.statement,
        componentBundleStatement:
            input.fixture.request.componentBundleStatement,
        componentProofBundle: {
            backendStatementDigest: lowerHexDigest('component-backend'),
            ballotProofStatementDigest:
                input.fixture.statement.ballotProofStatementDigest,
            bundleCoverage: 'full-encoded-score-ballot-relation',
            componentBundleStatementDigest: lowerHexDigest(
                'component-bundle-statement',
            ),
            componentProofBundleDigest: lowerHexDigest(
                'component-proof-bundle',
            ),
            componentProofs: [],
            objectType: 'BallotProofComponentProofBundle',
            objectVersion: 1,
            relationStatementDigest: lowerHexDigest('component-relation'),
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
        ballotPackageDigest: input.ballotPackage.ballotPackageDigest,
        ballotProofStatementDigest:
            input.ballotPackage.ballotProofStatement.ballotProofStatementDigest,
        receiverPayloadCiphertextRoot:
            payloadReference.receiverPayloadCiphertextRoot,
        receiverPayloadDigest: payloadReference.receiverPayloadDigest,
        shareCommitmentDigest: commitmentReference.shareCommitmentDigest,
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
    readonly closeRecordDigest: ProtocolDigest;
    readonly contributorActionContextDigest: ProtocolDigest;
    readonly contributorIdentity: string;
    readonly contributorRosterExternalAcceptanceDigest: ProtocolDigest;
    readonly contributorRosterPosition: number;
    readonly kernel: TranscriptCoreKernel;
    readonly postVotingClosedContextDigest: ProtocolDigest;
    readonly proverRandomnessHex: string;
    readonly unsafeSmallRosterAcknowledged: boolean;
    readonly votingClosedBoardHeadDigest: ProtocolDigest;
    readonly witness: AggregateDerivationWitnessInput;
}): AggregateDerivationComponent => {
    const statement = input.ballotPackage.ballotProofStatement;
    const shareCommitment = shareCommitmentForContributor({
        ballotPackage: input.ballotPackage,
        contributorIdentity: input.contributorIdentity,
        contributorRosterPosition: input.contributorRosterPosition,
    });
    const ballotSetDigest = deriveAggregateDerivationBallotSetDigest({
        ballotPackageDigests: [input.ballotPackage.ballotPackageDigest],
        closeRecordDigest: input.closeRecordDigest,
        manifestDigest: statement.manifestDigest,
        pollSpecDigest: statement.pollSpecDigest,
        postVotingClosedContextDigest: input.postVotingClosedContextDigest,
        rosterDigest: statement.rosterDigest,
        thresholdProfileDigest: statement.thresholdProfileDigest,
        votingClosedBoardHeadDigest: input.votingClosedBoardHeadDigest,
    });
    const commitmentBodyDigest = deriveAggregateCommitmentBodyDigest({
        commitmentPolynomialVector: shareCommitment.commitmentPolynomialVector,
        shareCommitmentProfileDigest: statement.shareCommitmentProfileDigest,
    });
    const commitmentPayload: Omit<
        AggregateShareCommitment,
        'aggregateShareCommitmentDigest'
    > = {
        ballotSetDigest,
        ceremonyId: statement.ceremonyId,
        commitmentBodyDigest,
        commitmentPolynomialVector: shareCommitment.commitmentPolynomialVector,
        contributorIdentity: input.contributorIdentity,
        contributorRosterPosition: input.contributorRosterPosition,
        manifestDigest: statement.manifestDigest,
        objectType: 'AggregateShareCommitment',
        objectVersion: 1,
        pollSpecDigest: statement.pollSpecDigest,
        rosterDigest: statement.rosterDigest,
        shareCommitmentProfileDigest: statement.shareCommitmentProfileDigest,
        shareVectorWidth: statement.shareVectorWidth,
    };
    const aggregateCommitment: AggregateShareCommitment = {
        ...commitmentPayload,
        aggregateShareCommitmentDigest:
            deriveAggregateShareCommitmentDigest(commitmentPayload),
    };
    const challengeDomainDigest = deriveProtocolDigest(
        'ChallengeDomainDigest',
        {
            aggregateDerivationProofEncodingProfileId,
            aggregateDerivationProofParameterProfileId,
            aggregateDerivationProofProfileId,
            aggregateShareCommitmentDigest:
                aggregateCommitment.aggregateShareCommitmentDigest,
            ballotSetDigest,
            purpose: 'aggregate-derivation-proof-challenge-v1',
            shareCommitmentMessageBoundCertDigest:
                input.certificate.shareCommitmentMessageBoundCertDigest,
        },
    );
    const statementPayload: Omit<
        AggregateDerivationStatement,
        'aggregateDerivationStatementDigest'
    > = {
        aggregateCommitmentDigest:
            aggregateCommitment.aggregateShareCommitmentDigest,
        aggregateInputEncodingProfileDigest:
            statement.aggregateInputEncodingProfileDigest,
        aggregateShareCommitmentDigest:
            aggregateCommitment.aggregateShareCommitmentDigest,
        ballotScoreEncodingProfileDigest:
            statement.ballotScoreEncodingProfileDigest,
        ballotSetDigest,
        ballotShareLayoutProfileDigest:
            statement.ballotShareLayoutProfileDigest,
        canonicalTurnout: 1,
        ceremonyId: statement.ceremonyId,
        challengeDomainDigest,
        closeRecordDigest: input.closeRecordDigest,
        contributorActionContextDigest: input.contributorActionContextDigest,
        contributorIdentity: input.contributorIdentity,
        contributorRosterExternalAcceptanceDigest:
            input.contributorRosterExternalAcceptanceDigest,
        contributorRosterPosition: input.contributorRosterPosition,
        encodedAggregateLayoutDigest: statement.encodedAggregateLayoutDigest,
        encodedShareVectorLayoutDigest:
            statement.encodedShareVectorLayoutDigest,
        manifestDigest: statement.manifestDigest,
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
        pollSpecDigest: statement.pollSpecDigest,
        postVotingClosedContextDigest: input.postVotingClosedContextDigest,
        proofEncodingProfileId: aggregateDerivationProofEncodingProfileId,
        proofParameterProfileId: aggregateDerivationProofParameterProfileId,
        proofProfileId: aggregateDerivationProofProfileId,
        receiverEncryptionProfileDigest:
            statement.receiverEncryptionProfileDigest,
        rosterDigest: statement.rosterDigest,
        shareCommitmentMessageBoundCertDigest:
            input.certificate.shareCommitmentMessageBoundCertDigest,
        shareCommitmentProfileDigest: statement.shareCommitmentProfileDigest,
        shareVectorWidth: statement.shareVectorWidth,
        thresholdProfileDigest: statement.thresholdProfileDigest,
        ...(input.unsafeSmallRosterAcknowledged
            ? { unsafeSmallRosterAcknowledged: true as const }
            : {}),
        votingClosedBoardHeadDigest: input.votingClosedBoardHeadDigest,
    };
    const aggregateStatement = {
        ...statementPayload,
        aggregateDerivationStatementDigest:
            deriveAggregateDerivationStatementDigest(statementPayload),
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
    readonly aggregateSelectionPolicyDigest: ProtocolDigest;
    readonly ballotPackage: ClaimBearingBallotPackage;
    readonly bridgeWitnessPrivacyProfileDigest: ProtocolDigest;
    readonly certificate: ReturnType<
        typeof createShareCommitmentMessageBoundCert
    >;
    readonly contributorRosterPosition: number;
    readonly heParamDigest: ProtocolDigest;
    readonly kernel: TranscriptCoreKernel;
    readonly setupPackage: Record<string, unknown>;
    readonly unsafeSmallRosterAcknowledged: boolean;
    readonly variant: Variant;
}): ContributionBuild => {
    const statement = input.ballotPackage.ballotProofStatement;
    const contributorIdentity = `receiver-${input.contributorRosterPosition}`;
    const contributorRosterExternalAcceptanceDigest =
        statement.rosterExternalAcceptanceDigest;
    const closeRecordDigest = deriveProtocolDigest('CloseRecordDigest', {
        ceremonyId: statement.ceremonyId,
        closeKind: 'VotingClosed',
        votingClosedBoardHeadDigest: lowerHexDigest('closed-board-head'),
    });
    const postVotingClosedContextDigest = deriveProtocolDigest(
        'PostVotingClosedContextDigest',
        {
            ceremonyId: statement.ceremonyId,
            closeRecordDigest,
            electionManifestDigest: statement.manifestDigest,
            votingClosedBoardHeadDigest: lowerHexDigest('closed-board-head'),
        },
    );
    const actionContext = actionContextForContributor({
        contributorIdentity,
        contributorRosterExternalAcceptanceDigest,
        postVotingClosedContextDigest,
        statement,
    });
    const aggregateWitness = aggregateWitnessForContributor({
        contributorRosterPosition: input.contributorRosterPosition,
        fixture: createVariantBallotProofRecordGenerationFixture({
            optionCount: input.variant.optionCount,
            rosterSize: input.variant.rosterSize,
        }),
    });
    const aggregateDerivationComponent = createAggregateComponentForContributor(
        {
            ballotPackage: input.ballotPackage,
            certificate: input.certificate,
            closeRecordDigest,
            contributorActionContextDigest: actionContext.actionContextDigest,
            contributorIdentity,
            contributorRosterExternalAcceptanceDigest,
            contributorRosterPosition: input.contributorRosterPosition,
            kernel: input.kernel,
            postVotingClosedContextDigest,
            proverRandomnessHex: '66'.repeat(32),
            unsafeSmallRosterAcknowledged: input.unsafeSmallRosterAcknowledged,
            votingClosedBoardHeadDigest: lowerHexDigest('closed-board-head'),
            witness: aggregateWitness,
        },
    );
    const bridgeGeneration = measure(() =>
        input.kernel.generateAggregateBridgeEncryption({
            aggregateDerivationComponent,
            aggregateSelectionPolicyDigest:
                input.aggregateSelectionPolicyDigest,
            aggregateWitness,
            bridgeWitnessPrivacyProfileDigest:
                input.bridgeWitnessPrivacyProfileDigest,
            heParamDigest: input.heParamDigest,
            includeCanonicalBytesHex: true,
            proverRandomnessHex: '77'.repeat(32),
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
            aggregateSelectionPolicyDigest:
                input.aggregateSelectionPolicyDigest,
            bridgeEncryption,
            bridgeWitnessPrivacyProfileDigest:
                input.bridgeWitnessPrivacyProfileDigest,
            heParamDigest: input.heParamDigest,
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
    const bridgeProofRecord = createPendingBridgeProofRecordFromBridgeEvidence({
        aggregateDerivationComponent,
        aggregateSelectionPolicyDigest: input.aggregateSelectionPolicyDigest,
        bridgeEncryptionEvidence:
            bridgeEncryption as PendingBridgeProofRecordFromEvidenceInput['bridgeEncryptionEvidence'],
        bridgeEvidenceVerification:
            bridgeVerificationResult as PendingBridgeProofRecordFromEvidenceInput['bridgeEvidenceVerification'],
        bridgeWitnessPrivacyProfileDigest:
            input.bridgeWitnessPrivacyProfileDigest,
        heParamDigest: input.heParamDigest,
        setupPackage:
            input.setupPackage as PendingBridgeProofRecordFromEvidenceInput['setupPackage'],
    });
    const aggregateContribution =
        createAggregateContributionFromBridgeProofRecord({
            actionContext,
            boardPosition: input.contributorRosterPosition,
            bridgeProofRecord,
            closeRecordDigest,
            signature: ({ aggregateContributionDigest }) =>
                signatureForContributor({
                    actionContext,
                    objectRoot: aggregateContributionDigest,
                    statement,
                }),
        });
    const contributionVerification = verifyAggregateContributionStructure(
        aggregateContribution,
    );
    if (!contributionVerification.ok) {
        throw new Error('Aggregate contribution structure did not verify.');
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
