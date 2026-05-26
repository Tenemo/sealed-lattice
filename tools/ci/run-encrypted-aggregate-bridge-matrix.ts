import { spawn } from 'node:child_process';
import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { performance } from 'node:perf_hooks';

import {
    canonicalJson,
    deriveProtocolDigest,
} from '#packages/crypto/src/index';
import {
    createPendingBridgeProofRecordFromBridgeEvidence,
    type PendingBridgeProofRecordFromEvidenceInput,
} from '#packages/protocol/src/ballot-privacy/aggregate-bridge/structure-verification';
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
    createAggregateReadyRecord,
    createBallotPrivacyProfileSet,
    createShareCommitmentMessageBoundCert,
    selectFirstValidAggregateContributions,
    verifyAggregateContributionStructure,
    verifyAggregateReadyRecordStructure,
    type AggregateDerivationWitnessInput,
} from '#packages/protocol/src/ballot-privacy/index';
import { deriveThresholdProfile } from '#packages/protocol/src/lifecycle/thresholds';
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
import { loadTranscriptCoreKernel } from '#packages/wasm/src/index';

type TranscriptCoreKernel = Awaited<
    ReturnType<typeof loadTranscriptCoreKernel>
>;

type MatrixMode =
    | 'axes'
    | 'full'
    | 'prototype'
    | 'representative'
    | 'sentinels';

type Variant = {
    readonly optionCount: number;
    readonly rosterSize: number;
};

type MatrixRow = {
    readonly aggregateCoordinateCount: number;
    readonly aggregateReadyVerificationTime: number;
    readonly claimTier: string;
    readonly ciphertextShape: Record<string, unknown>;
    readonly failureReason: string | null;
    readonly optionCount: number;
    readonly proofByteLength: number;
    readonly proverTime: number;
    readonly publicArtifactWitnessCleanResult: boolean;
    readonly rosterSize: number;
    readonly selectedContributionCount: number;
    readonly shareVectorWidth: number;
    readonly status: 'passed' | 'failed';
    readonly thresholdProfileHash: ProtocolDigest;
    readonly trusteeAggregateThreshold: number;
    readonly verifierTime: number;
};

type NegativeCheck = {
    readonly check: string;
    readonly expectedFailureObserved: boolean;
    readonly failureReason: string | null;
    readonly optionCount: number;
    readonly rosterSize: number;
    readonly suite: 'cheap' | 'sentinel';
};

type ContributionBuild = {
    readonly aggregateContribution: AggregateContribution;
    readonly aggregateDerivationComponent: AggregateDerivationComponent;
    readonly aggregateWitness: AggregateDerivationWitnessInput;
    readonly bridgeEncryption: Record<string, unknown>;
    readonly bridgeVerification: Record<string, unknown>;
    readonly proofByteLength: number;
    readonly proverTime: number;
    readonly verifierTime: number;
};

type VariantBuildResult = {
    readonly aggregateReadyRow: MatrixRow;
    readonly benchmarkRow: MatrixRow | null;
    readonly negativeChecks: readonly NegativeCheck[];
    readonly privateRelationRow: MatrixRow;
    readonly proofRow: MatrixRow;
};

type IndexedVariantBuildResult = VariantBuildResult & {
    readonly variantIndex: number;
};

const outputDirectory = path.join(process.cwd(), 'temp', 'm9');

const workerOutputPrefix = 'SEALED_LATTICE_M9_ROW_RESULT=';

const forbiddenPublicArtifactFieldNames = new Set([
    'aggregateInputPlaintext',
    'aggregateIntegerShareVector',
    'aggregateOpeningRandomness',
    'aggregateScore',
    'aggregateScoreBits',
    'aggregateShareWitness',
    'aggregateWitness',
    'bgvPlaintext',
    'comparisonInputs',
    'encryptionError',
    'encryptionNoise',
    'encryptionRandomizer',
    'encryptionRandomness',
    'layoutPlaintextWitness',
    'noiseWitness',
    'plaintextComparisonInputs',
    'plaintextScoreBitInputs',
    'quotientWitness',
    'rankWitness',
    'rawAggregateWitness',
    'receiverPlaintext',
    'sourceWitnessCoefficients',
    'tPvss',
    't_pvss',
]);

const publicArtifactIsWitnessClean = (value: unknown): boolean => {
    if (Array.isArray(value)) {
        return value.every(publicArtifactIsWitnessClean);
    }
    if (typeof value !== 'object' || value === null) {
        return true;
    }

    return Object.entries(value).every(
        ([fieldName, fieldValue]) =>
            !forbiddenPublicArtifactFieldNames.has(fieldName) &&
            publicArtifactIsWitnessClean(fieldValue),
    );
};

const sentinelVariants = new Set([
    '3:2',
    '3:20',
    '4:2',
    '9:20',
    '10:2',
    '10:20',
    '16:2',
    '16:20',
    '20:2',
    '20:20',
]);

const benchmarkVariantKeys = new Set(['20:20', '20:2', '3:2', '3:20', '10:20']);

const lowerHexDigest = (label: string): ProtocolDigest =>
    deriveProtocolDigest('ChallengeDomainDigest', {
        label,
        purpose: 'encrypted-aggregate-bridge-matrix',
    });

const variantKey = (variant: Variant): string =>
    `${variant.rosterSize}:${variant.optionCount}`;

const parseVariantKey = (key: string): Variant => {
    const [rosterSizeText, optionCountText] = key.split(':');
    const rosterSize = Number(rosterSizeText);
    const optionCount = Number(optionCountText);
    if (
        !Number.isInteger(rosterSize) ||
        !Number.isInteger(optionCount) ||
        rosterSize < 3 ||
        rosterSize > 20 ||
        optionCount < 2 ||
        optionCount > 20
    ) {
        throw new Error(
            `Invalid encrypted aggregate bridge variant key: ${key}`,
        );
    }

    return { optionCount, rosterSize };
};

const argumentValue = (name: string): string | null => {
    const argumentIndex = process.argv.indexOf(name);
    if (argumentIndex < 0) {
        return null;
    }
    const value = process.argv[argumentIndex + 1];
    if (value === undefined || value.startsWith('--')) {
        throw new Error(`Missing value for ${name}.`);
    }

    return value;
};

const matrixMode = (): MatrixMode => {
    if (process.argv.includes('--prototype')) {
        return 'prototype';
    }
    if (process.argv.includes('--axes')) {
        return 'axes';
    }
    if (process.argv.includes('--representative')) {
        return 'representative';
    }
    if (process.argv.includes('--sentinels')) {
        return 'sentinels';
    }

    return 'full';
};

const variantsForMode = (mode: MatrixMode): readonly Variant[] => {
    if (mode === 'prototype') {
        return [{ optionCount: 20, rosterSize: 20 }];
    }
    const variants = Array.from({ length: 18 }, (_unusedRoster, rosterIndex) =>
        Array.from({ length: 19 }, (_unusedOption, optionIndex) => ({
            optionCount: optionIndex + 2,
            rosterSize: rosterIndex + 3,
        })),
    ).flat();
    if (mode === 'axes') {
        return variants.filter(
            (variant) =>
                variant.rosterSize === 20 || variant.optionCount === 20,
        );
    }
    if (mode === 'representative' || mode === 'sentinels') {
        return variants.filter((variant) =>
            sentinelVariants.has(variantKey(variant)),
        );
    }

    return variants;
};

const requestedWorkerCount = (): number => {
    const argumentWorkerCount = argumentValue('--workers');
    const environmentWorkerCount = process.env.SEALED_LATTICE_M9_WORKERS;
    const rawWorkerCount = argumentWorkerCount ?? environmentWorkerCount ?? '1';
    const workerCount = Number(rawWorkerCount);
    if (!Number.isInteger(workerCount) || workerCount < 1) {
        throw new Error(`Invalid M9 worker count: ${rawWorkerCount}`);
    }

    return Math.min(workerCount, 40);
};

const claimTierForRosterSize = (rosterSize: number): string =>
    rosterSize < 10 ? 'micro-roster-outside-claim' : 'claim-candidate';

const measure = <Result>(
    action: () => Result,
): {
    readonly elapsedMilliseconds: number;
    readonly result: Result;
} => {
    const startedAt = performance.now();
    const result = action();

    return {
        elapsedMilliseconds: performance.now() - startedAt,
        result,
    };
};

const roundedMilliseconds = (milliseconds: number): number =>
    Math.round(milliseconds);

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
    readonly statement: ClaimBearingBallotPackage['ballotProofStatement'];
}): ProtocolSignatureEnvelope => ({
    profile: {
        algorithm: 'ML-DSA-65',
        contextString: 'sealed-lattice-matrix',
        contextStringByteLength: 'sealed-lattice-matrix'.length,
        errataStatus: 'test-fixture',
        fips204Version: 'FIPS 204',
        mode: 'PureMLDSA',
        providerBuildDigest: lowerHexDigest('signature-provider-build'),
        providerName: 'sealed-lattice-fixture-provider',
        providerVersion: '0.0.0',
    },
    publicKeyBytesHex: '00'.repeat(32),
    publicKeyDigest: lowerHexDigest(
        `signature-public-key-${input.actionContext.signerIdentity}`,
    ),
    signatureBytesHex: '11'.repeat(64),
    signatureDigest: lowerHexDigest(
        `signature-${input.actionContext.signerIdentity}`,
    ),
    signedRoot: {
        boardHeadDigest: input.actionContext.boardHeadDigest,
        byteLength: 0,
        ceremonyId: input.statement.ceremonyId,
        chunkMerkleRoot: null,
        contextDigest: input.actionContext.contextDigest,
        deviceEpoch: input.actionContext.deviceEpoch,
        manifestDigest: input.statement.manifestDigest,
        objectRoot: lowerHexDigest(
            `aggregate-contribution-signed-root-${input.actionContext.signerIdentity}`,
        ),
        objectType: 'AggregateContribution',
        objectVersion: 1,
        recoveryEpoch: input.actionContext.recoveryEpoch,
        signerIdentity: input.actionContext.signerIdentity,
        signerRole: 'Trustee',
    },
});

const createSyntheticBallotPackageShell = (input: {
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

const setupParticipants = (
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

const createContribution = (input: {
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
            signature: signatureForContributor({ actionContext, statement }),
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

const currentRecoveryEpochMap = (
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

const assertFailure = (action: () => unknown): string | null => {
    try {
        const result = action();
        if (
            typeof result === 'object' &&
            result !== null &&
            'ok' in result &&
            (result as { readonly ok?: unknown }).ok === false
        ) {
            return null;
        }

        return 'mutation unexpectedly passed';
    } catch {
        return null;
    }
};

const mutateLastHexDigit = (value: unknown): string => {
    const hex = String(value);
    const replacement = hex.endsWith('0') ? '1' : '0';

    return `${hex.slice(0, -1)}${replacement}`;
};

const bridgeWithMutatedProof = (
    bridgeEncryption: Record<string, unknown>,
    proofMutator: (proof: Record<string, unknown>) => void,
): Record<string, unknown> => {
    const proof = JSON.parse(
        Buffer.from(
            String(bridgeEncryption.bridgeProofBytesHex),
            'hex',
        ).toString('utf8'),
    ) as Record<string, unknown>;
    proofMutator(proof);
    const bridgeProofBytesHex = Buffer.from(
        canonicalJson(proof),
        'utf8',
    ).toString('hex');
    const bridgeProofBytesDigest = deriveProtocolDigest('ProofBytesDigest', {
        proofBytesHex: bridgeProofBytesHex,
        purpose: 'm9-bridge-encryption-proof-bytes-v1',
    });

    return {
        ...bridgeEncryption,
        bridgeProofBytesHex,
        bridgeProofBytesDigest,
        bridgeProofRoot: deriveProtocolDigest('BridgeProofRecordDigest', {
            aggregateDerivationComponentDigest:
                bridgeEncryption.aggregateDerivationComponentDigest,
            aggregateDerivationStatementDigest:
                bridgeEncryption.aggregateDerivationStatementDigest,
            bgvPublicKeyRoot: bridgeEncryption.bgvPublicKeyRoot,
            bridgeProofProfileDigest: bridgeEncryption.bridgeProofProfileDigest,
            bridgeProofStatementDigest:
                bridgeEncryption.bridgeProofStatementDigest,
            collectivePublicKeyRoot: bridgeEncryption.collectivePublicKeyRoot,
            encryptedAggregateShareCiphertextRoot:
                bridgeEncryption.encryptedAggregateShareCiphertextRoot,
            proofBytesDigest: bridgeProofBytesDigest,
            purpose: 'm9-bridge-encryption-proof-root-v1',
        }),
    };
};

const runCheapNegativeChecks = (input: {
    readonly aggregateSelectionPolicyDigest: ProtocolDigest;
    readonly bridgeWitnessPrivacyProfileDigest: ProtocolDigest;
    readonly contribution: ContributionBuild;
    readonly heParamDigest: ProtocolDigest;
    readonly kernel: TranscriptCoreKernel;
    readonly setupPackage: Record<string, unknown>;
    readonly variant: Variant;
}): readonly NegativeCheck[] => {
    const base = {
        optionCount: input.variant.optionCount,
        rosterSize: input.variant.rosterSize,
        suite: 'cheap' as const,
    };
    const verifyBridge = (
        aggregateDerivationComponent: unknown,
        bridgeEncryption: unknown,
        setupPackage: unknown,
        aggregateSelectionPolicyDigest = input.aggregateSelectionPolicyDigest,
    ): unknown =>
        input.kernel.verifyAggregateBridgeEncryption({
            aggregateDerivationComponent,
            aggregateSelectionPolicyDigest,
            bridgeEncryption,
            bridgeWitnessPrivacyProfileDigest:
                input.bridgeWitnessPrivacyProfileDigest,
            heParamDigest: input.heParamDigest,
            setupPackage,
        });
    const component = input.contribution.aggregateDerivationComponent;
    const bridgeEncryption = input.contribution.bridgeEncryption;
    const checks: readonly [string, () => unknown][] = [
        [
            'wrong n',
            () =>
                verifyBridge(
                    {
                        ...component,
                        statement: {
                            ...component.statement,
                            participantCount:
                                component.statement.participantCount + 1,
                        },
                    },
                    bridgeEncryption,
                    input.setupPackage,
                ),
        ],
        [
            'wrong m',
            () =>
                verifyBridge(
                    {
                        ...component,
                        statement: {
                            ...component.statement,
                            optionCount: component.statement.optionCount + 1,
                        },
                    },
                    bridgeEncryption,
                    input.setupPackage,
                ),
        ],
        [
            'wrong shareVectorWidth',
            () =>
                verifyBridge(
                    {
                        ...component,
                        statement: {
                            ...component.statement,
                            shareVectorWidth:
                                component.statement.shareVectorWidth + 1,
                        },
                    },
                    bridgeEncryption,
                    input.setupPackage,
                ),
        ],
        [
            'wrong threshold profile hash',
            () =>
                verifyBridge(component, bridgeEncryption, {
                    ...input.setupPackage,
                    setupInputs: {
                        ...(input.setupPackage.setupInputs as Record<
                            string,
                            unknown
                        >),
                        thresholdProfileDigest: lowerHexDigest(
                            'wrong-threshold-profile',
                        ),
                    },
                }),
        ],
        [
            'wrong contributor index',
            () =>
                verifyBridge(
                    {
                        ...component,
                        statement: {
                            ...component.statement,
                            contributorRosterPosition:
                                component.statement.contributorRosterPosition +
                                1,
                        },
                    },
                    bridgeEncryption,
                    input.setupPackage,
                ),
        ],
        [
            'wrong BGV profile hash',
            () =>
                verifyBridge(
                    component,
                    {
                        ...bridgeEncryption,
                        profileDigest: lowerHexDigest('wrong-bgv-profile'),
                    },
                    input.setupPackage,
                ),
        ],
        [
            'wrong public key root',
            () =>
                verifyBridge(
                    component,
                    {
                        ...bridgeEncryption,
                        bgvPublicKeyRoot: lowerHexDigest('wrong-bgv-key'),
                    },
                    input.setupPackage,
                ),
        ],
        [
            'wrong aggregate input layout hash',
            () =>
                verifyBridge(component, bridgeEncryption, {
                    ...input.setupPackage,
                    profileBindings: {
                        ...(input.setupPackage.profileBindings as Record<
                            string,
                            unknown
                        >),
                        encryptedAggregateInputLayoutDigest:
                            lowerHexDigest('wrong-layout'),
                    },
                }),
        ],
        [
            'wrong VotingClosed hash',
            () =>
                verifyBridge(
                    {
                        ...component,
                        statement: {
                            ...component.statement,
                            votingClosedBoardHeadDigest:
                                lowerHexDigest('wrong-board-head'),
                        },
                    },
                    bridgeEncryption,
                    input.setupPackage,
                ),
        ],
        [
            'wrong selected ballot set hash',
            () =>
                verifyBridge(
                    {
                        ...component,
                        statement: {
                            ...component.statement,
                            ballotSetDigest: lowerHexDigest('wrong-ballot-set'),
                        },
                    },
                    bridgeEncryption,
                    input.setupPackage,
                ),
        ],
        [
            'pending bridge record selected',
            () =>
                createAggregateContributionFromBridgeProofRecord({
                    actionContext:
                        input.contribution.aggregateContribution.actionContext,
                    boardPosition:
                        input.contribution.aggregateContribution.boardPosition,
                    bridgeProofRecord: {
                        ...input.contribution.aggregateContribution
                            .bridgeProofRecord,
                        bridgeProofVerificationStatus:
                            'BridgeProofBackendPending',
                    },
                    closeRecordDigest:
                        input.contribution.aggregateContribution
                            .closeRecordDigest,
                    signature:
                        input.contribution.aggregateContribution.signature,
                }),
        ],
        [
            'sampled-only bridge evidence accepted',
            () =>
                verifyBridge(
                    component,
                    {
                        ...bridgeEncryption,
                        bridgeProofVerificationStatus:
                            'BridgeProofBackendPending',
                    },
                    input.setupPackage,
                ),
        ],
        [
            'witness disclosure flag present',
            () =>
                verifyBridge(
                    component,
                    {
                        ...bridgeEncryption,
                        bgvPlaintext: [1, 2, 3],
                    },
                    input.setupPackage,
                ),
        ],
    ];

    return checks.map(([check, action]) => {
        const failureReason = assertFailure(action);

        return {
            ...base,
            check,
            expectedFailureObserved: failureReason === null,
            failureReason,
        };
    });
};

const runSentinelNegativeChecks = (input: {
    readonly aggregateSelectionPolicyDigest: ProtocolDigest;
    readonly bridgeWitnessPrivacyProfileDigest: ProtocolDigest;
    readonly contribution: ContributionBuild;
    readonly heParamDigest: ProtocolDigest;
    readonly kernel: TranscriptCoreKernel;
    readonly setupPackage: Record<string, unknown>;
    readonly variant: Variant;
}): readonly NegativeCheck[] => {
    const base = {
        optionCount: input.variant.optionCount,
        rosterSize: input.variant.rosterSize,
        suite: 'sentinel' as const,
    };
    const verifyMutatedProof = (
        check: string,
        proofMutator: (proof: Record<string, unknown>) => void,
    ): NegativeCheck => {
        const mutatedBridge = bridgeWithMutatedProof(
            input.contribution.bridgeEncryption,
            proofMutator,
        );
        const failureReason = assertFailure(() =>
            input.kernel.verifyAggregateBridgeEncryption({
                aggregateDerivationComponent:
                    input.contribution.aggregateDerivationComponent,
                aggregateSelectionPolicyDigest:
                    input.aggregateSelectionPolicyDigest,
                bridgeEncryption: mutatedBridge,
                bridgeWitnessPrivacyProfileDigest:
                    input.bridgeWitnessPrivacyProfileDigest,
                heParamDigest: input.heParamDigest,
                setupPackage: input.setupPackage,
            }),
        );

        return {
            ...base,
            check,
            expectedFailureObserved: failureReason === null,
            failureReason,
        };
    };
    const verifyMutatedPublicInput = (
        check: string,
        mutation: {
            readonly aggregateDerivationComponent?: unknown;
            readonly bridgeEncryption?: unknown;
            readonly setupPackage?: unknown;
        },
    ): NegativeCheck => {
        const failureReason = assertFailure(() =>
            input.kernel.verifyAggregateBridgeEncryption({
                aggregateDerivationComponent:
                    mutation.aggregateDerivationComponent ??
                    input.contribution.aggregateDerivationComponent,
                aggregateSelectionPolicyDigest:
                    input.aggregateSelectionPolicyDigest,
                bridgeEncryption:
                    mutation.bridgeEncryption ??
                    input.contribution.bridgeEncryption,
                bridgeWitnessPrivacyProfileDigest:
                    input.bridgeWitnessPrivacyProfileDigest,
                heParamDigest: input.heParamDigest,
                setupPackage: mutation.setupPackage ?? input.setupPackage,
            }),
        );

        return {
            ...base,
            check,
            expectedFailureObserved: failureReason === null,
            failureReason,
        };
    };
    const mutateSharedWitnessResponse =
        (fieldName: string): ((proof: Record<string, unknown>) => void) =>
        (proof) => {
            const sharedProof = proof.bridgeSharedWitnessProof as {
                readonly checks: Record<string, unknown>[];
            };
            sharedProof.checks[0][fieldName] = mutateLastHexDigit(
                sharedProof.checks[0][fieldName],
            );
        };
    const checks = [
        verifyMutatedProof(
            'wrong M6 opening',
            mutateSharedWitnessResponse('aggregateOpeningResponseHex'),
        ),
        verifyMutatedProof(
            'wrong reduced coordinate',
            mutateSharedWitnessResponse('aggregateReducedResponseHex'),
        ),
        verifyMutatedProof(
            'wrong quotient',
            mutateSharedWitnessResponse('aggregateQuotientResponseHex'),
        ),
        verifyMutatedPublicInput('wrong quotient bound', {
            aggregateDerivationComponent: {
                ...input.contribution.aggregateDerivationComponent,
                shareCommitmentMessageBoundCert: {
                    ...input.contribution.aggregateDerivationComponent
                        .shareCommitmentMessageBoundCert,
                    quotientBoundForAggregateReduction:
                        input.contribution.aggregateDerivationComponent
                            .shareCommitmentMessageBoundCert
                            .quotientBoundForAggregateReduction + 1,
                },
            },
        }),
        verifyMutatedProof(
            'wrong encoded coordinate order',
            mutateSharedWitnessResponse('aggregateShareResponseHex'),
        ),
        verifyMutatedProof('wrong slot layout', (proof) => {
            const statement = proof.bridgeProofStatement as Record<
                string,
                unknown
            >;
            statement.bridgeLayoutDigest = lowerHexDigest('wrong-slot-layout');
        }),
        verifyMutatedProof(
            'wrong batch encoding',
            mutateSharedWitnessResponse('batchCoefficientResponseHex'),
        ),
        verifyMutatedProof('wrong plaintext polynomial', (proof) => {
            proof.plaintextRoot = lowerHexDigest('wrong-plaintext-polynomial');
        }),
        verifyMutatedPublicInput('wrong RNS limb', {
            bridgeEncryption: {
                ...input.contribution.bridgeEncryption,
                canonicalBytesHex: mutateLastHexDigit(
                    input.contribution.bridgeEncryption.canonicalBytesHex,
                ),
            },
        }),
        verifyMutatedPublicInput('wrong ciphertext component', {
            bridgeEncryption: {
                ...input.contribution.bridgeEncryption,
                ciphertextRoot: lowerHexDigest('wrong-ciphertext-component'),
            },
        }),
        verifyMutatedProof(
            'wrong encryption randomness',
            mutateSharedWitnessResponse('cipherRandomizerResponseHex'),
        ),
        verifyMutatedProof(
            'wrong noise bound',
            mutateSharedWitnessResponse('boundedPerturbationZeroResponseHex'),
        ),
        verifyMutatedPublicInput('wrong collective public key', {
            setupPackage: {
                ...input.setupPackage,
                collectivePublicKey: {
                    ...(input.setupPackage.collectivePublicKey as Record<
                        string,
                        unknown
                    >),
                    collectivePublicKeyRoot: lowerHexDigest(
                        'wrong-collective-public-key',
                    ),
                },
            },
        }),
        verifyMutatedPublicInput('wrong setup root', {
            setupPackage: {
                ...input.setupPackage,
                setupPackageDigest: lowerHexDigest('wrong-setup-package'),
            },
        }),
        verifyMutatedPublicInput('wrong board context', {
            aggregateDerivationComponent: {
                ...input.contribution.aggregateDerivationComponent,
                statement: {
                    ...input.contribution.aggregateDerivationComponent
                        .statement,
                    votingClosedBoardHeadDigest: lowerHexDigest(
                        'wrong-board-context',
                    ),
                },
            },
        }),
        verifyMutatedPublicInput('wrong action context', {
            aggregateDerivationComponent: {
                ...input.contribution.aggregateDerivationComponent,
                statement: {
                    ...input.contribution.aggregateDerivationComponent
                        .statement,
                    contributorActionContextDigest: lowerHexDigest(
                        'wrong-action-context',
                    ),
                },
            },
        }),
        verifyMutatedProof(
            'same M6 subproof but different BGV plaintext',
            (proof) => {
                proof.plaintextRoot = lowerHexDigest('wrong-plaintext-root');
            },
        ),
        verifyMutatedProof(
            'same BGV ciphertext but different M6 commitment',
            (proof) => {
                proof.aggregateRelationCommitmentDigest = lowerHexDigest(
                    'wrong-aggregate-relation',
                );
            },
        ),
        verifyMutatedProof('forged BridgeProofRelationChecked', (proof) => {
            proof.bridgeSharedWitnessProof = {
                objectType: 'AggregateBridgeSharedWitnessProof',
            };
        }),
        verifyMutatedProof(
            'witness field included in public artifact',
            (proof) => {
                proof.aggregateIntegerShareVector = [1, 2, 3];
            },
        ),
    ];

    return checks;
};

const runSelectionNegativeChecks = (input: {
    readonly aggregateSelectionPolicyDigest: ProtocolDigest;
    readonly postVotingClosedContextDigest: ProtocolDigest;
    readonly selectedContributionRecords: readonly AggregateContribution[];
    readonly trusteeAggregateThreshold: number;
    readonly variant: Variant;
}): readonly NegativeCheck[] => {
    const remainingContributions = input.selectedContributionRecords.slice(1);
    const failureReason = assertFailure(() =>
        selectFirstValidAggregateContributions({
            aggregateContributionQuorum: input.trusteeAggregateThreshold,
            contributions: remainingContributions,
            currentRecoveryEpochMap: currentRecoveryEpochMap(
                remainingContributions,
            ),
            expectedAggregateSelectionPolicyDigest:
                input.aggregateSelectionPolicyDigest,
            requiredPostVotingClosedContextDigest:
                input.postVotingClosedContextDigest,
        }),
    );

    return [
        {
            check: 'wrong selected contributor set',
            expectedFailureObserved: failureReason === null,
            failureReason,
            optionCount: input.variant.optionCount,
            rosterSize: input.variant.rosterSize,
            suite: 'cheap',
        },
    ];
};

const buildVariant = (input: {
    readonly kernel: TranscriptCoreKernel;
    readonly variant: Variant;
}): VariantBuildResult => {
    const thresholdProfile = deriveThresholdProfile({
        casualMicroRosterAcknowledged: input.variant.rosterSize < 10,
        rosterSize: input.variant.rosterSize,
    });
    const trusteeAggregateThreshold = thresholdProfile.pvssThreshold;
    const fixture = createVariantBallotProofRecordGenerationFixture({
        optionCount: input.variant.optionCount,
        rosterSize: input.variant.rosterSize,
    });
    const ballotPackage = createSyntheticBallotPackageShell({ fixture });
    const profileSet = createBallotPrivacyProfileSet({
        optionCount: input.variant.optionCount,
    });
    const certificate = createShareCommitmentMessageBoundCert({
        maximumCanonicalTurnout: 20,
        shareCommitmentProfile: profileSet.shareCommitmentProfile,
    });
    const setupPackage = input.kernel.generateBgvPassiveSetup({
        ceremonyId: fixture.statement.ceremonyId,
        manifestDigest: fixture.statement.manifestDigest,
        participants: setupParticipants(input.variant.rosterSize),
        rosterDigest: fixture.statement.rosterDigest,
        setupSeed: `encrypted-aggregate-bridge-${variantKey(input.variant)}`,
        thresholdProfileDigest: fixture.statement.thresholdProfileDigest,
    }) as Record<string, unknown>;
    if (setupPackage.ok === false) {
        throw new Error(
            `Setup generation failed: ${canonicalJson(setupPackage)}`,
        );
    }
    const aggregateSelectionPolicyDigest = deriveProtocolDigest(
        'AggregateSelectionPolicyDigest',
        {
            optionCount: input.variant.optionCount,
            purpose: 'encrypted-aggregate-bridge-selection-policy-v1',
            rosterSize: input.variant.rosterSize,
            thresholdProfileDigest: fixture.statement.thresholdProfileDigest,
        },
    );
    const bridgeWitnessPrivacyProfileDigest = deriveProtocolDigest(
        'BridgeWitnessPrivacyProfileDigest',
        {
            optionCount: input.variant.optionCount,
            purpose: 'encrypted-aggregate-bridge-witness-privacy-v1',
            rosterSize: input.variant.rosterSize,
        },
    );
    const heParamDigest = deriveProtocolDigest('HEParamDigest', {
        optionCount: input.variant.optionCount,
        purpose: 'encrypted-aggregate-bridge-he-param-v1',
        rosterSize: input.variant.rosterSize,
    });
    const contributions = Array.from(
        { length: trusteeAggregateThreshold },
        (_unusedValue, contributorIndex) =>
            createContribution({
                aggregateSelectionPolicyDigest,
                ballotPackage,
                bridgeWitnessPrivacyProfileDigest,
                certificate,
                contributorRosterPosition: contributorIndex + 1,
                heParamDigest,
                kernel: input.kernel,
                setupPackage,
                unsafeSmallRosterAcknowledged: input.variant.rosterSize < 10,
                variant: input.variant,
            }),
    );
    const selectedContributionRecords = contributions.map(
        (contribution) => contribution.aggregateContribution,
    );
    const selection = selectFirstValidAggregateContributions({
        aggregateContributionQuorum: trusteeAggregateThreshold,
        contributions: selectedContributionRecords,
        currentRecoveryEpochMap: currentRecoveryEpochMap(
            selectedContributionRecords,
        ),
        expectedAggregateSelectionPolicyDigest: aggregateSelectionPolicyDigest,
        requiredPostVotingClosedContextDigest:
            selectedContributionRecords[0].postVotingClosedContextDigest,
    });
    if (!selection.ok || selection.firstValidOrderDigest === undefined) {
        throw new Error(
            `Contribution selection failed: ${canonicalJson(selection)}`,
        );
    }
    const firstValidOrderDigest = selection.firstValidOrderDigest;
    const aggregateReadyMeasurement = measure(() =>
        createAggregateReadyRecord({
            aggregateContributionQuorum: trusteeAggregateThreshold,
            firstValidOrderDigest,
            rosterSize: input.variant.rosterSize,
            selectedContributions: selection.selectedContributions,
        }),
    );
    const aggregateReadyVerificationMeasurement = measure(() =>
        verifyAggregateReadyRecordStructure(aggregateReadyMeasurement.result),
    );
    if (!aggregateReadyVerificationMeasurement.result.ok) {
        throw new Error(
            `Aggregate-ready verification failed: ${canonicalJson(
                aggregateReadyVerificationMeasurement.result,
            )}`,
        );
    }
    const firstBridge = contributions[0].bridgeEncryption;
    const rowBase = {
        aggregateCoordinateCount: fixture.statement.shareVectorWidth,
        aggregateReadyVerificationTime: roundedMilliseconds(
            aggregateReadyVerificationMeasurement.elapsedMilliseconds,
        ),
        claimTier: claimTierForRosterSize(input.variant.rosterSize),
        ciphertextShape: {
            basisId: firstBridge.basisId,
            canonicalByteLength: firstBridge.canonicalByteLength,
            coefficientCount: firstBridge.coefficientCount,
            level: firstBridge.level,
            slotCount: firstBridge.slotCount,
        },
        failureReason: null,
        optionCount: input.variant.optionCount,
        proofByteLength: contributions.reduce(
            (sum, contribution) => sum + contribution.proofByteLength,
            0,
        ),
        proverTime: contributions.reduce(
            (sum, contribution) =>
                sum + roundedMilliseconds(contribution.proverTime),
            0,
        ),
        publicArtifactWitnessCleanResult: publicArtifactIsWitnessClean({
            aggregateReadyRecord: aggregateReadyMeasurement.result,
            bridgeEncryption: contributions.map(
                (contribution) => contribution.bridgeEncryption,
            ),
            contributions: selectedContributionRecords,
        }),
        rosterSize: input.variant.rosterSize,
        selectedContributionCount: trusteeAggregateThreshold,
        shareVectorWidth: fixture.statement.shareVectorWidth,
        status: 'passed' as const,
        thresholdProfileHash: fixture.statement.thresholdProfileDigest,
        trusteeAggregateThreshold,
        verifierTime: contributions.reduce(
            (sum, contribution) =>
                sum + roundedMilliseconds(contribution.verifierTime),
            0,
        ),
    };
    const privateRelationMeasurement = measure(() =>
        input.kernel.evaluateAggregateBridgeRelation({
            aggregateDerivationComponent:
                contributions[0].aggregateDerivationComponent,
            aggregateSelectionPolicyDigest,
            aggregateWitness: contributions[0].aggregateWitness,
            bridgeEncryption: contributions[0].bridgeEncryption,
            bridgeWitnessPrivacyProfileDigest,
            heParamDigest,
            proverRandomnessHex: '77'.repeat(32),
            setupPackage,
        }),
    );
    const privateRelation = privateRelationMeasurement.result as Record<
        string,
        unknown
    >;
    if (privateRelation.ok !== true) {
        throw new Error(
            `Private bridge relation failed: ${canonicalJson(privateRelation)}`,
        );
    }
    const negativeChecks = [
        ...runCheapNegativeChecks({
            aggregateSelectionPolicyDigest,
            bridgeWitnessPrivacyProfileDigest,
            contribution: contributions[0],
            heParamDigest,
            kernel: input.kernel,
            setupPackage,
            variant: input.variant,
        }),
        ...runSelectionNegativeChecks({
            aggregateSelectionPolicyDigest,
            postVotingClosedContextDigest:
                selectedContributionRecords[0].postVotingClosedContextDigest,
            selectedContributionRecords,
            trusteeAggregateThreshold,
            variant: input.variant,
        }),
        ...(sentinelVariants.has(variantKey(input.variant))
            ? runSentinelNegativeChecks({
                  aggregateSelectionPolicyDigest,
                  bridgeWitnessPrivacyProfileDigest,
                  contribution: contributions[0],
                  heParamDigest,
                  kernel: input.kernel,
                  setupPackage,
                  variant: input.variant,
              })
            : []),
    ];

    return {
        aggregateReadyRow: {
            ...rowBase,
            aggregateReadyVerificationTime: roundedMilliseconds(
                aggregateReadyVerificationMeasurement.elapsedMilliseconds,
            ),
        },
        benchmarkRow: benchmarkVariantKeys.has(variantKey(input.variant))
            ? rowBase
            : null,
        negativeChecks,
        privateRelationRow: {
            ...rowBase,
            proverTime: roundedMilliseconds(
                privateRelationMeasurement.elapsedMilliseconds,
            ),
            verifierTime: 0,
        },
        proofRow: rowBase,
    };
};

const failedRow = (variant: Variant, failureReason: unknown): MatrixRow => {
    const thresholdProfile = deriveThresholdProfile({
        casualMicroRosterAcknowledged: variant.rosterSize < 10,
        rosterSize: variant.rosterSize,
    });

    return {
        aggregateCoordinateCount: variant.optionCount * 11,
        aggregateReadyVerificationTime: 0,
        claimTier: claimTierForRosterSize(variant.rosterSize),
        ciphertextShape: {},
        failureReason:
            failureReason instanceof Error
                ? failureReason.message
                : String(failureReason),
        optionCount: variant.optionCount,
        proofByteLength: 0,
        proverTime: 0,
        publicArtifactWitnessCleanResult: false,
        rosterSize: variant.rosterSize,
        selectedContributionCount: thresholdProfile.pvssThreshold,
        shareVectorWidth: variant.optionCount * 11,
        status: 'failed',
        thresholdProfileHash: lowerHexDigest(
            `failed-threshold-${variantKey(variant)}`,
        ),
        trusteeAggregateThreshold: thresholdProfile.pvssThreshold,
        verifierTime: 0,
    };
};

const matrixMarkdown = (input: {
    readonly title: string;
    readonly rows: readonly MatrixRow[];
}): string => {
    const lines = [
        `# ${input.title}`,
        '',
        '| n | m | claim tier | t_pvss | selected | shareVectorWidth | aggregate coordinates | proof bytes | prover ms | verifier ms | aggregate-ready verifier ms | witness-clean | status | failure reason |',
        '| -: | -: | - | -: | -: | -: | -: | -: | -: | -: | -: | - | - | - |',
        ...input.rows.map((row) =>
            [
                row.rosterSize,
                row.optionCount,
                row.claimTier,
                row.trusteeAggregateThreshold,
                row.selectedContributionCount,
                row.shareVectorWidth,
                row.aggregateCoordinateCount,
                row.proofByteLength,
                row.proverTime.toFixed(1),
                row.verifierTime.toFixed(1),
                row.aggregateReadyVerificationTime.toFixed(1),
                row.publicArtifactWitnessCleanResult ? 'passed' : 'failed',
                row.status,
                row.failureReason ?? '',
            ].join(' | '),
        ),
    ];

    return `${lines.join('\n')}\n`;
};

const negativeMarkdown = (checks: readonly NegativeCheck[]): string => {
    const lines = [
        '# Encrypted aggregate bridge negative fixture report',
        '',
        '| n | m | suite | check | expected failure observed | failure reason |',
        '| -: | -: | - | - | - | - |',
        ...checks.map((check) =>
            [
                check.rosterSize,
                check.optionCount,
                check.suite,
                check.check,
                check.expectedFailureObserved ? 'yes' : 'no',
                check.failureReason ?? '',
            ].join(' | '),
        ),
    ];

    return `${lines.join('\n')}\n`;
};

const writeArtifact = async (
    fileName: string,
    content: string,
): Promise<void> => {
    await writeFile(path.join(outputDirectory, fileName), content, 'utf8');
};

const failedVariantResult = (
    variant: Variant,
    failureReason: unknown,
): VariantBuildResult => {
    const row = failedRow(variant, failureReason);

    return {
        aggregateReadyRow: row,
        benchmarkRow: null,
        negativeChecks: [],
        privateRelationRow: row,
        proofRow: row,
    };
};

const runWorkerRow = async (): Promise<boolean> => {
    const workerRowKey = argumentValue('--worker-row');
    if (workerRowKey === null) {
        return false;
    }

    const variant = parseVariantKey(workerRowKey);
    const kernel = await loadTranscriptCoreKernel();
    const result = (() => {
        try {
            return buildVariant({ kernel, variant });
        } catch (error) {
            return failedVariantResult(variant, error);
        }
    })();
    console.log(`${workerOutputPrefix}${canonicalJson(result)}`);

    return true;
};

const runVariantInChildProcess = async (
    variant: Variant,
): Promise<VariantBuildResult> =>
    new Promise((resolve) => {
        const packageManagerCli = process.env.npm_execpath;
        const scriptPath = path.resolve(
            process.cwd(),
            'tools',
            'ci',
            'run-encrypted-aggregate-bridge-matrix.ts',
        );
        const workerArguments =
            packageManagerCli === undefined || packageManagerCli.length === 0
                ? [
                      path.resolve(
                          process.cwd(),
                          'node_modules',
                          'tsx',
                          'dist',
                          'cli.mjs',
                      ),
                      scriptPath,
                      '--worker-row',
                      variantKey(variant),
                  ]
                : [
                      packageManagerCli,
                      'exec',
                      'tsx',
                      scriptPath,
                      '--worker-row',
                      variantKey(variant),
                  ];
        const childProcess = spawn(process.execPath, workerArguments, {
            cwd: process.cwd(),
            env: {
                ...process.env,
                SEALED_LATTICE_M9_WORKERS: '1',
            },
            stdio: ['ignore', 'pipe', 'pipe'],
        });
        let standardOutput = '';
        let standardError = '';
        childProcess.stdout.setEncoding('utf8');
        childProcess.stderr.setEncoding('utf8');
        childProcess.stdout.on('data', (chunk: string) => {
            standardOutput += chunk;
        });
        childProcess.stderr.on('data', (chunk: string) => {
            standardError += chunk;
            process.stderr.write(chunk);
        });
        childProcess.on('error', (error) => {
            resolve(failedVariantResult(variant, error));
        });
        childProcess.on('close', (exitCode) => {
            const resultLine = standardOutput
                .split(/\r?\n/u)
                .find((line) => line.startsWith(workerOutputPrefix));
            if (resultLine === undefined) {
                resolve(
                    failedVariantResult(
                        variant,
                        `M9 worker exited with code ${String(exitCode)} without row output. ${standardError.slice(-2000)}`,
                    ),
                );

                return;
            }

            try {
                resolve(
                    JSON.parse(
                        resultLine.slice(workerOutputPrefix.length),
                    ) as VariantBuildResult,
                );
            } catch (error) {
                resolve(failedVariantResult(variant, error));
            }
        });
    });

const runSequentialVariantBuilds = async (
    variants: readonly Variant[],
): Promise<readonly IndexedVariantBuildResult[]> => {
    const kernel = await loadTranscriptCoreKernel();
    const results: IndexedVariantBuildResult[] = [];
    for (const [variantIndex, variant] of variants.entries()) {
        console.log(
            `Encrypted aggregate bridge row started: n=${variant.rosterSize}, m=${variant.optionCount}`,
        );
        const result = (() => {
            try {
                return buildVariant({ kernel, variant });
            } catch (error) {
                return failedVariantResult(variant, error);
            }
        })();
        results.push({ ...result, variantIndex });
        console.log(
            `Encrypted aggregate bridge row finished: n=${variant.rosterSize}, m=${variant.optionCount}`,
        );
    }

    return results;
};

const runParallelVariantBuilds = async (input: {
    readonly variants: readonly Variant[];
    readonly workerCount: number;
}): Promise<readonly IndexedVariantBuildResult[]> => {
    const results: IndexedVariantBuildResult[] = [];
    let nextVariantIndex = 0;
    const workerSlotCount = Math.min(input.workerCount, input.variants.length);
    await Promise.all(
        Array.from(
            { length: workerSlotCount },
            async (_unused, workerIndex) => {
                while (true) {
                    const variantIndex = nextVariantIndex;
                    nextVariantIndex += 1;
                    const variant = input.variants[variantIndex];
                    if (variant === undefined) {
                        break;
                    }
                    console.log(
                        `Encrypted aggregate bridge row started: n=${variant.rosterSize}, m=${variant.optionCount}, worker=${workerIndex + 1}`,
                    );
                    const result = await runVariantInChildProcess(variant);
                    results.push({ ...result, variantIndex });
                    console.log(
                        `Encrypted aggregate bridge row finished: n=${variant.rosterSize}, m=${variant.optionCount}, worker=${workerIndex + 1}, status=${result.proofRow.status}`,
                    );
                }
            },
        ),
    );

    return [...results].sort(
        (left, right) => left.variantIndex - right.variantIndex,
    );
};

const appendVariantResult = (input: {
    readonly aggregateReadyRows: MatrixRow[];
    readonly benchmarkRows: MatrixRow[];
    readonly negativeChecks: NegativeCheck[];
    readonly privateRows: MatrixRow[];
    readonly proofRows: MatrixRow[];
    readonly result: VariantBuildResult;
}): void => {
    input.privateRows.push(input.result.privateRelationRow);
    input.proofRows.push(input.result.proofRow);
    input.aggregateReadyRows.push(input.result.aggregateReadyRow);
    input.negativeChecks.push(...input.result.negativeChecks);
    if (input.result.benchmarkRow !== null) {
        input.benchmarkRows.push(input.result.benchmarkRow);
    }
};

const main = async (): Promise<void> => {
    if (await runWorkerRow()) {
        return;
    }

    const mode = matrixMode();
    const variants = variantsForMode(mode);
    const workerCount = requestedWorkerCount();
    await mkdir(outputDirectory, { recursive: true });
    const privateRows: MatrixRow[] = [];
    const proofRows: MatrixRow[] = [];
    const aggregateReadyRows: MatrixRow[] = [];
    const benchmarkRows: MatrixRow[] = [];
    const negativeChecks: NegativeCheck[] = [];
    const variantResults =
        workerCount <= 1
            ? await runSequentialVariantBuilds(variants)
            : await runParallelVariantBuilds({ variants, workerCount });
    for (const result of variantResults) {
        appendVariantResult({
            aggregateReadyRows,
            benchmarkRows,
            negativeChecks,
            privateRows,
            proofRows,
            result,
        });
    }
    const slowestRow = [...proofRows]
        .filter((row) => row.status === 'passed')
        .sort((left, right) => right.proverTime - left.proverTime)[0];
    const benchmarkRowsByVariant = new Map(
        benchmarkRows.map((row) => [
            variantKey({
                optionCount: row.optionCount,
                rosterSize: row.rosterSize,
            }),
            row,
        ]),
    );
    if (slowestRow !== undefined) {
        benchmarkRowsByVariant.set(
            variantKey({
                optionCount: slowestRow.optionCount,
                rosterSize: slowestRow.rosterSize,
            }),
            slowestRow,
        );
    }
    const finalBenchmarkRows = [...benchmarkRowsByVariant.values()];
    const allRowsPassed =
        proofRows.every((row) => row.status === 'passed') &&
        aggregateReadyRows.every((row) => row.status === 'passed') &&
        privateRows.every((row) => row.status === 'passed');
    const allNegativesPassed = negativeChecks.every(
        (check) => check.expectedFailureObserved,
    );
    const closureLedger = {
        labels: {
            M9AggregateReadyVariantMatrixClosed:
                allRowsPassed && mode === 'full',
            M9PrivateRelationVariantMatrixClosed:
                allRowsPassed && mode === 'full',
            M9ProofVariantMatrixClosed: allRowsPassed && mode === 'full',
            M9Prototype20x20Closed: proofRows.some(
                (row) =>
                    row.rosterSize === 20 &&
                    row.optionCount === 20 &&
                    row.status === 'passed',
            ),
            M9ScopedRelationClosed:
                allRowsPassed && allNegativesPassed && mode === 'full',
        },
        mode,
        negativeChecksPassed: allNegativesPassed,
        rowCount: proofRows.length,
        rowsPassed: allRowsPassed,
        requiredFullMatrixRowCount: 342,
    };

    await writeArtifact(
        'm9-private-relation-variant-matrix.json',
        `${canonicalJson({ mode, rows: privateRows })}\n`,
    );
    await writeArtifact(
        'm9-private-relation-variant-matrix.md',
        matrixMarkdown({
            rows: privateRows,
            title: 'Encrypted aggregate bridge private relation variant matrix',
        }),
    );
    await writeArtifact(
        'm9-proof-variant-matrix.json',
        `${canonicalJson({ mode, rows: proofRows })}\n`,
    );
    await writeArtifact(
        'm9-proof-variant-matrix.md',
        matrixMarkdown({
            rows: proofRows,
            title: 'Encrypted aggregate bridge proof variant matrix',
        }),
    );
    await writeArtifact(
        'm9-aggregate-ready-variant-matrix.json',
        `${canonicalJson({ mode, rows: aggregateReadyRows })}\n`,
    );
    await writeArtifact(
        'm9-aggregate-ready-variant-matrix.md',
        matrixMarkdown({
            rows: aggregateReadyRows,
            title: 'Encrypted aggregate bridge aggregate-ready variant matrix',
        }),
    );
    await writeArtifact(
        'm9-negative-fixture-report.json',
        `${canonicalJson({ checks: negativeChecks, mode })}\n`,
    );
    await writeArtifact(
        'm9-negative-fixture-report.md',
        negativeMarkdown(negativeChecks),
    );
    await writeArtifact(
        'm9-benchmark-report.json',
        `${canonicalJson({ mode, rows: finalBenchmarkRows })}\n`,
    );
    await writeArtifact(
        'm9-benchmark-report.md',
        matrixMarkdown({
            rows: finalBenchmarkRows,
            title: 'Encrypted aggregate bridge benchmark report',
        }),
    );
    await writeArtifact(
        'm9-closure-ledger.json',
        `${canonicalJson(closureLedger)}\n`,
    );
    await writeArtifact(
        'm9-closure-ledger.md',
        [
            '# Encrypted aggregate bridge closure ledger',
            '',
            `Mode: ${mode}`,
            `Rows passed: ${allRowsPassed ? 'yes' : 'no'}`,
            `Negative checks passed: ${allNegativesPassed ? 'yes' : 'no'}`,
            `M9Prototype20x20Closed: ${closureLedger.labels.M9Prototype20x20Closed ? 'true' : 'false'}`,
            `M9PrivateRelationVariantMatrixClosed: ${closureLedger.labels.M9PrivateRelationVariantMatrixClosed ? 'true' : 'false'}`,
            `M9ProofVariantMatrixClosed: ${closureLedger.labels.M9ProofVariantMatrixClosed ? 'true' : 'false'}`,
            `M9AggregateReadyVariantMatrixClosed: ${closureLedger.labels.M9AggregateReadyVariantMatrixClosed ? 'true' : 'false'}`,
            `M9ScopedRelationClosed: ${closureLedger.labels.M9ScopedRelationClosed ? 'true' : 'false'}`,
            '',
        ].join('\n'),
    );
    if (!allRowsPassed || !allNegativesPassed) {
        process.exitCode = 1;
    }
};

await main();
