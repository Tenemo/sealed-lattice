import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";

import { deriveProtocolDigest } from "#packages/crypto/src/digests.js";
import {
    createBallotPrivacyProfileSet,
    createShareCommitmentMessageBoundCert,
} from "#packages/protocol/src/ballot-privacy/profiles.js";
import { buildEncodedScoreFieldLinearProofProjection } from "#packages/protocol/src/ballot-privacy/ballot-proof-linear-statement.js";
import { lowerBallotPrivacyRelationToBackendStatement } from "#packages/protocol/src/ballot-privacy/relation-backend-lowering.js";
import type { BallotPrivacyRelationBackendPublicContext } from "#packages/protocol/src/ballot-privacy/relation-backend-lowering.js";
import type { BallotPrivacyRelationCompilerInput } from "#packages/protocol/src/ballot-privacy/relation-compiler.js";
import type { ProtocolDigest } from "#packages/types/src/index.js";

const parameterProfileId = "encoded-score-field-linear-compatibility-v1";
const sourceRingDegree = 64;
const witnessL2BoundSquared = "65536";

const digest = (label: string): ProtocolDigest =>
    deriveProtocolDigest("ChallengeDomainDigest", {
        label,
        purpose: "ballot-field-linear-proof-vector-input",
    });

const oneHotScore = (score: number): readonly number[] =>
    Array.from({ length: 10 }, (_unusedValue, scoreIndex) =>
        scoreIndex + 1 === score ? 1 : 0,
    );

const miniEncodedShareVector = (input: {
    readonly firstOptionScoreShare: number;
    readonly secondOptionScoreShare: number;
}): readonly number[] => [
    input.firstOptionScoreShare,
    ...oneHotScore(7),
    input.secondOptionScoreShare,
    ...oneHotScore(3),
];

const miniEncodedCoordinateShamirCoefficients =
    (): readonly (readonly number[])[] => [
        [65_536],
        ...Array.from({ length: 10 }, () => [0] as const),
        [9],
        ...Array.from({ length: 10 }, () => [0] as const),
    ];

const miniRelationInput = (): BallotPrivacyRelationCompilerInput => ({
    encodedCoordinateShamirCoefficients:
        miniEncodedCoordinateShamirCoefficients(),
    normalizedScores: [7, 3],
    optionCount: 2,
    pvssThreshold: 2,
    receivers: [
        {
            receiverIdentity: "receiver-1",
            receiverRosterPosition: 1,
            receiverShareVector: miniEncodedShareVector({
                firstOptionScoreShare: 6,
                secondOptionScoreShare: 12,
            }),
        },
        {
            receiverIdentity: "receiver-2",
            receiverRosterPosition: 2,
            receiverShareVector: miniEncodedShareVector({
                firstOptionScoreShare: 5,
                secondOptionScoreShare: 21,
            }),
        },
        {
            receiverIdentity: "receiver-3",
            receiverRosterPosition: 3,
            receiverShareVector: miniEncodedShareVector({
                firstOptionScoreShare: 4,
                secondOptionScoreShare: 30,
            }),
        },
    ],
    rosterSize: 3,
    scoreOneHotWitnesses: [oneHotScore(7), oneHotScore(3)],
});

const publicContextForRoster = (
    rosterSize: number,
): BallotPrivacyRelationBackendPublicContext => {
    const profileSet = createBallotPrivacyProfileSet();
    const certificate = createShareCommitmentMessageBoundCert({
        maximumCanonicalTurnout: Math.max(20, rosterSize),
        shareCommitmentProfile: profileSet.shareCommitmentProfile,
    });
    const receiverReferences = Array.from(
        { length: rosterSize },
        (_unusedValue, receiverOffset) => ({
            receiverIdentity: `receiver-${receiverOffset + 1}`,
            receiverRosterPosition: receiverOffset + 1,
        }),
    );

    return {
        actionContextDigest: digest(`action-context-${rosterSize}`),
        aggregateInputEncodingProfileDigest:
            profileSet.aggregateInputEncodingProfile
                .aggregateInputEncodingProfileDigest,
        ballotProofProfileDigest:
            profileSet.ballotProofProfile.ballotProofProfileDigest,
        ballotProofStatementDigest: digest(
            `ballot-proof-statement-${rosterSize}`,
        ),
        ballotScoreEncodingProfileDigest:
            profileSet.ballotScoreEncodingProfile
                .ballotScoreEncodingProfileDigest,
        ballotShareLayoutProfileDigest:
            profileSet.ballotShareLayoutProfile.ballotShareLayoutProfileDigest,
        ceremonyId: `ballot-field-linear-proof-vector-${rosterSize}`,
        encodedAggregateLayoutDigest:
            profileSet.encodedAggregateLayoutProfile
                .encodedAggregateLayoutDigest,
        encodedShareVectorLayoutDigest:
            profileSet.encodedShareVectorLayoutProfile
                .encodedShareVectorLayoutDigest,
        manifestDigest: digest(`manifest-${rosterSize}`),
        pollSpecDigest: digest(`poll-spec-${rosterSize}`),
        receiverEncryptionProfileDigest:
            profileSet.receiverEncryptionProfile
                .receiverEncryptionProfileDigest,
        receiverKeyProofRoot: digest(`receiver-key-proof-root-${rosterSize}`),
        receiverKeyRoot: digest(`receiver-key-root-${rosterSize}`),
        receiverPayloads: receiverReferences.map((receiverReference) => ({
            ciphertextBodyDigest: digest(
                `receiver-payload-ciphertext-body-${rosterSize}-${receiverReference.receiverRosterPosition}`,
            ),
            ciphertextChunkCount: 1,
            ciphertextChunkDigest: digest(
                `receiver-payload-ciphertext-chunks-${rosterSize}-${receiverReference.receiverRosterPosition}`,
            ),
            plaintextBitLength: 704,
            ...receiverReference,
            receiverPayloadCiphertextRoot: digest(
                `receiver-payload-ciphertext-root-${rosterSize}-${receiverReference.receiverRosterPosition}`,
            ),
            receiverPayloadDigest: digest(
                `receiver-payload-${rosterSize}-${receiverReference.receiverRosterPosition}`,
            ),
        })),
        receiverPublicKeys: receiverReferences.map((receiverReference) => ({
            keyMaterialDigest: digest(
                `receiver-public-key-material-${rosterSize}-${receiverReference.receiverRosterPosition}`,
            ),
            publicMatrixSeedDigest: digest(
                `receiver-public-matrix-seed-${rosterSize}-${receiverReference.receiverRosterPosition}`,
            ),
            ...receiverReference,
            receiverPublicKeyDigest: digest(
                `receiver-public-key-${rosterSize}-${receiverReference.receiverRosterPosition}`,
            ),
        })),
        rosterDigest: digest(`roster-${rosterSize}`),
        rosterExternalAcceptanceDigest: digest(
            `roster-external-acceptance-${rosterSize}`,
        ),
        scoreMembershipProfileDigest:
            profileSet.scoreMembershipProfile.scoreMembershipProfileDigest,
        shareCommitmentMessageBoundCertDigest:
            certificate.shareCommitmentMessageBoundCertDigest,
        shareCommitmentProfileDigest:
            profileSet.shareCommitmentProfile.shareCommitmentProfileDigest,
        shareCommitments: receiverReferences.map((receiverReference) => ({
            commitmentBodyDigest: digest(
                `share-commitment-body-${rosterSize}-${receiverReference.receiverRosterPosition}`,
            ),
            commitmentPolynomialVectorDigest: digest(
                `share-commitment-polynomial-vector-${rosterSize}-${receiverReference.receiverRosterPosition}`,
            ),
            ...receiverReference,
            shareCommitmentDigest: digest(
                `share-commitment-${rosterSize}-${receiverReference.receiverRosterPosition}`,
            ),
        })),
    };
};

export const generateBallotFieldLinearProofOracleInput = async (
    outputPath: string,
): Promise<void> => {
    const relationInput = miniRelationInput();
    const publicContext = publicContextForRoster(relationInput.rosterSize);
    const loweringResult = lowerBallotPrivacyRelationToBackendStatement({
        publicContext,
        relationInput,
    });
    if (!loweringResult.ok) {
        throw new Error(
            `Mini encoded-score relation did not lower: ${loweringResult.refusedObjects
                .map((refusal) => refusal.message)
                .join("; ")}`,
        );
    }

    const projection = buildEncodedScoreFieldLinearProofProjection({
        ballotProofStatementDigest: publicContext.ballotProofStatementDigest,
        loweredStatement: loweringResult.statement,
        parameterProfileId,
        relationInput,
        sourceRingDegree,
        witnessL2BoundSquared,
    });
    const output = {
        generationStatus: "generated",
        objectType: "BallotFieldLinearProofOracleInput",
        objectVersion: 1,
        parameterProfileId,
        projectionCoverage: "encoded-score-field-rows-only",
        relationShape: {
            optionCount: relationInput.optionCount,
            rosterSize: relationInput.rosterSize,
            shareVectorWidth: relationInput.optionCount * 11,
            statementColumns: projection.linearStatement.statementColumns,
            statementRows: projection.linearStatement.statementRows,
        },
        relationStatementDigest:
            loweringResult.statement.relationStatementDigest,
        backendStatementDigest:
            loweringResult.statement.backendStatement.backendStatementDigest,
        linearStatement: projection.linearStatement,
        privateWitnessVectorCoefficients:
            projection.privateWitnessVectorCoefficients,
        sourceBackendColumnIndices: projection.sourceBackendColumnIndices,
        sourceRowBatchName: projection.sourceRowBatchName,
    };

    await mkdir(path.dirname(outputPath), { recursive: true });
    await writeFile(outputPath, `${JSON.stringify(output)}\n`);
};
