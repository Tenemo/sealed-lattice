import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';

import { deriveProtocolHash } from '#packages/crypto/src/hashes.js';
import { buildEncodedScoreFieldLinearProofProjection } from '#packages/protocol/src/ballot-privacy/ballot-proof-linear-statement.js';
import {
    createBallotPrivacyProfileSet,
    createShareCommitmentMessageBoundCert,
} from '#packages/protocol/src/ballot-privacy/profiles.js';
import { lowerBallotPrivacyRelationToBackendStatement } from '#packages/protocol/src/ballot-privacy/relation-backend-lowering.js';
import type { BallotPrivacyRelationBackendPublicContext } from '#packages/protocol/src/ballot-privacy/relation-backend-lowering.js';
import type { BallotPrivacyRelationCompilerInput } from '#packages/protocol/src/ballot-privacy/relation-compiler.js';
import type { ProtocolHash } from '#packages/types/src/index.js';

const parameterProfileId = 'encoded-score-field-linear-proof-parameter-v1';
const sourceRingDegree = 64;
const witnessL2BoundSquared = '65536';

const hash = (label: string): ProtocolHash =>
    deriveProtocolHash('ChallengeDomainHash', {
        label,
        purpose: 'ballot-field-linear-proof-vector-input',
    });

const oneHotScore = (score: number): readonly number[] =>
    Array.from({ length: 10 }, (_unusedValue, scoreIndex) =>
        scoreIndex + 1 === score ? 1 : 0,
    );

// Hand-tuned 2-option/3-receiver mini relation: scores 7 and 3, with the per-option
// scalar share given by Shamir evaluation of a degree-1 polynomial at the roster point
// (firstOption shares 6,5,4 for receivers 1,2,3 fit slope -1; secondOption 12,21,30
// fit slope 9). oneHotScore(7)/oneHotScore(3) carry the one-hot bucket witnesses.
const miniEncodedShareVector = (input: {
    readonly firstOptionScoreShare: number;
    readonly secondOptionScoreShare: number;
}): readonly number[] => [
    input.firstOptionScoreShare,
    ...oneHotScore(7),
    input.secondOptionScoreShare,
    ...oneHotScore(3),
];

// Per-coordinate degree-1 Shamir coefficients: [65_536] is the slope for option-1's
// scalar (65536 == -1 mod 65537), [9] is option-2's slope; all bucket coordinates have
// slope 0. The constant terms (the recovered scores) live in the shares above.
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
            receiverIdentity: 'receiver-1',
            receiverRosterPosition: 1,
            receiverShareVector: miniEncodedShareVector({
                firstOptionScoreShare: 6,
                secondOptionScoreShare: 12,
            }),
        },
        {
            receiverIdentity: 'receiver-2',
            receiverRosterPosition: 2,
            receiverShareVector: miniEncodedShareVector({
                firstOptionScoreShare: 5,
                secondOptionScoreShare: 21,
            }),
        },
        {
            receiverIdentity: 'receiver-3',
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
        actionContextHash: hash(`action-context-${rosterSize}`),
        aggregateInputEncodingProfileHash:
            profileSet.aggregateInputEncodingProfile
                .aggregateInputEncodingProfileHash,
        ballotProofProfileHash:
            profileSet.ballotProofProfile.ballotProofProfileHash,
        ballotProofStatementHash: hash(`ballot-proof-statement-${rosterSize}`),
        ballotScoreEncodingProfileHash:
            profileSet.ballotScoreEncodingProfile
                .ballotScoreEncodingProfileHash,
        ballotShareLayoutProfileHash:
            profileSet.ballotShareLayoutProfile.ballotShareLayoutProfileHash,
        ceremonyId: `ballot-field-linear-proof-vector-${rosterSize}`,
        encodedAggregateLayoutHash:
            profileSet.encodedAggregateLayoutProfile.encodedAggregateLayoutHash,
        encodedShareVectorLayoutHash:
            profileSet.encodedShareVectorLayoutProfile
                .encodedShareVectorLayoutHash,
        manifestHash: hash(`manifest-${rosterSize}`),
        pollSpecHash: hash(`poll-spec-${rosterSize}`),
        receiverEncryptionProfileHash:
            profileSet.receiverEncryptionProfile.receiverEncryptionProfileHash,
        receiverKeyProofRoot: hash(`receiver-key-proof-root-${rosterSize}`),
        receiverKeyRoot: hash(`receiver-key-root-${rosterSize}`),
        receiverPayloads: receiverReferences.map((receiverReference) => ({
            ciphertextBodyHash: hash(
                `receiver-payload-ciphertext-body-${rosterSize}-${receiverReference.receiverRosterPosition}`,
            ),
            ciphertextChunkCount: 1,
            ciphertextChunkHash: hash(
                `receiver-payload-ciphertext-chunks-${rosterSize}-${receiverReference.receiverRosterPosition}`,
            ),
            // 704 = 64 coordinates x 11 bits, matching the encoded payload layout.
            plaintextBitLength: 704,
            ...receiverReference,
            receiverPayloadCiphertextRoot: hash(
                `receiver-payload-ciphertext-root-${rosterSize}-${receiverReference.receiverRosterPosition}`,
            ),
            receiverPayloadHash: hash(
                `receiver-payload-${rosterSize}-${receiverReference.receiverRosterPosition}`,
            ),
        })),
        receiverPublicKeys: receiverReferences.map((receiverReference) => ({
            keyMaterialHash: hash(
                `receiver-public-key-material-${rosterSize}-${receiverReference.receiverRosterPosition}`,
            ),
            publicMatrixSeedHash: hash(
                `receiver-public-matrix-seed-${rosterSize}-${receiverReference.receiverRosterPosition}`,
            ),
            ...receiverReference,
            receiverPublicKeyHash: hash(
                `receiver-public-key-${rosterSize}-${receiverReference.receiverRosterPosition}`,
            ),
        })),
        rosterHash: hash(`roster-${rosterSize}`),
        rosterExternalAcceptanceHash: hash(
            `roster-external-acceptance-${rosterSize}`,
        ),
        scoreMembershipProfileHash:
            profileSet.scoreMembershipProfile.scoreMembershipProfileHash,
        shareCommitmentMessageBoundCertHash:
            certificate.shareCommitmentMessageBoundCertHash,
        shareCommitmentProfileHash:
            profileSet.shareCommitmentProfile.shareCommitmentProfileHash,
        shareCommitments: receiverReferences.map((receiverReference) => ({
            commitmentBodyHash: hash(
                `share-commitment-body-${rosterSize}-${receiverReference.receiverRosterPosition}`,
            ),
            commitmentPolynomialVectorHash: hash(
                `share-commitment-polynomial-vector-${rosterSize}-${receiverReference.receiverRosterPosition}`,
            ),
            ...receiverReference,
            shareCommitmentHash: hash(
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
                .join('; ')}`,
        );
    }

    const projection = buildEncodedScoreFieldLinearProofProjection({
        ballotProofStatementHash: publicContext.ballotProofStatementHash,
        loweredStatement: loweringResult.statement,
        parameterProfileId,
        relationInput,
        sourceRingDegree,
        witnessL2BoundSquared,
    });
    const output = {
        generationStatus: 'generated',
        objectType: 'BallotFieldLinearProofOracleInput',
        objectVersion: 1,
        parameterProfileId,
        projectionCoverage: 'encoded-score-field-rows-only',
        relationShape: {
            optionCount: relationInput.optionCount,
            rosterSize: relationInput.rosterSize,
            shareVectorWidth: relationInput.optionCount * 11,
            statementColumns: projection.linearStatement.statementColumns,
            statementRows: projection.linearStatement.statementRows,
        },
        relationStatementHash: loweringResult.statement.relationStatementHash,
        backendStatementHash:
            loweringResult.statement.backendStatement.backendStatementHash,
        linearStatement: projection.linearStatement,
        privateWitnessVectorCoefficients:
            projection.privateWitnessVectorCoefficients,
        sourceBackendColumnIndices: projection.sourceBackendColumnIndices,
        sourceRowBatchName: projection.sourceRowBatchName,
    };

    await mkdir(path.dirname(outputPath), { recursive: true });
    await writeFile(outputPath, `${JSON.stringify(output)}\n`);
};
