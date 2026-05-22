import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

import type { ClaimBearingBallotPackage } from '@sealed-lattice/types';

import {
    loadTranscriptCoreKernel,
    type BallotPrivacyKernelVerification,
    type BallotPrivacyProofGeneration,
} from '../../../src/index';

import {
    aggregateWitnessFromReceiverPlaintext,
    type AggregateDerivationWitnessInput,
} from '#packages/protocol/src/ballot-privacy/index';
import { createMandatoryProfileBallotProofRecordGenerationFixture } from '#tests/support/ballot-privacy-proof-record-generation-fixtures';

type CeremonyPublicInput = {
    readonly ceremonyId: string;
    readonly duplicateBallotPolicyDigest: string;
    readonly manifestDigest: string;
    readonly pollSpecDigest: string;
    readonly receiverKeyProofRoot: string;
    readonly receiverKeyRoot: string;
    readonly rosterDigest: string;
    readonly scoreDomainDigest: string;
    readonly thresholdProfileDigest: string;
    readonly tiePolicyDigest: string;
};

type VoterPrivateInput = {
    readonly actionContextDigest: string;
    readonly normalizedScores: readonly number[];
    readonly payloadContextDigest: string;
    readonly randomnessSeedLabel: string;
    readonly rosterExternalAcceptanceDigest: string;
    readonly voterIdentity: string;
    readonly voterIdentityDigest: string;
    readonly voterRosterPosition: number;
    readonly voterSigningKeyDigest: string;
};

export type FullCeremonyVoterWorkerInput = {
    readonly ceremony: CeremonyPublicInput;
    readonly contributorRosterPosition: number;
    readonly voter: VoterPrivateInput;
};

type VerificationSummary = {
    readonly acceptedDigests: readonly string[];
    readonly ok: boolean;
    readonly operation: string;
    readonly refusedMessages: readonly string[];
    readonly statusLabels: readonly string[];
    readonly unresolvedReason: string | null;
};

export type FullCeremonyPublicVoterArtifact = {
    readonly ballotPackage: ClaimBearingBallotPackage;
    readonly ballotPackageDigest: string;
    readonly packageVerification: VerificationSummary;
    readonly schemaVersion: 1;
    readonly voterIdentity: string;
    readonly voterRosterPosition: number;
};

export type FullCeremonyVoterWorkerOutput = {
    readonly contributorWitness: AggregateDerivationWitnessInput;
    readonly oracleScoreMetadata: {
        readonly normalizedScores: readonly number[];
        readonly voterIdentity: string;
    };
    readonly publicArtifact: FullCeremonyPublicVoterArtifact;
};

const summarizeVerification = (
    verification: BallotPrivacyKernelVerification,
): VerificationSummary => ({
    acceptedDigests: verification.acceptedDigests,
    ok: verification.ok,
    operation: verification.operation,
    refusedMessages: verification.refusedObjects.map(
        (refusal) => refusal.message,
    ),
    statusLabels: verification.statusLabels,
    unresolvedReason: verification.unresolvedReason,
});

const createFixtureBallotPackage = (input: {
    readonly fixture: ReturnType<
        typeof createMandatoryProfileBallotProofRecordGenerationFixture
    >;
    readonly generation: BallotPrivacyProofGeneration;
}): ClaimBearingBallotPackage =>
    ({
        objectType: 'ClaimBearingBallotPackage',
        objectVersion: 1,
        ballotPackageDigest:
            input.fixture.request.statement.ballotPackageDigest,
        ballotProofStatement: input.fixture.request.statement,
        ballotProof: input.generation.ballotProof,
        proofBytesHex: input.generation.proofBytesHex,
        linearStatement: input.fixture.request.linearStatement,
        parameterSet: input.generation.parameterSet,
        proofEncoding: input.generation.proofEncoding,
        publicRandomnessHex: input.fixture.request.publicRandomnessHex,
        componentBundleStatement:
            input.fixture.request.componentBundleStatement,
        componentProofBundle: input.generation.componentProofBundle,
        componentProofInputs: input.generation.componentProofInputs,
        receiverKeyProofRootEvidence:
            input.fixture.receiverKeyProofRootEvidence,
        receiverPayloads: input.fixture.claimBearingReceiverPayloads,
        shareCommitments: input.fixture.claimBearingShareCommitments,
    }) as ClaimBearingBallotPackage;

const contributorWitnessFromFixture = (input: {
    readonly contributorRosterPosition: number;
    readonly fixture: ReturnType<
        typeof createMandatoryProfileBallotProofRecordGenerationFixture
    >;
}): AggregateDerivationWitnessInput => {
    const receiverPayloadPlaintext =
        input.fixture.projectionWitness.receiverPayloadPlaintexts?.find(
            (plaintext) =>
                plaintext.receiverRosterPosition ===
                input.contributorRosterPosition,
        );
    const shareCommitmentOpening =
        input.fixture.projectionWitness.shareCommitmentOpenings.find(
            (opening) =>
                opening.receiverRosterPosition ===
                input.contributorRosterPosition,
        );
    if (
        receiverPayloadPlaintext === undefined ||
        shareCommitmentOpening === undefined
    ) {
        throw new Error(
            'Full ceremony voter fixture is missing contributor witness material.',
        );
    }

    return aggregateWitnessFromReceiverPlaintext({
        openingRandomness: shareCommitmentOpening.openingRandomness,
        receiverShareVector: receiverPayloadPlaintext.receiverShareVector,
    });
};

const requireSuccessfulGeneration = (
    generation: BallotPrivacyProofGeneration,
): void => {
    if (!generation.ok || generation.generatedProofBytes !== true) {
        throw new Error(
            `Ballot proof generation failed: ${generation.refusedObjects
                .map((refusal) => refusal.message)
                .join(' ')}`,
        );
    }
};

const requireSuccessfulVerification = (
    verification: BallotPrivacyKernelVerification,
): void => {
    if (!verification.ok) {
        throw new Error(
            `Ballot package verification failed: ${verification.refusedObjects
                .map((refusal) => refusal.message)
                .join(' ')}`,
        );
    }
};

export const generateFullCeremonyVoterArtifact = async (
    input: FullCeremonyVoterWorkerInput,
): Promise<FullCeremonyVoterWorkerOutput> => {
    const fixture = createMandatoryProfileBallotProofRecordGenerationFixture({
        normalizedScores: input.voter.normalizedScores,
        randomnessSeedLabel: input.voter.randomnessSeedLabel,
        statementContext: {
            actionContextDigest: input.voter.actionContextDigest,
            ceremonyId: input.ceremony.ceremonyId,
            duplicateBallotPolicyDigest:
                input.ceremony.duplicateBallotPolicyDigest,
            manifestDigest: input.ceremony.manifestDigest,
            payloadContextDigest: input.voter.payloadContextDigest,
            pollSpecDigest: input.ceremony.pollSpecDigest,
            receiverKeyProofRoot: input.ceremony.receiverKeyProofRoot,
            receiverKeyRoot: input.ceremony.receiverKeyRoot,
            rosterDigest: input.ceremony.rosterDigest,
            rosterExternalAcceptanceDigest:
                input.voter.rosterExternalAcceptanceDigest,
            scoreDomainDigest: input.ceremony.scoreDomainDigest,
            thresholdProfileDigest: input.ceremony.thresholdProfileDigest,
            tiePolicyDigest: input.ceremony.tiePolicyDigest,
            voterIdentityDigest: input.voter.voterIdentityDigest,
            voterRosterPosition: input.voter.voterRosterPosition,
            voterSigningKeyDigest: input.voter.voterSigningKeyDigest,
        },
    });
    const kernel = await loadTranscriptCoreKernel();
    const generation = kernel.generateBallotProofRecord(fixture.request);
    requireSuccessfulGeneration(generation);

    const ballotPackage = createFixtureBallotPackage({
        fixture,
        generation,
    });
    const packageVerification = kernel.verifyClaimBearingBallotPackage({
        ballotPackage,
    });
    requireSuccessfulVerification(packageVerification);

    return {
        contributorWitness: contributorWitnessFromFixture({
            contributorRosterPosition: input.contributorRosterPosition,
            fixture,
        }),
        oracleScoreMetadata: {
            normalizedScores: input.voter.normalizedScores,
            voterIdentity: input.voter.voterIdentity,
        },
        publicArtifact: {
            ballotPackage,
            ballotPackageDigest: ballotPackage.ballotPackageDigest,
            packageVerification: summarizeVerification(packageVerification),
            schemaVersion: 1,
            voterIdentity: input.voter.voterIdentity,
            voterRosterPosition: input.voter.voterRosterPosition,
        },
    };
};

const runWorkerFromStandardInput = async (): Promise<void> => {
    const inputText = readFileSync(0, 'utf8');
    const workerInput = JSON.parse(inputText) as FullCeremonyVoterWorkerInput;
    const output = await generateFullCeremonyVoterArtifact(workerInput);

    process.stdout.write(JSON.stringify(output));
};

const scriptEntryPoint = process.argv[1];
const isMainModule =
    scriptEntryPoint !== undefined &&
    import.meta.url === pathToFileURL(scriptEntryPoint).href;

if (isMainModule) {
    await runWorkerFromStandardInput();
}
